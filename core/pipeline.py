"""
Orquestracao do pipeline de analise.

Concentra a ordem das etapas, o que cada uma alimenta e o tratamento de
falha. Fica aqui, e nao no main.py, porque a interface grafica precisa
executar exatamente a mesma analise - duplicar a orquestracao entre CLI e
GUI garantiria que as duas divergissem com o tempo.

Duas regras que valem para o pipeline inteiro:

  1. Falha de uma etapa nao derruba as outras. Se o PE nao parseia, o
     mapeamento ATT&CK segue com as strings; se o VirusTotal esta fora do
     ar, o resto do relatorio continua valendo. Cada falha vira um registro
     em `erros`, com o estagio identificado, e o relatorio mostra o que
     faltou em vez de fingir completude.

  2. Nenhuma consulta externa acontece sem pedido explicito. O padrao de
     `OpcoesAnalise.enriquecer` e False: consultar o VirusTotal revela a
     terceiros quais hashes voce esta investigando, e essa decisao e do
     analista.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable

from core import (
    cvss_calculator,
    deobfuscator,
    group_attribution,
    killchain,
    mitre_mapper,
    pe_analyzer,
    string_extractor,
    yara_generator,
)
from core import resumo_ia as resumo_ia_mod

logger = logging.getLogger(__name__)


class Estagio(str, Enum):
    """Etapas do pipeline, na ordem de execucao."""

    EXTRACAO = "Extracao de strings"
    PE = "Analise do PE"
    DESOFUSCACAO = "Desofuscacao"
    YARA = "Geracao da regra YARA"
    MITRE = "Mapeamento ATT&CK"
    KILLCHAIN = "Cyber Kill Chain"
    ATRIBUICAO = "Atribuicao de grupo"
    CVSS = "Score CVSS"
    VIRUSTOTAL = "Consulta ao VirusTotal"
    SHODAN = "Consulta ao Shodan"
    MALWAREBAZAAR = "Consulta ao MalwareBazaar"
    RESUMO_IA = "Resumo por IA local"
    CONCLUIDO = "Concluido"


# Callback de progresso: (estagio, mensagem, fracao de 0.0 a 1.0).
CallbackProgresso = Callable[[Estagio, str, float], None]

# Callback de cancelamento: devolve True quando o usuario pediu para parar.
CallbackCancelamento = Callable[[], bool]


@dataclass
class OpcoesAnalise:
    """O que executar e como."""

    # --- Analise local ---
    usar_floss: bool = True
    # "auto", "pe", "sc32" ou "sc64". Em auto, artefato sem cabecalho de PE
    # e tentado como shellcode nas duas arquiteturas.
    formato: str = "auto"
    tamanho_minimo_de_string: int = 4
    timeout_floss: int = 300
    gerar_yara: bool = True
    maximo_de_strings_yara: int = 20
    amostras_benignas: list[str] = field(default_factory=list)

    # --- ATT&CK ---
    usar_stix: bool = True
    baixar_stix_se_faltar: bool = True
    caminho_cache_stix: str = ""

    # --- CVSS (so quando o artefato explora CVE conhecida) ---
    vetor_cvss: str = ""
    cve: str = ""

    # --- Enriquecimento externo ---
    # Padrao False por design: consulta externa revela a terceiros o que
    # esta sendo investigado, e isso precisa ser escolha consciente.
    enriquecer: bool = False
    maximo_de_consultas: int = 20

    # --- Resumo por LLM local ---
    # Roda no Ollama em localhost: nenhum dado sai da maquina. Ainda assim
    # e opcional, porque depende de um servico externo ao processo estar
    # de pe e custa tempo de geracao.
    resumo_ia: bool = False
    modelo_ia: str = "llama3.1:8b"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ErroDeEstagio:
    """Falha de uma etapa, sem interromper as demais."""

    estagio: Estagio
    mensagem: str
    fatal: bool = False

    def __str__(self) -> str:
        return f"{self.estagio.value}: {self.mensagem}"

    def to_dict(self) -> dict:
        return {
            "estagio": self.estagio.value,
            "mensagem": self.mensagem,
            "fatal": self.fatal,
        }


@dataclass
class ResultadoAnalise:
    """Tudo que o pipeline produziu para um artefato."""

    caminho: str
    iniciado_em: str = ""
    concluido_em: str = ""
    duracao_segundos: float = 0.0
    cancelado: bool = False

    opcoes: OpcoesAnalise = field(default_factory=OpcoesAnalise)

    # --- Resultados por etapa (None quando a etapa nao rodou) ---
    extracao: string_extractor.ResultadoExtracao | None = None
    info_pe: pe_analyzer.InfoPE | None = None
    desofuscacao: deobfuscator.ResultadoDesofuscacao | None = None
    regra_yara: yara_generator.RegraYara | None = None
    mapeamento: mitre_mapper.ResultadoMapeamento | None = None
    kill_chain: killchain.ResultadoKillChain | None = None
    atribuicao: group_attribution.ResultadoAtribuicao | None = None
    cvss: cvss_calculator.ResultadoCVSS | None = None
    virustotal: list = field(default_factory=list)
    shodan: list = field(default_factory=list)
    # Consultas a NVD, uma por CVE citada pelo artefato.
    nvd: list = field(default_factory=list)
    # ResultadoMalwareBazaar, quando a consulta ocorre. O tipo nao e
    # importado para core/ nao depender de enrichment/, que so entra em
    # cena quando o enriquecimento e pedido.
    malwarebazaar: object | None = None
    resumo_ia: resumo_ia_mod.ResumoIA | None = None

    erros: list[ErroDeEstagio] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    # ----- Consultas -----

    @property
    def concluido(self) -> bool:
        """True quando o pipeline chegou ao fim sem erro fatal."""
        return bool(self.concluido_em) and not any(e.fatal for e in self.erros)

    @property
    def sha256(self) -> str:
        return self.extracao.sha256 if self.extracao else ""

    @property
    def iocs(self) -> list:
        """
        Todos os IOCs, os visiveis e os que estavam atras de ofuscacao.

        Deduplicados por (valor, tipo), mantendo a evidencia mais forte -
        a mesma regra do string_extractor.
        """
        todos = list(self.extracao.iocs) if self.extracao else []
        if self.desofuscacao:
            todos.extend(self.desofuscacao.iocs_revelados)

        ordem = {"alta": 3, "media": 2, "baixa": 1}
        melhores: dict[tuple, object] = {}
        for ioc in todos:
            chave = (ioc.valor, ioc.tipo)
            atual = melhores.get(chave)
            if atual is None or ordem.get(ioc.confianca.value, 0) > ordem.get(
                atual.confianca.value, 0
            ):
                melhores[chave] = ioc

        return sorted(melhores.values(), key=lambda i: (i.tipo.value, i.valor))

    def todos_os_avisos(self) -> list[str]:
        """Avisos de todas as etapas, reunidos para o relatorio."""
        reunidos = list(self.avisos)
        for atributo in ("extracao", "mapeamento", "kill_chain", "atribuicao", "cvss"):
            objeto = getattr(self, atributo, None)
            if objeto is not None:
                reunidos.extend(getattr(objeto, "avisos", []))
        if self.regra_yara:
            reunidos.extend(self.regra_yara.avisos)
        return reunidos

    def resumo(self) -> dict:
        return {
            "arquivo": Path(self.caminho).name,
            "sha256": self.sha256[:16] + "..." if self.sha256 else "",
            "strings": len(self.extracao.strings) if self.extracao else 0,
            "iocs": len(self.iocs),
            "achados_desofuscacao": (
                len(self.desofuscacao.achados) if self.desofuscacao else 0
            ),
            "tecnicas": len(self.mapeamento.tecnicas) if self.mapeamento else 0,
            "yara_valida": bool(self.regra_yara and self.regra_yara.valida),
            "erros": len(self.erros),
            "duracao": round(self.duracao_segundos, 1),
        }

    def to_dict(self) -> dict:
        """Serializa para JSON, com as etapas ausentes como null."""
        saida: dict = {
            "caminho": self.caminho,
            "iniciado_em": self.iniciado_em,
            "concluido_em": self.concluido_em,
            "duracao_segundos": round(self.duracao_segundos, 2),
            "cancelado": self.cancelado,
            "opcoes": self.opcoes.to_dict(),
            "erros": [e.to_dict() for e in self.erros],
            "avisos": self.todos_os_avisos(),
            "resumo": self.resumo(),
        }

        for nome in (
            "extracao", "info_pe", "desofuscacao", "regra_yara",
            "mapeamento", "kill_chain", "atribuicao", "cvss", "resumo_ia",
        ):
            objeto = getattr(self, nome)
            saida[nome] = objeto.to_dict() if objeto is not None else None

        saida["virustotal"] = [r.to_dict() for r in self.virustotal]
        saida["shodan"] = [r.to_dict() for r in self.shodan]
        saida["nvd"] = [r.to_dict() for r in self.nvd]
        saida["malwarebazaar"] = (
            self.malwarebazaar.to_dict() if self.malwarebazaar else None
        )
        return saida


class _Executor:
    """
    Executa as etapas isolando as falhas.

    Existe para nao repetir try/except identico dez vezes no corpo do
    pipeline, e para o progresso ser reportado de um lugar so.
    """

    def __init__(
        self,
        resultado: ResultadoAnalise,
        progresso: CallbackProgresso | None,
        cancelado: CallbackCancelamento | None,
        total_de_etapas: int,
    ):
        self.resultado = resultado
        self._progresso = progresso
        self._cancelado = cancelado
        self.total = max(1, total_de_etapas)
        self.concluidas = 0

    @property
    def foi_cancelado(self) -> bool:
        return bool(self._cancelado and self._cancelado())

    def anunciar(self, estagio: Estagio, mensagem: str = "") -> None:
        if self._progresso:
            self._progresso(estagio, mensagem, self.concluidas / self.total)

    def rodar(self, estagio: Estagio, funcao, fatal: bool = False):
        """
        Executa uma etapa, capturando qualquer excecao.

        Returns:
            O que a funcao devolveu, ou None se ela falhou ou foi pulada.
        """
        if self.foi_cancelado:
            return None

        self.anunciar(estagio)
        inicio = time.monotonic()

        try:
            valor = funcao()
        except Exception as erro:  # etapa nenhuma pode derrubar o pipeline
            logger.exception("falha em %s", estagio.value)
            self.resultado.erros.append(
                ErroDeEstagio(
                    estagio=estagio,
                    mensagem=f"{type(erro).__name__}: {erro}",
                    fatal=fatal,
                )
            )
            valor = None
        finally:
            self.concluidas += 1

        logger.debug("%s levou %.2fs", estagio.value, time.monotonic() - inicio)
        return valor


def analisar(
    caminho: str | Path,
    opcoes: OpcoesAnalise | None = None,
    progresso: CallbackProgresso | None = None,
    cancelado: CallbackCancelamento | None = None,
    config=None,
) -> ResultadoAnalise:
    """
    Executa a analise completa de um artefato.

    Args:
        caminho: o arquivo a analisar.
        opcoes: o que executar. O padrao nao faz consulta externa nenhuma.
        progresso: chamado a cada etapa, para a GUI mostrar andamento.
        cancelado: consultado entre etapas; quando devolve True, o pipeline
            para e devolve o que ja tiver.
        config: configuracoes (chaves de API). Padrao: as do .env.

    Returns:
        ResultadoAnalise, sempre. Erro de etapa fica registrado em `erros`;
        so arquivo ilegivel produz resultado sem extracao.
    """
    caminho = Path(caminho)
    opcoes = opcoes or OpcoesAnalise()

    resultado = ResultadoAnalise(
        caminho=str(caminho),
        iniciado_em=datetime.now(timezone.utc).isoformat(),
        opcoes=opcoes,
    )
    inicio = time.monotonic()

    # O total serve so para a barra de progresso; nao precisa ser exato.
    total = 6 + sum(
        (
            opcoes.gerar_yara,
            bool(opcoes.vetor_cvss),
            opcoes.enriquecer,
            opcoes.enriquecer,
            opcoes.enriquecer,
            opcoes.resumo_ia,
        )
    )
    executor = _Executor(resultado, progresso, cancelado, total)

    # ---------- 1. Extracao (fundacao: tudo depende dela) ----------

    resultado.extracao = executor.rodar(
        Estagio.EXTRACAO,
        lambda: string_extractor.extrair(
            caminho,
            tamanho_minimo=opcoes.tamanho_minimo_de_string,
            usar_floss=opcoes.usar_floss,
            timeout=opcoes.timeout_floss,
            formato=opcoes.formato,
        ),
        fatal=True,
    )

    if resultado.extracao is None:
        # Sem strings nao ha o que analisar: as demais etapas nao teriam
        # entrada. Encerra aqui.
        #
        # Duas causas levam a este ponto e elas precisam ser distinguidas:
        # o arquivo nao pode ser lido (erro fatal ja registrado) ou o
        # usuario cancelou antes da primeira etapa (nenhum erro). Sem esta
        # distincao, um cancelamento voltaria como analise vazia
        # bem-sucedida.
        resultado.cancelado = executor.foi_cancelado
        if resultado.cancelado:
            resultado.avisos.append(
                "analise cancelada antes da extracao: nenhum dado foi produzido"
            )
        resultado.concluido_em = datetime.now(timezone.utc).isoformat()
        resultado.duracao_segundos = time.monotonic() - inicio
        return resultado

    # ---------- 2. PE ----------

    resultado.info_pe = executor.rodar(
        Estagio.PE, lambda: pe_analyzer.analisar(caminho)
    )

    # ---------- 3. Desofuscacao ----------

    resultado.desofuscacao = executor.rodar(
        Estagio.DESOFUSCACAO,
        lambda: deobfuscator.desofuscar(resultado.extracao.strings),
    )

    # ---------- 4. YARA ----------

    if opcoes.gerar_yara:
        resultado.regra_yara = executor.rodar(
            Estagio.YARA,
            lambda: yara_generator.gerar(
                caminho,
                resultado.extracao,
                resultado.desofuscacao,
                resultado.info_pe,
                maximo_de_strings=opcoes.maximo_de_strings_yara,
                amostras_benignas=list(opcoes.amostras_benignas),
            ),
        )

    # ---------- 5. ATT&CK ----------

    attack = None
    if opcoes.usar_stix:
        attack = executor.rodar(
            Estagio.MITRE,
            lambda: mitre_mapper.carregar_attack(
                opcoes.caminho_cache_stix or mitre_mapper.CAMINHO_CACHE_PADRAO,
                baixar_se_faltar=opcoes.baixar_stix_se_faltar,
            ),
        )
        if attack is None:
            resultado.avisos.append(
                "STIX do ATT&CK indisponivel: o mapeamento usou o catalogo "
                "local e a atribuicao de grupo nao pode ser feita"
            )

    resultado.mapeamento = executor.rodar(
        Estagio.MITRE,
        lambda: mitre_mapper.mapear(
            resultado.extracao, resultado.desofuscacao, resultado.info_pe, attack
        ),
    )

    # ---------- 6. Kill Chain ----------

    if resultado.mapeamento is not None:
        resultado.kill_chain = executor.rodar(
            Estagio.KILLCHAIN, lambda: killchain.montar(resultado.mapeamento)
        )

        # ---------- 7. Atribuicao ----------

        resultado.atribuicao = executor.rodar(
            Estagio.ATRIBUICAO,
            lambda: group_attribution.atribuir(resultado.mapeamento, attack),
        )

    # ---------- 8. CVSS ----------
    #
    # Duas origens possiveis para o vetor, nesta ordem de precedencia:
    #
    #   1. O que o analista informou. Se ele digitou um vetor, e porque
    #      sabe algo que a ferramenta nao sabe - nao cabe sobrescrever.
    #   2. Busca na NVD a partir de uma CVE encontrada nas strings do
    #      artefato. E o caso comum: o binario cita "CVE-2021-44228" e o
    #      vetor oficial vem de graca, sem o analista precisar decorar.
    #
    # A segunda depende de rede, entao so acontece com enriquecimento
    # ligado - o mesmo criterio de toda consulta externa.

    if opcoes.vetor_cvss:
        resultado.cvss = executor.rodar(
            Estagio.CVSS,
            lambda: cvss_calculator.calcular(opcoes.vetor_cvss, opcoes.cve),
        )
    elif opcoes.enriquecer:
        resultado.cvss = executor.rodar(Estagio.CVSS, lambda: _cvss_da_nvd(resultado, config))

    # ---------- 9. Enriquecimento externo ----------

    if opcoes.enriquecer:
        _enriquecer(resultado, executor, opcoes, config)
    else:
        resultado.avisos.append(
            "enriquecimento externo desabilitado: nenhum dado foi enviado a "
            "servico de terceiros"
        )

    # ---------- 10. Resumo por IA local ----------
    #
    # Por ultimo de proposito: ele resume o que todas as etapas anteriores
    # produziram, entao precisa delas concluidas.

    if opcoes.resumo_ia:
        resultado.resumo_ia = executor.rodar(
            Estagio.RESUMO_IA,
            lambda: resumo_ia_mod.gerar_resumo(resultado, modelo=opcoes.modelo_ia),
        )
        if resultado.resumo_ia is not None and resultado.resumo_ia.invencoes:
            resultado.avisos.append(
                f"o resumo por IA contem {len(resultado.resumo_ia.invencoes)} "
                "afirmacao(oes) sem respaldo nos achados; veja a secao do resumo"
            )

    # ---------- Encerramento ----------

    resultado.cancelado = executor.foi_cancelado
    resultado.concluido_em = datetime.now(timezone.utc).isoformat()
    resultado.duracao_segundos = time.monotonic() - inicio

    executor.concluidas = executor.total
    executor.anunciar(Estagio.CONCLUIDO, "analise concluida")

    logger.info("analise concluida: %s", resultado.resumo())
    return resultado


def _cvss_da_nvd(resultado: ResultadoAnalise, config):
    """
    Busca o vetor CVSS a partir de uma CVE citada pelo artefato.

    Resolve a assimetria que existia: o campo CVSS era preenchimento
    manual, o que obrigava o analista a saber o vetor de cor. Mas CVSS
    descreve uma VULNERABILIDADE, nao um artefato - nao ha como derivar um
    vetor de um binario. O que da para fazer, e que faltava, e notar que o
    artefato REFERENCIA uma CVE (isso o string_extractor ja faz, offline) e
    buscar o vetor oficial daquela CVE.

    Quando ha mais de uma CVE citada, vale a de maior score: e a que define
    o pior caso, e o relatorio precisa da mais severa em destaque. As
    demais continuam listadas como IOC.

    Returns:
        ResultadoCVSS, ou None quando nao ha CVE citada ou a NVD nao
        respondeu. Nao levanta excecao: o executor trata, e a ausencia de
        CVSS nao invalida o resto da analise.
    """
    from core.string_extractor import TipoIOC
    from enrichment import nvd_client

    cves = [i.valor for i in resultado.iocs if i.tipo is TipoIOC.CVE]
    if not cves:
        return None

    cliente = nvd_client.criar(config)
    if cliente is None:
        resultado.avisos.append(
            "CVE citada no artefato, mas a consulta a NVD foi pulada: "
            "enriquecimento desabilitado"
        )
        return None

    melhor = None
    melhor_score = -1.0

    with cliente:
        for cve in cves[:5]:  # teto: a NVD limita a 5 requisicoes por janela
            consulta = cliente.consultar(cve)
            resultado.nvd.append(consulta)

            if not consulta.encontrado or not consulta.vetor:
                continue
            if consulta.score_base > melhor_score:
                melhor_score = consulta.score_base
                melhor = consulta

    if melhor is None:
        resultado.avisos.append(
            f"CVE citada ({', '.join(cves[:3])}), mas a NVD nao devolveu "
            "vetor CVSS para nenhuma delas"
        )
        return None

    if len(cves) > 1:
        resultado.avisos.append(
            f"{len(cves)} CVEs citadas no artefato; o CVSS exibido e o da "
            f"mais severa ({melhor.cve}). As demais estao na lista de IOCs"
        )

    cvss = cvss_calculator.calcular(melhor.vetor, melhor.cve)
    cvss.avisos.append(
        "vetor obtido automaticamente da NVD a partir de CVE citada pelo "
        "artefato. O score descreve a vulnerabilidade, nao este arquivo: "
        "que ele a explore, e com que sucesso, a analise estatica nao diz"
    )
    return cvss


def _enriquecer(
    resultado: ResultadoAnalise,
    executor: _Executor,
    opcoes: OpcoesAnalise,
    config,
) -> None:
    """
    Consulta VirusTotal e Shodan.

    Importado aqui dentro para que o pipeline funcione mesmo sem as
    dependencias de rede carregadas, e para deixar claro que a rede so
    entra quando o enriquecimento e pedido.
    """
    from enrichment import malwarebazaar_client, shodan_client, virustotal_client

    if config is None:
        from config.settings import CONFIG as config

    iocs = resultado.iocs

    # --- VirusTotal ---

    def virustotal():
        cliente = virustotal_client.criar(config)
        if cliente is None:
            resultado.avisos.append(
                "VirusTotal pulado: chave nao configurada ou enriquecimento "
                "desabilitado no .env"
            )
            return []

        with cliente:
            saida = [cliente.consultar_hash(resultado.extracao.sha256)]
            saida.extend(
                cliente.consultar_iocs(iocs, maximo=opcoes.maximo_de_consultas)
            )
            return saida

    resultado.virustotal = executor.rodar(Estagio.VIRUSTOTAL, virustotal) or []

    # --- Shodan ---

    def shodan():
        cliente = shodan_client.criar(config)
        if cliente is None:
            resultado.avisos.append(
                "Shodan pulado: chave nao configurada ou enriquecimento "
                "desabilitado no .env"
            )
            return []

        with cliente:
            return cliente.consultar_iocs(iocs, maximo=opcoes.maximo_de_consultas)

    resultado.shodan = executor.rodar(Estagio.SHODAN, shodan) or []

    # --- MalwareBazaar ---

    def bazaar():
        cliente = malwarebazaar_client.criar(config)
        if cliente is None:
            resultado.avisos.append(
                "MalwareBazaar pulado: Auth-Key nao configurada ou "
                "enriquecimento desabilitado no .env"
            )
            return None

        with cliente:
            # So consulta por hash. Baixar amostra e acao separada e
            # deliberada, nunca efeito colateral de analisar um arquivo.
            return cliente.consultar_hash(resultado.extracao.sha256)

    resultado.malwarebazaar = executor.rodar(Estagio.MALWAREBAZAAR, bazaar)
