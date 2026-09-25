"""
Resumo executivo gerado por LLM local, via Ollama.

O relatorio do Nut-Shell Mapper e todo tabela: preciso, mas trabalhoso de ler para
quem so quer saber "o que e este artefato". Um paragrafo em linguagem
natural resolve isso - e e a unica parte do pipeline onde um modelo de
linguagem ajuda de verdade.

POR QUE LOCAL

O Ollama roda inteiramente em localhost. Diferente do VirusTotal e do
Shodan, nada sai da maquina: nenhum hash, nenhum IOC, nenhum trecho do
artefato chega a terceiros. Essa e a unica forma de integracao de IA
compativel com o principio que atravessa o projeto - por isso nao ha, e
nao havera, opcao de usar API de nuvem aqui.

A TENSAO CENTRAL, E COMO ELA E RESOLVIDA

Todo o resto do framework foi construido sobre uma regra: evidencia
acompanha conclusao, e nada e afirmado alem do que foi observado. Tecnica
ATT&CK e "capacidade observada", nunca "comportamento executado";
sobreposicao de tecnicas nao e atribuicao; o relatorio lista o que NAO foi
analisado.

Um LLM e estruturalmente propenso ao oposto. Ele escreve com prazer "esta
amostra e Emotet e se comunica com infraestrutura do APT29" a partir de
evidencia fraca ou nenhuma. Um resumo assim, no topo do relatorio,
desfaria a cautela de todas as secoes abaixo.

A resposta deste modulo nao e confiar no modelo, e sim TORNAR A SAIDA DELE
CONFERIVEL - o mesmo espirito da regra YARA, que e testada contra a
propria amostra antes de ser considerada valida:

  1. O modelo so recebe achados estruturados. Nunca as strings cruas,
     nunca bytes do artefato, nunca o binario.
  2. Toda afirmacao verificavel do texto gerado e conferida contra a
     analise: cada ID de tecnica, cada IOC, cada nome de grupo citado tem
     que existir no que foi observado. O que o modelo inventar e
     detectado, listado e sinalizado.
  3. Um resumo com invencao e marcado como nao confiavel. O texto nao e
     escondido - esconder impediria o analista de ver o erro - mas ele
     nunca aparece sem o aviso do que foi inventado.
  4. O resumo nunca substitui secao de evidencia. E texto adicional.
  5. Temperatura zero e instrucao explicita de nao extrapolar.
  6. Desligado por padrao, como todo o resto que depende de servico
     externo ao processo.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from core.modelo_hf import QWEN, comando_de_instalacao

logger = logging.getLogger(__name__)


URL_OLLAMA_PADRAO = "http://localhost:11434"
# Unica fonte do nome do modelo padrao: CLI, pipeline, ponte e interface
# leem daqui. E o Qwen3.5-9B do Hugging Face (ver core/modelo_hf.py, com o
# motivo medido da escolha); `python main.py instalar-ia` baixa e registra.
# Antes dele, o llama3.1:8b; o granite4.2:8b ficou de fora por gerar a
# 0,8 token/s numa RTX 5070 de 8 GB. Qualquer modelo instalado no Ollama
# continua escolhivel na interface.
MODELO_PADRAO = QWEN.nome_ollama

# A primeira chamada carrega varios GB do disco para a memoria e pode
# passar de dois minutos; as seguintes, com o modelo quente, levam
# segundos. O timeout precisa caber no pior caso.
TIMEOUT_PADRAO = 600

# Mantem o modelo carregado entre analises consecutivas, evitando pagar o
# carregamento de novo a cada artefato.
MANTER_CARREGADO = "10m"

# Quantos itens de cada lista entram no prompt. O modelo nao precisa de
# tudo para escrever um paragrafo, e prompt menor gera resposta melhor.
LIMITE_IOCS = 15
LIMITE_TECNICAS = 15


# ============================================================
# Tipos
# ============================================================


@dataclass(frozen=True)
class Invencao:
    """Uma afirmacao do resumo que nao corresponde a nenhum achado."""

    tipo: str  # tecnica, ioc, grupo
    valor: str
    explicacao: str

    def __str__(self) -> str:
        return f"{self.tipo}: {self.valor} — {self.explicacao}"


@dataclass
class ResumoIA:
    """O resumo gerado e o resultado da sua verificacao."""

    texto: str = ""
    modelo: str = ""
    gerado: bool = False
    erro: str = ""
    duracao_segundos: float = 0.0

    # Afirmacoes do texto que nao existem na analise.
    invencoes: list[Invencao] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    @property
    def confiavel(self) -> bool:
        """
        True quando nada foi inventado.

        "Confiavel" aqui significa apenas que o texto nao cita nada que a
        analise nao tenha observado. Nao significa que a interpretacao do
        modelo esteja correta - isso continua sendo julgamento do analista.
        """
        return self.gerado and not self.invencoes

    @property
    def ressalva(self) -> str:
        """Aviso que precisa acompanhar o texto onde quer que ele apareca."""
        if not self.gerado:
            return ""
        base = (
            f"Resumo gerado por modelo de linguagem local ({self.modelo}), "
            "a partir dos achados desta análise. É texto de apoio, não "
            "evidência: as seções deste relatório são a fonte."
        )
        if self.invencoes:
            base += (
                f" ATENÇÃO: {len(self.invencoes)} afirmação(ões) do texto não "
                "correspondem a nenhum achado e estão listadas abaixo."
            )
        return base

    def to_dict(self) -> dict:
        return asdict(self)


class ErroResumoIA(Exception):
    """Falha ao gerar o resumo."""


# ============================================================
# Montagem do prompt
# ============================================================

INSTRUCAO = """Voce e um analista de threat intelligence escrevendo o resumo \
executivo de uma analise estatica de artefato.

REGRAS ABSOLUTAS:
- Use SOMENTE os achados listados abaixo. Nao acrescente nenhum indicador, \
tecnica, familia de malware ou grupo que nao esteja explicitamente na lista.
- Se os achados nao permitem concluir algo, diga que nao permitem. Nao \
preencha lacuna com suposicao.
- Uma tecnica ATT&CK listada significa que a CAPACIDADE foi observada no \
binario, nao que o comportamento foi executado. Escreva assim.
- Grupos listados tem apenas repertorio de tecnicas parecido. Isso NAO e \
atribuicao. Se citar algum, deixe essa limitacao explicita.
- Nao invente nome de familia de malware. Se nenhum foi identificado, diga \
que nao foi identificado.

FORMATO:
- Portugues do Brasil, 2 a 3 paragrafos curtos, no maximo 250 palavras.
- Tom tecnico e direto, sem introducao do tipo "este relatorio apresenta".
- Comece pelo que o artefato aparenta ser e o que foi observado de mais \
relevante.

ACHADOS DA ANALISE:
"""


def _montar_contexto(r: Any) -> str:
    """
    Monta o bloco de achados que vai no prompt.

    So entra o que foi estruturado pela analise. As strings cruas do
    artefato nunca sao enviadas: alem de inflar o prompt, elas poderiam
    conter dado sensivel da amostra, e o modelo nao precisa delas para
    resumir o que os outros modulos ja concluiram.
    """
    linhas: list[str] = []

    # --- Identificacao ---
    from pathlib import Path

    linhas.append(f"Arquivo: {Path(r.caminho).name}")
    if r.extracao:
        linhas.append(f"SHA256: {r.extracao.sha256}")
        linhas.append(f"Tamanho: {r.extracao.tamanho_bytes} bytes")

    if r.info_pe and r.info_pe.e_pe:
        linhas.append(
            f"Formato: PE {r.info_pe.tipo} {r.info_pe.arquitetura}"
            f" (imphash {r.info_pe.imphash or 'ausente'})"
        )
        if r.info_pe.indicios:
            linhas.append("Indicios estruturais do PE:")
            linhas += [f"  - {d}" for d in r.info_pe.indicios[:6]]
    elif r.info_pe:
        linhas.append("Formato: nao e um executavel PE")

    # --- Strings ---
    if r.extracao:
        resumo = r.extracao.resumo()
        linhas.append(
            f"Strings: {resumo['total_strings']} no total "
            f"({resumo['stack']} stack, {resumo['decoded']} decodificadas)"
        )
        if not r.extracao.usou_floss:
            linhas.append(
                "  (o FLOSS nao foi usado: so strings estaticas foram vistas)"
            )

    # --- Desofuscacao ---
    if r.desofuscacao and r.desofuscacao.achados:
        linhas.append(f"Ofuscacao detectada: {len(r.desofuscacao.achados)} achado(s)")
        for a in r.desofuscacao.achados[:5]:
            linhas.append(f"  - {a.cadeia} revelou: {a.decodificado[:80]}")

    # --- IOCs ---
    iocs = r.iocs
    if iocs:
        linhas.append(f"Indicadores ({len(iocs)}):")
        for i in iocs[:LIMITE_IOCS]:
            obs = f" [{i.observacao}]" if i.observacao else ""
            linhas.append(f"  - {i.tipo.value} ({i.confianca.value}): {i.valor}{obs}")
    else:
        linhas.append("Indicadores: nenhum identificado")

    # --- ATT&CK ---
    if r.mapeamento and r.mapeamento.tecnicas:
        linhas.append(f"Tecnicas ATT&CK observadas ({len(r.mapeamento.tecnicas)}):")
        for t in r.mapeamento.tecnicas[:LIMITE_TECNICAS]:
            evidencia = t.evidencias[0].trecho[:60] if t.evidencias else "sem detalhe"
            linhas.append(
                f"  - {t.tecnica_id} {t.nome} (confianca {t.confianca.value})"
                f" — evidencia: {evidencia}"
            )
    else:
        linhas.append("Tecnicas ATT&CK: nenhuma identificada com evidencia suficiente")

    # --- Kill Chain ---
    if r.kill_chain:
        cobertos = [e.value for e in r.kill_chain.estagios_cobertos]
        linhas.append(
            f"Kill Chain: {len(cobertos)} de 7 estagios com evidencia"
            + (f" ({', '.join(cobertos)})" if cobertos else "")
        )

    # --- Atribuicao ---
    if r.atribuicao and r.atribuicao.candidatos:
        linhas.append(
            "Grupos com repertorio parecido (NAO e atribuicao, apenas "
            "sobreposicao de tecnicas):"
        )
        for c in r.atribuicao.candidatos[:5]:
            linhas.append(
                f"  - {c.nome} ({c.grupo_id}), pontuacao {c.pontuacao:.2f},"
                f" {len(c.tecnicas_em_comum)} tecnicas em comum"
            )
    else:
        linhas.append("Grupos: nenhuma sobreposicao significativa")

    # --- Enriquecimento ---
    if r.virustotal:
        for v in r.virustotal:
            if v.tipo == "arquivo":
                linhas.append(f"VirusTotal (hash): {v.resumo_de_deteccao}")
                if v.familia_sugerida:
                    linhas.append(f"  familia sugerida pelo VT: {v.familia_sugerida}")
    bazaar = getattr(r, "malwarebazaar", None)
    if bazaar is not None and getattr(bazaar, "encontrado", False):
        linhas.append(f"MalwareBazaar: familia {bazaar.familia or 'sem rotulo'}")
        if bazaar.tags:
            linhas.append(f"  tags: {', '.join(bazaar.tags)}")

    # --- YARA ---
    if r.regra_yara:
        linhas.append(
            "Regra YARA gerada: "
            + ("valida (casa com a amostra)" if r.regra_yara.valida else "invalida")
        )

    # --- O que faltou ---
    if r.erros:
        linhas.append("Etapas que falharam:")
        linhas += [f"  - {e}" for e in r.erros]

    linhas.append(
        "Natureza da analise: ESTATICA. O artefato nao foi executado; "
        "comportamento de runtime nao esta coberto."
    )

    return "\n".join(linhas)


# ============================================================
# Verificacao da saida
# ============================================================

RE_TECNICA = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
RE_GRUPO = re.compile(r"\bG\d{4}\b")
RE_IPV4_TEXTO = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_URL_TEXTO = re.compile(r"\bhttps?://[^\s,;)\"']+", re.IGNORECASE)

# Pontuacao que encosta na URL quando ela termina a frase. Sem remover, o
# indicador aparece no relatorio como "http://exemplo.com/a." - com o ponto
# final colado, o que atrapalha copiar o valor.
PONTUACAO_FINAL = ".,;:!?)]}\"'"

# Familias de malware que o modelo tende a citar de memoria. Se aparecerem
# sem estar nos achados, e invencao - e das mais perigosas, porque um nome
# de familia errado no topo do relatorio contamina toda a leitura.
FAMILIAS_COMUNS = (
    "emotet", "trickbot", "qakbot", "qbot", "dridex", "ryuk", "conti",
    "lockbit", "revil", "sodinokibi", "wannacry", "notpetya", "mirai",
    "agent tesla", "formbook", "remcos", "asyncrat", "njrat", "redline",
    "raccoon", "vidar", "cobalt strike", "metasploit", "icedid", "bumblebee",
    "gootloader", "zloader", "ursnif", "gozi", "azorult", "lumma",
)


def _normalizar(texto: str) -> str:
    return texto.lower().strip()


def verificar(texto: str, r: Any) -> list[Invencao]:
    """
    Confere cada afirmacao verificavel do resumo contra a analise.

    Devolve a lista do que o modelo citou e a analise nao observou. Lista
    vazia significa que nada foi inventado - nao que a interpretacao esteja
    certa, apenas que ela nao se apoia em fato inexistente.
    """
    invencoes: list[Invencao] = []

    # --- Tecnicas ATT&CK ---
    observadas = (
        {t.tecnica_id for t in r.mapeamento.tecnicas} if r.mapeamento else set()
    )
    for citada in set(RE_TECNICA.findall(texto)):
        if citada not in observadas:
            invencoes.append(
                Invencao(
                    tipo="tecnica",
                    valor=citada,
                    explicacao=(
                        "citada no resumo mas não está entre as técnicas "
                        "mapeadas nesta análise"
                    ),
                )
            )

    # --- Grupos ---
    grupos_observados = set()
    nomes_de_grupo = set()
    if r.atribuicao:
        for c in r.atribuicao.candidatos:
            grupos_observados.add(c.grupo_id)
            nomes_de_grupo.add(_normalizar(c.nome))
            nomes_de_grupo.update(_normalizar(a) for a in c.aliases)

    for citado in set(RE_GRUPO.findall(texto)):
        if citado not in grupos_observados:
            invencoes.append(
                Invencao(
                    tipo="grupo",
                    valor=citado,
                    explicacao=(
                        "citado no resumo mas não está entre os candidatos "
                        "levantados"
                    ),
                )
            )

    # --- IOCs de rede ---
    iocs_observados = {_normalizar(i.valor) for i in r.iocs}
    # Um IOC pode ser citado como parte de outro (o IP dentro da URL), entao
    # a checagem e por conteudo, nao por igualdade exata.
    def _consta(valor: str) -> bool:
        v = _normalizar(valor)
        return any(v in obs or obs in v for obs in iocs_observados)

    citados = {
        valor.rstrip(PONTUACAO_FINAL)
        for valor in RE_IPV4_TEXTO.findall(texto) + RE_URL_TEXTO.findall(texto)
    }
    for citado in citados:
        if not _consta(citado):
            invencoes.append(
                Invencao(
                    tipo="ioc",
                    valor=citado,
                    explicacao=(
                        "indicador citado no resumo mas não encontrado no "
                        "artefato"
                    ),
                )
            )

    # --- Familias de malware ---
    familias_conhecidas = set()
    for v in getattr(r, "virustotal", []):
        if getattr(v, "familia_sugerida", ""):
            familias_conhecidas.add(_normalizar(v.familia_sugerida))
    bazaar = getattr(r, "malwarebazaar", None)
    if bazaar is not None and getattr(bazaar, "familia", ""):
        familias_conhecidas.add(_normalizar(bazaar.familia))
    # Tags do Bazaar tambem trazem nome de familia.
    if bazaar is not None:
        familias_conhecidas.update(_normalizar(t) for t in getattr(bazaar, "tags", []))

    minusculo = _normalizar(texto)
    for familia in FAMILIAS_COMUNS:
        if familia not in minusculo:
            continue
        if any(familia in conhecida for conhecida in familias_conhecidas):
            continue
        invencoes.append(
            Invencao(
                tipo="familia",
                valor=familia,
                explicacao=(
                    "família de malware citada no resumo sem nenhuma fonte "
                    "desta análise ter feito essa identificação"
                ),
            )
        )

    return invencoes


# ============================================================
# Cliente
# ============================================================


@dataclass
class EstadoGeracao:
    """
    Como vai a geracao, enquanto ela acontece.

    Existe para que quem espera consiga distinguir "esta gerando devagar"
    de "travou". Sem isso a unica saida e matar o processo no escuro.
    """

    # O que o modelo escreveu ate agora.
    texto_parcial: str
    # Quantos pedacos chegaram. Aproxima a contagem de tokens: o Ollama
    # manda um por token gerado, mas isso e detalhe do servidor e nao uma
    # garantia, entao o nome nao promete token.
    pedacos: int
    segundos: float
    concluido: bool = False

    @property
    def por_segundo(self) -> float:
        """Ritmo da geracao. Zero enquanto nao da para estimar."""
        return self.pedacos / self.segundos if self.segundos > 0.5 else 0.0

    def resumo(self) -> str:
        """Uma linha curta para barra de status."""
        if self.concluido:
            return f"resumo gerado: {self.pedacos} tokens em {self.segundos:.0f}s"
        ritmo = f", {self.por_segundo:.1f}/s" if self.por_segundo else ""
        return f"gerando resumo: {self.pedacos} tokens em {self.segundos:.0f}s{ritmo}"


# Chamado a cada pedaco recebido do modelo.
CallbackGeracao = Callable[[EstadoGeracao], None]


class ClienteOllama:
    """Acesso ao Ollama local."""

    def __init__(
        self,
        url: str = URL_OLLAMA_PADRAO,
        modelo: str = MODELO_PADRAO,
        timeout: int = TIMEOUT_PADRAO,
    ):
        self.url = url.rstrip("/")
        self.modelo = modelo
        self.timeout = timeout

    def disponivel(self) -> tuple[bool, str]:
        """
        Verifica se o servidor responde e se o modelo esta presente.

        Devolve (disponivel, motivo). O motivo explica o que fazer quando
        nao esta - servidor fora do ar e modelo ausente exigem acoes
        diferentes.
        """
        import requests

        try:
            resposta = requests.get(f"{self.url}/api/tags", timeout=10)
            resposta.raise_for_status()
        except Exception as erro:
            # Nao respondeu pode ser "nao instalado" ou "fechado", e o
            # remedio e diferente. O executavel no disco separa os dois.
            if not _executavel_ollama():
                return False, (
                    "O Ollama não está instalado. Baixe em ollama.com/download "
                    f"e depois rode: {comando_de_instalacao(self.modelo)}"
                )
            return False, (
                f"O Ollama está instalado, mas não respondeu em {self.url} "
                f"({type(erro).__name__}). Abra o aplicativo Ollama."
            )

        modelos = [m.get("name", "") for m in resposta.json().get("models", [])]
        if not modelos:
            return False, (
                "Ollama está rodando mas não tem nenhum modelo. "
                f"Rode: {comando_de_instalacao(self.modelo)}"
            )

        # O nome pode vir com ou sem a tag (":latest" implicito).
        base = self.modelo.split(":")[0]
        if not any(m == self.modelo or m.split(":")[0] == base for m in modelos):
            return False, (
                f"modelo '{self.modelo}' não encontrado. "
                f"Disponíveis: {', '.join(modelos)}. "
                f"Para instalar: {comando_de_instalacao(self.modelo)}"
            )

        return True, ""

    def gerar(
        self,
        prompt: str,
        progresso: CallbackGeracao | None = None,
        formato: dict | None = None,
        max_tokens: int = 600,
    ) -> str:
        """
        Gera texto a partir do prompt.

        A resposta vem em streaming mesmo quando ninguem esta observando. O
        motivo nao e estetico: uma geracao de 8B leva de dez segundos a
        varios minutos, e com `stream: False` a conexao fica muda esse tempo
        todo. Quem espera nao consegue distinguir "esta gerando" de
        "travou", e o unico recurso vira matar o processo - as vezes a
        segundos do fim.

        Args:
            prompt: o texto de entrada.
            progresso: chamado a cada pedaco recebido, com o estado parcial
                da geracao. Opcional.
            formato: esquema JSON que a resposta deve seguir. O Ollama
                restringe a geracao a ele, o que torna a saida conferivel
                campo a campo em vez de texto livre.
            max_tokens: teto da resposta.

        Raises:
            ErroResumoIA: servidor fora do ar, modelo ausente ou resposta
                malformada.
        """
        import requests

        partes: list[str] = []
        inicio = time.monotonic()

        corpo: dict[str, Any] = {
            "model": self.modelo,
            "prompt": prompt,
            "stream": True,
            "keep_alive": MANTER_CARREGADO,
            # Modelos com raciocinio (Qwen3.5, por exemplo) "pensam" antes de
            # responder, gastando o limite de tokens num texto que ninguem
            # le e deixando o JSON pela metade. Para quem nao raciocina, o
            # campo e ignorado.
            "think": False,
            "options": {
                # Temperatura zero: o resumo precisa ser o mais
                # literal possivel em relacao aos achados. Nao ha
                # nada a ganhar com criatividade aqui.
                "temperature": 0,
                "num_predict": max_tokens,
            },
        }
        if formato is not None:
            corpo["format"] = formato

        try:
            resposta = requests.post(
                f"{self.url}/api/generate",
                json=corpo,
                timeout=self.timeout,
                stream=True,
            )
            resposta.raise_for_status()

            for linha in resposta.iter_lines(decode_unicode=False):
                if not linha:
                    continue

                # Cada linha e um JSON completo. Uma linha malformada no
                # meio do fluxo nao justifica descartar o que ja chegou.
                try:
                    pedaco = json.loads(linha)
                except ValueError:
                    logger.debug("linha não-JSON no fluxo do Ollama, ignorada")
                    continue

                if pedaco.get("error"):
                    raise ErroResumoIA(f"o Ollama recusou: {pedaco['error']}")

                partes.append(pedaco.get("response", ""))

                if progresso is not None:
                    progresso(
                        EstadoGeracao(
                            texto_parcial="".join(partes),
                            pedacos=len(partes),
                            segundos=time.monotonic() - inicio,
                            concluido=bool(pedaco.get("done")),
                        )
                    )

                if pedaco.get("done"):
                    break

        except ErroResumoIA:
            raise
        except Exception as erro:
            # O que ja chegou nao se aproveita: um resumo cortado no meio
            # seria pior que nenhum, porque parece completo.
            raise ErroResumoIA(
                f"falha ao chamar o Ollama: {type(erro).__name__}: {erro}"
            ) from erro

        texto = "".join(partes)
        if not texto.strip():
            raise ErroResumoIA("o modelo devolveu resposta vazia")

        return texto.strip()


# ============================================================
# Diagnostico do ambiente
# ============================================================


@dataclass
class DiagnosticoOllama:
    """
    Em que pe esta o Ollama nesta maquina.

    "Nao respondeu" junta tres situacoes com remedios diferentes - nao
    instalado, instalado mas fechado, aberto mas sem o modelo - e a
    mensagem generica deixava o analista adivinhar qual era a dele.
    """

    # "nao_instalado", "parado", "sem_modelo" ou "pronto".
    estado: str
    instalado: bool
    rodando: bool
    versao: str = ""
    executavel: str = ""
    modelos: list[str] = field(default_factory=list)
    modelo_pedido: str = MODELO_PADRAO
    modelo_presente: bool = False
    # O que fazer, numa frase. Vazio quando esta pronto.
    orientacao: str = ""
    # O comando que instala o modelo pedido.
    comando_instalacao: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _executavel_ollama() -> str:
    """
    Onde o Ollama esta instalado, ou "" se nao estiver.

    O PATH nao basta: o instalador do Windows poe o executavel em
    %LOCALAPPDATA%, e um terminal aberto antes da instalacao nao enxerga
    a mudanca no PATH.
    """
    import os
    import shutil
    from pathlib import Path

    encontrado = shutil.which("ollama")
    if encontrado:
        return encontrado

    candidatos = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe",
        Path("/Applications/Ollama.app/Contents/Resources/ollama"),
        Path("/usr/local/bin/ollama"),
        Path("/usr/bin/ollama"),
    ]
    for candidato in candidatos:
        if str(candidato) not in ("", ".") and candidato.is_file():
            return str(candidato)
    return ""


def _versao_pelo_executavel(executavel: str) -> str:
    """
    Versao do cliente, para quando o servidor esta fechado.

    `ollama --version` sem servidor imprime um aviso e, depois, a versao
    do cliente - e ela que interessa aqui.
    """
    import subprocess

    try:
        saida = subprocess.run(
            [executavel, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""

    texto = (saida.stdout or "") + (saida.stderr or "")
    achado = re.search(r"\d+\.\d+\.\d+", texto)
    return achado.group() if achado else ""


def diagnosticar_ollama(
    modelo: str = MODELO_PADRAO, url: str = URL_OLLAMA_PADRAO
) -> DiagnosticoOllama:
    """
    Descobre se o Ollama esta instalado, aberto e com o modelo pedido.

    Nunca levanta excecao: o diagnostico existe justamente para os casos
    em que as coisas nao estao funcionando.
    """
    import requests

    url = url.rstrip("/")
    modelo = modelo or MODELO_PADRAO

    # --- Esta rodando? ---
    try:
        resposta = requests.get(f"{url}/api/version", timeout=3)
        resposta.raise_for_status()
        versao = str(resposta.json().get("version", ""))
        rodando = True
    except Exception:
        versao = ""
        rodando = False

    if not rodando:
        executavel = _executavel_ollama()
        if not executavel:
            return DiagnosticoOllama(
                estado="nao_instalado",
                instalado=False,
                rodando=False,
                modelo_pedido=modelo,
            comando_instalacao=comando_de_instalacao(modelo),
                orientacao=(
                    "O Ollama não está instalado. Baixe em ollama.com/download "
                    f"e depois rode: {comando_de_instalacao(modelo)}"
                ),
            )
        return DiagnosticoOllama(
            estado="parado",
            instalado=True,
            rodando=False,
            versao=_versao_pelo_executavel(executavel),
            executavel=executavel,
            modelo_pedido=modelo,
            comando_instalacao=comando_de_instalacao(modelo),
            orientacao=(
                "O Ollama está instalado, mas fechado. Abra o aplicativo "
                "Ollama (ou rode: ollama serve) e verifique de novo."
            ),
        )

    # --- Rodando: tem o modelo? ---
    try:
        tags = requests.get(f"{url}/api/tags", timeout=5).json()
        modelos = sorted(m.get("name", "") for m in tags.get("models", []) if m.get("name"))
    except Exception:
        modelos = []

    base = modelo.split(":")[0]
    presente = any(m == modelo or m.split(":")[0] == base for m in modelos)

    if not presente:
        return DiagnosticoOllama(
            estado="sem_modelo",
            instalado=True,
            rodando=True,
            versao=versao,
            modelos=modelos,
            modelo_pedido=modelo,
            comando_instalacao=comando_de_instalacao(modelo),
            orientacao=f"O Ollama está aberto, mas sem o modelo. Rode: {comando_de_instalacao(modelo)}",
        )

    return DiagnosticoOllama(
        estado="pronto",
        instalado=True,
        rodando=True,
        versao=versao,
        modelos=modelos,
        modelo_pedido=modelo,
        modelo_presente=True,
    )


# ============================================================
# API principal
# ============================================================


def gerar_resumo(
    resultado: Any,
    modelo: str = MODELO_PADRAO,
    url: str = URL_OLLAMA_PADRAO,
    timeout: int = TIMEOUT_PADRAO,
    progresso: CallbackGeracao | None = None,
) -> ResumoIA:
    """
    Gera o resumo executivo da analise usando o LLM local.

    Args:
        resultado: o ResultadoAnalise do pipeline.
        modelo: nome do modelo no Ollama.
        url: endereco do servidor Ollama.
        timeout: limite em segundos. A primeira chamada carrega o modelo e
            pode passar de dois minutos.
        progresso: chamado a cada pedaco gerado, para quem quiser mostrar o
            andamento. Esta e a unica etapa do pipeline que leva minutos
            sem produzir sinal nenhum por conta propria.

    Returns:
        ResumoIA, sempre. Falha vira `erro` preenchido, nunca excecao: o
        resumo e um adicional, e a analise nao pode depender dele.
    """
    resumo = ResumoIA(modelo=modelo)
    cliente = ClienteOllama(url=url, modelo=modelo, timeout=timeout)

    disponivel, motivo = cliente.disponivel()
    if not disponivel:
        resumo.erro = motivo
        return resumo

    prompt = INSTRUCAO + _montar_contexto(resultado)
    inicio = time.monotonic()

    try:
        resumo.texto = cliente.gerar(prompt, progresso=progresso)
    except ErroResumoIA as erro:
        resumo.erro = str(erro)
        resumo.duracao_segundos = time.monotonic() - inicio
        return resumo

    resumo.duracao_segundos = time.monotonic() - inicio
    resumo.gerado = True

    # --- A verificacao e o ponto do modulo ---
    resumo.invencoes = verificar(resumo.texto, resultado)

    if resumo.invencoes:
        logger.warning(
            "resumo do LLM contém %d afirmação(ões) sem respaldo nos achados",
            len(resumo.invencoes),
        )
        resumo.avisos.append(
            f"{len(resumo.invencoes)} afirmação(ões) do resumo não "
            "correspondem a nenhum achado desta análise"
        )

    logger.info(
        "resumo gerado em %.1fs (%d invenções detectadas)",
        resumo.duracao_segundos,
        len(resumo.invencoes),
    )
    return resumo


def resumir_em_texto(resumo: ResumoIA) -> str:
    """Rendericao para o CLI e o relatorio."""
    if not resumo.gerado:
        return f"Resumo por IA não gerado: {resumo.erro or 'motivo desconhecido'}"

    linhas = [resumo.texto, "", resumo.ressalva]

    if resumo.invencoes:
        linhas += ["", "Afirmações sem respaldo nos achados:"]
        linhas += [f"  ! {i}" for i in resumo.invencoes]

    return "\n".join(linhas)
