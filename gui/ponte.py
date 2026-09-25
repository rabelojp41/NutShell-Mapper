"""
Ponte entre a interface web e o Python.

A interface e uma pagina HTML local rendida por um QWebEngineView. Ela nao
fala com servidor nenhum: chama os metodos desta classe pelo QWebChannel,
que e um canal em memoria entre o JavaScript e o Python do mesmo processo.

Por que nao um servidor HTTP local, que seria o caminho mais comum: um
servidor em localhost aceita requisicao de QUALQUER pagina aberta no
navegador do analista. Um site malicioso poderia mandar a ferramenta
baixar uma amostra do MalwareBazaar ou gravar arquivo em disco. Sem porta
aberta, essa superficie simplesmente nao existe.

Tres regras que esta classe segue:

  1. Nenhum metodo confia no que vem do JavaScript. A pagina rende dado
     extraido de malware, e o dado e do adversario; se algum dia uma
     string escapar para HTML, o que ela conseguir chamar daqui precisa
     ser inofensivo. Por isso so abre link de host conhecido, so abre
     arquivo que a propria ponte gravou, e toda acao que traz malware
     para o disco exige o dialogo nativo do sistema.

  2. Toda resposta e JSON, e todo erro vira {"ok": false, "erro": ...}.
     Excecao atravessando o canal chega ao JavaScript como silencio.

  3. O que demora (download, consulta de rede) roda fora da thread da
     interface e responde pelo sinal `tarefaConcluida`. Bloquear a thread
     principal congela a pagina inteira.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from PySide6.QtCore import QObject, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QFileDialog, QWidget

from core.pipeline import OpcoesAnalise
from core.resumo_ia import MODELO_PADRAO
from gui.toca_discos import TocaDiscos
from gui.worker import ExecutorDeAnalise

logger = logging.getLogger(__name__)


# Hosts que a interface pode abrir no navegador do sistema. Lista fechada
# de proposito: a pagina mostra URLs extraidas de malware, e um clique num
# indicador nunca pode virar uma visita ao C2.
HOSTS_PERMITIDOS = frozenset(
    {
        "attack.mitre.org",
        "nvd.nist.gov",
        "www.virustotal.com",
        "bazaar.abuse.ch",
        "urlhaus.abuse.ch",
        "threatfox.abuse.ch",
        "yaraify.abuse.ch",
        "malpedia.caad.fkie.fraunhofer.de",
        "www.shodan.io",
        "www.abuseipdb.com",
        "otx.alienvault.com",
        "urlscan.io",
        "platform.censys.io",
        "haveibeenpwned.com",
        "intelx.io",
        "mitre-attack.github.io",
        "ollama.com",
    }
)

FORMATOS_DE_RELATORIO = ("md", "json", "pdf", "docx")
FORMATOS_DE_ARTEFATO = ("auto", "pe", "sc32", "sc64")


# ============================================================
# Serializacao
# ============================================================


def _serializar(objeto: Any) -> Any:
    """Converte o que o json nao conhece por conta propria."""
    if isinstance(objeto, Enum):
        return objeto.value
    if isinstance(objeto, Path):
        return str(objeto)
    if isinstance(objeto, (set, frozenset, tuple)):
        return list(objeto)
    if is_dataclass(objeto) and not isinstance(objeto, type):
        return asdict(objeto)
    return str(objeto)


def para_json(objeto: Any) -> str:
    return json.dumps(objeto, default=_serializar, ensure_ascii=False)


def resultado_para_dict(resultado) -> dict:
    """
    O resultado inteiro, no formato que a pagina consome.

    Parte do `to_dict()` do pipeline e acrescenta o que ele deixa de fora
    por ser propriedade calculada: os IOCs consolidados (inclusive os
    revelados pela desofuscacao), o hash completo e os veredictos de
    validade que a pagina precisa mostrar sem recalcular.
    """
    dados = resultado.to_dict()
    dados["sha256"] = resultado.sha256
    dados["iocs"] = [asdict(i) for i in resultado.iocs]
    dados["nome"] = Path(resultado.caminho).name

    if resultado.regra_yara is not None and dados.get("regra_yara"):
        dados["regra_yara"]["valida"] = resultado.regra_yara.valida

    if resultado.resumo_ia is not None and dados.get("resumo_ia"):
        dados["resumo_ia"]["confiavel"] = resultado.resumo_ia.confiavel
        dados["resumo_ia"]["ressalva"] = resultado.resumo_ia.ressalva

    extracao = resultado.extracao
    if extracao is not None and dados.get("extracao"):
        dados["extracao"]["md5"] = getattr(extracao, "md5", "")
        dados["extracao"]["tamanho_bytes"] = getattr(extracao, "tamanho_bytes", 0)

    return dados


def descrever_arquivo(caminho: Path) -> dict:
    """
    O que a pagina mostra sobre o arquivo antes da analise.

    Le so os primeiros bytes, para dizer o formato provavel. Nao executa,
    nao parseia - a analise e que decide o que o arquivo e.
    """
    try:
        tamanho = caminho.stat().st_size
        with caminho.open("rb") as arquivo:
            cabecalho = arquivo.read(8)
    except OSError as erro:
        return {"ok": False, "erro": f"nao foi possivel ler o arquivo: {erro}"}

    if cabecalho[:2] == b"MZ":
        formato = "Executável Windows (PE)"
    elif cabecalho[:4] == b"\x7fELF":
        formato = "Executável Linux (ELF)"
    elif cabecalho[:4] == b"%PDF":
        formato = "Documento PDF"
    elif cabecalho[:2] == b"PK":
        formato = "Arquivo ZIP / Office"
    elif cabecalho[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        formato = "Documento Office legado (OLE)"
    elif tamanho == 0:
        formato = "Arquivo vazio"
    else:
        formato = "Binário sem cabeçalho conhecido"

    return {
        "ok": True,
        "caminho": str(caminho),
        "nome": caminho.name,
        "tamanho": tamanho,
        "formato": formato,
    }


# ============================================================
# Ponte
# ============================================================


class Ponte(QObject):
    """
    O que a pagina pode pedir ao Python.

    Sinais (Python -> pagina), todos com JSON:
        arquivoSelecionado : arquivo escolhido por dialogo ou arrastado
        progresso          : {estagio, mensagem, fracao}
        concluido          : o resultado inteiro
        falhou             : erro que impediu qualquer resultado
        tarefaConcluida    : {id, ok, dados | erro} de tarefa em segundo plano
        arrastando         : {ativo} enquanto um arquivo e arrastado por cima
        discoMudou         : estado do toca-discos (faixa, tocando, posicao)
    """

    arquivoSelecionado = Signal(str)
    progresso = Signal(str)
    concluido = Signal(str)
    falhou = Signal(str)
    tarefaConcluida = Signal(str)
    # {id, mensagem}: andamento de tarefa longa em segundo plano.
    andamentoTarefa = Signal(str)
    arrastando = Signal(str)
    # {ok, nome, caminho}: .eml escolhido ou arrastado para a janela.
    emailSelecionado = Signal(str)
    discoMudou = Signal(str)

    def __init__(self, janela: QWidget):
        super().__init__(janela)
        self._janela = janela
        self._arquivo: Path | None = None
        self._resultado = None
        # Arquivos que esta ponte gravou. So eles podem ser abertos pela
        # pagina: abrir caminho arbitrario vindo do JavaScript seria
        # entregar um "execute isto" a quem controlar a pagina.
        self._gravados: set[str] = set()
        # Amostras baixadas e ainda nao extraidas, por SHA256.
        self._amostras: dict[str, Any] = {}
        # E-mail escolhido e o resultado da ultima analise dele.
        self._email: Path | None = None
        self._resultado_email = None
        # O que acompanha o e-mail analisado: consultas de dominio, Diamond,
        # piramide, grafo e, quando pedidos, regra YARA e resumo por IA.
        self._email_extra: dict[str, Any] = {}

        self._executor = ExecutorDeAnalise(self)
        self._executor.progresso.connect(self._ao_progredir)
        self._executor.concluido.connect(self._ao_concluir)
        self._executor.falhou.connect(self._ao_falhar)

        self.toca_discos = TocaDiscos(pai=self)
        self.toca_discos.mudou.connect(self.discoMudou)

    # ------------------------------------------------------------
    # Arquivo
    # ------------------------------------------------------------

    def definir_arquivo(self, caminho: Path) -> None:
        """Chamado pelo dialogo e pelo arrastar-e-soltar da janela."""
        if caminho.suffix.lower() == ".eml":
            # Soltar um e-mail na janela leva para a analise de e-mail, e
            # nao para a analise de artefato, que so veria texto.
            self.definir_email(caminho)
            return
        descricao = descrever_arquivo(caminho)
        if descricao.get("ok"):
            self._arquivo = caminho
        self.arquivoSelecionado.emit(para_json(descricao))

    @Slot()
    def escolherArquivo(self) -> None:
        caminho, _ = QFileDialog.getOpenFileName(
            self._janela, "Selecionar artefato", "", "Todos os arquivos (*)"
        )
        if caminho:
            self.definir_arquivo(Path(caminho))

    # ------------------------------------------------------------
    # Estado do ambiente
    # ------------------------------------------------------------

    @Slot(result=str)
    def estado(self) -> str:
        """
        Como esta o ambiente: chaves, Ollama, ATT&CK.

        Nunca devolve chave, nem mascarada. A pagina so precisa saber se
        existe.
        """
        from config.settings import CONFIG
        from core.mitre_mapper import CAMINHO_CACHE_PADRAO

        cache = Path(CONFIG.mitre_cache_dir) / CAMINHO_CACHE_PADRAO.name
        return para_json(
            {
                "chaves": {
                    "virustotal": bool(CONFIG.virustotal_api_key),
                    "shodan": bool(CONFIG.shodan_api_key),
                    "malwarebazaar": bool(CONFIG.malwarebazaar_api_key),
                },
                "enriquecimento_habilitado": CONFIG.enable_enrichment,
                "env_encontrado": CONFIG.env_encontrado,
                "attack": {
                    "em_cache": cache.exists(),
                    "tamanho_mb": round(cache.stat().st_size / 2**20, 1)
                    if cache.exists()
                    else 0,
                },
                "formatos_de_artefato": list(FORMATOS_DE_ARTEFATO),
                "formatos_de_relatorio": list(FORMATOS_DE_RELATORIO),
                "modelo_padrao": MODELO_PADRAO,
                "fontes_de_reputacao": _fontes_de_reputacao(),
                "analisando": self._executor.rodando,
            }
        )

    @Slot(str)
    def verificarOllama(self, modelo: str) -> None:
        """Checa o Ollama em segundo plano: pode levar ate 10 s se estiver fora."""

        def verificar():
            from core.resumo_ia import diagnosticar_ollama

            return diagnosticar_ollama(modelo or MODELO_PADRAO).to_dict()

        self._em_segundo_plano("ollama", verificar)

    # ------------------------------------------------------------
    # Analise
    # ------------------------------------------------------------

    @Slot(str, result=str)
    def analisar(self, opcoes_json: str) -> str:
        if self._arquivo is None:
            return para_json({"ok": False, "erro": "nenhum arquivo selecionado"})
        if self._executor.rodando:
            return para_json({"ok": False, "erro": "ja existe uma analise em andamento"})

        try:
            pedido = json.loads(opcoes_json or "{}")
            opcoes = _opcoes_da_pagina(pedido)
        except (ValueError, TypeError) as erro:
            return para_json({"ok": False, "erro": f"opcoes invalidas: {erro}"})

        self._resultado = None
        self._executor.iniciar(self._arquivo, opcoes)
        return para_json({"ok": True})

    @Slot()
    def cancelar(self) -> None:
        self._executor.cancelar()

    def _ao_progredir(self, estagio: str, mensagem: str, fracao: float) -> None:
        self.progresso.emit(
            para_json({"estagio": estagio, "mensagem": mensagem, "fracao": fracao})
        )

    def _ao_concluir(self, resultado) -> None:
        self._resultado = resultado
        try:
            self.concluido.emit(para_json(resultado_para_dict(resultado)))
        except Exception as erro:
            # Um resultado que nao serializa e bug nosso, mas o analista
            # precisa saber que a analise terminou e o que houve.
            logger.exception("falha ao serializar o resultado")
            self.falhou.emit(f"a analise terminou, mas o resultado nao pode ser exibido: {erro}")

    def _ao_falhar(self, mensagem: str) -> None:
        self.falhou.emit(mensagem)

    # ------------------------------------------------------------
    # Exportacao
    # ------------------------------------------------------------

    @Slot(str, result=str)
    def exportarRelatorio(self, formato: str) -> str:
        if self._resultado is None:
            return _erro("nenhuma analise concluida")
        if formato not in FORMATOS_DE_RELATORIO:
            return _erro(f"formato desconhecido: {formato}")

        sugestao = f"{Path(self._resultado.caminho).stem}_{self._resultado.sha256[:8]}.{formato}"
        caminho, _ = QFileDialog.getSaveFileName(
            self._janela, "Salvar relatório", sugestao, f"{formato.upper()} (*.{formato})"
        )
        if not caminho:
            return para_json({"ok": False, "cancelado": True})

        from reports import report_generator

        try:
            destino = report_generator.FORMATOS[formato](self._resultado, caminho)
        except Exception as erro:
            logger.exception("falha ao exportar relatorio")
            return _erro(str(erro))

        self._gravados.add(str(Path(destino).resolve()))
        return para_json({"ok": True, "caminho": str(destino)})

    @Slot(str, result=str)
    def exportarIndicadores(self, confianca_minima: str) -> str:
        """
        Grava CSV, STIX e MISP de uma vez: sao pequenos, e adivinhar qual o
        analista vai precisar custaria mais um dialogo.
        """
        if self._resultado is None:
            return _erro("nenhuma analise concluida")

        from core.string_extractor import Confianca
        from reports import ioc_export

        try:
            corte = Confianca(confianca_minima or "media")
        except ValueError:
            return _erro(f"confianca desconhecida: {confianca_minima}")

        destino = QFileDialog.getExistingDirectory(
            self._janela,
            "Onde salvar os indicadores",
            str(Path(self._resultado.caminho).parent),
        )
        if not destino:
            return para_json({"ok": False, "cancelado": True})

        saidas = ioc_export.exportar(
            self._resultado, destino, ["csv", "stix", "misp"], confianca_minima=corte
        )
        if not saidas:
            return _erro("nenhum formato pode ser gravado")

        for saida in saidas.values():
            self._gravados.add(str(Path(saida.caminho).resolve()))
        self._gravados.add(str(Path(destino).resolve()))

        return para_json(
            {
                "ok": True,
                "pasta": destino,
                "formatos": {f: s.to_dict() for f, s in saidas.items()},
            }
        )

    @Slot(result=str)
    def salvarYara(self) -> str:
        if self._resultado is None or self._resultado.regra_yara is None:
            return _erro("nenhuma regra YARA gerada")

        regra = self._resultado.regra_yara
        caminho, _ = QFileDialog.getSaveFileName(
            self._janela, "Salvar regra YARA", f"{regra.nome}.yar", "YARA (*.yar)"
        )
        if not caminho:
            return para_json({"ok": False, "cancelado": True})

        from core.yara_generator import salvar

        try:
            destino = salvar(regra, caminho, forcar=True)
        except Exception as erro:
            return _erro(str(erro))

        self._gravados.add(str(Path(destino).resolve()))
        return para_json({"ok": True, "caminho": str(destino)})

    @Slot(str)
    def revisarYara(self, modelo: str) -> None:
        """
        Explica e revisa a regra YARA com o modelo local.

        A parte calculada (condição, fatos, fraquezas) sai mesmo com o
        Ollama desligado; a do modelo, quando ele responde.
        """
        resultado = self._resultado
        if resultado is None or resultado.regra_yara is None:
            self.tarefaConcluida.emit(
                para_json({"id": "revisao_yara", "ok": False, "erro": "nenhuma regra YARA gerada"})
            )
            return

        ultimo = [0.0]

        def andamento(estado) -> None:
            # Mesmo limite do resumo: o modelo emite dezenas de pedaços por
            # segundo, e ninguém lê nessa velocidade.
            agora = time.monotonic()
            if estado.concluido or agora - ultimo[0] >= 0.5:
                ultimo[0] = agora
                self.andamentoTarefa.emit(
                    para_json(
                        {
                            "id": "revisao_yara",
                            "mensagem": f"{estado.pedacos} tokens em {estado.segundos:.0f}s",
                        }
                    )
                )

        def revisar():
            from core.revisao_yara import revisar_regra

            revisao = revisar_regra(
                resultado.regra_yara,
                resultado,
                modelo=modelo or MODELO_PADRAO,
                progresso=andamento,
            )
            dados = revisao.to_dict()
            dados["sha256"] = resultado.sha256
            return dados

        self._em_segundo_plano("revisao_yara", revisar)

    # ------------------------------------------------------------
    # Sistema
    # ------------------------------------------------------------

    @Slot(str, result=str)
    def copiar(self, texto: str) -> str:
        QGuiApplication.clipboard().setText(texto or "")
        return para_json({"ok": True})

    @Slot(str, result=str)
    def abrirLink(self, url: str) -> str:
        """Abre no navegador do sistema, e so para host conhecido."""
        partes = urlparse(url or "")
        if partes.scheme != "https" or partes.hostname not in HOSTS_PERMITIDOS:
            logger.warning("link recusado: %s", url)
            return _erro("link fora da lista de sites permitidos")
        QDesktopServices.openUrl(QUrl(url))
        return para_json({"ok": True})

    @Slot(str, result=str)
    def abrirArquivo(self, caminho: str) -> str:
        """Abre um arquivo ou pasta gravado por esta ponte, e nenhum outro."""
        try:
            alvo = str(Path(caminho).resolve())
        except OSError:
            return _erro("caminho invalido")
        if alvo not in self._gravados:
            logger.warning("abertura recusada, arquivo nao gravado pela ponte: %s", caminho)
            return _erro("so e possivel abrir o que a ferramenta gravou")
        QDesktopServices.openUrl(QUrl.fromLocalFile(alvo))
        return para_json({"ok": True})

    # ------------------------------------------------------------
    # MalwareBazaar
    # ------------------------------------------------------------

    @Slot(str)
    def bazaarConsultar(self, valor: str) -> None:
        """Consulta por hash. Nao baixa nada."""
        valor = (valor or "").strip()

        def consultar():
            from config.settings import CONFIG
            from enrichment import malwarebazaar_client

            cliente = malwarebazaar_client.criar(CONFIG)
            if cliente is None:
                raise RuntimeError(
                    "Auth-Key do MalwareBazaar nao configurada, ou enriquecimento "
                    "desabilitado no .env. A chave e obtida em auth.abuse.ch."
                )
            with cliente:
                r = cliente.consultar_hash(valor)
            if r.erro:
                raise RuntimeError(r.erro)
            return r.to_dict()

        if not valor:
            self.tarefaConcluida.emit(para_json({"id": "bazaar", "ok": False, "erro": "informe o hash"}))
            return
        self._em_segundo_plano("bazaar", consultar)

    @Slot(str)
    def bazaarBaixar(self, sha256: str) -> None:
        """
        Baixa a amostra como ZIP cifrado. Nao descompacta.

        A pagina ja pediu confirmacao; o dialogo nativo de pasta e a segunda
        barreira, e a que nao pode ser contornada por script.
        """
        from config.settings import CONFIG

        sha256 = (sha256 or "").strip()
        destino = QFileDialog.getExistingDirectory(
            self._janela, "Onde salvar a amostra (ZIP cifrado)", str(CONFIG.samples_dir)
        )
        if not destino:
            self.tarefaConcluida.emit(para_json({"id": "baixar", "ok": False, "cancelado": True}))
            return

        def baixar():
            from enrichment import malwarebazaar_client

            cliente = malwarebazaar_client.criar(CONFIG)
            if cliente is None:
                raise RuntimeError("Auth-Key do MalwareBazaar nao configurada")
            with cliente:
                amostra = cliente.baixar_amostra(sha256, destino)
            self._amostras[sha256] = amostra
            self._gravados.add(str(Path(amostra.caminho).resolve()))
            self._gravados.add(str(Path(destino).resolve()))
            return {"caminho": str(amostra.caminho), "senha": amostra.senha, "sha256": sha256}

        self._em_segundo_plano("baixar", baixar)

    @Slot(str, result=str)
    def bazaarExtrair(self, sha256: str) -> str:
        """
        Descompacta a amostra baixada: e o que grava malware vivo em disco.

        Pede uma confirmacao nativa final, alem da que a pagina ja mostrou.
        E a unica acao do Nut-Shell Mapper com esse efeito, e ela nao pode ser
        disparada so por JavaScript.
        """
        from PySide6.QtWidgets import QMessageBox

        amostra = self._amostras.get((sha256 or "").strip())
        if amostra is None:
            return _erro("amostra nao encontrada: baixe antes de extrair")

        resposta = QMessageBox.warning(
            self._janela,
            "Extrair malware",
            "Confirme que está em ambiente ISOLADO: máquina virtual, sem rede "
            "compartilhada, com snapshot.\n\nO arquivo será gravado sem extensão, "
            "mas continua sendo malware.\n\nExtrair?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if resposta != QMessageBox.Yes:
            return para_json({"ok": False, "cancelado": True})

        from config.settings import CONFIG
        from enrichment import malwarebazaar_client

        cliente = malwarebazaar_client.criar(CONFIG)
        if cliente is None:
            return _erro("Auth-Key do MalwareBazaar nao configurada")

        try:
            extraida = cliente.extrair_amostra(amostra, confirmo_ambiente_isolado=True)
        except Exception as erro:
            return _erro(str(erro))

        self._amostras.pop(sha256, None)
        self.definir_arquivo(Path(extraida.caminho))
        return para_json(
            {"ok": True, "caminho": str(extraida.caminho), "hash_confere": extraida.hash_confere}
        )

    # ------------------------------------------------------------
    # ATT&CK
    # ------------------------------------------------------------

    @Slot()
    def atualizarAttack(self) -> None:
        def atualizar():
            from core.mitre_mapper import MitreAttack

            attack = MitreAttack()
            attack.baixar(forcar=True)
            attack.carregar(baixar_se_faltar=False)
            return {"versao": attack.versao or "desconhecida", "objetos": len(attack._por_id)}

        self._em_segundo_plano("attack", atualizar)

    # ------------------------------------------------------------
    # Infra
    # ------------------------------------------------------------

    def _em_segundo_plano(self, identificador: str, funcao: Callable[[], Any]) -> None:
        """
        Roda fora da thread da interface e responde por `tarefaConcluida`.

        O sinal emitido desta thread e entregue na thread da interface pelo
        proprio Qt: a Ponte vive la, e a conexao vira enfileirada.
        """

        def rodar():
            try:
                dados = funcao()
                resposta = {"id": identificador, "ok": True, "dados": dados}
            except Exception as erro:
                logger.warning("tarefa %s falhou: %s", identificador, erro)
                resposta = {"id": identificador, "ok": False, "erro": str(erro)}
            self.tarefaConcluida.emit(para_json(resposta))

        threading.Thread(target=rodar, name=f"ponte-{identificador}", daemon=True).start()

    # ------------------------------------------------------------
    # E-mail e dominio
    # ------------------------------------------------------------

    def definir_email(self, caminho: Path) -> None:
        self._email = caminho
        self._resultado_email = None
        self._email_extra = {}
        self.emailSelecionado.emit(para_json({"ok": True, "nome": caminho.name, "caminho": str(caminho)}))

    @Slot()
    def escolherEmail(self) -> None:
        caminho, _ = QFileDialog.getOpenFileName(
            self._janela, "Selecionar e-mail", "", "E-mail (*.eml);;Todos os arquivos (*)"
        )
        if caminho:
            self.definir_email(Path(caminho))

    @Slot(bool)
    def analisarEmail(self, online: bool) -> None:
        """
        Analisa o e-mail escolhido. Com `online`, consulta tambem os dominios
        envolvidos - so o nome de cada dominio sai da maquina.
        """
        caminho = self._email
        if caminho is None:
            self.tarefaConcluida.emit(para_json({"id": "email", "ok": False, "erro": "nenhum e-mail selecionado"}))
            return

        def analisar():
            from core.analise_email import analisar_email
            from core.diamante import diamante_do_email
            from core.dominios import e_webmail, registravel
            from core.grafo import grafo_do_email
            from core.piramide import piramide_do_email

            resultado = analisar_email(caminho)
            dados = resultado.to_dict()
            dados["nome"] = caminho.name
            dados["dominios"] = []
            if online:
                from enrichment.consulta_dominio import consultar_dominio

                alvos: list[str] = []
                candidatos = [i.dominio for i in resultado.identidades if i.campo != "Message-ID"]
                candidatos += [l.dominio for l in resultado.links if l.tipo in ("http", "encurtador")]
                candidatos += [urlparse(u).hostname or "" for u in resultado.imagens_remotas]
                for d in candidatos:
                    base = registravel(d) if d else ""
                    if base and not e_webmail(base) and base not in alvos:
                        alvos.append(base)
                for alvo in alvos[:6]:
                    self.andamentoTarefa.emit(para_json({"id": "email", "mensagem": f"Consultando {alvo}…"}))
                    try:
                        dados["dominios"].append(consultar_dominio(alvo, certificados=True).to_dict())
                    except ValueError:
                        continue
            dados["reputacao"] = []
            if online:
                from enrichment.consulta_reputacao import consultar_reputacao, indicadores_do_email

                def andamento(mensagem: str) -> None:
                    self.andamentoTarefa.emit(para_json({"id": "email", "mensagem": f"Reputação · {mensagem}"}))

                reputacao = consultar_reputacao(
                    indicadores_do_email(resultado, diamante_do_email(resultado, dados["dominios"])), progresso=andamento
                )
                dados["reputacao"] = [x.to_dict() for x in reputacao]
            diamante = diamante_do_email(resultado, dados["dominios"], dados["reputacao"])
            piramide = piramide_do_email(resultado, diamante)
            grafo = grafo_do_email(resultado, diamante, dados["dominios"])
            dados["diamante"] = diamante.to_dict()
            dados["piramide"] = piramide.to_dict()
            dados["grafo"] = grafo.to_dict()
            # So vira o resultado corrente quando tudo deu certo: um PDF de
            # analise pela metade seria pior que nenhum.
            self._resultado_email = resultado
            self._email_extra = {"consultas": dados["dominios"], "reputacao": dados["reputacao"], "diamante": diamante,
                                 "piramide": piramide, "grafo": grafo}
            return dados

        self._em_segundo_plano("email", analisar)

    @Slot(str, bool, bool, bool)
    def adicionarContribuicao(self, texto: str, usar_ia: bool, online: bool, certeza: bool) -> None:
        """
        Achado do analista: extrai os indicadores, classifica (IA ou regra),
        roda as pesquisas escolhidas e refaz Diamond, piramide e grafo.
        """
        if self._resultado_email is None:
            self.tarefaConcluida.emit(para_json({"id": "contribuicao", "ok": False, "erro": "nenhum e-mail analisado"}))
            return
        resultado = self._resultado_email
        extra = self._email_extra

        def andamento(mensagem) -> None:
            texto_ = mensagem if isinstance(mensagem, str) else mensagem.resumo()
            self.andamentoTarefa.emit(para_json({"id": "contribuicao", "mensagem": texto_}))

        def processar():
            from core import contribuicao as ct
            from core.diamante import diamante_do_email
            from core.grafo import grafo_do_email
            from core.piramide import piramide_do_email

            c = ct.nova_contribuicao(texto, resultado, extra.get("diamante"), modo="certeza" if certeza else "verificar")
            if not (usar_ia and ct.classificar_com_ia(c, resultado, extra.get("diamante"), progresso=andamento)):
                ct.classificar_por_regra(c, resultado)
            ct.executar_acoes(c, online=online, progresso=andamento)
            anteriores = extra.setdefault("contribuicoes", [])
            confirmadas = [x for x in anteriores if x.entra_na_analise]
            ct.validar(
                c, resultado,
                list(extra.get("consultas", [])) + [d for x in confirmadas for d in x.resultados.get("dominios", [])],
                list(extra.get("reputacao", [])) + [y for x in confirmadas for y in x.resultados.get("reputacao", [])],
                online=online,
            )
            contribuicoes = anteriores + [c]
            dados = self._recompor_email(resultado, extra, contribuicoes, ct, diamante_do_email, grafo_do_email, piramide_do_email)
            if resultado is self._resultado_email:
                extra["contribuicoes"] = contribuicoes
                extra.update(dados["_objetos"])
            del dados["_objetos"]
            return dados

        self._em_segundo_plano("contribuicao", processar)

    @Slot(str, result=str)
    def removerContribuicao(self, identificador: str) -> str:
        if self._resultado_email is None:
            return _erro("nenhum e-mail analisado")
        from core import contribuicao as ct
        from core.diamante import diamante_do_email
        from core.grafo import grafo_do_email
        from core.piramide import piramide_do_email

        extra = self._email_extra
        restantes = [c for c in extra.get("contribuicoes", []) if c.id != identificador]
        dados = self._recompor_email(self._resultado_email, extra, restantes, ct, diamante_do_email, grafo_do_email, piramide_do_email)
        extra["contribuicoes"] = restantes
        extra.update(dados.pop("_objetos"))
        return para_json({"ok": True, **dados})

    @staticmethod
    def _recompor_email(resultado, extra, contribuicoes, ct, diamante_do_email, grafo_do_email, piramide_do_email) -> dict:
        # So o que foi confirmado (ou afirmado com certeza) alimenta a analise.
        validas = [c for c in contribuicoes if c.entra_na_analise]
        consultas = list(extra.get("consultas", [])) + [d for c in validas for d in c.resultados.get("dominios", [])]
        reputacao = list(extra.get("reputacao", [])) + [x for c in validas for x in c.resultados.get("reputacao", [])]
        diamante = diamante_do_email(resultado, consultas, reputacao)
        grafo = grafo_do_email(resultado, diamante, consultas)
        ct.aplicar(diamante, grafo, contribuicoes)
        piramide = piramide_do_email(resultado, diamante)
        return {
            "diamante": diamante.to_dict(), "grafo": grafo.to_dict(), "piramide": piramide.to_dict(),
            "contribuicoes": [c.to_dict() for c in contribuicoes],
            "_objetos": {"diamante": diamante, "grafo": grafo, "piramide": piramide},
        }

    @Slot(result=str)
    def gerarYaraEmail(self) -> str:
        if self._resultado_email is None:
            return _erro("nenhum e-mail analisado")
        from core.yara_email import gerar_regra_email

        regra = gerar_regra_email(self._resultado_email)
        self._email_extra["regra"] = regra
        dados = regra.to_dict()
        dados["valida"] = regra.valida and not regra.falsos_positivos
        return para_json({"ok": True, "regra": dados})

    @Slot(result=str)
    def salvarYaraEmail(self) -> str:
        regra = self._email_extra.get("regra")
        if regra is None or not regra.texto:
            return _erro("gere a regra primeiro")
        caminho, _ = QFileDialog.getSaveFileName(self._janela, "Salvar regra YARA", f"{regra.nome}.yar", "YARA (*.yar)")
        if not caminho:
            return para_json({"ok": False, "cancelado": True})
        Path(caminho).write_text(regra.texto, encoding="utf-8")
        self._gravados.add(str(Path(caminho).resolve()))
        return para_json({"ok": True, "caminho": caminho})

    @Slot(str)
    def resumirEmailComIA(self, modelo: str) -> None:
        """Resumo executivo pela IA local, conferido. Roda em segundo plano."""
        if self._resultado_email is None:
            self.tarefaConcluida.emit(para_json({"id": "ia_email", "ok": False, "erro": "nenhum e-mail analisado"}))
            return
        resultado = self._resultado_email
        extra = dict(self._email_extra)

        def andamento(estado) -> None:
            self.andamentoTarefa.emit(para_json({"id": "ia_email", "mensagem": estado.resumo()}))

        def gerar():
            from core.ia_email import gerar_resumo_email

            resumo = gerar_resumo_email(resultado, extra.get("diamante"), extra.get("consultas"), extra.get("reputacao"),
                                        modelo=modelo or MODELO_PADRAO, progresso=andamento)
            if resultado is self._resultado_email:
                self._email_extra["resumo"] = resumo
            dados = resumo.to_dict()
            dados["confiavel"] = resumo.confiavel
            dados["ressalva"] = resumo.ressalva
            return dados

        self._em_segundo_plano("ia_email", gerar)

    @Slot(result=str)
    def salvarPdfEmail(self) -> str:
        if self._resultado_email is None:
            return _erro("nenhum e-mail analisado")
        from core.yara_email import gerar_regra_email
        from reports.relatorio_executivo import ErroRelatorioExecutivo, salvar_pdf_email

        r = self._resultado_email
        extra = self._email_extra
        sugestao = f"{Path(r.caminho).stem}_{r.sha256[:8]}_executivo.pdf"
        caminho, _ = QFileDialog.getSaveFileName(self._janela, "Salvar relatório executivo", sugestao, "PDF (*.pdf)")
        if not caminho:
            return para_json({"ok": False, "cancelado": True})
        if "regra" not in extra:
            extra["regra"] = gerar_regra_email(r)
        try:
            salvar_pdf_email(r, caminho, extra.get("diamante"), extra.get("piramide"), extra.get("grafo"),
                             extra.get("resumo"), extra.get("regra"), extra.get("consultas"), extra.get("reputacao"),
                             extra.get("contribuicoes"))
        except (ErroRelatorioExecutivo, OSError) as erro:
            return _erro(str(erro))
        self._gravados.add(str(Path(caminho).resolve()))
        return para_json({"ok": True, "caminho": caminho, "com_ia": "resumo" in extra})

    @Slot(result=str)
    def exportarNavigatorEmail(self) -> str:
        diamante = self._email_extra.get("diamante")
        if self._resultado_email is None or diamante is None:
            return _erro("nenhum e-mail analisado")
        from reports.navigator import salvar_layer

        r = self._resultado_email
        caminho, _ = QFileDialog.getSaveFileName(
            self._janela, "Salvar layer do ATT&CK Navigator", f"{Path(r.caminho).stem}_navigator.json", "JSON (*.json)"
        )
        if not caminho:
            return para_json({"ok": False, "cancelado": True})
        salvar_layer(f"E-mail: {r.assunto[:60]}", diamante.ttps, caminho, f"Técnicas observadas em {Path(r.caminho).name}.")
        self._gravados.add(str(Path(caminho).resolve()))
        return para_json({"ok": True, "caminho": caminho})

    @Slot(str, result=str)
    def exportarIndicadoresEmail(self, confianca_minima: str) -> str:
        if self._resultado_email is None:
            return _erro("nenhum e-mail analisado")

        from core.string_extractor import Confianca
        from reports import ioc_export

        try:
            corte = Confianca(confianca_minima or "media")
        except ValueError:
            return _erro(f"confianca desconhecida: {confianca_minima}")
        destino = QFileDialog.getExistingDirectory(self._janela, "Onde salvar os indicadores", "")
        if not destino:
            return para_json({"ok": False, "cancelado": True})
        saidas = ioc_export.exportar(self._resultado_email, destino, ["csv", "stix", "misp"], confianca_minima=corte)
        if not saidas:
            return _erro("nenhum formato pode ser gravado")
        for saida in saidas.values():
            self._gravados.add(str(Path(saida.caminho).resolve()))
        self._gravados.add(str(Path(destino).resolve()))
        return para_json({"ok": True, "pasta": destino, "formatos": {f: x.to_dict() for f, x in saidas.items()}})

    @Slot(str, bool)
    def consultarDominio(self, dominio: str, subdominios: bool) -> None:
        """DNS, idade e subdominios, de forma passiva. Roda em segundo plano."""
        dominio = (dominio or "").strip()[:253]

        def consultar():
            from enrichment.consulta_dominio import consultar_dominio

            return consultar_dominio(dominio, certificados=subdominios).to_dict()

        self._em_segundo_plano("dominio", consultar)

    # ------------------------------------------------------------
    # Toca-discos
    # ------------------------------------------------------------
    #
    # A pagina so manda indice e numero. Caminho de arquivo nunca vem do
    # JavaScript: o toca-discos confere o indice contra a lista que ele
    # mesmo montou a partir de midia/.

    @Slot(result=str)
    def discoCatalogo(self) -> str:
        return para_json({"ok": True, **self.toca_discos.catalogo(), "estado": self.toca_discos.estado()})

    @Slot(result=str)
    def discoRecarregar(self) -> str:
        self.toca_discos.recarregar()
        return self.discoCatalogo()

    @Slot()
    def discoAlternar(self) -> None:
        self.toca_discos.alternar()

    @Slot()
    def discoProxima(self) -> None:
        self.toca_discos.proxima()

    @Slot()
    def discoAnterior(self) -> None:
        self.toca_discos.anterior()

    @Slot(int, int, result=str)
    def discoEscolher(self, album: int, faixa: int) -> str:
        if not self.toca_discos.escolher(album, faixa):
            return _erro("faixa inexistente")
        return para_json({"ok": True})

    @Slot(int)
    def discoBuscar(self, milissegundos: int) -> None:
        self.toca_discos.buscar(milissegundos)

    @Slot(int)
    def discoVolume(self, volume: int) -> None:
        self.toca_discos.definir_volume(volume)

    @Slot(result=str)
    def discoAbrirPasta(self) -> str:
        pasta = self.toca_discos.pasta
        try:
            pasta.mkdir(parents=True, exist_ok=True)
        except OSError as erro:
            return _erro(f"nao foi possivel criar a pasta de musica: {erro}")
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(pasta)))
        return para_json({"ok": True})

    def encerrar(self) -> None:
        """Chamado no fechamento da janela."""
        if self._executor.rodando:
            self._executor.cancelar()
        self.toca_discos.parar()


def _fontes_de_reputacao() -> list[str]:
    try:
        from enrichment.consulta_reputacao import fontes_configuradas

        return fontes_configuradas()
    except Exception:
        return []


def _erro(mensagem: str) -> str:
    return para_json({"ok": False, "erro": mensagem})


def _opcoes_da_pagina(pedido: dict) -> OpcoesAnalise:
    """
    Monta as opcoes a partir do que a pagina mandou, validando cada campo.

    O dicionario vem do JavaScript: tipo errado ou valor fora da faixa vira
    erro aqui, e nao excecao no meio do pipeline.
    """
    formato = str(pedido.get("formato", "auto"))
    if formato not in FORMATOS_DE_ARTEFATO:
        raise ValueError(f"formato desconhecido: {formato}")

    minimo = int(pedido.get("tamanho_minimo_de_string", 4))
    if not 3 <= minimo <= 64:
        raise ValueError("tamanho minimo de string fora da faixa 3-64")

    return OpcoesAnalise(
        usar_floss=bool(pedido.get("usar_floss", True)),
        formato=formato,
        tamanho_minimo_de_string=minimo,
        gerar_yara=bool(pedido.get("gerar_yara", True)),
        usar_stix=bool(pedido.get("usar_stix", True)),
        vetor_cvss=str(pedido.get("vetor_cvss", "")).strip(),
        cve=str(pedido.get("cve", "")).strip(),
        enriquecer=bool(pedido.get("enriquecer", False)),
        resumo_ia=bool(pedido.get("resumo_ia", False)),
        modelo_ia=str(pedido.get("modelo_ia", "") or MODELO_PADRAO).strip(),
    )
