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
        "www.shodan.io",
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
    """

    arquivoSelecionado = Signal(str)
    progresso = Signal(str)
    concluido = Signal(str)
    falhou = Signal(str)
    tarefaConcluida = Signal(str)
    # {id, mensagem}: andamento de tarefa longa em segundo plano.
    andamentoTarefa = Signal(str)
    arrastando = Signal(str)

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

        self._executor = ExecutorDeAnalise(self)
        self._executor.progresso.connect(self._ao_progredir)
        self._executor.concluido.connect(self._ao_concluir)
        self._executor.falhou.connect(self._ao_falhar)

    # ------------------------------------------------------------
    # Arquivo
    # ------------------------------------------------------------

    def definir_arquivo(self, caminho: Path) -> None:
        """Chamado pelo dialogo e pelo arrastar-e-soltar da janela."""
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
        E a unica acao do RabMapper com esse efeito, e ela nao pode ser
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

    def encerrar(self) -> None:
        """Chamado no fechamento da janela."""
        if self._executor.rodando:
            self._executor.cancelar()


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
