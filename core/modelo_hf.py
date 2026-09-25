"""
Instalacao do modelo de IA a partir do Hugging Face.

O modelo padrao nao vem do catalogo do Ollama: vem do Hugging Face, em
GGUF, e e registrado no Ollama local. O Ollama continua sendo so o motor que
roda o modelo na GPU; nada sai da maquina durante a analise.

Por que nao `ollama pull hf.co/...`: nesta versao do Ollama o pull do
Hugging Face falha no redirecionamento para a CDN (cdn.hf.co). Baixar o
arquivo direto e registrar com `ollama create` da no mesmo, e ainda permite
conferir o SHA256 contra o publicado no repositorio - o arquivo tem 5,7 GB,
e um download corrompido so apareceria como resposta estranha do modelo.
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests

logger = logging.getLogger(__name__)

RAIZ = Path(__file__).resolve().parent.parent
PEDACO = 8 * 2**20


@dataclass(frozen=True)
class ModeloHF:
    nome_ollama: str
    repositorio: str
    arquivo: str
    sha256: str
    tamanho: int

    @property
    def url(self) -> str:
        return f"https://huggingface.co/{self.repositorio}/resolve/main/{self.arquivo}"

    @property
    def pagina(self) -> str:
        return f"https://huggingface.co/{self.repositorio}"


# Qwen3.5-9B, quantizado em Q4_K_M (5,7 GB): cabe inteiro numa GPU de 8 GB.
# Escolhido por medicao contra o llama3.1:8b, nas mesmas tarefas: zero erro
# de conferencia tambem no teste de prompt injection (o llama errou um),
# leitura correta da condicao da regra YARA ("4 das 10 strings"; o llama
# leu "10 strings") e texto 100% em portugues. Custa ~60% mais tempo na
# revisao, porque explica mais. O Qwen3.6 e o 3.8 nao cabem em 8 GB.
QWEN = ModeloHF(
    nome_ollama="qwen3.5-9b-hf",
    repositorio="unsloth/Qwen3.5-9B-GGUF",
    arquivo="Qwen3.5-9B-Q4_K_M.gguf",
    sha256="03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8",
    tamanho=5_680_522_464,
)
MODELOS_HF = {QWEN.nome_ollama: QWEN}


class ErroInstalacao(Exception):
    pass


def comando_de_instalacao(modelo: str) -> str:
    """O que o analista roda para ter o modelo: o nosso comando, ou o pull do Ollama."""
    if modelo in MODELOS_HF:
        return "python main.py instalar-ia"
    return f"ollama pull {modelo}"


def pasta_padrao() -> Path:
    """
    Onde o GGUF e baixado antes de ir para o Ollama. Ao lado da pasta de
    modelos do Ollama (OLLAMA_MODELS), para o arquivo de 5,7 GB cair no
    mesmo disco que o Ollama ja usa; sem ela, em data/modelos.
    """
    configurada = os.environ.get("NUTSHELL_PASTA_MODELOS")
    if configurada:
        return Path(configurada)
    ollama = os.environ.get("OLLAMA_MODELS")
    if ollama:
        return Path(ollama).parent / "gguf"
    return RAIZ / "data" / "modelos"


def sha256_do_arquivo(caminho: Path, progresso: Callable[[str, float], None] | None = None) -> str:
    h = hashlib.sha256()
    total = caminho.stat().st_size or 1
    lido = 0
    with caminho.open("rb") as arquivo:
        while bloco := arquivo.read(PEDACO):
            h.update(bloco)
            lido += len(bloco)
            if progresso:
                progresso("conferindo", lido / total)
    return h.hexdigest()


def baixar(modelo: ModeloHF, pasta: Path, progresso: Callable[[str, float], None] | None = None) -> Path:
    """
    Baixa o GGUF, retomando de onde parou se ja houver um pedaco em disco,
    e so devolve o caminho depois de conferir o SHA256.
    """
    pasta.mkdir(parents=True, exist_ok=True)
    destino = pasta / modelo.arquivo
    parcial = destino.with_suffix(destino.suffix + ".parcial")

    if destino.exists() and destino.stat().st_size == modelo.tamanho:
        if sha256_do_arquivo(destino, progresso) == modelo.sha256:
            return destino
        destino.unlink()

    inicio = parcial.stat().st_size if parcial.exists() else 0
    cabecalhos = {"User-Agent": "NutShellMapper/1.0"}
    if inicio:
        cabecalhos["Range"] = f"bytes={inicio}-"
    with requests.get(modelo.url, headers=cabecalhos, stream=True, timeout=60) as resposta:
        if resposta.status_code == 416:
            inicio = 0
        elif resposta.status_code not in (200, 206):
            raise ErroInstalacao(f"download falhou: HTTP {resposta.status_code}")
        if resposta.status_code == 200 and inicio:
            # O servidor ignorou o Range: recomeca do zero.
            inicio = 0
        modo = "ab" if inicio else "wb"
        baixado = inicio
        with parcial.open(modo) as arquivo:
            for bloco in resposta.iter_content(PEDACO):
                arquivo.write(bloco)
                baixado += len(bloco)
                if progresso:
                    progresso("baixando", baixado / modelo.tamanho)

    if parcial.stat().st_size != modelo.tamanho:
        raise ErroInstalacao(
            f"download incompleto ({parcial.stat().st_size} de {modelo.tamanho} bytes); rode de novo para continuar"
        )
    obtido = sha256_do_arquivo(parcial, progresso)
    if obtido != modelo.sha256:
        parcial.unlink()
        raise ErroInstalacao(
            f"SHA256 não confere (esperado {modelo.sha256[:16]}…, obtido {obtido[:16]}…); o arquivo foi apagado"
        )
    parcial.replace(destino)
    return destino


def registrar_no_ollama(modelo: ModeloHF, gguf: Path, executavel: str) -> None:
    """`ollama create` a partir do GGUF. O Ollama le o template de chat do proprio arquivo."""
    modelfile = gguf.with_name(f"Modelfile.{modelo.nome_ollama}")
    modelfile.write_text(f"FROM {gguf}\n", encoding="utf-8")
    try:
        subprocess.run(
            [executavel, "create", modelo.nome_ollama, "-f", str(modelfile)],
            check=True, capture_output=True, encoding="utf-8", errors="replace", timeout=1800,
        )
    except subprocess.CalledProcessError as erro:
        raise ErroInstalacao(f"ollama create falhou: {(erro.stderr or erro.stdout or '').strip()[-300:]}") from erro
    finally:
        modelfile.unlink(missing_ok=True)


def instalar(
    modelo: ModeloHF = QWEN,
    pasta: Path | None = None,
    manter_gguf: bool = False,
    progresso: Callable[[str, float], None] | None = None,
) -> Path:
    """
    Baixa, confere e registra. Depois do `ollama create`, o Ollama guarda a
    propria copia do modelo; o GGUF baixado vira duplicata de 5,7 GB e e
    apagado, a menos que se peca para manter.
    """
    from core.resumo_ia import _executavel_ollama

    executavel = _executavel_ollama()
    if not executavel:
        raise ErroInstalacao("o Ollama não está instalado: baixe em ollama.com/download e rode de novo")
    gguf = baixar(modelo, pasta or pasta_padrao(), progresso)
    if progresso:
        progresso("registrando", 1.0)
    registrar_no_ollama(modelo, gguf, executavel)
    if not manter_gguf:
        gguf.unlink(missing_ok=True)
    return gguf
