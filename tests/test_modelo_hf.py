"""Testes da instalacao do modelo a partir do Hugging Face, sem rede."""

from __future__ import annotations

import hashlib

import pytest

from core import modelo_hf
from core.modelo_hf import ErroInstalacao, ModeloHF, baixar, comando_de_instalacao

CONTEUDO = b"GGUF" + bytes(range(256)) * 40


def _modelo(conteudo: bytes = CONTEUDO) -> ModeloHF:
    return ModeloHF("teste-hf", "org/repo", "m.gguf", hashlib.sha256(conteudo).hexdigest(), len(conteudo))


class _Resposta:
    def __init__(self, corpo: bytes, status: int):
        self.corpo, self.status_code = corpo, status

    def iter_content(self, tamanho):
        for i in range(0, len(self.corpo), 1000):
            yield self.corpo[i:i + 1000]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


@pytest.fixture
def servidor(monkeypatch):
    """Um 'Hugging Face' que respeita o cabecalho Range, e anota os pedidos."""
    pedidos = []
    servido = {"corpo": CONTEUDO}

    def falso_get(url, headers=None, stream=None, timeout=None):
        pedidos.append(dict(headers or {}))
        faixa = (headers or {}).get("Range")
        if faixa:
            inicio = int(faixa.split("=")[1].rstrip("-"))
            return _Resposta(servido["corpo"][inicio:], 206)
        return _Resposta(servido["corpo"], 200)

    monkeypatch.setattr(modelo_hf.requests, "get", falso_get)
    return pedidos, servido


def test_baixa_e_confere(tmp_path, servidor):
    caminho = baixar(_modelo(), tmp_path)
    assert caminho.read_bytes() == CONTEUDO
    assert not (tmp_path / "m.gguf.parcial").exists()


def test_retoma_download_interrompido(tmp_path, servidor):
    pedidos, _ = servidor
    (tmp_path / "m.gguf.parcial").write_bytes(CONTEUDO[:3000])
    caminho = baixar(_modelo(), tmp_path)
    assert pedidos[-1]["Range"] == "bytes=3000-"
    assert caminho.read_bytes() == CONTEUDO


def test_sha256_errado_apaga_o_arquivo(tmp_path, servidor):
    _, servido = servidor
    servido["corpo"] = CONTEUDO[:-1] + b"X"  # mesmo tamanho, um byte trocado
    with pytest.raises(ErroInstalacao, match="SHA256"):
        baixar(_modelo(), tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_arquivo_ja_baixado_nao_e_baixado_de_novo(tmp_path, servidor):
    pedidos, _ = servidor
    (tmp_path / "m.gguf").write_bytes(CONTEUDO)
    baixar(_modelo(), tmp_path)
    assert pedidos == []


def test_comando_de_instalacao():
    assert comando_de_instalacao(modelo_hf.QWEN.nome_ollama) == "python main.py instalar-ia"
    assert comando_de_instalacao("llama3.1:8b") == "ollama pull llama3.1:8b"


def test_modelo_padrao_e_o_do_hugging_face():
    from core.resumo_ia import MODELO_PADRAO, diagnosticar_ollama

    assert MODELO_PADRAO == modelo_hf.QWEN.nome_ollama
    assert modelo_hf.QWEN.url.startswith("https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/")


def test_pasta_padrao_fica_ao_lado_do_ollama(monkeypatch, tmp_path):
    monkeypatch.delenv("NUTSHELL_PASTA_MODELOS", raising=False)
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "models"))
    assert modelo_hf.pasta_padrao() == tmp_path / "gguf"
    monkeypatch.setenv("NUTSHELL_PASTA_MODELOS", str(tmp_path / "outra"))
    assert modelo_hf.pasta_padrao() == tmp_path / "outra"
