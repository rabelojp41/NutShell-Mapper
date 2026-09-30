"""
Chaves de API gravadas pela interface.

O que precisa ser verdade:

  - A chave vai para o .env e em nenhum outro lugar; o resto do arquivo
    (comentarios, outras chaves) sobrevive a gravacao.
  - Um valor malicioso nao consegue escrever uma segunda linha no .env.
  - O estado devolvido a pagina nunca contem a chave.
  - O .env e suas variantes nunca entram no Git.
  - "Rede fora" nao e "chave invalida".
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from config import chaves, settings
from enrichment.base import RespostaEnriquecimento

CHAVE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Um .env temporario, e o ambiente do processo restaurado no fim."""
    antes = dict(os.environ)
    caminho = tmp_path / "config" / ".env"
    caminho.parent.mkdir()
    caminho.write_text(
        "# cabecalho que precisa sobreviver\n"
        "VIRUSTOTAL_API_KEY=coloque_sua_chave_aqui\n"
        "SHODAN_API_KEY=outra_chave_que_fica_1234\n"
        "ABUSEIPDB_API_KEY=         # https://www.abuseipdb.com/account/api\n"
        "ENABLE_ENRICHMENT=true\n",
        encoding="utf-8",
    )
    for c in chaves.CATALOGO:
        monkeypatch.delenv(c.variavel, raising=False)
    monkeypatch.setattr(settings, "CAMINHO_ENV", caminho)
    monkeypatch.setattr(settings, "CONFIG", settings.Configuracoes())
    yield caminho
    os.environ.clear()
    os.environ.update(antes)


def test_grava_a_chave_e_preserva_o_resto_do_arquivo(env):
    chaves.salvar("VIRUSTOTAL_API_KEY", CHAVE, env)
    texto = env.read_text(encoding="utf-8")
    assert f"VIRUSTOTAL_API_KEY={CHAVE}\n" in texto
    assert "# cabecalho que precisa sobreviver" in texto
    assert "SHODAN_API_KEY=outra_chave_que_fica_1234" in texto
    assert texto.count("VIRUSTOTAL_API_KEY") == 1


def test_mantem_o_comentario_da_linha(env):
    chaves.salvar("ABUSEIPDB_API_KEY", CHAVE, env)
    linha = next(l for l in env.read_text(encoding="utf-8").splitlines() if l.startswith("ABUSEIPDB_API_KEY"))
    assert linha.startswith(f"ABUSEIPDB_API_KEY={CHAVE}")
    assert "# https://www.abuseipdb.com/account/api" in linha
    # E o comentario nao vira parte da chave na leitura.
    assert settings.carregar(env).abuseipdb_api_key == CHAVE


def test_variavel_ausente_e_acrescentada(env):
    chaves.salvar("CENSYS_API_TOKEN", "censys_pat_" + CHAVE, env)
    assert env.read_text(encoding="utf-8").rstrip().endswith(f"CENSYS_API_TOKEN=censys_pat_{CHAVE}")


def test_variavel_repetida_vira_uma_so(env):
    env.write_text("OTX_API_KEY=velha1234567\nOTX_API_KEY=velha7654321\n", encoding="utf-8")
    chaves.salvar("OTX_API_KEY", CHAVE, env)
    assert env.read_text(encoding="utf-8").count("OTX_API_KEY=") == 1


def test_sem_env_parte_do_modelo(tmp_path, monkeypatch):
    antes = dict(os.environ)
    try:
        exemplo = tmp_path / ".env.example"
        exemplo.write_text("# modelo\nSHODAN_API_KEY=coloque_sua_chave_aqui\n", encoding="utf-8")
        monkeypatch.setattr(settings, "CAMINHO_ENV_EXEMPLO", exemplo)
        monkeypatch.setattr(settings, "CONFIG", settings.Configuracoes())
        destino = tmp_path / ".env"
        chaves.salvar("SHODAN_API_KEY", CHAVE, destino)
        assert destino.read_text(encoding="utf-8") == f"# modelo\nSHODAN_API_KEY={CHAVE}\n"
    finally:
        os.environ.clear()
        os.environ.update(antes)


def test_vale_na_hora_sem_reiniciar(env):
    config_antiga = settings.CONFIG
    chaves.salvar("URLSCAN_API_KEY", "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0", env)
    # O mesmo objeto, atualizado: quem ja importou o CONFIG ve a chave nova.
    assert settings.CONFIG is config_antiga
    assert config_antiga.urlscan_api_key == "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"


def test_remover_apaga_do_arquivo_e_da_sessao(env):
    chaves.salvar("OTX_API_KEY", CHAVE, env)
    estado = chaves.remover("OTX_API_KEY", env)
    assert "OTX_API_KEY=\n" in env.read_text(encoding="utf-8")
    assert settings.CONFIG.otx_api_key == ""
    assert not next(c for c in estado["chaves"] if c["variavel"] == "OTX_API_KEY")["configurada"]
    # Nem recarregando o .env ela volta.
    assert settings.carregar(env).otx_api_key == ""


@pytest.mark.parametrize("valor", [
    CHAVE + "\nENABLE_ENRICHMENT=false",
    CHAVE + "\rENABLE_ENRICHMENT=false",
    CHAVE + " # comentario",
    'abc"12345678',
    "abc$HOME12345",
    "curta",
    "x" * 513,
    "coloque_sua_chave_aqui",
])
def test_valor_que_mudaria_o_env_e_recusado(env, valor):
    antes = env.read_text(encoding="utf-8")
    with pytest.raises(chaves.ErroDeChave) as erro:
        chaves.salvar("VIRUSTOTAL_API_KEY", valor, env)
    assert env.read_text(encoding="utf-8") == antes
    # A mensagem de erro nao repete o segredo.
    assert CHAVE not in str(erro.value)


def test_so_variaveis_do_catalogo(env):
    with pytest.raises(chaves.ErroDeChave):
        chaves.salvar("ENABLE_ENRICHMENT", "false_12345678", env)
    with pytest.raises(chaves.ErroDeChave):
        chaves.remover("PATH", env)


def test_estado_nunca_contem_a_chave(env):
    chaves.salvar("VIRUSTOTAL_API_KEY", CHAVE, env)
    estado = chaves.estado(env)
    texto = json.dumps(estado)
    assert CHAVE not in texto
    assert CHAVE[:4] + "..." not in texto
    vt = next(c for c in estado["chaves"] if c["variavel"] == "VIRUSTOTAL_API_KEY")
    assert vt["configurada"] and vt["origem"] == "arquivo"
    # O valor de exemplo nao conta como configurada.
    assert estado["configuradas"] == 2  # VirusTotal e a do Shodan que ja estava


def test_chave_do_ambiente_e_identificada(env, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", CHAVE)
    hibp = next(c for c in chaves.estado(env)["chaves"] if c["variavel"] == "HIBP_API_KEY")
    assert hibp["configurada"] and hibp["origem"] == "ambiente"


def test_env_e_variantes_nunca_vao_para_o_git():
    raiz = Path(settings.RAIZ)
    if not (raiz / ".git").exists():
        pytest.skip("fora de um repositorio git")
    for caminho in ("config/.env", "config/.env.abc123.tmp", "config/.env.bak", ".env"):
        r = subprocess.run(["git", "check-ignore", "-q", caminho], cwd=raiz, capture_output=True)
        assert r.returncode == 0, f"{caminho} nao esta no .gitignore"
    r = subprocess.run(["git", "check-ignore", "-q", "config/.env.example"], cwd=raiz, capture_output=True)
    assert r.returncode == 1, "o modelo sem chave precisa continuar versionado"
    rastreados = subprocess.run(["git", "ls-files", "config"], cwd=raiz, capture_output=True, text=True).stdout.split()
    assert "config/.env" not in rastreados


# ------------------------------------------------------------
# Teste da chave com o servico
# ------------------------------------------------------------


def _resposta(erro="", dados=None):
    r = RespostaEnriquecimento(fonte="x", erro=erro, dados=dados or {})
    r.consultado = not erro
    return r


def test_chave_aceita(env):
    chaves.salvar("SHODAN_API_KEY", CHAVE, env)
    vistos = []

    def requisitar(nome, teste, valor):
        vistos.append((nome, teste.caminho, valor))
        return _resposta(dados={"plan": "dev", "query_credits": 100})

    r = chaves.testar("SHODAN_API_KEY", requisitar)
    assert r["valida"] is True and "plano dev" in r["mensagem"]
    # O teste usa a conta, nao um indicador de analise.
    assert vistos == [("Shodan", "/api-info", CHAVE)]


def test_chave_rejeitada(env):
    chaves.salvar("VIRUSTOTAL_API_KEY", CHAVE, env)
    r = chaves.testar("VIRUSTOTAL_API_KEY", lambda *_: _resposta("chave do VirusTotal rejeitada (HTTP 401): ..."))
    assert r["valida"] is False


def test_abusech_rejeita_no_corpo(env):
    chaves.salvar("MALWAREBAZAAR_API_KEY", CHAVE, env)
    r = chaves.testar("MALWAREBAZAAR_API_KEY", lambda *_: _resposta(dados={"query_status": "unknown_auth_key"}))
    assert r["valida"] is False


def test_rede_fora_nao_e_chave_invalida(env):
    chaves.salvar("OTX_API_KEY", CHAVE, env)
    r = chaves.testar("OTX_API_KEY", lambda *_: _resposta("falha de rede: Read timed out"))
    assert r["valida"] is None


def test_sem_chave_nao_consulta(env):
    def requisitar(*_):
        raise AssertionError("nao deveria consultar")

    assert chaves.testar("HIBP_API_KEY", requisitar)["valida"] is False


def test_consultas_desligadas_nao_consultam(env):
    chaves.salvar("OTX_API_KEY", CHAVE, env)
    settings.CONFIG.enable_enrichment = False

    def requisitar(*_):
        raise AssertionError("nao deveria consultar")

    assert chaves.testar("OTX_API_KEY", requisitar)["valida"] is None


def test_todo_servico_do_catalogo_tem_teste():
    assert set(chaves.TESTES) == set(chaves.POR_VARIAVEL)


def test_comentario_na_linha_vazia_nao_vira_chave(tmp_path, monkeypatch):
    # Linha do .env.example: sem valor, so o link. O python-dotenv entrega o
    # comentario como valor, e ele passava por chave configurada.
    antes = dict(os.environ)
    try:
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        caminho = tmp_path / ".env"
        caminho.write_text("ABUSEIPDB_API_KEY=         # https://www.abuseipdb.com/account/api\n", encoding="utf-8")
        assert settings.carregar(caminho).abuseipdb_api_key == ""
        assert not next(c for c in chaves.estado(caminho)["chaves"] if c["variavel"] == "ABUSEIPDB_API_KEY")["configurada"]
    finally:
        os.environ.clear()
        os.environ.update(antes)
