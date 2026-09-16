"""
Testes do string_extractor.

O foco esta nos falsos positivos: detectar "http://evil.com" e facil, o que
derruba extrator de IOC na pratica e classificar "kernel32.dll" como dominio
e "6.1.7600" como endereco IP.

Rodar: python -m pytest tests/test_string_extractor.py -v
"""

from __future__ import annotations

import pytest

from core.string_extractor import (
    Confianca,
    ErroExtracao,
    StringExtraida,
    TipoIOC,
    TipoString,
    detectar_iocs,
    extrair,
    _extrair_nativo,
)


def _iocs(*textos: str) -> list:
    """Atalho: roda a deteccao sobre strings soltas."""
    strings = [StringExtraida(valor=t, tipo=TipoString.STATIC) for t in textos]
    return detectar_iocs(strings)


def _valores(iocs, tipo: TipoIOC) -> set[str]:
    return {i.valor for i in iocs if i.tipo is tipo}


# ============================================================
# Falsos positivos - o que realmente importa
# ============================================================


@pytest.mark.parametrize(
    "texto",
    [
        "kernel32.dll",
        "ADVAPI32.dll",
        "msvcrt.dll",
        "config.ini",
        "GetProcAddress.exe",
        "api-ms-win-core-file-l1-2-0.dll",
        "settings.json",
        "libcrypto.so",
    ],
)
def test_nome_de_arquivo_nao_e_dominio(texto):
    """Extensao de arquivo nunca deve ser tratada como TLD."""
    assert _valores(_iocs(texto), TipoIOC.DOMINIO) == set()


@pytest.mark.parametrize(
    "texto,ip",
    [
        ("FileVersion 1.0.0.1", "1.0.0.1"),
        ("Assembly version 4.0.0.0", "4.0.0.0"),
        ("build 2.1.3.7", "2.1.3.7"),
        ("1.2.3.4", "1.2.3.4"),
        # Caso real: versao do simple_launcher embutida no floss.exe.
        ("1.1.0.14", "1.1.0.14"),
    ],
)
def test_numero_de_versao_vira_ip_de_baixa_confianca(texto, ip):
    """
    Versao casa com a regex de IPv4 e nao ha como descartar com certeza -
    entao ela e mantida, mas rebaixada, para o analista decidir.
    """
    encontrados = [i for i in _iocs(texto) if i.tipo is TipoIOC.IPV4 and i.valor == ip]
    assert encontrados, f"{ip} deveria ser reportado"
    assert encontrados[0].confianca is Confianca.BAIXA
    assert encontrados[0].observacao


def test_ip_invalido_nao_e_detectado():
    """Octeto fora da faixa 0-255 nao e IPv4."""
    assert _valores(_iocs("999.888.777.666"), TipoIOC.IPV4) == set()


@pytest.mark.parametrize(
    "ip,trecho_observacao",
    [
        ("0.1.2.3", "invalida"),
        ("127.5.5.5", "loopback"),
        ("169.254.10.1", "link-local"),
        ("239.255.255.250", "multicast"),
    ],
)
def test_faixa_reservada_e_baixa_confianca(ip, trecho_observacao):
    """Nenhum destes pode ser um C2 na internet."""
    achado = [i for i in _iocs(ip) if i.tipo is TipoIOC.IPV4][0]
    assert achado.confianca is Confianca.BAIXA
    assert trecho_observacao in achado.observacao


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.10", "172.16.4.9"])
def test_ip_privado_e_ioc_valido_porem_marcado(ip):
    """
    RFC 1918 e IOC legitimo (C2 interno, movimento lateral), mas o Shodan
    nao tera nada sobre ele - a observacao avisa o enriquecimento.
    """
    achado = [i for i in _iocs(ip) if i.tipo is TipoIOC.IPV4][0]
    assert achado.confianca is Confianca.MEDIA
    assert "RFC 1918" in achado.observacao


def test_ip_publico_roteavel_e_media_sem_ressalva():
    achado = [i for i in _iocs("45.77.12.3") if i.tipo is TipoIOC.IPV4][0]
    assert achado.confianca is Confianca.MEDIA
    assert achado.observacao == ""


def test_ip_publico_conhecido_e_ruido():
    """Resolvedor publico e localhost sao IOC fraco."""
    for ip in ("8.8.8.8", "127.0.0.1"):
        achado = [i for i in _iocs(ip) if i.tipo is TipoIOC.IPV4][0]
        assert achado.confianca is Confianca.BAIXA


# ============================================================
# Deteccao positiva
# ============================================================


def test_url_e_alta_confianca():
    iocs = _iocs("POST http://185.22.11.9:8080/gate.php HTTP/1.1")
    urls = _valores(iocs, TipoIOC.URL)
    assert "http://185.22.11.9:8080/gate.php" in urls

    # O IP dentro da URL e promovido a alta confianca.
    ip = [i for i in iocs if i.tipo is TipoIOC.IPV4][0]
    assert ip.valor == "185.22.11.9"
    assert ip.confianca is Confianca.ALTA


def test_dominio_em_url_e_promovido():
    iocs = _iocs("https://malicious-c2.xyz/panel/login")
    dominio = [i for i in iocs if i.tipo is TipoIOC.DOMINIO][0]
    assert dominio.valor == "malicious-c2.xyz"
    assert dominio.confianca is Confianca.ALTA


def test_c2_isolado_tem_confianca_media():
    """Dominio fora de URL e plausivel, mas o contexto nao confirma."""
    dominio = [i for i in _iocs("update-server.ru") if i.tipo is TipoIOC.DOMINIO][0]
    assert dominio.confianca is Confianca.MEDIA


def test_chave_de_registro_de_persistencia():
    texto = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    chaves = _valores(_iocs(texto), TipoIOC.CHAVE_REGISTRO)
    assert any("CurrentVersion" in c for c in chaves)


def test_caminho_unc():
    texto = r"\\10.0.0.5\admin$\svchost.exe"
    assert _valores(_iocs(texto), TipoIOC.CAMINHO_UNC)


def test_caminho_windows():
    texto = r"C:\Users\vitima\AppData\Roaming\payload.exe"
    caminhos = _valores(_iocs(texto), TipoIOC.CAMINHO_WINDOWS)
    assert any("AppData" in c for c in caminhos)


def test_email():
    assert _valores(_iocs("contato: operador@protonmail.com"), TipoIOC.EMAIL) == {
        "operador@protonmail.com"
    }


def test_email_nao_duplica_como_dominio():
    """O dominio do e-mail ja esta contabilizado no proprio e-mail."""
    iocs = _iocs("operador@protonmail.com")
    assert _valores(iocs, TipoIOC.DOMINIO) == set()


def test_carteira_bitcoin():
    texto = "Envie 0.5 BTC para 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert _valores(_iocs(texto), TipoIOC.BITCOIN)


# ============================================================
# Deduplicacao
# ============================================================


def test_dedup_mantem_maior_confianca():
    """
    O mesmo IP aparece solto e dentro de uma URL. Deve sobrar um so registro,
    com a confianca da melhor evidencia.
    """
    iocs = _iocs("45.77.12.3", "conectando em http://45.77.12.3/beacon")
    ips = [i for i in iocs if i.tipo is TipoIOC.IPV4 and i.valor == "45.77.12.3"]
    assert len(ips) == 1
    assert ips[0].confianca is Confianca.ALTA


# ============================================================
# Extrator nativo
# ============================================================


def test_extrator_nativo_ascii_e_utf16():
    dados = b"\x00\x01ASCII-VISIVEL\x00" + "UNICODE-AQUI".encode("utf-16-le")
    valores = {s.valor for s in _extrair_nativo(dados, 4)}
    assert "ASCII-VISIVEL" in valores
    assert "UNICODE-AQUI" in valores


def test_utf16_nao_rouba_caractere_da_ascii_vizinha():
    """
    Regressao: "...VISIVEL\\x00" seguido de UTF-16LE fazia o "L" ser
    absorvido pelo casamento UTF-16, produzindo "LUNICODE-AQUI".
    """
    dados = b"ASCII-VISIVEL\x00" + "UNICODE-AQUI".encode("utf-16-le")
    valores = {s.valor for s in _extrair_nativo(dados, 4)}
    assert "UNICODE-AQUI" in valores
    assert "LUNICODE-AQUI" not in valores
    assert "ASCII-VISIVEL" in valores


def test_utf16_precedida_de_byte_nulo_e_preservada():
    """O ajuste de alinhamento nao pode cortar string bem-formada."""
    dados = b"\x00\x00" + "C2-SERVER".encode("utf-16-le")
    valores = {s.valor for s in _extrair_nativo(dados, 4)}
    assert "C2-SERVER" in valores


def test_extrator_nativo_respeita_tamanho_minimo():
    dados = b"\x00ab\x00abcdefgh\x00"
    valores = {s.valor for s in _extrair_nativo(dados, 4)}
    assert "ab" not in valores
    assert "abcdefgh" in valores


# ============================================================
# Pipeline ponta a ponta
# ============================================================


def test_extrair_arquivo_real(tmp_path):
    """Fluxo completo sobre um arquivo texto (nao-PE: cai no fallback)."""
    amostra = tmp_path / "amostra.txt"
    amostra.write_text(
        "GET http://c2-node.top/config HTTP/1.1\r\n"
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "\r\n"
        "kernel32.dll\r\n"
        "FileVersion 6.1.7600.16385\r\n",
        encoding="ascii",
    )

    resultado = extrair(amostra, usar_floss=False)

    assert resultado.sha256 and len(resultado.sha256) == 64
    assert resultado.tamanho_bytes == amostra.stat().st_size
    assert resultado.usou_floss is False
    assert resultado.strings

    tipos = {i.tipo for i in resultado.iocs}
    assert TipoIOC.URL in tipos
    assert TipoIOC.CHAVE_REGISTRO in tipos
    # kernel32.dll nao pode ter virado dominio
    assert "kernel32.dll" not in _valores(resultado.iocs, TipoIOC.DOMINIO)

    # Serializavel para o relatorio e para a GUI.
    assert resultado.to_dict()["sha256"] == resultado.sha256


def test_arquivo_inexistente():
    with pytest.raises(ErroExtracao):
        extrair("nao_existe_em_lugar_nenhum.bin")


def test_arquivo_vazio(tmp_path):
    vazio = tmp_path / "vazio.bin"
    vazio.write_bytes(b"")
    with pytest.raises(ErroExtracao):
        extrair(vazio)


# ============================================================
# FLOSS de verdade: strings construidas em runtime
#
# Estes testes rodam o FLOSS real sobre shellcode gerado, e sao os unicos
# da suite que exercitam a emulacao. Existem porque o diferencial do FLOSS
# e recuperar string que nunca aparece literal no arquivo, e esse caminho
# nao pode ser validado com binario benigno nem com duble.
# ============================================================

import shutil
import subprocess
import sys as _sys
from pathlib import Path as _Path

from tests.shellcode_de_teste import ANCORA_ESTATICA, gerar_amostra

TEXTOS_OCULTOS = [
    "http://stack-c2.top/gate.php",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "cmd.exe /c whoami",
]


def _floss_disponivel() -> bool:
    candidato = _Path(_sys.executable).parent / "floss.exe"
    return candidato.exists() or shutil.which("floss") is not None


# Estes testes rodam a emulacao de verdade e levam dezenas de segundos.
# Para pular: python -m pytest -m "not lento"
precisa_de_floss = pytest.mark.skipif(
    not _floss_disponivel(), reason="FLOSS nao esta instalado neste ambiente"
)
lento = pytest.mark.lento


@pytest.fixture(scope="module")
def shellcode(tmp_path_factory):
    caminho = tmp_path_factory.mktemp("sc") / "runtime.bin"
    caminho.write_bytes(gerar_amostra(TEXTOS_OCULTOS))
    return caminho


def test_shellcode_nao_contem_as_strings_literais(shellcode):
    """
    A premissa do teste: se as strings estivessem literais no arquivo, o
    extrator nativo as acharia e nada sobre o FLOSS estaria sendo provado.
    """
    dados = shellcode.read_bytes()
    for texto in TEXTOS_OCULTOS:
        assert texto.encode() not in dados
    # A ancora, essa sim, precisa estar literal.
    assert ANCORA_ESTATICA in dados


def test_extrator_nativo_nao_ve_as_strings_ocultas(shellcode):
    valores = {s.valor for s in extrair(shellcode, usar_floss=False).strings}
    for texto in TEXTOS_OCULTOS:
        assert texto not in valores


@precisa_de_floss
@lento
def test_floss_recupera_strings_de_runtime(shellcode):
    """
    O teste central do modulo: o FLOSS emula o codigo e recupera strings
    que a varredura estatica nao ve.
    """
    resultado = extrair(shellcode, timeout=300)

    assert resultado.usou_floss is True
    assert resultado.formato_floss == "sc32"

    de_runtime = {
        s.valor
        for s in resultado.strings
        if s.tipo is not TipoString.STATIC
    }
    for texto in TEXTOS_OCULTOS:
        assert texto in de_runtime, f"o FLOSS nao recuperou {texto!r}"


@precisa_de_floss
@lento
def test_ioc_oculto_chega_com_a_procedencia_certa(shellcode):
    """O IOC precisa saber que veio de string construida em runtime."""
    resultado = extrair(shellcode, timeout=300)

    url = next(i for i in resultado.iocs if i.tipo is TipoIOC.URL)
    assert url.valor == "http://stack-c2.top/gate.php"
    assert url.confianca is Confianca.ALTA
    assert url.tipo_string is not TipoString.STATIC


@precisa_de_floss
@lento
def test_arquitetura_de_shellcode_e_deduzida_com_aviso(shellcode):
    """
    Shellcode nao tem cabecalho de onde deduzir a arquitetura. O framework
    tenta as duas, e o palpite precisa ficar registrado.
    """
    resultado = extrair(shellcode, timeout=300)
    assert any("shellcode sc32" in a for a in resultado.avisos)


@precisa_de_floss
@lento
def test_formato_explicito_e_respeitado(shellcode):
    resultado = extrair(shellcode, formato="sc32", timeout=300)
    assert resultado.formato_floss == "sc32"
    assert resultado.usou_floss is True


def test_saida_vazia_do_floss_tem_mensagem_honesta(tmp_path, monkeypatch):
    """
    O FLOSS encerra a analise inteira, em silencio e com codigo 0, quando o
    arquivo nao tem nenhuma string estatica - ha um `if not static_strings:
    return 0` no main dele. Reportar isso como "FLOSS falhou: codigo de
    saida 0" seria enganoso: ele rodou bem e decidiu nao analisar.

    O gatilho e dificil de reproduzir de forma deterministica (codigo de
    maquina costuma conter sequencias ASCII por acaso), entao o que se
    testa aqui e a nossa reacao, simulando a saida vazia.
    """
    import subprocess as _sub

    from core import string_extractor

    class _Processo:
        returncode = 0
        stdout = b""
        stderr = b""

    monkeypatch.setattr(_sub, "run", lambda *a, **k: _Processo())
    monkeypatch.setattr(
        string_extractor, "_localizar_floss", lambda: "floss-simulado"
    )

    amostra = tmp_path / "vazio_para_o_floss.bin"
    amostra.write_bytes(b"conteudo qualquer para o extrator nativo achar " * 4)

    resultado = extrair(amostra, formato="sc32")

    assert resultado.usou_floss is False  # caiu no extrator nativo
    assert any("nenhuma string estatica" in a for a in resultado.avisos)
    assert not any("codigo de saida 0" in a for a in resultado.avisos)
    # O extrator nativo salvou a analise.
    assert resultado.strings
