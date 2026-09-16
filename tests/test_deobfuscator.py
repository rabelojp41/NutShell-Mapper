"""
Testes do deobfuscator.

Dois riscos opostos, e os testes cobrem os dois:
  - deixar passar ofuscacao real (falso negativo)
  - "decodificar" texto comum em lixo e reportar como achado (falso positivo)

O segundo e o mais perigoso: XOR de 1 byte tem 255 chaves, e sem um filtro
de plausibilidade varias delas produzem algo imprimivel por acaso.
"""

from __future__ import annotations

import base64
import gzip
import zlib

import pytest

from core.deobfuscator import (
    LEGIBILIDADE_MINIMA,
    PONTUACAO_MINIMA,
    Tecnica,
    desofuscar,
    desofuscar_blob,
    desofuscar_valor,
    entropia_shannon,
    legibilidade,
    parece_codificado,
    parece_texto_claro,
    pontuar,
    razao_imprimivel,
)
from core.string_extractor import StringExtraida, TipoIOC, TipoString


def _textos(achados) -> list[str]:
    return [a.decodificado for a in achados]


def _xor(dados: bytes, chave: int) -> bytes:
    return bytes(b ^ chave for b in dados)


# ============================================================
# Metricas
# ============================================================


def test_entropia_faixas_conhecidas():
    assert entropia_shannon(b"") == 0.0
    assert entropia_shannon(b"AAAAAAAAAAAAAAAA") == 0.0  # um simbolo so
    # Texto natural fica numa faixa intermediaria.
    assert 3.0 < entropia_shannon(b"the quick brown fox jumps over") < 5.0
    # 256 bytes distintos = entropia maxima.
    assert entropia_shannon(bytes(range(256))) == pytest.approx(8.0)


def test_razao_imprimivel():
    assert razao_imprimivel(b"texto puro") == 1.0
    assert razao_imprimivel(b"\x00\x01\x02\x03") == 0.0
    assert razao_imprimivel(b"ab\x00\x00") == 0.5


def test_pontuacao_rejeita_binario():
    nota, ancoras = pontuar(b"\x8f\x2a\xff\x01\x9c\xde\x44\x7b")
    assert nota == 0.0
    assert ancoras == ()


def test_pontuacao_premia_ancora():
    com_ancora, ancoras = pontuar(b"http://c2-node.top/gate.php")
    sem_ancora, _ = pontuar(b"qwerty uiop asdfgh jklzxc")
    assert ancoras
    assert com_ancora > sem_ancora
    assert com_ancora >= PONTUACAO_MINIMA


# ============================================================
# Triagem
# ============================================================


def test_triagem_descarta_string_curta():
    assert parece_codificado("abc") is False


def test_triagem_descarta_texto_ja_em_claro():
    """Se a string ja tem uma ancora, ela nao esta ofuscada."""
    assert parece_codificado("http://exemplo.com/a") is False
    assert parece_codificado(r"C:\Windows\System32\kernel32.dll") is False


def test_triagem_aceita_base64():
    assert parece_codificado(base64.b64encode(b"algum conteudo aqui").decode())


def test_triagem_aceita_hex():
    assert parece_codificado(b"conteudo hex aqui".hex())


# ============================================================
# Decodificadores individuais
# ============================================================


def test_base64_simples():
    alvo = "http://malicioso.xyz/stage2.bin"
    achados = desofuscar_valor(base64.b64encode(alvo.encode()).decode())
    assert alvo in _textos(achados)
    melhor = achados[0]
    assert Tecnica.BASE64 in melhor.tecnicas
    assert "http://" in melhor.ancoras


def test_base64_sem_preenchimento():
    """Malware costuma cortar o '=' final."""
    alvo = "powershell -enc bypass"
    codificado = base64.b64encode(alvo.encode()).decode().rstrip("=")
    assert alvo in _textos(desofuscar_valor(codificado))


def test_base64_urlsafe():
    alvo = "https://cdn-node.top/config?id=1"
    codificado = base64.urlsafe_b64encode(alvo.encode()).decode()
    achados = desofuscar_valor(codificado)
    assert alvo in _textos(achados)


def test_hex():
    alvo = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    assert alvo in _textos(desofuscar_valor(alvo.encode().hex()))


def test_hex_com_separador():
    alvo = "cmd.exe /c whoami"
    codificado = ":".join(f"{b:02x}" for b in alvo.encode())
    assert alvo in _textos(desofuscar_valor(codificado))


def test_rot13():
    alvo = "powershell.exe"
    import codecs

    codificado = codecs.encode(alvo, "rot_13")
    assert alvo in _textos(desofuscar_valor(codificado))


def test_xor_1_byte_recupera_chave():
    alvo = b"http://185.220.101.44/gate.php"
    achados = desofuscar_blob(_xor(alvo, 0x4D))
    correto = [a for a in achados if a.decodificado == alvo.decode()]
    assert correto, "decodificacao correta nao foi encontrada"
    assert correto[0].chave == "0x4d"
    assert Tecnica.XOR_1_BYTE in correto[0].tecnicas


def test_zlib():
    alvo = b"LoadLibraryA GetProcAddress VirtualAlloc CreateProcessW"
    achados = desofuscar_blob(zlib.compress(alvo))
    assert alvo.decode() in _textos(achados)


def test_gzip():
    alvo = b"http://backup-c2.ru/beacon"
    achados = desofuscar_blob(gzip.compress(alvo))
    assert alvo.decode() in _textos(achados)


# ============================================================
# Cadeia
# ============================================================


def test_cadeia_base64_sobre_xor():
    """Stager tipico: XOR e depois Base64 para virar texto."""
    alvo = b"http://stage2-drop.top/payload.dll"
    codificado = base64.b64encode(_xor(alvo, 0x2A)).decode()

    achados = desofuscar_valor(codificado)
    correto = [a for a in achados if a.decodificado == alvo.decode()]
    assert correto, f"cadeia nao resolvida; obtive {_textos(achados)[:3]}"
    assert correto[0].tecnicas[0] is Tecnica.BASE64
    assert Tecnica.XOR_1_BYTE in correto[0].tecnicas
    assert correto[0].chave == "0x2a"


def test_cadeia_base64_sobre_zlib():
    alvo = b"powershell -nop -w hidden -enc SQBFAFgA"
    codificado = base64.b64encode(zlib.compress(alvo)).decode()
    assert alvo.decode() in _textos(desofuscar_valor(codificado))


def test_cadeia_aparece_em_formato_legivel():
    alvo = b"cmd.exe /c schtasks /create"
    codificado = base64.b64encode(_xor(alvo, 0x11)).decode()
    correto = [a for a in desofuscar_valor(codificado) if a.decodificado == alvo.decode()]
    assert "base64" in correto[0].cadeia
    assert "0x11" in correto[0].cadeia


# ============================================================
# Falso positivo
# ============================================================


def test_nao_inventa_achado_em_nome_de_api():
    """
    "CryptEncrypt" e Base64 sintaticamente valido, mas decodifica em bytes
    sem sentido. Nao pode virar achado.
    """
    for nome in ("CryptEncrypt", "GetProcAddress", "VirtualAllocEx"):
        for a in desofuscar_valor(nome, pular_triagem=True):
            assert a.pontuacao >= PONTUACAO_MINIMA
            # Se passou, precisa ter evidencia concreta, nao so imprimivel.
            assert a.ancoras, f"{nome} -> {a.decodificado!r} sem ancora"


def test_texto_em_claro_nao_gera_achado():
    assert desofuscar_valor("Mozilla/5.0 (Windows NT 10.0; Win64)") == []


@pytest.mark.parametrize(
    "prosa",
    [
        "This indicates a bug in your application. It is most likely the result",
        "Expected to find a command ending in .exe in the shebang line",
        "Unable to create process using the given path",
        "Attempt to initialize the CRT more than once",
    ],
)
def test_prosa_em_claro_nao_e_candidata(prosa):
    """
    Regressao: mensagem de erro do compilador era aceita como candidata a
    ROT13 (e 100% alfabetica), e o ROT13 seguido de XOR produzia lixo que
    por acaso continha ancora como ".dll" ou "HKLM".
    """
    assert parece_texto_claro(prosa) is True
    assert parece_codificado(prosa) is False


def test_dado_codificado_nao_e_confundido_com_prosa():
    """O corte de prosa nao pode descartar dado realmente codificado."""
    assert parece_texto_claro(base64.b64encode(b"http://c2.top/a").decode()) is False
    assert parece_texto_claro(b"cmd.exe /c whoami".hex()) is False


def test_legibilidade():
    assert legibilidade("http://c2-node.top/gate.php") == 1.0
    assert legibilidade("") == 0.0
    # Regressao: este passava por ser 100% imprimivel e conter ".dll".
    assert legibilidade("^A.DLLLOLL^") < LEGIBILIDADE_MINIMA


def test_ancora_dentro_de_lixo_nao_vira_achado():
    """
    Regressao: XOR de string binaria produziu "^A.DLLLOLL^", que contem a
    ancora ".dll" mas nao e texto nenhum.
    """
    lixo = bytes(b ^ 0x01 for b in b"^A.DLLLOLL^")
    for a in desofuscar_blob(lixo):
        assert legibilidade(a.decodificado) >= LEGIBILIDADE_MINIMA


def test_binario_benigno_nao_gera_achado():
    """
    Um binario legitimo nao deve produzir nenhum achado de desofuscacao.
    E o teste que mais pega regressao de falso positivo.
    """
    import pathlib
    import sys as _sys

    floss = pathlib.Path(_sys.executable).parent / "floss.exe"
    if not floss.exists():
        pytest.skip("floss.exe nao disponivel neste ambiente")

    from core.string_extractor import extrair

    extracao = extrair(floss, usar_floss=False)
    resultado = desofuscar(extracao.strings)

    assert resultado.candidatos_avaliados > 0, "triagem descartou tudo: teste inutil"
    assert resultado.achados == [], (
        f"falso positivo em binario benigno: "
        f"{[(a.cadeia, a.decodificado[:40]) for a in resultado.achados]}"
    )


def test_string_aleatoria_nao_produz_xor_falso():
    """
    Ruido binario nao deve produzir achado de XOR. Sem o filtro de
    pontuacao, varias das 255 chaves acertariam algo imprimivel por acaso.
    """
    ruido = bytes(range(32, 126)) * 2
    achados = desofuscar_blob(ruido)
    for a in achados:
        assert a.ancoras, f"achado sem evidencia: {a.cadeia} -> {a.decodificado[:40]!r}"


# ============================================================
# Integracao com o extrator
# ============================================================


def test_desofuscar_revela_ioc_escondido():
    """O ponto do modulo: achar C2 que a varredura de string nao ve."""
    escondido = base64.b64encode(b"http://c2-oculto.xyz/gate.php").decode()
    strings = [
        StringExtraida(valor="kernel32.dll", tipo=TipoString.STATIC),
        StringExtraida(valor=escondido, tipo=TipoString.DECODED),
        StringExtraida(valor="GetProcAddress", tipo=TipoString.STATIC),
    ]

    resultado = desofuscar(strings)

    assert resultado.achados
    urls = {i.valor for i in resultado.iocs_revelados if i.tipo is TipoIOC.URL}
    assert "http://c2-oculto.xyz/gate.php" in urls

    dominios = {i.valor for i in resultado.iocs_revelados if i.tipo is TipoIOC.DOMINIO}
    assert "c2-oculto.xyz" in dominios


def test_preserva_tipo_da_string_de_origem():
    escondido = base64.b64encode(b"http://origem-stack.top/a").decode()
    strings = [StringExtraida(valor=escondido, tipo=TipoString.STACK)]
    resultado = desofuscar(strings)
    assert resultado.achados[0].tipo_string is TipoString.STACK


def test_string_repetida_avaliada_uma_vez():
    escondido = base64.b64encode(b"http://repetido.xyz/x").decode()
    strings = [StringExtraida(valor=escondido, tipo=TipoString.STATIC)] * 5
    resultado = desofuscar(strings)
    assert resultado.candidatos_avaliados == 1


def test_resultado_serializavel():
    escondido = base64.b64encode(b"http://serial.top/a").decode()
    resultado = desofuscar([StringExtraida(valor=escondido, tipo=TipoString.STATIC)])
    d = resultado.to_dict()
    assert d["achados"][0]["decodificado"] == "http://serial.top/a"
