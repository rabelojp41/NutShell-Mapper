"""
Testes do yara_generator.

O criterio de uma regra boa e duplo: precisa casar com a amostra que a
originou e nao casar com software legitimo. Regra gerada automaticamente
falha quase sempre no segundo, porque as strings mais frequentes de um
binario sao as menos distintivas.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yara

from core.string_extractor import (
    IOC,
    Confianca,
    ResultadoExtracao,
    StringExtraida,
    TipoIOC,
    TipoString,
)
from core.yara_generator import (
    ErroGeracaoYara,
    _descartar,
    _nome_de_regra,
    gerar,
    salvar,
    selecionar_strings,
)


def _extracao(valores, iocs=(), **kwargs) -> ResultadoExtracao:
    """Monta um ResultadoExtracao minimo para teste."""
    strings = [
        v if isinstance(v, StringExtraida) else StringExtraida(valor=v, tipo=TipoString.STATIC)
        for v in valores
    ]
    return ResultadoExtracao(
        caminho=kwargs.get("caminho", "amostra.bin"),
        tamanho_bytes=kwargs.get("tamanho_bytes", 4096),
        md5="0" * 32,
        sha256="0" * 64,
        strings=strings,
        iocs=list(iocs),
    )


# ============================================================
# Lista de bloqueio
# ============================================================


@pytest.mark.parametrize(
    "valor",
    [
        "kernel32.dll",
        "GetProcAddress",
        "Microsoft Visual C++ Runtime",
        "api-ms-win-core-file-l1-2-0",
        "This program cannot be run in DOS mode",
        "1.2.3.4",
        "{4590F811-1D3A-11D0-891F-00AA004B2E24}",
        "aaaaaaaaaaaa",
        "!!!!!!!!!!",
        "abc",
        "0123456789ABCDEF",
    ],
)
def test_strings_genericas_sao_descartadas(valor):
    """O que casaria com meio Windows nao pode entrar na regra."""
    assert _descartar(valor), f"{valor!r} deveria ter sido descartada"


@pytest.mark.parametrize(
    "valor",
    [
        "Mutex_Sn4kE_2024_v3",
        "/gate.php?uid=%s&os=%d",
        "Seus arquivos foram criptografados",
        "X-Session-Token: aBc123",
    ],
)
def test_strings_distintivas_passam(valor):
    assert _descartar(valor) == "", f"{valor!r} nao deveria ter sido descartada"


# ============================================================
# Pontuacao e selecao
# ============================================================


def test_string_de_runtime_ganha_de_string_estatica():
    """
    Stack e decoded sao construidas pelo proprio malware em execucao;
    estatica pode ser do compilador. A de runtime vale mais.
    """
    extracao = _extracao(
        [
            StringExtraida(valor="AlvoDeRuntime_x91", tipo=TipoString.DECODED),
            StringExtraida(valor="AlvoEstatico_x91", tipo=TipoString.STATIC),
        ]
    )
    selecionadas = selecionar_strings(extracao)
    assert selecionadas[0].valor == "AlvoDeRuntime_x91"


def test_string_de_ioc_e_priorizada():
    ioc = IOC(
        valor="http://c2.top/a",
        tipo=TipoIOC.URL,
        confianca=Confianca.ALTA,
        origem="POST http://c2.top/a HTTP/1.1",
        tipo_string=TipoString.STATIC,
    )
    extracao = _extracao(
        ["POST http://c2.top/a HTTP/1.1", "OutraStringQualquer_77"], iocs=[ioc]
    )
    selecionadas = selecionar_strings(extracao)
    assert selecionadas[0].valor == "POST http://c2.top/a HTTP/1.1"
    assert "IOC" in selecionadas[0].motivo


def test_respeita_o_maximo():
    extracao = _extracao([f"StringDistintiva_{i:03d}_xyz" for i in range(60)])
    assert len(selecionar_strings(extracao, maximo=7)) == 7


def test_motivo_e_preenchido():
    """Sem o motivo a regra vira lista opaca e ninguem revisa."""
    extracao = _extracao(["Mutex_Sn4kE_2024_v3"])
    assert selecionar_strings(extracao)[0].motivo


# ============================================================
# Nome da regra
# ============================================================


@pytest.mark.parametrize(
    "entrada,esperado",
    [
        ("amostra-01", "amostra_01"),
        ("2024_trojan", "r_2024_trojan"),
        ("nome com espaco", "nome_com_espaco"),
        ("!!!", "artefato"),
    ],
)
def test_nome_de_regra_vira_identificador_valido(entrada, esperado):
    nome = _nome_de_regra(entrada)
    assert nome == esperado
    # Precisa ser aceito pelo compilador de verdade.
    yara.compile(source=f"rule {nome} {{ condition: true }}")


# ============================================================
# Geracao e validacao
# ============================================================


def _amostra(tmp_path: Path, conteudo: bytes, nome: str = "amostra.bin") -> Path:
    caminho = tmp_path / nome
    caminho.write_bytes(conteudo)
    return caminho


def test_regra_compila_e_casa_com_a_amostra(tmp_path):
    marcas = [
        b"Mutex_Sn4kE_2024_v3",
        b"/gate.php?uid=%s&os=%d",
        b"X-Session-Token: aBc123",
        b"Seus arquivos foram criptografados",
        b"C2_FALLBACK_NODE_07",
    ]
    conteudo = b"\x00\x11" + b"\x00".join(marcas) + b"\x00" * 64
    caminho = _amostra(tmp_path, conteudo)

    extracao = _extracao(
        [m.decode() for m in marcas],
        caminho=str(caminho),
        tamanho_bytes=len(conteudo),
    )

    regra = gerar(caminho, extracao, nome_regra="teste_familia")

    assert regra.compila
    assert regra.casa_com_a_amostra
    assert regra.valida
    assert regra.minimo_para_casar >= 1
    # Compila de fato, fora do modulo.
    yara.compile(source=regra.texto)


def test_regra_nao_casa_com_arquivo_sem_relacao(tmp_path):
    marcas = [f"MarcaExclusiva_{i}_zZq" for i in range(6)]
    conteudo = "\n".join(marcas).encode()
    caminho = _amostra(tmp_path, conteudo)
    extracao = _extracao(marcas, caminho=str(caminho), tamanho_bytes=len(conteudo))

    regra = gerar(caminho, extracao)
    assert regra.valida

    outro = _amostra(tmp_path, b"conteudo totalmente diferente\n" * 20, "outro.bin")
    regras = yara.compile(source=regra.texto)
    assert regras.match(str(outro)) == []


def test_falso_positivo_e_reportado(tmp_path):
    """Se a regra casa com um arquivo benigno, isso precisa aparecer."""
    marcas = [f"MarcaCompartilhada_{i}_qq" for i in range(6)]
    conteudo = "\n".join(marcas).encode()
    caminho = _amostra(tmp_path, conteudo)

    # O "benigno" contem exatamente as mesmas marcas: a regra vai casar.
    benigno = _amostra(tmp_path, conteudo, "benigno.bin")

    extracao = _extracao(marcas, caminho=str(caminho), tamanho_bytes=len(conteudo))
    regra = gerar(caminho, extracao, amostras_benignas=[benigno])

    assert regra.falsos_positivos == [str(benigno)]
    assert any("generica demais" in a for a in regra.avisos)


def test_sem_string_distintiva_levanta_erro(tmp_path):
    caminho = _amostra(tmp_path, b"kernel32.dll\x00GetProcAddress\x00")
    extracao = _extracao(["kernel32.dll", "GetProcAddress"], caminho=str(caminho))

    with pytest.raises(ErroGeracaoYara, match="nenhuma string distintiva"):
        gerar(caminho, extracao)


def test_regra_fraca_gera_aviso(tmp_path):
    conteudo = b"MarcaUnica_abc123_xyz\x00"
    caminho = _amostra(tmp_path, conteudo)
    extracao = _extracao(
        ["MarcaUnica_abc123_xyz"], caminho=str(caminho), tamanho_bytes=len(conteudo)
    )

    regra = gerar(caminho, extracao)
    assert any("regra fraca" in a for a in regra.avisos)


def test_strings_sao_escapadas(tmp_path):
    """Aspas e barras precisam sobreviver ao texto da regra."""
    marcas = [
        r'C:\Temp\payload"x".exe',
        r"HKCU\Software\Zx9\Run",
        "Mutex_com_\\barra_e_\"aspas\"",
        "OutraMarca_qwerty_88",
    ]
    conteudo = "\n".join(marcas).encode()
    caminho = _amostra(tmp_path, conteudo)
    extracao = _extracao(marcas, caminho=str(caminho), tamanho_bytes=len(conteudo))

    regra = gerar(caminho, extracao)
    assert regra.compila
    yara.compile(source=regra.texto)


# ============================================================
# Gravacao
# ============================================================


def test_salvar_escreve_arquivo(tmp_path):
    marcas = [f"MarcaParaSalvar_{i}_kk" for i in range(6)]
    conteudo = "\n".join(marcas).encode()
    caminho = _amostra(tmp_path, conteudo)
    extracao = _extracao(marcas, caminho=str(caminho), tamanho_bytes=len(conteudo))

    regra = gerar(caminho, extracao, nome_regra="regra_salva")
    destino = salvar(regra, tmp_path / "saida" / "regra.yar")

    assert destino.exists()
    texto = destino.read_text(encoding="utf-8")
    assert "rule regra_salva" in texto
    yara.compile(source=texto)


def test_salvar_recusa_regra_invalida(tmp_path):
    from core.yara_generator import RegraYara

    invalida = RegraYara(nome="x", texto="rule x {}", compila=False)
    with pytest.raises(ErroGeracaoYara, match="nao sera salva"):
        salvar(invalida, tmp_path / "x.yar")

    # Com forcar=True grava assim mesmo, para inspecao.
    assert salvar(invalida, tmp_path / "x.yar", forcar=True).exists()


def test_meta_registra_hashes(tmp_path):
    marcas = [f"MarcaMeta_{i}_pp" for i in range(6)]
    conteudo = "\n".join(marcas).encode()
    caminho = _amostra(tmp_path, conteudo)
    extracao = _extracao(marcas, caminho=str(caminho), tamanho_bytes=len(conteudo))

    regra = gerar(caminho, extracao)
    assert extracao.sha256 in regra.texto
    assert extracao.md5 in regra.texto
    assert "aviso" in regra.texto  # revisao manual obrigatoria
