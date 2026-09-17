"""
Testes da exportacao de indicadores.

O risco aqui nao e o arquivo sair vazio - isso qualquer um percebe. E
exportar o indicador ERRADO: um valor de confianca baixa alimentando um
bloqueio automatico derruba servico legitimo, e um padrao STIX malformado e
recusado em silencio por quem importa.

Por isso a maior parte dos testes verifica o que NAO sai, e se o que sai
esta no formato que o destino entende.
"""

from __future__ import annotations

import csv
import json

import pytest

from core.pipeline import OpcoesAnalise, ResultadoAnalise, analisar
from core.string_extractor import Confianca, TipoIOC
from reports import ioc_export


@pytest.fixture
def artefato(tmp_path):
    import base64

    caminho = tmp_path / "amostra.bin"
    caminho.write_bytes(
        "\n".join(
            [
                "http://185.220.101.44:8443/gate.php",
                base64.b64encode(b"http://backup-c2.top/beacon").decode(),
                "operador@protonmail.com",
                "Exploit para CVE-2021-44228",
                r"Software\Microsoft\Windows\CurrentVersion\Run\X",
                # Confianca baixa: numero de versao que casa com IPv4.
                "FileVersion 1.1.0.14",
            ]
        ).encode()
    )
    return caminho


@pytest.fixture
def resultado(artefato):
    return analisar(artefato, OpcoesAnalise(usar_floss=False, usar_stix=False))


# ============================================================
# O corte de confianca
# ============================================================


def test_confianca_baixa_nao_e_exportada(resultado, tmp_path):
    """
    Indicador de confianca baixa existe para o analista julgar. Alimentar
    um bloqueio automatico com "1.1.0.14, provavel numero de versao"
    produziria incidente, nao defesa.
    """
    baixos = [i.valor for i in resultado.iocs if i.confianca is Confianca.BAIXA]
    assert baixos, "o artefato de teste precisa ter algum IOC de confianca baixa"

    saida = ioc_export.exportar_csv(resultado, tmp_path / "i.csv")
    conteudo = (tmp_path / "i.csv").read_text(encoding="utf-8")

    for valor in baixos:
        assert valor not in conteudo
    assert saida.descartados_por_confianca == len(baixos)


def test_corte_pode_ser_afrouxado(resultado, tmp_path):
    """O padrao e conservador, mas o analista pode pedir tudo."""
    todos = ioc_export.exportar_csv(
        resultado, tmp_path / "todos.csv", confianca_minima=Confianca.BAIXA
    )
    padrao = ioc_export.exportar_csv(resultado, tmp_path / "padrao.csv")

    assert todos.exportados > padrao.exportados
    assert todos.descartados_por_confianca == 0


def test_corte_em_alta_deixa_so_o_inequivoco(resultado, tmp_path):
    saida = ioc_export.exportar_csv(
        resultado, tmp_path / "alta.csv", confianca_minima=Confianca.ALTA
    )
    linhas = list(csv.DictReader((tmp_path / "alta.csv").read_text(encoding="utf-8").splitlines()))
    assert all(l["confianca"] == "alta" for l in linhas)
    assert saida.exportados == len(linhas)


# ============================================================
# CSV
# ============================================================


def test_csv_leva_o_contexto_de_cada_indicador(resultado, tmp_path):
    """
    Sem a string de origem, quem recebe o indicador nao consegue verificar
    de onde ele saiu.
    """
    ioc_export.exportar_csv(resultado, tmp_path / "i.csv")
    linhas = list(
        csv.DictReader((tmp_path / "i.csv").read_text(encoding="utf-8").splitlines())
    )

    assert linhas
    for linha in linhas:
        assert linha["origem_string"]
        assert linha["artefato_sha256"] == resultado.sha256
        assert linha["confianca"] in ("alta", "media")


def test_csv_leva_todos_os_tipos(resultado, tmp_path):
    """
    O CSV e descritivo, nao acionavel: leva ate o que nao tem padrao STIX,
    como chave de registro.
    """
    ioc_export.exportar_csv(resultado, tmp_path / "i.csv")
    conteudo = (tmp_path / "i.csv").read_text(encoding="utf-8")
    assert "chave_registro" in conteudo


# ============================================================
# STIX 2.1
# ============================================================


def test_stix_produz_bundle_valido(resultado, tmp_path):
    saida = ioc_export.exportar_stix(resultado, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))

    assert bundle["type"] == "bundle"
    assert saida.exportados > 0

    tipos = {o["type"] for o in bundle["objects"]}
    assert "indicator" in tipos
    # O artefato precisa estar no bundle: sem ele, quem recebe ve uma lista
    # solta de indicadores sem saber que vieram todos da mesma amostra.
    assert "malware" in tipos
    assert "relationship" in tipos


def test_stix_relaciona_indicador_ao_artefato(resultado, tmp_path):
    ioc_export.exportar_stix(resultado, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))

    por_id = {o["id"]: o for o in bundle["objects"]}
    relacoes = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert relacoes

    for relacao in relacoes:
        assert relacao["source_ref"] in por_id
        assert relacao["target_ref"] in por_id


def test_cve_vira_vulnerability_e_nao_indicator(resultado, tmp_path):
    """
    Indicador e padrao que se procura em telemetria, e um numero de CVE nao
    se "detecta" numa rede. O STIX tem um objeto proprio para isso, e usar o
    errado faz o bundle ser mal interpretado por quem importa.
    """
    ioc_export.exportar_stix(resultado, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))

    vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert len(vulns) == 1
    assert vulns[0]["name"] == "CVE-2021-44228"
    assert vulns[0]["external_references"][0]["source_name"] == "cve"

    # E nenhum indicator carregando a CVE como padrao.
    padroes = " ".join(
        o.get("pattern", "") for o in bundle["objects"] if o["type"] == "indicator"
    )
    assert "CVE-2021-44228" not in padroes


def test_relacao_da_cve_e_targets_e_nao_uses(resultado, tmp_path):
    """
    "uses" implicaria exploracao comprovada. A analise estatica so viu a
    referencia - "targets" e o que ela sustenta.
    """
    ioc_export.exportar_stix(resultado, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))

    por_id = {o["id"]: o for o in bundle["objects"]}
    para_vuln = [
        o
        for o in bundle["objects"]
        if o["type"] == "relationship"
        and por_id[o["target_ref"]]["type"] == "vulnerability"
    ]
    assert para_vuln
    assert all(r["relationship_type"] == "targets" for r in para_vuln)


def test_chave_de_registro_vira_indicador_de_endpoint(resultado, tmp_path):
    """
    Nao ha padrao STIX de *rede* para chave de registro, mas o STIX 2.1 tem
    um objeto proprio para ela - e chave de execucao automatica e dos
    indicadores mais acionaveis que existem para caca em endpoint.
    """
    saida = ioc_export.exportar_stix(resultado, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))

    padroes = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    registro = [p for p in padroes if "windows-registry-key:key" in p]
    assert len(registro) == 1
    assert "CurrentVersion" in registro[0]
    assert not any("chave_registro" in s for s in saida.sem_representacao)


def test_caminho_vira_arquivo_mais_diretorio(tmp_path):
    """
    O STIX separa o arquivo do diretorio que o contem. Um caminho completo
    vira a conjuncao dos dois - e assim que OpenCTI e MISP esperam receber.
    """
    from core.string_extractor import IOC, TipoString

    r = _resultado_com(
        [
            IOC(
                valor=r"C:\Users\Public\svhost.exe",
                tipo=TipoIOC.CAMINHO_WINDOWS,
                confianca=Confianca.ALTA,
                origem="x",
                tipo_string=TipoString.STATIC,
            )
        ]
    )

    ioc_export.exportar_stix(r, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    padrao = next(o["pattern"] for o in bundle["objects"] if o["type"] == "indicator")

    assert "file:name = 'svhost.exe'" in padrao
    assert "file:parent_directory_ref.path" in padrao
    assert r"C:\\Users\\Public" in padrao


def test_barra_invertida_e_escapada(tmp_path):
    """
    A barra invertida e o caractere de escape do padrao STIX. Uma barra
    solta faz o parser do stix2 recusar o padrao inteiro - e caminho
    Windows e chave de registro sao feitos de barra invertida.
    """
    from stix2 import Indicator

    padrao = ioc_export._padrao_de_caminho(r"C:\Windows\System32\drivers\x.sys")
    assert "\\\\" in padrao

    # A prova real: o proprio stix2 aceita o padrao produzido.
    Indicator(pattern=padrao, pattern_type="stix", valid_from="2024-01-01T00:00:00Z")


def test_caminho_sem_arquivo_vira_diretorio(tmp_path):
    padrao = ioc_export._padrao_de_caminho("C:\\Users\\Public\\")
    assert padrao.startswith("[directory:path =")
    assert "file:name" not in padrao


def test_stix_reporta_o_que_nao_tem_representacao(tmp_path):
    """
    Hexadecimal que nao e MD5, SHA1 nem SHA256 nao recebe padrao chutado:
    fica de fora e e reportado, em vez de sumir em silencio.
    """
    saida = ioc_export.exportar_stix(
        _resultado_com([_hash_ioc("abc123")]), tmp_path / "b.json"
    )
    assert any("abc123" in s for s in saida.sem_representacao)


def test_confianca_vira_escala_stix(resultado, tmp_path):
    ioc_export.exportar_stix(resultado, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))

    for o in bundle["objects"]:
        if o["type"] == "indicator":
            assert 0 <= o["confidence"] <= 100


def test_aspas_no_valor_nao_quebram_o_padrao(tmp_path):
    """Aspas simples nao escapadas produziriam padrao STIX invalido."""
    from core.string_extractor import IOC, StringExtraida, TipoString

    r = ResultadoAnalise(caminho=str(tmp_path / "x.bin"))
    r.extracao = type(
        "E",
        (),
        {
            "sha256": "a" * 64,
            "iocs": [
                IOC(
                    valor="evil'domain.com",
                    tipo=TipoIOC.DOMINIO,
                    confianca=Confianca.ALTA,
                    origem="x",
                    tipo_string=TipoString.STATIC,
                )
            ],
        },
    )()

    ioc_export.exportar_stix(r, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    padrao = next(o["pattern"] for o in bundle["objects"] if o["type"] == "indicator")
    assert "\\'" in padrao


# ============================================================
# MISP
# ============================================================


def test_misp_produz_evento_importavel(resultado, tmp_path):
    ioc_export.exportar_misp(resultado, tmp_path / "e.json")
    evento = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))

    assert "Event" in evento
    assert evento["Event"]["Attribute"]
    assert evento["Event"]["published"] is False  # nunca publicar sozinho

    for atributo in evento["Event"]["Attribute"]:
        assert atributo["type"]
        assert atributo["category"]
        assert atributo["value"]


def test_misp_so_marca_to_ids_em_confianca_alta(resultado, tmp_path):
    """
    `to_ids` marca o atributo como pronto para virar regra de deteccao
    automatica. So confianca alta merece isso sem revisao humana.

    A unica excecao e o hash do proprio artefato, que nao vem da extracao:
    ele identifica a amostra e e sempre inequivoco.
    """
    ioc_export.exportar_misp(resultado, tmp_path / "e.json")
    evento = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))

    for atributo in evento["Event"]["Attribute"]:
        if atributo["to_ids"] and not atributo["comment"].startswith("Artefato"):
            assert "confianca alta" in atributo["comment"]


def test_misp_inclui_o_hash_do_artefato(resultado, tmp_path):
    """E o unico atributo que identifica a amostra de forma inequivoca."""
    ioc_export.exportar_misp(resultado, tmp_path / "e.json")
    evento = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))

    hashes = [
        a
        for a in evento["Event"]["Attribute"]
        if a["comment"].startswith("Artefato analisado")
    ]
    assert len(hashes) == 1
    assert hashes[0]["type"] == "sha256"
    assert hashes[0]["value"] == resultado.sha256


# ============================================================
# Hash embutido: o algoritmo vem do comprimento, nao do tipo
# ============================================================


def _resultado_com(iocs):
    """Monta um ResultadoAnalise minimo em torno de uma lista de IOCs."""
    r = ResultadoAnalise(caminho="amostra.bin")
    r.extracao = type("E", (), {"sha256": "a" * 64, "iocs": list(iocs)})()
    return r


def _hash_ioc(valor):
    from core.string_extractor import IOC, TipoString

    return IOC(
        valor=valor,
        tipo=TipoIOC.HASH,
        confianca=Confianca.ALTA,
        origem="hash embutido",
        tipo_string=TipoString.STATIC,
    )


@pytest.mark.parametrize(
    "valor, tipo_misp, nome_stix",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "md5", "MD5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1", "SHA-1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256", "SHA-256"),
    ],
)
def test_hash_sai_com_o_algoritmo_certo(valor, tipo_misp, nome_stix, tmp_path):
    """
    O extrator classifica MD5, SHA1 e SHA256 todos como TipoIOC.HASH - o
    comprimento e que diz qual e qual. Rotular um SHA256 como MD5 faz o
    MISP recusar o atributo na importacao, porque ele valida o valor contra
    o tipo declarado, e faz o padrao STIX nunca casar.
    """
    r = _resultado_com([_hash_ioc(valor)])

    ioc_export.exportar_misp(r, tmp_path / "e.json")
    evento = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))
    embutido = [a for a in evento["Event"]["Attribute"] if a["value"] == valor]
    assert len(embutido) == 1
    assert embutido[0]["type"] == tipo_misp

    ioc_export.exportar_stix(r, tmp_path / "b.json")
    bundle = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    padroes = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert padroes == [f"[file:hashes.'{nome_stix}' = '{valor}']"]


def test_hash_de_comprimento_estranho_e_reportado(tmp_path):
    """
    Um hexadecimal que nao e MD5, SHA1 nem SHA256 nao vira atributo com
    tipo chutado: sai da exportacao e e reportado.
    """
    r = _resultado_com([_hash_ioc("abc123")])

    saida = ioc_export.exportar_misp(r, tmp_path / "e.json")
    assert any("abc123" in s for s in saida.sem_representacao)

    evento = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))
    assert all(a["value"] != "abc123" for a in evento["Event"]["Attribute"])


# ============================================================
# Orquestracao
# ============================================================


def test_exporta_varios_formatos(resultado, tmp_path):
    saidas = ioc_export.exportar(resultado, tmp_path, ["csv", "stix", "misp"])
    assert set(saidas) == {"csv", "stix", "misp"}
    for s in saidas.values():
        assert s.caminho.exists()


def test_nome_inclui_prefixo_do_hash(resultado, tmp_path):
    saidas = ioc_export.exportar(resultado, tmp_path, ["csv"])
    assert resultado.sha256[:8] in saidas["csv"].caminho.name


def test_formato_desconhecido_e_ignorado(resultado, tmp_path):
    saidas = ioc_export.exportar(resultado, tmp_path, ["csv", "inventado"])
    assert "csv" in saidas
    assert "inventado" not in saidas


def test_falha_de_um_formato_nao_impede_os_outros(resultado, tmp_path, monkeypatch):
    """Ausencia do stix2 nao pode custar o CSV."""
    monkeypatch.setitem(
        ioc_export.FORMATOS,
        "stix",
        lambda *_a, **_k: (_ for _ in ()).throw(ioc_export.ErroExportacao("sem stix2")),
    )
    saidas = ioc_export.exportar(resultado, tmp_path, ["stix", "csv"])
    assert "csv" in saidas
    assert "stix" not in saidas


def test_analise_sem_ioc_gera_arquivo_vazio_mas_valido(tmp_path):
    vazio = ResultadoAnalise(caminho=str(tmp_path / "x.bin"))
    saidas = ioc_export.exportar(vazio, tmp_path, ["csv", "stix", "misp"])

    assert saidas["csv"].exportados == 0
    # O bundle STIX continua valido, so com o artefato dentro.
    bundle = json.loads(saidas["stix"].caminho.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"


def test_resultado_serializavel(resultado, tmp_path):
    saidas = ioc_export.exportar(resultado, tmp_path, ["csv"])
    assert json.dumps(saidas["csv"].to_dict())
