"""
Testes do mitre_mapper e do killchain.

Nenhum teste toca a rede: o bundle STIX real tem ~45 MB, e depender dele
tornaria a suite lenta e quebrada offline. O conftest fornece um bundle
sintetico com a mesma estrutura.

O risco principal aqui e mapear tecnica sem base. Importar OpenProcess nao
e injecao de processo; e por isso que varias regras exigem mais de um sinal.
"""

from __future__ import annotations

import json

import pytest

from core.deobfuscator import Achado, ResultadoDesofuscacao, Tecnica
from core.killchain import (
    ORDEM_DOS_ESTAGIOS,
    Estagio,
    montar,
    resumir_em_texto,
)
from core.mitre_mapper import (
    CATALOGO,
    CATALOGO_POR_ID,
    ErroMitre,
    MitreAttack,
    ResultadoMapeamento,
    TecnicaMapeada,
    TipoSinal,
    carregar_attack,
    mapear,
)
from core.pe_analyzer import InfoPE, Secao
from core.string_extractor import Confianca, ResultadoExtracao, StringExtraida, TipoString


# ============================================================
# Helpers
# ============================================================


def _extracao(*valores: str) -> ResultadoExtracao:
    return ResultadoExtracao(
        caminho="amostra.bin",
        tamanho_bytes=1024,
        md5="0" * 32,
        sha256="0" * 64,
        strings=[StringExtraida(valor=v, tipo=TipoString.STATIC) for v in valores],
    )


def _pe(apis: list[str] = None, secoes: list[Secao] = None) -> InfoPE:
    info = InfoPE(e_pe=True, arquitetura="x86", tipo="EXE")
    if apis:
        info.imports = {"kernel32.dll": list(apis)}
    if secoes:
        info.secoes = secoes
    return info


def _secao(nome: str, entropia: float = 5.0, x: bool = False, w: bool = False) -> Secao:
    return Secao(
        nome=nome,
        endereco_virtual=0x1000,
        tamanho_virtual=0x1000,
        tamanho_bruto=0x1000,
        entropia=entropia,
        executavel=x,
        gravavel=w,
    )


def _ids(resultado: ResultadoMapeamento) -> set[str]:
    return set(resultado.ids())


# ============================================================
# Integridade do catalogo
# ============================================================


def test_catalogo_sem_id_duplicado():
    ids = [r.tecnica_id for r in CATALOGO]
    assert len(ids) == len(set(ids)), "ha tecnica repetida no catalogo"


def test_catalogo_tem_id_no_formato_attack():
    import re

    for regra in CATALOGO:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", regra.tecnica_id), regra.tecnica_id


def test_catalogo_tem_tatica_conhecida():
    """Toda tatica usada precisa ter estagio na Kill Chain."""
    from core.killchain import TATICA_PARA_ESTAGIO

    for regra in CATALOGO:
        assert regra.taticas, f"{regra.tecnica_id} sem tatica"
        for tatica in regra.taticas:
            assert tatica in TATICA_PARA_ESTAGIO, f"{tatica} sem estagio"


def test_catalogo_tem_sinais_e_descricao():
    for regra in CATALOGO:
        assert regra.sinais, f"{regra.tecnica_id} sem sinal"
        assert regra.descricao, f"{regra.tecnica_id} sem descricao"
        assert regra.minimo_de_sinais <= len(regra.sinais), (
            f"{regra.tecnica_id} exige mais sinais do que possui"
        )


def test_subtecnica_tem_pai_coerente():
    for regra in CATALOGO:
        if regra.e_subtecnica:
            assert regra.tecnica_pai.startswith("T")


# ============================================================
# Mapeamento por API
# ============================================================


def test_injecao_de_processo_por_apis():
    info = _pe(["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"])
    resultado = mapear(_extracao(), info_pe=info)

    assert "T1055" in _ids(resultado)
    t = next(t for t in resultado.tecnicas if t.tecnica_id == "T1055")
    assert t.confianca is Confianca.ALTA
    assert all(e.tipo is TipoSinal.API for e in t.evidencias)


def test_api_isolada_nao_dispara_injecao():
    """
    OpenProcess sozinho nao e injecao de processo. A regra exige dois
    sinais exatamente para evitar esse tipo de conclusao.
    """
    resultado = mapear(_extracao(), info_pe=_pe(["OpenProcess"]))
    assert "T1055" not in _ids(resultado)


def test_variantes_a_e_w_sao_reconhecidas():
    """RegSetValueEx no catalogo precisa casar com RegSetValueExW no binario."""
    info = _pe(["CreateServiceW", "OpenSCManagerW"])
    assert "T1543.003" in _ids(mapear(_extracao(), info_pe=info))


def test_keylogging():
    info = _pe(["SetWindowsHookExW", "GetAsyncKeyState"])
    resultado = mapear(_extracao(), info_pe=info)
    t = next(t for t in resultado.tecnicas if t.tecnica_id == "T1056.001")
    assert t.confianca is Confianca.ALTA


# ============================================================
# Mapeamento por string
# ============================================================


def test_persistencia_por_run_key():
    extracao = _extracao(r"Software\Microsoft\Windows\CurrentVersion\Run")
    assert "T1547.001" in _ids(mapear(extracao))


def test_ransomware_por_nota_de_resgate():
    extracao = _extracao(
        "Seus arquivos foram criptografados com AES-256",
        "README_HOW_TO_DECRYPT.txt",
    )
    resultado = mapear(extracao)
    t = next(t for t in resultado.tecnicas if t.tecnica_id == "T1486")
    assert t.confianca is Confianca.ALTA


def test_destruicao_de_shadow_copies():
    extracao = _extracao("vssadmin.exe delete shadows /all /quiet")
    resultado = mapear(extracao)
    assert "T1490" in _ids(resultado)


def test_powershell_codificado():
    extracao = _extracao("powershell.exe -nop -w hidden -enc SQBFAFgA")
    resultado = mapear(extracao)
    t = next(t for t in resultado.tecnicas if t.tecnica_id == "T1059.001")
    assert t.confianca is Confianca.ALTA


def test_c2_em_porta_nao_padrao():
    extracao = _extracao("http://185.220.101.44:8443/gate.php")
    assert "T1571" in _ids(mapear(extracao))


def test_porta_padrao_nao_dispara_t1571():
    extracao = _extracao("http://exemplo.com:443/a", "http://exemplo.com:80/b")
    assert "T1571" not in _ids(mapear(extracao))


def test_deteccao_de_sandbox():
    extracao = _extracao("VBoxService.exe", "detecting vmware environment")
    assert "T1497.001" in _ids(mapear(extracao))


# ============================================================
# Mapeamento por indicio de PE
# ============================================================


def test_empacotamento_por_secao():
    info = _pe(
        ["LoadLibraryA"],
        [_secao("UPX0", entropia=7.8, x=True, w=True), _secao("UPX1", entropia=7.9)],
    )
    resultado = mapear(_extracao(), info_pe=info)
    assert "T1027.002" in _ids(resultado)
    assert "T1027" in _ids(resultado)


def test_binario_limpo_nao_dispara_empacotamento():
    info = _pe(
        [f"Funcao{i}" for i in range(30)],
        [_secao(".text", entropia=6.2, x=True), _secao(".data", entropia=3.1, w=True)],
    )
    assert "T1027.002" not in _ids(mapear(_extracao(), info_pe=info))


# ============================================================
# Mapeamento por desofuscacao
# ============================================================


def test_desofuscacao_dispara_t1140():
    desofuscacao = ResultadoDesofuscacao(
        achados=[
            Achado(
                original="aHR0cDovL2MyLnRvcC9h",
                decodificado="http://c2.top/a",
                tecnicas=(Tecnica.BASE64,),
                chave=None,
                pontuacao=1.0,
                ancoras=("http://",),
            )
        ]
    )
    resultado = mapear(_extracao(), desofuscacao=desofuscacao)
    assert "T1140" in _ids(resultado)
    assert "T1132.001" in _ids(resultado)


def test_conteudo_desofuscado_alimenta_o_mapeamento():
    """String revelada pela desofuscacao precisa valer como evidencia."""
    desofuscacao = ResultadoDesofuscacao(
        achados=[
            Achado(
                original="<ofuscado>",
                decodificado="vssadmin delete shadows /all",
                tecnicas=(Tecnica.XOR_1_BYTE,),
                chave="0x2a",
                pontuacao=1.0,
                ancoras=(),
            )
        ]
    )
    assert "T1490" in _ids(mapear(_extracao(), desofuscacao=desofuscacao))


# ============================================================
# Avisos e limites
# ============================================================


def test_avisa_quando_nao_e_pe():
    resultado = mapear(_extracao("qualquer coisa"))
    assert any("nao e um PE" in a for a in resultado.avisos)


def test_avisa_quando_stix_ausente():
    resultado = mapear(_extracao(), info_pe=_pe(["CreateRemoteThread"]))
    assert resultado.fonte == "catalogo_local"
    assert any("STIX oficial nao carregado" in a for a in resultado.avisos)


def test_artefato_inocente_nao_gera_tecnica():
    """Um arquivo sem nenhum sinal nao pode produzir tecnicas do nada."""
    resultado = mapear(_extracao("Hello World", "Arial", "1234"))
    assert resultado.tecnicas == []


def test_evidencia_e_sempre_anexada():
    resultado = mapear(_extracao(), info_pe=_pe(["CreateRemoteThread", "VirtualAllocEx"]))
    for t in resultado.tecnicas:
        assert t.evidencias, f"{t.tecnica_id} sem evidencia"
        for e in t.evidencias:
            assert e.trecho


def test_resultado_serializavel():
    resultado = mapear(_extracao(), info_pe=_pe(["CreateRemoteThread", "VirtualAllocEx"]))
    assert json.dumps(resultado.to_dict(), default=str)


# ============================================================
# Camada STIX
# ============================================================


def test_carrega_bundle_e_indexa(attack):
    assert attack.carregado
    assert attack.versao == "99.0"
    assert attack.objeto("T1055")["name"] == "Process Injection"
    assert attack.objeto("G0016")["name"] == "APT29"
    assert attack.objeto("T9999") is None


def test_enriquecimento_sobrepoe_o_catalogo(attack):
    info = _pe(["WriteProcessMemory", "CreateRemoteThread"])
    resultado = mapear(_extracao(), info_pe=info, attack=attack)

    t = next(t for t in resultado.tecnicas if t.tecnica_id == "T1055")
    assert t.confirmada_no_stix
    assert t.nome == "Process Injection"
    assert set(t.taticas) == {"defense-evasion", "privilege-escalation"}
    assert t.url.startswith("https://attack.mitre.org/techniques/")
    assert resultado.fonte == "stix"
    assert resultado.versao_attack == "99.0"


def test_enriquecimento_preserva_evidencia_e_confianca(attack):
    """O STIX diz o que a tecnica e; quem observou o artefato fomos nos."""
    info = _pe(["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"])
    sem = mapear(_extracao(), info_pe=info)
    com = mapear(_extracao(), info_pe=info, attack=attack)

    a = next(t for t in sem.tecnicas if t.tecnica_id == "T1055")
    b = next(t for t in com.tecnicas if t.tecnica_id == "T1055")
    assert a.confianca == b.confianca
    assert len(a.evidencias) == len(b.evidencias)


def test_tecnica_fora_do_stix_e_sinalizada(attack):
    """
    O bundle sintetico nao tem T1486... tem. Usa uma que ele nao tem para
    conferir que a ausencia vira aviso, e nao silencio.
    """
    extracao = _extracao("SetWindowsHookExW usado aqui", "GetAsyncKeyState")
    info = _pe(["SetWindowsHookExW", "GetAsyncKeyState"])
    resultado = mapear(extracao, info_pe=info, attack=attack)

    t = next(t for t in resultado.tecnicas if t.tecnica_id == "T1056.001")
    assert not t.confirmada_no_stix
    assert any("ausentes no STIX" in a for a in resultado.avisos)


def test_grupos_que_usam_tecnica(attack):
    nomes = {g["name"] for g in attack.grupos_que_usam("T1055")}
    assert nomes == {"APT29", "FIN7"}
    assert {g["name"] for g in attack.grupos_que_usam("T1486")} == {"Lazarus Group"}
    assert attack.grupos_que_usam("T9999") == []


def test_cache_ausente_sem_download_levanta_erro(tmp_path):
    with pytest.raises(ErroMitre, match="nao encontrado"):
        MitreAttack(tmp_path / "nao_existe.json").carregar(baixar_se_faltar=False)


def test_cache_corrompido_da_mensagem_util(tmp_path):
    ruim = tmp_path / "ruim.json"
    ruim.write_text("{ isso nao e json", encoding="utf-8")
    with pytest.raises(ErroMitre, match="invalido"):
        MitreAttack(ruim).carregar(baixar_se_faltar=False)


def test_carregar_attack_devolve_none_sem_cache(tmp_path):
    """O pipeline nao pode parar por falta do STIX."""
    assert carregar_attack(tmp_path / "ausente.json", baixar_se_faltar=False) is None


# ============================================================
# Kill Chain
# ============================================================


def test_sempre_sete_estagios():
    kc = montar(ResultadoMapeamento())
    assert len(kc.estagios) == 7
    assert [e.estagio for e in kc.estagios] == list(ORDEM_DOS_ESTAGIOS)
    assert all(e.vazio for e in kc.estagios)


def test_estagio_vazio_e_reportado_como_sem_evidencia():
    """Nao ocorreu e diferente de nao foi observado."""
    kc = montar(ResultadoMapeamento())
    assert any("ausencia de evidencia nao e evidencia de ausencia" in a for a in kc.avisos)


def test_tecnica_com_duas_taticas_aparece_em_dois_estagios():
    """
    T1547.001 e persistencia e escalada de privilegio ao mesmo tempo.
    Esconder isso distorceria o modelo do ATT&CK.
    """
    tecnica = TecnicaMapeada(
        tecnica_id="T1547.001",
        nome="Registry Run Keys",
        taticas=["persistence", "privilege-escalation"],
        confianca=Confianca.ALTA,
    )
    kc = montar(ResultadoMapeamento(tecnicas=[tecnica]))

    assert tecnica in kc.por_estagio(Estagio.INSTALACAO).tecnicas
    assert tecnica in kc.por_estagio(Estagio.EXPLORACAO).tecnicas


def test_c2_vai_para_comando_e_controle():
    tecnica = TecnicaMapeada("T1071.001", "Web Protocols", ["command-and-control"])
    kc = montar(ResultadoMapeamento(tecnicas=[tecnica]))
    assert kc.por_estagio(Estagio.COMANDO_E_CONTROLE).tecnicas == [tecnica]


def test_impacto_vai_para_acoes_no_objetivo():
    tecnica = TecnicaMapeada("T1486", "Data Encrypted for Impact", ["impact"])
    kc = montar(ResultadoMapeamento(tecnicas=[tecnica]))
    assert kc.por_estagio(Estagio.ACOES_NO_OBJETIVO).tecnicas == [tecnica]


def test_traducao_editorial_e_sinalizada():
    """Discovery no estagio pos-intrusao e escolha nossa, e precisa aparecer."""
    tecnica = TecnicaMapeada("T1057", "Process Discovery", ["discovery"])
    kc = montar(ResultadoMapeamento(tecnicas=[tecnica]))

    estagio = kc.por_estagio(Estagio.ACOES_NO_OBJETIVO)
    assert "discovery" in estagio.taticas_ambiguas
    assert any("traducao editorial" in a for a in kc.avisos)


def test_tatica_desconhecida_vira_aviso():
    tecnica = TecnicaMapeada("T9999", "Inventada", ["tatica-que-nao-existe"])
    kc = montar(ResultadoMapeamento(tecnicas=[tecnica]))
    assert any("sem estagio correspondente" in a for a in kc.avisos)


def test_cobertura():
    tecnicas = [
        TecnicaMapeada("T1059.003", "cmd", ["execution"]),
        TecnicaMapeada("T1547.001", "run key", ["persistence"]),
        TecnicaMapeada("T1071.001", "http", ["command-and-control"]),
    ]
    kc = montar(ResultadoMapeamento(tecnicas=tecnicas))
    assert len(kc.estagios_cobertos) == 3
    assert kc.cobertura == pytest.approx(3 / 7)


def test_ordenacao_por_confianca_dentro_do_estagio():
    tecnicas = [
        TecnicaMapeada("T1010", "fraca", ["discovery"], confianca=Confianca.BAIXA),
        TecnicaMapeada("T1057", "forte", ["discovery"], confianca=Confianca.ALTA),
    ]
    kc = montar(ResultadoMapeamento(tecnicas=tecnicas))
    estagio = kc.por_estagio(Estagio.ACOES_NO_OBJETIVO)
    assert estagio.tecnicas[0].tecnica_id == "T1057"
    assert estagio.maior_confianca is Confianca.ALTA


def test_resumo_em_texto_cobre_os_sete_estagios():
    tecnica = TecnicaMapeada("T1486", "ransomware", ["impact"], confianca=Confianca.ALTA)
    texto = resumir_em_texto(montar(ResultadoMapeamento(tecnicas=[tecnica])))

    for estagio in ORDEM_DOS_ESTAGIOS:
        assert estagio.value in texto
    assert "T1486" in texto
    assert "sem evidencia neste artefato" in texto


def test_killchain_serializavel():
    tecnica = TecnicaMapeada("T1486", "ransomware", ["impact"])
    assert json.dumps(montar(ResultadoMapeamento(tecnicas=[tecnica])).to_dict(), default=str)


# ============================================================
# Pipeline completo, sem rede
# ============================================================


def test_pipeline_ransomware_sintetico(attack):
    """Um artefato com cara de ransomware precisa aparecer na Kill Chain."""
    extracao = _extracao(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "vssadmin delete shadows /all /quiet",
        "Seus arquivos foram criptografados",
        "POST /gate.php HTTP/1.1",
        "http://185.220.101.44:8443/gate.php",
    )
    info = _pe(
        ["CryptEncrypt", "CryptGenKey", "InternetOpenA", "HttpSendRequestA",
         "FindFirstFileW", "FindNextFileW"],
        [_secao(".text", 6.3, x=True)],
    )

    mapeamento = mapear(extracao, info_pe=info, attack=attack)
    ids = _ids(mapeamento)

    assert {"T1486", "T1490", "T1547.001", "T1071.001", "T1083"} <= ids

    kc = montar(mapeamento)
    assert Estagio.INSTALACAO in kc.estagios_cobertos
    assert Estagio.COMANDO_E_CONTROLE in kc.estagios_cobertos
    assert Estagio.ACOES_NO_OBJETIVO in kc.estagios_cobertos


def test_sinal_fraco_isolado_nao_reporta_tecnica():
    """
    Regressao: GetTickCount (peso 0.2) esta em quase todo binario MSVC e
    sozinho fazia aparecer "evasao de sandbox" num executavel benigno.
    """
    resultado = mapear(_extracao(), info_pe=_pe(["GetTickCount"]))
    assert "T1497.001" not in _ids(resultado)


def test_sinal_fraco_com_reforco_volta_a_reportar():
    """O piso corta ruido, nao evidencia real."""
    extracao = _extracao("VBoxService.exe detectado")
    resultado = mapear(extracao, info_pe=_pe(["GetTickCount"]))
    assert "T1497.001" in _ids(resultado)
