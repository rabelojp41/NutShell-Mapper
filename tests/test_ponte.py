"""
Testes da interface web: a ponte com o Python e a pagina em si.

A pagina rende dado extraido de malware e fala com uma ponte que grava
arquivo e baixa amostra. As duas perguntas que estes testes respondem:

  1. Um dado malicioso consegue virar codigo na pagina? (XSS)
  2. Se virasse, o que ele conseguiria pedir a ponte?

A primeira precisa da pagina de verdade, rodando no QtWebEngine - teste de
unidade do JavaScript nao pega o que o navegador faz com o DOM. A segunda
se testa direto na ponte, sem pagina.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

pytest.importorskip("PySide6.QtWebEngineWidgets")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QWidget  # noqa: E402

from core.pipeline import OpcoesAnalise, analisar  # noqa: E402
from gui import ponte as ponte_mod  # noqa: E402
from gui.ponte import (  # noqa: E402
    Ponte,
    _opcoes_da_pagina,
    descrever_arquivo,
    para_json,
    resultado_para_dict,
)


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def ponte(app, monkeypatch):
    abertos = []
    monkeypatch.setattr(ponte_mod.QDesktopServices, "openUrl", lambda url: abertos.append(url.toString()) or True)
    p = Ponte(QWidget())
    p.abertos = abertos
    return p


@pytest.fixture(scope="session")
def resultado_real(tmp_path_factory):
    import base64

    pasta = tmp_path_factory.mktemp("ponte")
    amostra = pasta / "amostra.bin"
    amostra.write_bytes(
        b"\n".join(
            [
                b"http://185.220.101.44:8443/gate.php",
                base64.b64encode(b"http://backup-c2.top/beacon"),
                b"powershell.exe -nop -w hidden -enc SQBFAFgA",
                rb"Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                b"vssadmin.exe delete shadows /all /quiet",
                b"Seus arquivos foram criptografados com AES-256",
            ]
        )
    )
    return analisar(amostra, OpcoesAnalise(usar_floss=False, usar_stix=False))


# ============================================================
# Ponte: o que a pagina consegue pedir
# ============================================================


@pytest.mark.parametrize(
    "url",
    [
        "https://attack.mitre.org/techniques/T1059/001/",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://ollama.com/download",
    ],
)
def test_abre_link_de_site_conhecido(ponte, url):
    assert json.loads(ponte.abrirLink(url))["ok"] is True
    assert ponte.abertos == [url]


@pytest.mark.parametrize(
    "url",
    [
        # Indicador extraido do malware: clicar nunca pode visitar o C2.
        "http://185.220.101.44:8443/gate.php",
        "https://backup-c2.top/beacon",
        # Host permitido, mas sem TLS.
        "http://attack.mitre.org/techniques/T1059/",
        # Esquemas que executariam ou abririam coisa local.
        "javascript:alert(1)",
        "file:///C:/Windows/System32/calc.exe",
        # Host permitido so no comeco do nome.
        "https://attack.mitre.org.evil.com/",
        "",
    ],
)
def test_recusa_link_fora_da_lista(ponte, url):
    resposta = json.loads(ponte.abrirLink(url))
    assert resposta["ok"] is False
    assert ponte.abertos == []


def test_so_abre_arquivo_que_a_propria_ponte_gravou(ponte, tmp_path):
    """
    Abrir caminho arbitrario vindo da pagina seria entregar um "execute
    isto" a quem controlasse a pagina - inclusive a amostra extraida.
    """
    qualquer = tmp_path / "qualquer.exe"
    qualquer.write_bytes(b"MZ")

    assert json.loads(ponte.abrirArquivo(str(qualquer)))["ok"] is False
    assert json.loads(ponte.abrirArquivo(r"C:\Windows\System32\calc.exe"))["ok"] is False
    assert ponte.abertos == []

    gravado = tmp_path / "relatorio.pdf"
    gravado.write_bytes(b"%PDF")
    ponte._gravados.add(str(gravado.resolve()))
    assert json.loads(ponte.abrirArquivo(str(gravado)))["ok"] is True


def test_estado_nunca_devolve_chave(ponte, monkeypatch):
    """A pagina so precisa saber se a chave existe, nunca o valor."""
    from config.settings import CONFIG

    segredos = {
        "virustotal_api_key": "vt-SEGREDO-0123456789abcdef",
        "shodan_api_key": "shodan-SEGREDO-9876",
        "malwarebazaar_api_key": "mb-SEGREDO-5555",
    }
    for campo, valor in segredos.items():
        monkeypatch.setattr(CONFIG, campo, valor)

    texto = ponte.estado()
    for valor in segredos.values():
        assert valor not in texto
        # Nem um pedaco, como faria uma chave "mascarada".
        assert valor[-6:] not in texto

    estado = json.loads(texto)
    assert estado["chaves"] == {"virustotal": True, "shodan": True, "malwarebazaar": True}


def test_analisar_sem_arquivo_e_recusado(ponte):
    assert json.loads(ponte.analisar("{}"))["ok"] is False


@pytest.mark.parametrize(
    "pedido, trecho_do_erro",
    [
        ({"formato": "exe; rm -rf /"}, "formato"),
        ({"tamanho_minimo_de_string": 1}, "faixa"),
        ({"tamanho_minimo_de_string": 10_000}, "faixa"),
        ({"tamanho_minimo_de_string": "abc"}, ""),
    ],
)
def test_opcoes_invalidas_sao_recusadas(pedido, trecho_do_erro):
    with pytest.raises((ValueError, TypeError)) as erro:
        _opcoes_da_pagina(pedido)
    assert trecho_do_erro in str(erro.value)


def test_opcoes_padrao_sao_conservadoras():
    """Pedido vazio nao liga nada que saia da maquina."""
    opcoes = _opcoes_da_pagina({})
    assert opcoes.enriquecer is False
    assert opcoes.resumo_ia is False
    assert opcoes.formato == "auto"


def test_resultado_serializa_com_o_que_a_pagina_precisa(resultado_real):
    dados = json.loads(para_json(resultado_para_dict(resultado_real)))

    assert dados["sha256"] == resultado_real.sha256
    assert dados["nome"] == "amostra.bin"
    # Os IOCs consolidados, inclusive os revelados pela desofuscacao.
    valores = {i["valor"] for i in dados["iocs"]}
    assert "http://backup-c2.top/beacon" in valores
    # Veredito calculado, que o to_dict do pipeline deixa de fora.
    assert isinstance(dados["regra_yara"]["valida"], bool)
    # Enum vira o valor, nao "Confianca.ALTA".
    assert all(i["confianca"] in ("alta", "media", "baixa") for i in dados["iocs"])


def test_descrever_arquivo(tmp_path):
    pe = tmp_path / "a.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 62)
    assert "PE" in descrever_arquivo(pe)["formato"]

    vazio = tmp_path / "vazio.bin"
    vazio.write_bytes(b"")
    assert descrever_arquivo(vazio)["formato"] == "Arquivo vazio"

    assert descrever_arquivo(tmp_path / "nao-existe")["ok"] is False


# ============================================================
# Pagina de verdade
# ============================================================


def _esperar(ms):
    laco = QEventLoop()
    QTimer.singleShot(ms, laco.quit)
    laco.exec()


def _js(janela, codigo, espera=5000):
    resultado = {}
    laco = QEventLoop()

    def pronto(valor):
        resultado["v"] = valor
        laco.quit()

    janela.visao.page().runJavaScript(codigo, 0, pronto)
    QTimer.singleShot(espera, laco.quit)
    laco.exec()
    return resultado.get("v")


@pytest.fixture(scope="module")
def janela(app):
    from gui.janela_web import JanelaWeb

    j = JanelaWeb()
    j.resize(1400, 900)
    j.show()
    for _ in range(100):
        _esperar(100)
        if _js(j, "typeof estado !== 'undefined' && !!estado.ambiente") is True:
            break
    else:
        pytest.fail("a pagina nao ficou pronta")
    yield j
    j.close()


VISTAS = [
    "visao", "indicadores", "tecnicas", "killchain", "atribuicao", "desofuscacao",
    "strings", "pe", "yara", "enriquecimento", "ia", "avisos", "bazaar", "config", "nova",
    "email", "dominio",
]

# Cada um tenta executar codigo de um jeito diferente. Se qualquer um
# funcionar, window.__invadido deixa de ser undefined.
CARGAS = [
    '<img src=x onerror="window.__invadido=1">',
    "<script>window.__invadido=2</script>",
    '<svg onload="window.__invadido=3"></svg>',
    '"><iframe src="javascript:window.parent.__invadido=4"></iframe>',
    "<a href=\"javascript:window.__invadido=5\">clique</a>",
    '<div style="background:url(javascript:window.__invadido=6)">x</div>',
]


def _envenenar(dados: dict) -> dict:
    """Poe as cargas em todo campo que vem do artefato e a pagina exibe."""
    carga = " ".join(CARGAS)
    dados["nome"] = carga
    for ioc in dados["iocs"]:
        ioc["valor"] = carga
        ioc["observacao"] = carga
        ioc["origem"] = carga
    for s in dados["extracao"]["strings"]:
        s["valor"] = carga
    for t in dados["mapeamento"]["tecnicas"]:
        t["descricao"] = carga
        for e in t["evidencias"]:
            e["trecho"] = carga
    for a in dados["desofuscacao"]["achados"]:
        a["original"] = carga
        a["decodificado"] = carga
    if dados.get("regra_yara"):
        dados["regra_yara"]["texto"] = carga
        dados["regra_yara"]["avisos"] = [carga]
    dados["avisos"] = [carga]
    dados["erros"] = [{"estagio": carga, "mensagem": carga, "fatal": False}]
    return dados


def test_dado_do_malware_nunca_vira_codigo(janela, resultado_real):
    """
    O teste que justifica a regra de nunca usar innerHTML com dado.

    Um malware pode embutir estas strings de proposito, contando que a
    ferramenta do analista as rende como HTML. Todas as telas sao
    percorridas com as cargas em todo campo exibido.
    """
    dados = _envenenar(resultado_para_dict(resultado_real))
    janela.ponte.concluido.emit(json.dumps(dados))
    _esperar(300)

    for vista in VISTAS:
        _js(janela, f"ir('{vista}')")
        _esperar(120)
        assert _js(janela, "typeof window.__invadido") == "undefined", f"codigo executou na tela {vista}"

        # Nenhum elemento perigoso foi criado a partir do dado. (Os <svg>
        # legitimos da pagina sao os icones, que nao tem onload.)
        perigosos = _js(
            janela,
            "document.querySelectorAll('#conteudo img, #conteudo script, #conteudo iframe, "
            "#conteudo a[href], #conteudo svg[onload], #conteudo [onerror]').length",
        )
        assert perigosos == 0, f"elemento perigoso na tela {vista}"

    # E o texto aparece como texto: o analista precisa ver a carga, nao
    # que ela suma.
    _js(janela, "ir('indicadores')")
    _esperar(150)
    assert _js(janela, "document.getElementById('conteudo').textContent.includes('onerror=')") is True


def test_navegacao_para_fora_e_bloqueada(janela):
    """
    A pagina tem acesso a ponte. Se ela pudesse navegar para um site, esse
    site herdaria o acesso.
    """
    _js(janela, "location.href = 'https://example.com/'")
    _esperar(400)
    _js(janela, "window.open('https://example.com/')")
    _esperar(200)
    url = janela.visao.url()
    assert url.isLocalFile()
    assert Path(url.toLocalFile()).name == "index.html"
    # A pagina continua viva e com a ponte.
    assert _js(janela, "typeof ponte.estado") == "function"


def test_todas_as_telas_rendem_sem_erro_de_javascript(janela, resultado_real, caplog):
    """
    Pega de uma vez erro de sintaxe, violacao da politica de seguranca e
    excecao dentro de uma tela - os tres ja aconteceram nesta interface.
    """
    caplog.set_level(logging.WARNING, logger="gui.janela_web")
    janela.ponte.concluido.emit(para_json(resultado_para_dict(resultado_real)))
    _esperar(300)

    for vista in VISTAS:
        _js(janela, f"ir('{vista}')")
        _esperar(120)
        falhou = _js(janela, "document.getElementById('conteudo').textContent.includes('Falha ao montar esta tela')")
        assert falhou is False, f"a tela {vista} quebrou"

    erros_js = [r.getMessage() for r in caplog.records if r.getMessage().startswith("js ")]
    assert erros_js == []


# ============================================================
# Revisao da regra YARA e blocos de IA
# ============================================================


def _revisao_envenenada(carga: str) -> dict:
    from core.revisao_yara import ComentarioDeString, RevisaoYara

    rv = RevisaoYara(
        modelo="llama3.1:8b",
        gerado=True,
        condicao_explicada=carga,
        fraquezas_calculadas=[carga],
        resumo=carga,
        pontos_fracos=[carga],
        sugestoes=[carga],
        problemas=[carga],
        comentarios=[
            ComentarioDeString(
                id="$s0", valor=carga, fatos=[carga], risco_calculado="alto",
                suspeita_de_injecao=True, comentada=True, o_que_e=carga,
                risco_ia="baixo", motivo_ia=carga, divergencia="subestima",
            )
        ],
    )
    return rv.to_dict()


def _com_resumo_ia(dados: dict, texto: str) -> dict:
    dados["opcoes"]["resumo_ia"] = True
    dados["resumo_ia"] = {
        "texto": texto, "modelo": "llama3.1:8b", "gerado": True, "erro": "",
        "duracao_segundos": 9.5, "invencoes": [{"tipo": "ioc", "valor": texto, "explicacao": texto}],
        "avisos": [], "confiavel": False, "ressalva": texto,
    }
    return dados


def test_revisao_da_regra_nao_vira_codigo(janela, resultado_real):
    """
    A revisão exibe as strings da regra - que vieram do malware - e o texto
    do modelo, que uma string de injection pode ter influenciado. Os dois
    são dado do adversário.
    """
    carga = " ".join(CARGAS)
    dados = _com_resumo_ia(resultado_para_dict(resultado_real), carga)
    janela.ponte.concluido.emit(json.dumps(dados))
    _esperar(300)
    _js(
        janela,
        "estado.revisaoYara = {sha: estado.resultado.sha256, carregando: false, dados: "
        + json.dumps(_revisao_envenenada(carga)) + "}",
    )

    for vista in ("yara", "visao", "ia"):
        _js(janela, f"ir('{vista}')")
        _esperar(150)
        assert _js(janela, "typeof window.__invadido") == "undefined", f"codigo executou em {vista}"
        perigosos = _js(
            janela,
            "document.querySelectorAll('#conteudo img, #conteudo script, #conteudo iframe, "
            "#conteudo a[href], #conteudo svg[onload], #conteudo [onerror]').length",
        )
        assert perigosos == 0, f"elemento perigoso em {vista}"


def test_nenhum_icone_fica_gigante(janela, resultado_real):
    """
    Um ícone sem tamanho definido cresce até a largura do contêiner. Isso
    aconteceu no cabeçalho da revisão e do resumo por IA, que nenhuma
    captura de tela tinha mostrado porque exigem um resultado de IA.
    """
    dados = _com_resumo_ia(resultado_para_dict(resultado_real), "Resumo de teste.")
    janela.ponte.concluido.emit(json.dumps(dados))
    _esperar(300)
    _js(
        janela,
        "estado.revisaoYara = {sha: estado.resultado.sha256, carregando: false, dados: "
        + json.dumps(_revisao_envenenada("texto")) + "}",
    )

    for vista in VISTAS:
        _js(janela, f"ir('{vista}')")
        _esperar(120)
        maior = _js(
            janela,
            "Math.max(0, ...[...document.querySelectorAll('svg')].map(s => s.getBoundingClientRect().width))",
        )
        assert maior <= 32, f"ícone de {maior}px na tela {vista}"


def test_revisar_sem_analise_responde_com_erro(ponte):
    respostas = []
    ponte.tarefaConcluida.connect(respostas.append)
    ponte.revisarYara("llama3.1:8b")
    assert json.loads(respostas[0]) == {"id": "revisao_yara", "ok": False, "erro": "nenhuma regra YARA gerada"}


def test_nome_de_musica_nao_vira_codigo(janela):
    """
    Titulo de faixa e nome de album vem de nome de arquivo. No Linux um
    nome de arquivo aceita < e >, entao eles passam pela mesma regra do
    dado de malware.
    """
    carga = " ".join(CARGAS)
    catalogo = {
        "ok": True,
        "pasta": carga,
        "albuns": [
            {"nome": carga, "artista": carga, "capa": None, "faixas": [carga, carga]},
            {"nome": carga, "artista": "", "capa": None, "faixas": []},
        ],
        "estado": {"album": 0, "faixa": 1, "tocando": True, "posicao_ms": 1000,
                   "duracao_ms": 5000, "volume": 50, "erro": carga},
    }
    _js(janela, f"receberCatalogo({json.dumps(catalogo)}); alternarListaDoDisco = async () => {{}};")
    _js(janela, "disco.listaAberta = true; renderizarListaDoDisco()")
    _esperar(150)

    assert _js(janela, "typeof window.__invadido") == "undefined"
    assert _js(janela, "document.querySelectorAll('#toca-discos script, #toca-discos iframe, #toca-discos [onerror], #toca-discos img').length") == 0
    assert _js(janela, "document.querySelectorAll('.td-faixa').length") == 2
    assert _js(janela, "document.querySelector('.td-titulo').textContent.includes('onerror=')") is True
    maior = _js(janela, "Math.max(0, ...[...document.querySelectorAll('#toca-discos svg')].map(s => s.getBoundingClientRect().width))")
    assert maior <= 32


def _email_envenenado(tmp_path, carga: str) -> dict:
    """Um e-mail real, analisado, com a carga em todo campo que a tela mostra."""
    from core.analise_email import analisar_email

    eml = tmp_path / "golpe.eml"
    eml.write_bytes(
        (
            "Received: from x (unknown [45.13.7.9]) by mx.destino.com; Thu, 27 Jul 2023 07:40:01 +0000\r\n"
            "From: Microsoft <a@golpe.top>\r\nReply-To: b@gmail.com\r\nSubject: s\r\n"
            "Content-Type: text/html\r\n\r\n"
            '<a href="https://golpe.top/l">x</a><div style="display:none">oculto</div>'
        ).encode()
    )
    d = analisar_email(eml).to_dict()
    d["nome"] = carga
    d["assunto"] = carga
    d["veredito"] = carga
    d["texto_oculto"] = carga
    d["avisos"] = [carga]
    d["cabecalhos"] = [[carga, carga]]
    for i in d["identidades"]:
        i.update(nome=carga, endereco=carga, campo=carga)
    for s in d["sinais"]:
        s.update(titulo=carga, detalhe=carga)
    for l in d["links"]:
        l.update(destino=carga, texto=carga, observacoes=[carga])
    for i in d["iocs"]:
        i.update(valor=carga, defang=carga, origem=carga)
    for s in d["saltos"]:
        s.update(de=carga, por=carga, ip=carga, de_reverso=carga)
    d["origem"].update(de=carga, ip=carga)
    d["anexos"] = [{"nome": carga, "tipo_declarado": carga, "tipo_real": carga, "tamanho": 1,
                    "md5": carga, "sha256": carga, "observacoes": [carga]}]
    d["dominios"] = [_dominio_envenenado(carga)]
    return d


def _dominio_envenenado(carga: str) -> dict:
    return {
        "dominio": carga, "registravel": carga, "dns": {"A": [carga], "MX": [carga]}, "spf": carga,
        "dmarc": carga, "criado_em": carga, "idade_dias": 3, "registrador": carga,
        "subdominios": [carga] * 20, "subdominios_truncados": False, "imitacao": carga,
        "observacoes": [carga], "erros": [carga],
    }


def test_email_e_dominio_nao_viram_codigo(janela, tmp_path):
    """
    A tela de e-mail mostra o que o atacante escreveu: assunto, nome do
    remetente, texto e destino de link, cabecalho inteiro. A de dominio
    mostra registro DNS e nome de certificado, que o dono do dominio escolhe.
    """
    carga = " ".join(CARGAS)
    dados = _email_envenenado(tmp_path, carga)
    _js(janela, f"estado.email.arquivo = {{nome: 'x.eml'}}; tarefas.email({{ok: true, dados: {json.dumps(dados)}}}); ir('email')")
    _js(janela, "document.querySelectorAll('details').forEach(d => d.open = true)")
    _esperar(200)
    _js(janela, f"tarefas.dominio({{ok: true, dados: {json.dumps(_dominio_envenenado(carga))}}}); ir('dominio')")
    _esperar(200)

    for vista in ("email", "dominio"):
        _js(janela, f"ir('{vista}')")
        _esperar(150)
        assert _js(janela, "typeof window.__invadido") == "undefined", f"codigo executou em {vista}"
        perigosos = _js(
            janela,
            "document.querySelectorAll('#conteudo img, #conteudo script, #conteudo iframe, "
            "#conteudo a[href], #conteudo svg[onload], #conteudo [onerror]').length",
        )
        assert perigosos == 0, f"elemento perigoso em {vista}"
        assert _js(janela, "document.getElementById('conteudo').textContent.includes('onerror=')") is True

    # Nenhum link do e-mail vira clicavel: o destino aparece como texto.
    _js(janela, "ir('email')")
    _esperar(150)
    assert _js(janela, "document.querySelectorAll('#conteudo a').length") == 0


def test_soltar_eml_leva_para_a_tela_de_email(janela, tmp_path):
    eml = tmp_path / "golpe.eml"
    eml.write_bytes(b"From: a@b.com\r\nSubject: s\r\n\r\nx")
    janela.ponte.definir_arquivo(eml)
    _esperar(200)
    assert _js(janela, "estado.vista") == "email"
    assert _js(janela, "estado.email.arquivo.nome") == "golpe.eml"
    # O artefato de analise estatica nao foi trocado por um e-mail.
    assert janela.ponte._arquivo != eml
