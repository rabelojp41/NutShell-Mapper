"""
Testes da analise de e-mail e da leitura de dominio.

As mensagens sao montadas aqui, uma por golpe, para cada sinal ter um teste
que falha se ele sumir. Uma amostra real (phishing pot) nao pode ir para o
repositorio: e e-mail de terceiro, com endereco de gente de verdade.
"""

from __future__ import annotations

import base64
import json
import textwrap
from pathlib import Path

import pytest

from core import dominios
from core.analise_email import ErroEmail, _enderecos, analisar_email, analisar_received, origem_provavel
from core.string_extractor import TipoIOC


def _eml(tmp_path: Path, cabecalhos: str, corpo: str = "", nome: str = "m.eml") -> Path:
    caminho = tmp_path / nome
    caminho.write_bytes((textwrap.dedent(cabecalhos).strip() + "\r\n\r\n" + corpo).encode("utf-8"))
    return caminho


RECEBIDO = """\
Received: from mx.destino.com (10.0.0.5) by caixa.destino.com with SMTP; Thu, 27 Jul 2023 07:40:06 +0000
Received: from mail.golpe.top (unknown [45.13.7.9]) by mx.destino.com with ESMTP id 1; Thu, 27 Jul 2023 07:40:01 +0000
Received: from pc-interno (192.168.0.10) by mail.golpe.top; Thu, 27 Jul 2023 07:39:58 +0000
"""


def codigos(r) -> set[str]:
    return {s.codigo for s in r.sinais}


# ============================================================
# Cabecalhos
# ============================================================


def test_caminho_em_ordem_e_origem_e_o_primeiro_ip_publico():
    valores = [l for l in RECEBIDO.splitlines() if l]
    saltos = analisar_received([v.removeprefix("Received: ") for v in valores])
    assert [s.ip for s in saltos] == ["192.168.0.10", "45.13.7.9", "10.0.0.5"]
    assert [s.atraso_segundos for s in saltos] == [None, 3.0, 5.0]
    origem = origem_provavel(saltos)
    # O IP privado antes dele e da rede do remetente (ou inventado por ele).
    assert origem.ip == "45.13.7.9" and origem.de == "mail.golpe.top"


def test_from_malformado_nao_perde_o_nome():
    """A virgula no nome e proposital: o parser padrao separa a marca do endereco."""
    assert _enderecos("Microsoft account team ,_<no-reply@x.com>") == [("Microsoft account team ,_", "no-reply@x.com")]


def test_autenticacao_vem_do_cabecalho_mais_alto(tmp_path):
    """Um Authentication-Results mais embaixo pode ter sido escrito pelo atacante."""
    r = analisar_email(_eml(tmp_path, """
        Authentication-Results: mx.destino.com; spf=fail smtp.mailfrom=golpe.top; dkim=none; dmarc=fail header.from=banco.com
        Authentication-Results: falso; spf=pass; dkim=pass; dmarc=pass
        From: Banco <avisos@banco.com>
        Subject: oi
    """, "texto"))
    a = r.autenticacao
    assert (a.spf, a.dkim, a.dmarc, a.dominio_envelope) == ("fail", "none", "fail", "golpe.top")
    assert {"spf_falhou", "dmarc_falhou", "dkim_ausente"} <= codigos(r)


def test_reply_to_para_webmail_e_envelope_diferente(tmp_path):
    r = analisar_email(_eml(tmp_path, """
        From: Suporte <suporte@empresa.com>
        Reply-To: suporte.empresa@gmail.com
        Return-Path: <bounce@disparos.xyz>
        Subject: Atualize seu cadastro
    """, "texto"))
    grav = {s.codigo: s.gravidade for s in r.sinais}
    assert grav["reply_to_desviado"] == "alta"
    assert "envelope_diferente" in grav


def test_mesmo_dono_nao_e_divergencia(tmp_path):
    """mail.empresa.com.br e empresa.com.br sao do mesmo dono."""
    r = analisar_email(_eml(tmp_path, """
        From: Empresa <noreply@empresa.com.br>
        Return-Path: <bounce@mail.empresa.com.br>
        Authentication-Results: mx; spf=pass smtp.mailfrom=mail.empresa.com.br; dkim=pass header.d=empresa.com.br; dmarc=pass header.from=empresa.com.br
        Subject: Nota fiscal de setembro
    """, "Segue a nota."))
    assert codigos(r) == set()
    assert r.veredito == "Nenhum sinal encontrado"


def test_personificacao_de_marca(tmp_path):
    r = analisar_email(_eml(tmp_path, """
        From: "Microsoft 365" <alerta@seguranca-conta.net>
        Subject: Sua senha expira hoje
    """, "texto"))
    assert "personificacao" in codigos(r)
    assert "urgencia" in codigos(r)


def test_cabecalho_unico_duplicado(tmp_path):
    r = analisar_email(_eml(tmp_path, """
        From: a@b.com
        Subject: um
        Subject: dois
    """, "x"))
    assert "cabecalho_duplicado" in codigos(r)


# ============================================================
# Corpo
# ============================================================


HTML = """Content-Type: text/html; charset=utf-8"""


def test_link_disfarcado_e_imitacao(tmp_path):
    corpo = (
        '<p>Acesse <a href="https://itau-seguranca.top/login">https://www.itau.com.br</a></p>'
        '<a href="https://paypa1.com/x">conta</a>'
        '<a href="http://185.22.1.9/a">aqui</a>'
        '<a href="https://bit.ly/abc">ver</a>'
        '<a href="javascript:alert(1)">x</a>'
    )
    r = analisar_email(_eml(tmp_path, f"From: a@b.com\nSubject: s\n{HTML}", corpo))
    c = codigos(r)
    assert {"link_disfarcado", "link_imitacao", "link_ip", "link_encurtado", "link_perigoso"} <= c
    assert any(t["id"] == "T1566.002" for t in r.tecnicas)
    urls = {i.valor for i in r.iocs if i.tipo == TipoIOC.URL}
    assert "https://itau-seguranca.top/login" in urls
    # javascript: nao e indicador de rede.
    assert not any(u.startswith("javascript") for u in urls)


def test_golpe_de_resposta_sem_link(tmp_path):
    corpo = '<a href="mailto:suporte.falso@gmail.com?subject=ajuda">Falar com o suporte</a>'
    r = analisar_email(_eml(tmp_path, f"From: a@b.com\nSubject: s\n{HTML}", corpo))
    assert "golpe_por_resposta" in codigos(r)
    assert "suporte.falso@gmail.com" in {i.valor for i in r.iocs}


def test_texto_oculto_e_pixel(tmp_path):
    palavras = " ".join(f"palavra{i}" for i in range(60))
    corpo = (
        f'<p>Oi</p><div style="display:none">{palavras}</div>'
        f'<style>{palavras}</style><style>p {{ color: red }}</style>'
        '<img src="https://rastreio.net/track/abc123" width="1" height="1">'
    )
    r = analisar_email(_eml(tmp_path, f"From: a@b.com\nSubject: s\n{HTML}", corpo))
    assert r.texto_visivel == "Oi"
    assert "color: red" not in r.texto_oculto  # CSS de verdade nao e texto escondido
    assert {"texto_oculto", "rastreamento"} <= codigos(r)


def test_formulario_e_script(tmp_path):
    corpo = '<form action="https://coleta.top/p"><input name="senha"></form><script>x()</script>'
    r = analisar_email(_eml(tmp_path, f"From: a@b.com\nSubject: s\n{HTML}", corpo))
    assert {"formulario", "script"} <= codigos(r)


# ============================================================
# Anexos
# ============================================================


def _com_anexo(tmp_path, nome: str, conteudo: bytes, tipo: str = "application/octet-stream") -> Path:
    b64 = base64.b64encode(conteudo).decode()
    corpo = (
        "--XX\r\nContent-Type: text/plain\r\n\r\nSegue anexo.\r\n"
        f'--XX\r\nContent-Type: {tipo}\r\nContent-Disposition: attachment; filename="{nome}"\r\n'
        f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--XX--\r\n"
    )
    return _eml(tmp_path, 'From: a@b.com\nSubject: s\nContent-Type: multipart/mixed; boundary="XX"', corpo)


def test_extensao_dupla_executavel(tmp_path):
    r = analisar_email(_com_anexo(tmp_path, "fatura.pdf.exe", b"MZ" + b"\0" * 100))
    anexo = r.anexos[0]
    assert anexo.tipo_real.startswith("executável")
    assert any("extensão dupla" in o for o in anexo.observacoes)
    assert any(s.gravidade == "alta" and s.codigo == "anexo" for s in r.sinais)
    assert anexo.sha256 in {i.valor for i in r.iocs if i.tipo == TipoIOC.HASH}
    assert {"T1566.001", "T1204"} <= {t["id"] for t in r.tecnicas} or "T1036" in {t["id"] for t in r.tecnicas}


def test_executavel_disfarcado_de_pdf(tmp_path):
    r = analisar_email(_com_anexo(tmp_path, "boleto.pdf", b"MZ" + b"\0" * 100))
    assert any("com extensão “.pdf”" in o for o in r.anexos[0].observacoes)


def test_html_smuggling(tmp_path):
    html = b"<html><script>var b=new Blob([atob('TVo=')]);</script></html>"
    r = analisar_email(_com_anexo(tmp_path, "documento.html", html, "text/html"))
    assert any("smuggling" in o for o in r.anexos[0].observacoes)
    assert "T1027.006" in {t["id"] for t in r.tecnicas}


def test_pdf_de_verdade_nao_e_acusado(tmp_path):
    r = analisar_email(_com_anexo(tmp_path, "relatorio.pdf", b"%PDF-1.7\n..."))
    assert r.anexos[0].tipo_real == "PDF"
    assert r.anexos[0].observacoes == []


# ============================================================
# Entrada e saida
# ============================================================


def test_arquivo_que_nao_e_email(tmp_path):
    caminho = tmp_path / "x.eml"
    caminho.write_bytes(b"")
    with pytest.raises(ErroEmail):
        analisar_email(caminho)


def test_msg_do_outlook_pede_eml(tmp_path):
    caminho = tmp_path / "x.msg"
    caminho.write_bytes(b"\xd0\xcf\x11\xe0" + b"\0" * 100)
    with pytest.raises(ErroEmail, match=".eml"):
        analisar_email(caminho)


def test_resultado_serializa_e_exporta(tmp_path):
    from reports import ioc_export

    r = analisar_email(_eml(tmp_path, RECEBIDO + "From: X <a@golpe.top>\nSubject: s\n" + HTML,
                            '<a href="https://golpe.top/l">l</a>'))
    dados = json.loads(json.dumps(r.to_dict(), ensure_ascii=False))
    assert dados["origem"]["ip"] == "45.13.7.9"
    assert any(i["defang"] == "hxxps://golpe[.]top/l" for i in dados["iocs"])
    saidas = ioc_export.exportar(r, tmp_path / "saida", ["csv", "stix"])
    assert saidas["csv"].exportados >= 3
    assert "45.13.7.9" in Path(saidas["stix"].caminho).read_text(encoding="utf-8")


# ============================================================
# Dominios
# ============================================================


@pytest.mark.parametrize("dominio, esperado", [
    ("login.conta.empresa.com.br", "empresa.com.br"),
    ("a.b.exemplo.co.uk", "exemplo.co.uk"),
    ("sub.exemplo.com", "exemplo.com"),
    ("EXEMPLO.COM.", "exemplo.com"),
    ("45.13.7.9", "45.13.7.9"),
])
def test_registravel(dominio, esperado):
    assert dominios.registravel(dominio) == esperado


@pytest.mark.parametrize("dominio, marca, como", [
    ("microsoft-verificacao.com", "microsoft", "contem"),
    ("paypa1.com", "paypal", "grafia"),
    ("rnicrosoft.com", "microsoft", "grafia"),
    ("arnazon.com", "amazon", "grafia"),
    ("nubamk.com.br", "nubank", "grafia"),
])
def test_imitacao_de_marca(dominio, marca, como):
    imit = dominios.imitacao_de_marca(dominio)
    assert imit is not None and (imit.marca, imit.como) == (marca, como)


def test_alfabeto_misturado():
    # "аpple" com "а" cirilico, como chega em punycode.
    cirilico = "аpple.com".encode("idna").decode()
    assert cirilico.startswith("xn--")
    assert dominios.imitacao_de_marca(cirilico).como == "unicode"


@pytest.mark.parametrize("dominio", ["microsoft.com", "login.microsoftonline.com", "itau.com.br",
                                     "empresa-qualquer.com", "github.com", "globo.com"])
def test_dominio_legitimo_nao_e_imitacao(dominio):
    assert dominios.imitacao_de_marca(dominio) is None


def test_defang():
    assert dominios.defang("https://mau.com/x") == "hxxps://mau[.]com/x"
    assert dominios.defang("a@b.com") == "a[@]b[.]com"


# ============================================================
# Consulta online (sem rede: respostas dubladas)
# ============================================================


class _Resposta:
    def __init__(self, dados, status=200):
        self._dados, self.status_code = dados, status
        self.ok = status < 400

    def json(self):
        return self._dados


def test_consulta_de_dominio_com_rede_dublada(monkeypatch):
    from enrichment import consulta_dominio as cd

    dns = {
        ("exemplo.com", "A"): [{"type": 1, "data": "1.2.3.4"}],
        ("exemplo.com", "MX"): [{"type": 15, "data": "10 mx.exemplo.com."}],
        ("exemplo.com", "NS"): [{"type": 2, "data": "ns1.exemplo.com."}],
        ("exemplo.com", "TXT"): [{"type": 16, "data": '"v=spf1 -all"'}],
        ("_dmarc.exemplo.com", "TXT"): [{"type": 16, "data": '"v=DMARC1; p=none"'}],
    }

    def falso_get(self, url, timeout=None, params=None, headers=None):
        if url == cd.DOH:
            return _Resposta({"Answer": dns.get((params["name"], params["type"]), [])})
        if url.startswith("https://rdap.org/"):
            return _Resposta({"events": [{"eventAction": "registration", "eventDate": "2099-01-01T00:00:00Z"}],
                              "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrador X"]]]}]})
        if url == cd.CRTSH:
            return _Resposta({}, 502)
        if url == cd.CERTSPOTTER:
            if params.get("after"):
                return _Resposta([])
            return _Resposta([{"id": "1", "dns_names": ["*.exemplo.com", "vpn.exemplo.com", "outro.com"]}])
        raise AssertionError(url)

    monkeypatch.setattr(cd.requests.Session, "get", falso_get)
    monkeypatch.setattr(cd, "ESPERA_CRTSH", 0)
    c = cd.consultar_dominio("www.exemplo.com".replace("www.", ""))
    assert c.dns["A"] == ["1.2.3.4"] and c.spf == "v=spf1 -all"
    assert c.registrador == "Registrador X"
    # crt.sh fora do ar: o Cert Spotter supre, e so nomes do dominio entram.
    assert c.subdominios == ["exemplo.com", "vpn.exemplo.com"]
    assert any("p=none" in o for o in c.observacoes)
    assert c.erros == []


def test_consulta_recusa_ip():
    from enrichment.consulta_dominio import consultar_dominio

    with pytest.raises(ValueError):
        consultar_dominio("8.8.8.8")


# ============================================================
# Regra YARA do e-mail
# ============================================================


CAMPANHA = """\
Received: from mx.vitima.com.br (10.0.0.5) by caixa.vitima.com.br; Thu, 27 Jul 2023 07:40:06 +0000
Received: from mail.golpe.top (unknown [45.13.7.9]) by mx.vitima.com.br; Thu, 27 Jul 2023 07:40:01 +0000
From: "Microsoft 365" <alerta@conta-segura.top>
To: fulano@vitima.com.br
Reply-To: suporte.ms365@gmail.com
Return-Path: <bounce@disparos.xyz>
Subject: Sua senha expira hoje - acao necessaria
Content-Type: text/html
"""


def test_regra_yara_da_campanha(tmp_path):
    from core.yara_email import gerar_regra_email

    corpo = '<a href="https://login-ms365.top/entrar">Manter senha</a>'
    eml = _eml(tmp_path, CAMPANHA, corpo)
    regra = gerar_regra_email(analisar_email(eml))
    assert regra.valida and not regra.falsos_positivos
    valores = {c.valor for c in regra.strings_usadas}
    assert {"suporte.ms365@gmail.com", "conta-segura.top", "disparos.xyz", "login-ms365.top", "45.13.7.9"} <= valores
    # Nada da vitima: nem o endereco, nem o dominio, nem o servidor dela.
    assert not any("vitima" in v for v in valores)
    # Webmail sozinho casaria com metade da caixa de qualquer um.
    assert "gmail.com" not in valores
    # Endereco e dominio do mesmo remetente contariam duas vezes.
    assert "alerta@conta-segura.top" not in valores


def test_regra_pega_outra_mensagem_da_mesma_campanha(tmp_path):
    import yara

    from core.yara_email import gerar_regra_email

    regra = gerar_regra_email(analisar_email(_eml(tmp_path, CAMPANHA, '<a href="https://login-ms365.top/a">x</a>')))
    irma = CAMPANHA.replace("fulano@vitima.com.br", "ciclano@outra.com").replace("Sua senha expira hoje - acao necessaria", "Verifique sua conta")
    dados = (textwrap.dedent(irma).strip() + "\r\n\r\n" + '<a href="https://login-ms365.top/b">y</a>').encode()
    assert yara.compile(source=regra.texto).match(data=dados)


def test_sem_material_nao_gera_regra(tmp_path):
    from core.yara_email import gerar_regra_email

    corpo = base64.b64encode(b'<a href="https://x.top">x</a>').decode()
    eml = _eml(tmp_path, "From: alguem@gmail.com\nSubject: oi\nContent-Type: text/html\nContent-Transfer-Encoding: base64", corpo)
    regra = gerar_regra_email(analisar_email(eml))
    assert not regra.valida
    assert regra.avisos
