"""
Regra YARA a partir de um e-mail de phishing.

A regra pega outras mensagens da MESMA campanha numa caixa de entrada, num
gateway de e-mail ou num acervo de .eml: o que se repete entre as mensagens
de uma campanha e a infraestrutura do atacante - dominio e endereco do
remetente, dominio do envelope, o Reply-To para onde ele quer a resposta,
os dominios dos links e do pixel de rastreamento, o assunto.

Tres cuidados que definem o que entra:

  1. So entra string que aparece LITERALMENTE no arquivo. O YARA le bytes,
     nao o e-mail decodificado: um link dentro de um corpo em base64 nao
     existe para ele, e uma regra que depende dele nunca casaria.
  2. Nada da vitima entra. O destinatario (To, Cc), o dominio da empresa
     dele e os servidores internos por onde a mensagem passou mudam a cada
     alvo; na regra, alem de inuteis, viram dado pessoal compartilhado.
  3. Nada generico entra sozinho: "gmail.com" ou "outlook.com" casariam com
     metade da caixa de qualquer um. O endereco inteiro no Gmail, esse sim,
     e do atacante.

Como na regra do artefato, ela so e considerada valida se compila, casa com
o proprio e-mail e NAO casa com um e-mail comum montado aqui.
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
from datetime import date
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yara

from core import dominios
from core.analise_email import ResultadoEmail
from core.yara_generator import RegraYara, StringCandidata, _escapar, _nome_de_regra, _sem_acento
from core.string_extractor import TipoString

logger = logging.getLogger(__name__)

TAMANHO_MINIMO_DE_ASSUNTO = 12
MAXIMO_DE_STRINGS = 12

# Um e-mail corriqueiro, para a regra provar que nao casa com qualquer coisa.
EMAIL_COMUM = (
    b"Received: from mail.empresa.com.br (mail.empresa.com.br [200.1.2.3]) by mx.destino.com.br;\r\n"
    b" Mon, 1 Sep 2025 10:00:00 -0300\r\n"
    b"From: Financeiro <financeiro@empresa.com.br>\r\n"
    b"To: voce@destino.com.br\r\n"
    b"Subject: Nota fiscal de agosto\r\n"
    b"Reply-To: financeiro@empresa.com.br\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n\r\n"
    b'<p>Segue a nota. Acesse <a href="https://www.empresa.com.br/notas">o portal</a>.</p>'
    b'<img src="https://www.empresa.com.br/logo.png">\r\n'
)


def _no_arquivo(valor: str, bruto_minusculo: bytes) -> bool:
    try:
        return valor.lower().encode("utf-8") in bruto_minusculo
    except UnicodeError:
        return False


def _dominios_da_vitima(r: ResultadoEmail) -> set[str]:
    """Dominios de quem recebeu e dos servidores dele: nunca entram na regra."""
    vitima: set[str] = set()
    for nome, valor in r.cabecalhos:
        if nome.lower() in ("to", "cc", "delivered-to", "x-original-to"):
            for pedaco in valor.replace(",", " ").split():
                if "@" in pedaco:
                    vitima.add(dominios.registravel(pedaco.strip("<>;\"'").rsplit("@", 1)[-1]))
    for salto in r.saltos:
        if r.origem is None or salto.ordem > r.origem.ordem:
            if salto.por:
                vitima.add(dominios.registravel(salto.por))
    vitima.discard("")
    return vitima


def candidatas(r: ResultadoEmail, bruto: bytes) -> list[StringCandidata]:
    """As strings da campanha, da mais para a menos distintiva."""
    minusculo = bruto.lower()
    vitima = _dominios_da_vitima(r)
    saida: list[StringCandidata] = []
    vistos: set[str] = set()

    def add(valor: str, pontuacao: float, motivo: str) -> None:
        valor = (valor or "").strip()
        if len(valor) < 5 or valor.lower() in vistos:
            return
        base = dominios.registravel(valor.rsplit("@", 1)[-1]) if "@" in valor or "." in valor else ""
        if base and base in vitima:
            return
        if not _no_arquivo(valor, minusculo):
            return
        vistos.add(valor.lower())
        saida.append(StringCandidata(valor, pontuacao, TipoString.STATIC, motivo))

    identidades = {i.campo: i for i in r.identidades if "@" in i.endereco}
    for campo, peso, motivo in (
        ("Reply-To", 0.95, "Reply-To: para onde o atacante quer a resposta"),
        ("From", 0.9, "remetente exibido"),
        ("Return-Path", 0.85, "remetente do envelope"),
        ("Sender", 0.8, "Sender"),
    ):
        ident = identidades.get(campo)
        if ident is None:
            continue
        # Endereco e dominio juntos contariam duas vezes a mesma ocorrencia
        # no "N of". Dominio do atacante sozinho ja basta, e pega outras
        # caixas dele; o endereco inteiro so entra quando o dominio e
        # generico (webmail), e ai ele e que identifica o atacante.
        if dominios.e_webmail(ident.dominio):
            add(ident.endereco, peso, motivo)
        else:
            add(ident.dominio, peso, f"domínio do {campo} ({motivo})")

    for link in r.links:
        if link.tipo in ("http", "ip", "encurtador") and link.dominio and not dominios.e_webmail(link.dominio):
            add(link.dominio, 0.8, "domínio de link no corpo")
        elif link.tipo == "mailto" and "@" in link.destino:
            add(unquote(link.destino[7:].split("?")[0]), 0.9, "destino dos botões (mailto)")
    for url in r.imagens_remotas:
        host = (urlsplit(url).hostname or "").lower()
        if host and not dominios.e_webmail(host):
            add(host, 0.7, "domínio do pixel de rastreamento")
    if r.origem is not None and r.origem.ip:
        add(r.origem.ip, 0.6, "IP do servidor de origem")
        if r.origem.de and "." in r.origem.de and not dominios.e_ip(r.origem.de):
            add(r.origem.de, 0.6, "nome que o servidor de origem declarou (HELO)")
    for anexo in r.anexos:
        if anexo.nome and anexo.nome != "(sem nome)":
            add(anexo.nome, 0.75, "nome do anexo")
    if len(r.assunto) >= TAMANHO_MINIMO_DE_ASSUNTO:
        add(r.assunto, 0.65, "assunto")

    saida.sort(key=lambda c: -c.pontuacao)
    return saida[:MAXIMO_DE_STRINGS]


def _minimo(quantidade: int) -> int:
    """Metade das strings, arredondada para cima, e nunca menos de 2."""
    if quantidade <= 2:
        return quantidade
    return max(2, -(-quantidade // 2))


def _texto(nome: str, r: ResultadoEmail, strings: list[StringCandidata], minimo: int) -> str:
    remetente = next((i for i in r.identidades if i.campo == "From"), None)
    marca = next((s.titulo.replace("Finge ser ", "") for s in r.sinais if s.codigo == "personificacao"), "")
    descricao = f"Campanha de phishing{' que se passa por ' + marca if marca else ''}"
    linhas = [
        f"rule {nome}",
        "{",
        "    meta:",
        '        autor = "Nut-Shell Mapper (gerada automaticamente)"',
        f'        data = "{date.today().isoformat()}"',
        f'        descricao = "{_escapar(_sem_acento(descricao))}"',
        f'        sha256_email = "{r.sha256}"',
    ]
    if remetente:
        linhas.append(f'        remetente = "{_escapar(remetente.endereco)}"')
    if r.tecnicas:
        linhas.append(f'        mitre_attack = "{", ".join(t["id"] for t in r.tecnicas)}"')
    linhas += [
        '        alvo = "arquivos .eml (caixa de entrada, gateway, acervo de mensagens)"',
        '        aviso = "Revisar antes de usar em producao: regra gerada a partir de um unico e-mail"',
        "",
        "    strings:",
        # Ancoras de formato: so arquivo de e-mail interessa.
        '        $eml_de = "From:" ascii',
        '        $eml_assunto = "Subject:" ascii',
    ]
    for i, c in enumerate(strings):
        linhas.append(f'        $c{i} = "{_escapar(c.valor)}" ascii wide nocase  // {c.pontuacao:.2f} | {_sem_acento(c.motivo)}')
    linhas += [
        "",
        "    condition:",
        f"        all of ($eml*) and {minimo} of ($c*)",
        "}",
    ]
    return "\n".join(linhas) + "\n"


def gerar_regra_email(r: ResultadoEmail, caminho: str | Path | None = None) -> RegraYara:
    """
    Monta e valida a regra. Devolve sempre um RegraYara; se nao houver
    material, ele volta invalido e com o motivo em `avisos`.
    """
    caminho = Path(caminho or r.caminho)
    bruto = caminho.read_bytes()
    base = next((i.dominio for i in r.identidades if i.campo == "From" and i.dominio), "") or "email"
    nome = _nome_de_regra(f"Phish_{base}_{r.sha256[:8]}")

    escolhidas = candidatas(r, bruto)
    regra = RegraYara(nome=nome, texto="", strings_usadas=escolhidas)
    if len(escolhidas) < 2:
        regra.avisos.append(
            "poucos indicadores da campanha aparecem literalmente no arquivo "
            "(corpo em base64, remetente em webmail): não há material para uma regra confiável"
        )
        return regra

    regra.minimo_para_casar = _minimo(len(escolhidas))
    regra.texto = _texto(nome, r, escolhidas, regra.minimo_para_casar)

    try:
        compilada = yara.compile(source=regra.texto)
    except yara.Error as erro:
        regra.avisos.append(f"a regra não compilou: {erro}")
        return regra
    regra.compila = True
    regra.casa_com_a_amostra = bool(compilada.match(data=bruto))
    if not regra.casa_com_a_amostra:
        regra.avisos.append("a regra não casa com o próprio e-mail")
    if compilada.match(data=EMAIL_COMUM):
        regra.falsos_positivos.append("e-mail comum de teste")
        regra.avisos.append("a regra casou com um e-mail comum: genérica demais")
    if any(dominios.e_webmail(c.valor) for c in escolhidas):
        regra.avisos.append("contém domínio de webmail sozinho: revise")
    return regra
