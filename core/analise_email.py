"""
Analise estatica de e-mail (.eml): de onde veio, quem finge ser, para onde
leva e o que carrega.

Nada aqui toca a rede. O e-mail e lido como dado:

  - Nenhum link e acessado. Visitar a URL de um phishing avisa o atacante
    de que alguem clicou - e o link pode ser unico por vitima.
  - Nenhuma imagem remota e baixada. O pixel de rastreamento existe
    justamente para dizer ao remetente que o e-mail foi aberto.
  - Nenhum anexo e aberto ou executado; so hash, tamanho e os primeiros
    bytes, para comparar o tipo real com a extensao.

A consulta de dominio (DNS, certificados, idade) mora em outro modulo e so
roda quando pedida.

Sobre confiar nos cabecalhos: todo cabecalho abaixo do primeiro `Received`
adicionado pelo seu proprio servidor pode ter sido escrito pelo atacante,
inclusive um `Authentication-Results` falso dizendo "spf=pass". Por isso a
autenticacao e lida do cabecalho MAIS ALTO, que foi o ultimo a ser escrito
- normalmente pelo servidor que entregou a mensagem.
"""

from __future__ import annotations

import email
import hashlib
import html
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from core import dominios
from core.string_extractor import IOC, RE_IPV4, RE_URL, Confianca, TipoIOC, TipoString

logger = logging.getLogger(__name__)

TAMANHO_MAXIMO = 50 * 2**20

GRAVIDADES = ("alta", "media", "baixa")
PESOS = {"alta": 30, "media": 15, "baixa": 5}

# Palavras de pressa e medo, os dois gatilhos de engenharia social.
RE_URGENCIA = re.compile(
    r"\b(urgent|immediately|suspend|suspended|unusual|verify|confirm your|locked|"
    r"expire|expired|password|sign.?in activity|security alert|final notice|"
    r"urgente|imediatamente|suspens|bloquead|verifique|confirme|atividade incomum|"
    r"senha|expira|expirad|último aviso|ultimo aviso|regularize|pendência|pendencia)",
    re.IGNORECASE,
)

# Extensoes que executam ou que existem para enganar quem abre.
EXTENSOES_PERIGOSAS = frozenset(
    """
    exe scr com pif bat cmd ps1 vbs vbe js jse wsf wsh hta msi msp lnk cpl jar
    iso img vhd vhdx dll reg url library-ms appref-ms one xll
    """.split()
)
EXTENSOES_COM_MACRO = frozenset({"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"})
EXTENSOES_HTML = frozenset({"htm", "html", "shtml", "svg", "xhtml"})

ASSINATURAS = [
    (b"MZ", "executável Windows (PE)"),
    (b"\x7fELF", "executável Linux (ELF)"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP (ou Office moderno)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Office legado (OLE)"),
    (b"Rar!", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"\x1f\x8b", "GZIP"),
    (b"\x89PNG", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "atalho do Windows (LNK)"),
]
# Um ISO tem a assinatura no setor 16, nao no comeco.
DESLOCAMENTO_ISO = 0x8001

# Cabecalhos que so podem aparecer uma vez (RFC 5322, 3.6). Duplicado e
# sinal de mensagem montada a mao para confundir filtro.
CABECALHOS_UNICOS = ("from", "to", "subject", "date", "message-id", "reply-to", "sender",
                     "content-type", "content-length", "content-transfer-encoding")


# ============================================================
# Estruturas
# ============================================================


@dataclass
class Salto:
    """Um servidor por onde a mensagem passou (um cabecalho Received)."""

    ordem: int            # 1 = o mais antigo, mais perto do remetente
    de: str               # nome que o servidor anterior se deu (HELO)
    de_reverso: str       # nome reverso que o receptor anotou, quando ha
    ip: str
    por: str
    protocolo: str
    quando: str           # ISO 8601, UTC
    atraso_segundos: float | None
    ip_publico: bool
    bruto: str


@dataclass
class Autenticacao:
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""
    dominio_envelope: str = ""   # smtp.mailfrom
    dominio_dkim: str = ""       # header.d / header.i
    dominio_from: str = ""       # header.from
    fonte: str = ""              # de qual cabecalho saiu


@dataclass
class Identidade:
    campo: str
    nome: str
    endereco: str
    dominio: str


@dataclass
class Link:
    destino: str
    texto: str
    dominio: str
    tipo: str        # http, mailto, ip, encurtador, script, dados, outro
    observacoes: list[str] = field(default_factory=list)


@dataclass
class Anexo:
    nome: str
    tipo_declarado: str
    tipo_real: str
    tamanho: int
    md5: str
    sha256: str
    observacoes: list[str] = field(default_factory=list)


@dataclass
class Sinal:
    codigo: str
    titulo: str
    detalhe: str
    gravidade: str
    tecnica: str = ""


@dataclass
class ResultadoEmail:
    caminho: str
    sha256: str = ""
    iniciado_em: str = ""
    assunto: str = ""
    data: str = ""
    cabecalhos: list[tuple[str, str]] = field(default_factory=list)
    saltos: list[Salto] = field(default_factory=list)
    origem: Salto | None = None
    autenticacao: Autenticacao = field(default_factory=Autenticacao)
    identidades: list[Identidade] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    imagens_remotas: list[str] = field(default_factory=list)
    anexos: list[Anexo] = field(default_factory=list)
    texto_visivel: str = ""
    texto_oculto: str = ""
    sinais: list[Sinal] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    pontuacao: int = 0
    veredito: str = ""
    tecnicas: list[dict] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    def identidade(self, campo: str) -> Identidade | None:
        candidatas = [i for i in self.identidades if i.campo == campo]
        return next((i for i in candidatas if "@" in i.endereco), candidatas[0] if candidatas else None)

    def to_dict(self) -> dict:
        dados = asdict(self)
        dados["iocs"] = [
            {**asdict(i), "tipo": i.tipo.value, "confianca": i.confianca.value,
             "tipo_string": i.tipo_string.value, "defang": dominios.defang(i.valor)}
            for i in self.iocs
        ]
        return dados


class ErroEmail(Exception):
    pass


# ============================================================
# Cabecalhos
# ============================================================


def _decodificar(valor) -> str:
    """Cabecalho em =?utf-8?B?...?= vira texto; lixo nao derruba a analise."""
    if valor is None:
        return ""
    try:
        return str(make_header(decode_header(str(valor))))
    except (UnicodeError, LookupError, ValueError, email.errors.HeaderParseError):
        return str(valor)


def _linha(valor: str) -> str:
    return re.sub(r"\s+", " ", valor or "").strip()


RE_RECEIVED_DE = re.compile(r"\bfrom\s+(\S+)(?:\s+\(([^)]*)\))?", re.IGNORECASE)
RE_RECEIVED_POR = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
RE_RECEIVED_COM = re.compile(r"\bwith\s+([\w/-]+)", re.IGNORECASE)
RE_IP_ENTRE_COLCHETES = re.compile(r"\[([0-9a-fA-F:.]+)\]")
RE_IP_LIVRE = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w.:])")


def _ip_do_trecho(trecho: str) -> str:
    for achado in RE_IP_ENTRE_COLCHETES.findall(trecho) + RE_IP_LIVRE.findall(trecho):
        if dominios.e_ip(achado):
            return achado.strip("[]")
    return ""


def analisar_received(valores: list[str]) -> list[Salto]:
    """
    Os Received em ordem cronologica. Cada servidor acrescenta o seu no
    TOPO; o primeiro da lista e o ultimo salto, entao a lista e invertida.
    """
    saltos: list[Salto] = []
    anterior: datetime | None = None
    for ordem, bruto in enumerate(reversed(valores), 1):
        texto = _linha(bruto)
        corpo, _, data = texto.rpartition(";")
        if not corpo:
            corpo, data = texto, ""

        de = de_reverso = ip = ""
        m = RE_RECEIVED_DE.search(corpo)
        if m:
            de = m.group(1).strip("[]")
            parenteses = m.group(2) or ""
            ip = _ip_do_trecho(parenteses) or (de if dominios.e_ip(de) else "")
            nomes = [p for p in re.split(r"[\s\[\]()]+", parenteses) if p and "." in p and not dominios.e_ip(p)]
            de_reverso = nomes[0] if nomes else ""
        por = (RE_RECEIVED_POR.search(corpo) or [None, ""])[1]
        protocolo = (RE_RECEIVED_COM.search(corpo) or [None, ""])[1]

        quando = ""
        atraso = None
        try:
            instante = parsedate_to_datetime(data.strip()) if data.strip() else None
        except (TypeError, ValueError, IndexError):
            instante = None
        if instante is not None:
            if instante.tzinfo is None:
                instante = instante.replace(tzinfo=timezone.utc)
            instante = instante.astimezone(timezone.utc)
            quando = instante.isoformat()
            if anterior is not None:
                atraso = (instante - anterior).total_seconds()
            anterior = instante

        saltos.append(
            Salto(ordem, de, de_reverso, ip, por, protocolo, quando, atraso, dominios.ip_publico(ip), texto)
        )
    return saltos


def origem_provavel(saltos: list[Salto]) -> Salto | None:
    """
    O primeiro salto, em ordem cronologica, com IP publico: e o servidor que
    entregou a mensagem para a internet. Saltos antes dele sao da rede
    interna do remetente (ou inventados por ele - nao da para confiar).
    """
    return next((s for s in saltos if s.ip_publico), None)


RE_AUT_METODO = {
    "spf": re.compile(r"\bspf\s*=\s*(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim\s*=\s*(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc\s*=\s*(\w+)", re.IGNORECASE),
}
RE_AUT_MAILFROM = re.compile(r"smtp\.mailfrom\s*=\s*\"?([^\s;\"]+)", re.IGNORECASE)
RE_AUT_DKIM_D = re.compile(r"header\.(?:d|i)\s*=\s*@?([^\s;]+)", re.IGNORECASE)
RE_AUT_FROM = re.compile(r"header\.from\s*=\s*([^\s;]+)", re.IGNORECASE)
RE_SPF_RESULTADO = re.compile(r"^\s*(\w+)", re.IGNORECASE)


def analisar_autenticacao(msg: Message) -> Autenticacao:
    aut = Autenticacao()
    resultados = msg.get_all("Authentication-Results") or msg.get_all("ARC-Authentication-Results") or []
    if resultados:
        texto = _linha(_decodificar(resultados[0]))
        aut.fonte = "Authentication-Results"
        for metodo, regex in RE_AUT_METODO.items():
            m = regex.search(texto)
            if m:
                setattr(aut, metodo, m.group(1).lower())
        if (m := RE_AUT_MAILFROM.search(texto)):
            aut.dominio_envelope = m.group(1).split("@")[-1].lower()
        if (m := RE_AUT_DKIM_D.search(texto)):
            aut.dominio_dkim = "" if m.group(1).lower() == "none" else m.group(1).lower()
        if (m := RE_AUT_FROM.search(texto)):
            aut.dominio_from = m.group(1).lower()
    if not aut.spf:
        spf = msg.get_all("Received-SPF") or []
        if spf and (m := RE_SPF_RESULTADO.match(_linha(_decodificar(spf[0])))):
            aut.spf = m.group(1).lower()
            aut.fonte = aut.fonte or "Received-SPF"
    return aut


RE_ENDERECO_ANGULAR = re.compile(r"<\s*([^<>\s]+@[^<>\s]+)\s*>")


def _enderecos(texto: str) -> list[tuple[str, str]]:
    """
    (nome, endereco) de um cabecalho de endereco.

    Com um so `<endereco>`, tudo antes dele e o nome - mesmo com virgula no
    meio. `Microsoft account team ,_<x@golpe.com>` e malformado de proposito:
    o parser padrao corta na virgula e separa "Microsoft" do endereco,
    escondendo justamente a marca que o golpe usa.
    """
    angulares = RE_ENDERECO_ANGULAR.findall(texto)
    if len(angulares) == 1:
        nome = texto[: texto.find("<")]
        return [(nome, angulares[0])]
    return getaddresses([texto])


def _identidades(msg: Message) -> list[Identidade]:
    saida = []
    for campo in ("From", "Sender", "Reply-To", "Return-Path"):
        brutos = msg.get_all(campo) or []
        for bruto in brutos:
            texto = _decodificar(bruto)
            for nome, endereco in _enderecos(texto):
                endereco = endereco.strip("<> ").lower()
                if not endereco and not nome:
                    continue
                # "Equipe ,_<x@y>" chega com o nome sujo; o que importa e legivel.
                nome = _linha(nome).strip(" ,_\"'")
                dominio = endereco.rsplit("@", 1)[-1] if "@" in endereco else ""
                saida.append(Identidade(campo, nome, endereco, dominio))
    mid = _decodificar(msg.get("Message-ID", "")).strip("<> \r\n\t")
    if "@" in mid:
        saida.append(Identidade("Message-ID", "", mid, mid.rsplit("@", 1)[-1].lower()))
    return saida


# ============================================================
# Corpo HTML
# ============================================================


ESTILOS_OCULTOS = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*(?:;|$)|"
    r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|max-height\s*:\s*0|mso-hide\s*:\s*all",
    re.IGNORECASE,
)
ELEMENTOS_VAZIOS = frozenset({"br", "img", "hr", "meta", "link", "input", "col", "base", "area", "source", "wbr"})


class _LeitorHtml(HTMLParser):
    """Separa o que o destinatario ve do que so o filtro de spam le."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.visivel: list[str] = []
        self.oculto: list[str] = []
        self.links: list[tuple[str, list[str]]] = []
        self.imagens: list[tuple[str, dict]] = []
        self.formularios: list[str] = []
        self.scripts = 0
        self.iframes: list[str] = []
        self.refresh: list[str] = []
        self._pilha: list[tuple[str, bool]] = []
        self._link_aberto: list[str] | None = None
        self._em_estilo = 0
        self._em_script = 0

    def _oculto_agora(self) -> bool:
        return any(o for _, o in self._pilha)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        oculto = bool(ESTILOS_OCULTOS.search(a.get("style", ""))) or "hidden" in a
        if tag == "style":
            self._em_estilo += 1
        elif tag == "script":
            self._em_script += 1
            self.scripts += 1
        elif tag == "a" and a.get("href"):
            self._link_aberto = []
            self.links.append((a["href"].strip(), self._link_aberto))
        elif tag == "img" and a.get("src"):
            self.imagens.append((a["src"].strip(), a))
        elif tag == "form":
            self.formularios.append(a.get("action", ""))
        elif tag in ("iframe", "frame", "embed", "object"):
            self.iframes.append(a.get("src", "") or a.get("data", ""))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.refresh.append(a.get("content", ""))
        if tag not in ELEMENTOS_VAZIOS:
            self._pilha.append((tag, oculto))

    def handle_endtag(self, tag):
        if tag == "style":
            self._em_estilo = max(0, self._em_estilo - 1)
        elif tag == "script":
            self._em_script = max(0, self._em_script - 1)
        elif tag == "a":
            self._link_aberto = None
        for i in range(len(self._pilha) - 1, -1, -1):
            if self._pilha[i][0] == tag:
                del self._pilha[i:]
                break

    def handle_data(self, dados):
        if not dados.strip() or self._em_script:
            return
        if self._em_estilo:
            # CSS de verdade tem chave. Texto solto dentro de <style> nao e
            # estilo: e palavra escondida para diluir o conteudo aos olhos
            # do filtro de spam ("hash busting").
            if "{" not in dados:
                self.oculto.append(dados)
            return
        (self.oculto if self._oculto_agora() else self.visivel).append(dados)
        if self._link_aberto is not None:
            self._link_aberto.append(dados)


def _texto(partes: list[str]) -> str:
    return re.sub(r"\s+", " ", " ".join(partes)).strip()


def _dominio_do_texto(texto: str) -> str:
    """O dominio que o texto de um link promete ("www.itau.com.br", "https://...")."""
    m = RE_URL.search(texto)
    if m:
        return (urlsplit(m.group(0)).hostname or "").lower()
    m = re.search(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", texto.lower())
    return m.group(1) if m else ""


def _classificar_link(destino: str, texto: str) -> Link:
    destino_limpo = html.unescape(destino).strip()
    esquema = destino_limpo.split(":", 1)[0].lower() if ":" in destino_limpo else ""
    link = Link(destino_limpo, _linha(texto)[:200], "", "outro")

    if esquema == "mailto":
        endereco = unquote(destino_limpo[7:].split("?", 1)[0]).strip().lower()
        link.tipo = "mailto"
        link.dominio = endereco.rsplit("@", 1)[-1] if "@" in endereco else ""
        if dominios.e_webmail(link.dominio):
            link.observacoes.append("o botão abre um e-mail para um webmail gratuito")
        return link
    if esquema in ("javascript", "vbscript"):
        link.tipo = "script"
        link.observacoes.append("o link executa código ao ser clicado")
        return link
    if esquema == "data":
        link.tipo = "dados"
        link.observacoes.append("o link carrega um documento embutido (data:), técnica de HTML smuggling")
        return link
    if esquema not in ("http", "https"):
        return link

    try:
        partes = urlsplit(destino_limpo)
        host = (partes.hostname or "").lower()
    except ValueError:
        link.observacoes.append("URL malformada")
        return link
    link.dominio = host
    link.tipo = "http"
    if dominios.e_ip(host):
        link.tipo = "ip"
        link.observacoes.append("aponta direto para um IP, sem domínio")
    elif dominios.e_encurtador(host):
        link.tipo = "encurtador"
        link.observacoes.append("encurtador esconde o destino real")
    if partes.username or "@" in (partes.netloc or ""):
        link.observacoes.append("tem “@” no endereço: o navegador ignora tudo antes dele")
    if esquema == "http":
        link.observacoes.append("sem HTTPS")
    prometido = _dominio_do_texto(link.texto)
    if prometido and host and not dominios.mesmo_dono(prometido, host):
        link.observacoes.append(f"o texto mostra “{prometido}”, mas o link leva a “{host}”")
    return link


# ============================================================
# Anexos
# ============================================================


def _tipo_real(conteudo: bytes) -> str:
    for assinatura, nome in ASSINATURAS:
        if conteudo.startswith(assinatura):
            return nome
    if conteudo[DESLOCAMENTO_ISO:DESLOCAMENTO_ISO + 5] == b"CD001":
        return "imagem de disco (ISO)"
    cabeca = conteudo[:512].lstrip().lower()
    if cabeca.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml")):
        return "HTML/SVG"
    return "desconhecido"


def _analisar_anexo(parte: Message) -> Anexo:
    nome = _decodificar(parte.get_filename() or "") or "(sem nome)"
    conteudo = parte.get_payload(decode=True) or b""
    anexo = Anexo(
        nome=nome,
        tipo_declarado=parte.get_content_type(),
        tipo_real=_tipo_real(conteudo),
        tamanho=len(conteudo),
        md5=hashlib.md5(conteudo).hexdigest(),
        sha256=hashlib.sha256(conteudo).hexdigest(),
    )
    partes_do_nome = nome.lower().rsplit(".", 2)
    extensao = partes_do_nome[-1] if len(partes_do_nome) > 1 else ""
    if len(partes_do_nome) == 3 and extensao in EXTENSOES_PERIGOSAS:
        anexo.observacoes.append(f"extensão dupla: parece “.{partes_do_nome[1]}”, mas é “.{extensao}”")
    elif extensao in EXTENSOES_PERIGOSAS:
        anexo.observacoes.append(f"“.{extensao}” executa ou monta conteúdo ao ser aberto")
    if extensao in EXTENSOES_COM_MACRO:
        anexo.observacoes.append("documento Office com macro")
    if extensao in EXTENSOES_HTML or anexo.tipo_real == "HTML/SVG":
        texto = conteudo[:200_000].decode("utf-8", "ignore").lower()
        if any(p in texto for p in ("atob(", "new blob", "msSaveOrOpenBlob".lower(), "createobjecturl")):
            anexo.observacoes.append("HTML que monta um arquivo no navegador (HTML smuggling)")
        elif "<form" in texto and ("password" in texto or "senha" in texto):
            anexo.observacoes.append("página de login embutida no anexo")
        else:
            anexo.observacoes.append("anexo HTML: abre no navegador, fora da proteção do cliente de e-mail")
    if anexo.tipo_real.startswith("executável") and extensao not in ("exe", "dll", "scr", "com", "sys"):
        anexo.observacoes.append(f"é um {anexo.tipo_real} com extensão “.{extensao}”")
    if anexo.tipo_real == "ZIP (ou Office moderno)" and len(conteudo) > 8 and conteudo[6] & 0x01:
        anexo.observacoes.append("ZIP protegido por senha: o antivírus do servidor não consegue olhar dentro")
    return anexo


# ============================================================
# Sinais e veredito
# ============================================================

TECNICAS = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598": "Phishing for Information",
    "T1656": "Impersonation",
    "T1036": "Masquerading",
    "T1027.006": "Obfuscated Files or Information: HTML Smuggling",
    "T1204": "User Execution",
}


def _sinais(r: ResultadoEmail, leitor: _LeitorHtml | None, duplicados: list[str]) -> list[Sinal]:
    s: list[Sinal] = []
    aut = r.autenticacao
    remetente = r.identidade("From")
    dom_from = remetente.dominio if remetente else ""
    envelope = r.identidade("Return-Path")
    dom_envelope = (envelope.dominio if envelope else "") or aut.dominio_envelope
    resposta = r.identidade("Reply-To")

    # --- Autenticacao ---
    if aut.spf in ("fail", "softfail"):
        s.append(Sinal("spf_falhou", f"SPF {aut.spf}", "O servidor que enviou não está autorizado pelo domínio do envelope.", "alta" if aut.spf == "fail" else "media"))
    elif aut.spf in ("none", "neutral", "permerror", "temperror"):
        s.append(Sinal("spf_ausente", f"SPF {aut.spf}", "O domínio do envelope não declara quais servidores podem enviar por ele.", "media"))
    if aut.dkim in ("fail", "none", "permerror"):
        s.append(Sinal("dkim_ausente", f"DKIM {aut.dkim}", "A mensagem não tem assinatura válida: o conteúdo pode ter sido montado por qualquer um.", "media"))
    if aut.dmarc in ("fail", "permerror", "none"):
        s.append(Sinal("dmarc_falhou", f"DMARC {aut.dmarc}", f"O domínio do remetente ({aut.dominio_from or dom_from}) não passou na política DMARC.", "alta" if aut.dmarc == "fail" else "media"))
    if not aut.fonte:
        s.append(Sinal("sem_autenticacao", "Sem resultado de autenticação", "Nenhum cabeçalho Authentication-Results: não dá para saber se SPF/DKIM/DMARC passaram.", "baixa"))

    # --- Identidade ---
    if dom_from and dom_envelope and not dominios.mesmo_dono(dom_from, dom_envelope):
        s.append(Sinal("envelope_diferente", "Remetente exibido ≠ remetente real",
                       f"O e-mail mostra “{dom_from}”, mas o envelope (Return-Path) é “{dom_envelope}”.", "media", "T1656"))
    if resposta and dom_from and not dominios.mesmo_dono(resposta.dominio, dom_from):
        grav = "alta" if dominios.e_webmail(resposta.dominio) else "media"
        s.append(Sinal("reply_to_desviado", "Respostas vão para outro endereço",
                       f"Quem responder escreve para {resposta.endereco}, não para {remetente.endereco}.", grav, "T1598"))

    marcas = []
    if remetente:
        marcas = dominios.marcas_no_texto(remetente.nome) or dominios.marcas_no_texto(r.assunto)
    for marca in marcas:
        if dom_from and not dominios.oficial_da_marca(dom_from, marca):
            s.append(Sinal("personificacao", f"Finge ser {marca.capitalize()}",
                           f"Nome ou assunto citam “{marca}”, mas o remetente é “{dom_from}”, que não é domínio da marca.", "alta", "T1656"))
            break
    if dom_from:
        imit = dominios.imitacao_de_marca(dom_from)
        if imit:
            s.append(Sinal("dominio_imitacao", "Domínio do remetente imita uma marca", imit.explicacao, "alta", "T1656"))
        if dominios.e_webmail(dom_from) and marcas:
            s.append(Sinal("marca_em_webmail", "Marca escrevendo de webmail gratuito",
                           f"Empresa não envia aviso oficial de {dom_from}.", "alta", "T1656"))

    # --- Links ---
    tem_link_http = False
    for link in r.links:
        if link.tipo in ("http", "ip", "encurtador"):
            tem_link_http = True
        if any("texto mostra" in o for o in link.observacoes):
            s.append(Sinal("link_disfarcado", "Link disfarçado", f"{link.observacoes[-1]}.", "alta", "T1566.002"))
        if link.tipo == "ip":
            s.append(Sinal("link_ip", "Link para IP", f"{link.destino[:120]}", "media", "T1566.002"))
        if link.tipo == "encurtador":
            s.append(Sinal("link_encurtado", "Link encurtado", f"{link.destino[:120]}", "baixa", "T1566.002"))
        if link.tipo in ("script", "dados"):
            s.append(Sinal("link_perigoso", "Link que executa conteúdo", link.observacoes[0], "alta", "T1027.006"))
        if link.dominio and link.tipo in ("http", "encurtador"):
            imit = dominios.imitacao_de_marca(link.dominio)
            if imit:
                s.append(Sinal("link_imitacao", "Link para domínio que imita marca", f"{link.dominio}: {imit.explicacao}", "alta", "T1566.002"))
    mailtos = [l for l in r.links if l.tipo == "mailto" and dominios.e_webmail(l.dominio)]
    if mailtos and not tem_link_http:
        s.append(Sinal("golpe_por_resposta", "Golpe de resposta (sem link)",
                       f"Os botões não levam a site nenhum: abrem um e-mail para {mailtos[0].destino[7:].split('?')[0]}. "
                       "É o formato de golpe que puxa a vítima para uma conversa, driblando filtros de URL.", "alta", "T1598"))

    # --- Corpo ---
    if leitor is not None:
        if leitor.formularios:
            s.append(Sinal("formulario", "Formulário dentro do e-mail", "O corpo tem um <form>: pede dados direto na mensagem.", "alta", "T1598"))
        if leitor.scripts:
            s.append(Sinal("script", "Script no corpo", "E-mail legítimo não traz <script>.", "media"))
        if leitor.refresh:
            s.append(Sinal("refresh", "Redirecionamento automático", "Meta refresh no HTML.", "media"))
    oculto = r.texto_oculto
    if len(oculto) > 200:
        s.append(Sinal("texto_oculto", "Texto escondido para enganar o filtro",
                       f"{len(oculto)} caracteres invisíveis ao leitor (palavras soltas para diluir o conteúdo aos olhos do antispam).", "media"))
    if r.imagens_remotas:
        rastreio = [u for u in r.imagens_remotas if "track" in u.lower() or "pixel" in u.lower() or "open" in u.lower()]
        if rastreio:
            s.append(Sinal("rastreamento", "Pixel de rastreamento",
                           f"Imagem invisível avisa o remetente quando o e-mail é aberto: {dominios.defang(rastreio[0][:100])}", "baixa"))
    if RE_URGENCIA.search(r.assunto) or RE_URGENCIA.search(r.texto_visivel[:3000]):
        s.append(Sinal("urgencia", "Pressão e urgência", "Assunto ou texto usa gatilhos de medo ou pressa.", "baixa"))
    if duplicados:
        s.append(Sinal("cabecalho_duplicado", "Cabeçalho que deveria ser único aparece repetido",
                       ", ".join(duplicados) + ". Mensagem montada à mão para confundir filtros.", "media"))

    # --- Anexos ---
    for anexo in r.anexos:
        for obs in anexo.observacoes:
            tecnica = "T1027.006" if "smuggling" in obs else ("T1036" if "extensão" in obs or "com extensão" in obs else "T1566.001")
            grav = "alta" if any(p in obs for p in ("executa", "dupla", "smuggling", "executável", "macro", "login")) else "media"
            s.append(Sinal("anexo", f"Anexo suspeito: {anexo.nome}", obs, grav, tecnica))

    return s


def _veredito(sinais: list[Sinal]) -> tuple[int, str]:
    pontos = min(100, sum(PESOS[x.gravidade] for x in sinais))
    altas = sum(1 for x in sinais if x.gravidade == "alta")
    if pontos >= 60 or altas >= 2:
        return pontos, "Phishing muito provável"
    if pontos >= 30 or altas == 1:
        return pontos, "Suspeito"
    if pontos > 0:
        return pontos, "Poucos sinais"
    return pontos, "Nenhum sinal encontrado"


def _tecnicas(sinais: list[Sinal], anexos: list[Anexo]) -> list[dict]:
    ids: dict[str, list[str]] = {}
    for x in sinais:
        if x.tecnica:
            ids.setdefault(x.tecnica, []).append(x.titulo)
    if any(x.tecnica.startswith("T1566.001") for x in sinais) or any(a.observacoes for a in anexos):
        ids.setdefault("T1204", []).append("depende de o usuário abrir o anexo")
    return [{"id": t, "nome": TECNICAS.get(t, t), "motivos": sorted(set(m))} for t, m in sorted(ids.items())]


# ============================================================
# IOCs
# ============================================================


def _iocs(r: ResultadoEmail) -> list[IOC]:
    vistos: set[tuple[str, TipoIOC]] = set()
    saida: list[IOC] = []

    def add(valor: str, tipo: TipoIOC, origem: str, confianca=Confianca.ALTA, obs: str = ""):
        valor = (valor or "").strip()
        if not valor or (valor.lower(), tipo) in vistos:
            return
        vistos.add((valor.lower(), tipo))
        saida.append(IOC(valor, tipo, confianca, origem, TipoString.STATIC, obs))

    if r.origem is not None:
        add(r.origem.ip, TipoIOC.IPV6 if ":" in r.origem.ip else TipoIOC.IPV4, "servidor de origem (Received)")
        if r.origem.de and not dominios.e_ip(r.origem.de) and "." in r.origem.de:
            add(r.origem.de.lower(), TipoIOC.DOMINIO, "HELO do servidor de origem", Confianca.MEDIA,
                "nome que o próprio servidor declarou; pode ser falso")
    for ident in r.identidades:
        if ident.campo == "Message-ID":
            continue
        if ident.endereco and "@" in ident.endereco:
            add(ident.endereco, TipoIOC.EMAIL, ident.campo)
        if ident.dominio and not dominios.e_webmail(ident.dominio):
            add(ident.dominio, TipoIOC.DOMINIO, ident.campo)
    for link in r.links:
        if link.tipo in ("http", "ip", "encurtador"):
            add(link.destino, TipoIOC.URL, "link no corpo")
            if link.dominio and not dominios.e_ip(link.dominio):
                add(link.dominio, TipoIOC.DOMINIO, "link no corpo")
            elif link.dominio:
                add(link.dominio, TipoIOC.IPV4, "link no corpo")
        elif link.tipo == "mailto" and "@" in link.destino:
            add(unquote(link.destino[7:].split("?")[0]).lower(), TipoIOC.EMAIL, "mailto no corpo")
    for url in r.imagens_remotas:
        add(url, TipoIOC.URL, "imagem remota (rastreamento)", Confianca.MEDIA)
        host = (urlsplit(url).hostname or "").lower()
        if host:
            add(host, TipoIOC.DOMINIO, "imagem remota (rastreamento)", Confianca.MEDIA)
    for anexo in r.anexos:
        add(anexo.sha256, TipoIOC.HASH, f"anexo {anexo.nome}")
    # IP citado no texto visivel ("login de 103.x.x.x") e isca, nao infraestrutura.
    for ip in RE_IPV4.findall(r.texto_visivel):
        if dominios.ip_publico(ip):
            add(ip, TipoIOC.IPV4, "citado no texto", Confianca.BAIXA, "IP mencionado na mensagem, provavelmente isca")
    return saida


# ============================================================
# Entrada
# ============================================================


def analisar_email(caminho: str | Path) -> ResultadoEmail:
    """Le um .eml e devolve tudo o que da para saber sem tocar a rede."""
    caminho = Path(caminho)
    try:
        if caminho.stat().st_size > TAMANHO_MAXIMO:
            raise ErroEmail(f"arquivo maior que {TAMANHO_MAXIMO // 2**20} MB")
        bruto = caminho.read_bytes()
    except OSError as erro:
        raise ErroEmail(f"não foi possível ler {caminho}: {erro}") from erro

    r = ResultadoEmail(
        caminho=str(caminho),
        sha256=hashlib.sha256(bruto).hexdigest(),
        iniciado_em=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    if caminho.suffix.lower() == ".msg" or bruto.startswith(b"\xd0\xcf\x11\xe0"):
        raise ErroEmail("arquivo .msg do Outlook: salve a mensagem como .eml (Arquivo → Salvar como) e tente de novo")

    # compat32: devolve o cabecalho como veio. A policy moderna "conserta"
    # endereco malformado, e o malformado e justamente evidencia.
    msg = email.message_from_bytes(bruto, policy=policy.compat32)
    if not msg.keys():
        raise ErroEmail("o arquivo não parece um e-mail: nenhum cabeçalho encontrado")

    r.cabecalhos = [(k, _linha(_decodificar(v))) for k, v in msg.items()]
    r.assunto = _linha(_decodificar(msg.get("Subject", "")))
    r.data = _linha(_decodificar(msg.get("Date", "")))
    r.saltos = analisar_received([str(v) for v in (msg.get_all("Received") or [])])
    r.origem = origem_provavel(r.saltos)
    if r.origem is None:
        for campo in ("X-Sender-IP", "X-Originating-IP"):
            ip = _ip_do_trecho(str(msg.get(campo, "")))
            if dominios.ip_publico(ip):
                r.origem = Salto(0, "", "", ip, "", "", "", None, True, f"{campo}: {ip}")
                r.avisos.append(f"origem tirada de {campo}: não há Received com IP público")
                break
    r.autenticacao = analisar_autenticacao(msg)
    r.identidades = _identidades(msg)

    contagem: dict[str, int] = {}
    for k in msg.keys():
        contagem[k.lower()] = contagem.get(k.lower(), 0) + 1
    duplicados = [k for k in CABECALHOS_UNICOS if contagem.get(k, 0) > 1]

    leitor: _LeitorHtml | None = None
    textos_planos: list[str] = []
    for parte in msg.walk():
        if parte.is_multipart():
            continue
        disposicao = (parte.get("Content-Disposition") or "").lower()
        tipo = parte.get_content_type()
        if parte.get_filename() or disposicao.startswith("attachment"):
            r.anexos.append(_analisar_anexo(parte))
            continue
        if tipo not in ("text/html", "text/plain"):
            continue
        carga = parte.get_payload(decode=True) or b""
        texto = carga.decode(parte.get_content_charset() or "utf-8", "replace")
        if tipo == "text/html":
            leitor = leitor or _LeitorHtml()
            try:
                leitor.feed(texto)
            except Exception as erro:  # HTML hostil nao derruba a analise
                r.avisos.append(f"HTML malformado, lido em parte: {erro}")
        else:
            textos_planos.append(texto)

    if leitor is not None:
        leitor.close()
        r.texto_visivel = _texto(leitor.visivel)
        r.texto_oculto = _texto(leitor.oculto)
        r.links = [_classificar_link(destino, " ".join(t)) for destino, t in leitor.links]
        for src, atributos in leitor.imagens:
            if src.lower().startswith(("http://", "https://", "//")):
                r.imagens_remotas.append(html.unescape(src))
        for src in leitor.iframes:
            if src:
                r.links.append(_classificar_link(src, ""))
    if textos_planos:
        plano = _texto(textos_planos)
        r.texto_visivel = r.texto_visivel or plano
        vistos = {l.destino for l in r.links}
        for url in RE_URL.findall(plano):
            if url not in vistos:
                r.links.append(_classificar_link(url, ""))
                vistos.add(url)

    r.sinais = _sinais(r, leitor, duplicados)
    r.pontuacao, r.veredito = _veredito(r.sinais)
    r.tecnicas = _tecnicas(r.sinais, r.anexos)
    r.iocs = _iocs(r)
    return r
