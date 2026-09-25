"""
Leitura de dominio sem rede: de quem ele e, e com quem ele quer parecer.

Tudo aqui e calculo local. Serve a analise de e-mail (o dominio do
remetente, dos links, do Reply-To) e ao comando `dominio`, que acrescenta a
parte online - DNS, certificados, RDAP - so quando pedida.

O que se decide aqui:

  - Dominio registravel ("eTLD+1"): `login.conta-segura.com.br` pertence a
    `conta-segura.com.br`. E o que se compara entre From, Return-Path e
    links; comparar o nome inteiro acusaria divergencia entre
    `mail.empresa.com` e `empresa.com`, que sao do mesmo dono.
  - Imitacao de marca: o nome da marca dentro de um dominio que nao e dela
    (`microsoft-verificacao.com`), ou uma grafia quase igual (`paypa1.com`,
    `rnicrosoft.com`), ou letra de outro alfabeto (`аpple.com` com "а"
    cirilico, que chega como punycode `xn--`).
  - Webmail gratuito: empresa nao manda aviso de seguranca de um Gmail.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

# Sufixos de dois niveis mais comuns. Nao e a Public Suffix List inteira -
# ela tem ~9 mil entradas e muda toda semana -, mas cobre o que aparece em
# phishing contra usuario brasileiro e internacional. Um sufixo que faltar
# aqui so faz o dominio registravel sair um nivel mais curto.
SUFIXOS_DE_DOIS_NIVEIS = frozenset(
    """
    com.br net.br org.br gov.br edu.br art.br blog.br eco.br emp.br ind.br
    inf.br jus.br leg.br mil.br adv.br eng.br med.br tur.br srv.br app.br
    co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk
    com.au net.au org.au gov.au edu.au
    co.jp ne.jp or.jp ac.jp go.jp
    co.nz org.nz co.za org.za co.in net.in org.in gov.in
    com.ar com.mx com.co com.pe com.ve com.uy com.py com.bo com.ec
    com.cn net.cn org.cn gov.cn com.hk com.tw com.sg com.my
    com.tr com.ru com.ua com.pl co.kr or.kr co.id co.th
    com.pt
    """.split()
)

# Marca -> dominios oficiais. So remetentes de verdade: webmail gratuito
# fica de fora de proposito, mesmo o da propria Microsoft ou do Google - um
# aviso "da equipe Microsoft" vindo de um @outlook.com qualquer e golpe.
MARCAS: dict[str, frozenset[str]] = {
    "microsoft": frozenset({"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                            "sharepoint.com", "onmicrosoft.com", "azure.com", "windows.com",
                            "microsoft365.com", "live.com", "msn.com", "xbox.com", "skype.com"}),
    "outlook": frozenset({"microsoft.com", "office.com", "office365.com"}),
    "office": frozenset({"microsoft.com", "office.com", "office365.com"}),
    "apple": frozenset({"apple.com", "icloud.com", "itunes.com"}),
    "icloud": frozenset({"apple.com", "icloud.com"}),
    "google": frozenset({"google.com", "youtube.com", "accounts.google.com"}),
    "paypal": frozenset({"paypal.com", "paypal.com.br", "paypal-communications.com"}),
    "amazon": frozenset({"amazon.com", "amazon.com.br", "amazonses.com", "amazonaws.com", "aws.com"}),
    "netflix": frozenset({"netflix.com"}),
    "facebook": frozenset({"facebook.com", "facebookmail.com", "meta.com", "fb.com"}),
    "instagram": frozenset({"instagram.com", "facebookmail.com", "meta.com"}),
    "whatsapp": frozenset({"whatsapp.com", "whatsapp.net", "meta.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "dropbox": frozenset({"dropbox.com", "dropboxmail.com"}),
    "adobe": frozenset({"adobe.com", "adobesign.com"}),
    "dhl": frozenset({"dhl.com", "dhl.com.br", "dhl.de"}),
    "fedex": frozenset({"fedex.com"}),
    "correios": frozenset({"correios.com.br"}),
    "itau": frozenset({"itau.com.br", "itau.com"}),
    "bradesco": frozenset({"bradesco.com.br", "bradesco.com"}),
    "santander": frozenset({"santander.com.br", "santander.com"}),
    "nubank": frozenset({"nubank.com.br", "nu.com.br"}),
    "caixa": frozenset({"caixa.gov.br"}),
    "mercadolivre": frozenset({"mercadolivre.com.br", "mercadolibre.com"}),
    "receita": frozenset({"receita.fazenda.gov.br", "fazenda.gov.br", "gov.br"}),
    "serasa": frozenset({"serasa.com.br", "serasaexperian.com.br"}),
    "binance": frozenset({"binance.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "steam": frozenset({"steampowered.com", "steamcommunity.com"}),
}

# Como a marca aparece escrita num nome de exibicao ou assunto.
APELIDOS_DE_MARCA = {
    "mercado livre": "mercadolivre",
    "banco do brasil": "bb",
    "itaú": "itau",
    "receita federal": "receita",
}
MARCAS.setdefault("bb", frozenset({"bb.com.br"}))

WEBMAIL_GRATUITO = frozenset(
    """
    gmail.com googlemail.com outlook.com hotmail.com hotmail.com.br live.com
    msn.com yahoo.com yahoo.com.br ymail.com aol.com icloud.com me.com
    proton.me protonmail.com gmx.com gmx.net mail.com mail.ru yandex.ru
    yandex.com zoho.com tutanota.com uol.com.br bol.com.br terra.com.br
    ig.com.br
    """.split()
)

ENCURTADORES = frozenset(
    """
    bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly cutt.ly rebrand.ly
    shorturl.at tiny.cc rb.gy s.id t.ly lnkd.in bl.ink qrco.de encurtador.com.br
    """.split()
)

# Trocas visuais classicas de typosquatting. "rn" lido como "m" e o mais
# traicoeiro: em fonte pequena, rnicrosoft e microsoft sao o mesmo desenho.
_CONFUSIVEIS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"),
                ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"), ("@", "a"), ("$", "s")]

RE_ROTULO = re.compile(r"^[a-z0-9-]{1,63}$")


@dataclass
class ImitacaoDeMarca:
    marca: str
    como: str  # "contem", "grafia", "unicode"
    explicacao: str


def normalizar(dominio: str) -> str:
    """Minusculo, sem ponto final, com punycode decodificado para Unicode."""
    dominio = (dominio or "").strip().strip(".").lower()
    if "xn--" in dominio:
        try:
            dominio = dominio.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            pass
    return dominio


def e_ip(valor: str) -> bool:
    try:
        ipaddress.ip_address(valor.strip("[]"))
        return True
    except ValueError:
        return False


def ip_publico(valor: str) -> bool:
    try:
        return ipaddress.ip_address(valor.strip("[]")).is_global
    except ValueError:
        return False


def registravel(dominio: str) -> str:
    """`a.b.empresa.com.br` -> `empresa.com.br`. IP volta como veio."""
    dominio = normalizar(dominio)
    if not dominio or e_ip(dominio):
        return dominio
    partes = dominio.split(".")
    if len(partes) >= 3 and ".".join(partes[-2:]) in SUFIXOS_DE_DOIS_NIVEIS:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])


def mesmo_dono(a: str, b: str) -> bool:
    return bool(a) and bool(b) and registravel(a) == registravel(b)


def e_webmail(dominio: str) -> bool:
    return registravel(dominio) in WEBMAIL_GRATUITO or normalizar(dominio) in WEBMAIL_GRATUITO


def e_encurtador(dominio: str) -> bool:
    return normalizar(dominio) in ENCURTADORES or registravel(dominio) in ENCURTADORES


def oficial_da_marca(dominio: str, marca: str) -> bool:
    oficiais = MARCAS.get(marca, frozenset())
    d = normalizar(dominio)
    return registravel(d) in oficiais or d in oficiais


def _sem_confusiveis(texto: str) -> str:
    for de, para in _CONFUSIVEIS:
        texto = texto.replace(de, para)
    return texto


def _distancia(a: str, b: str) -> int:
    """Levenshtein. Os rotulos sao curtos; o quadratico nao pesa."""
    if a == b:
        return 0
    anterior = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        atual = [i]
        for j, cb in enumerate(b, 1):
            atual.append(min(anterior[j] + 1, atual[j - 1] + 1, anterior[j - 1] + (ca != cb)))
        anterior = atual
    return anterior[-1]


def _alfabetos(texto: str) -> set[str]:
    nomes = set()
    for c in texto:
        if c.isalpha():
            nomes.add(unicodedata.name(c, "?").split(" ")[0])
    return nomes


def marcas_no_texto(texto: str) -> list[str]:
    """Marcas citadas num nome de exibicao ou assunto ("Microsoft account team")."""
    t = (texto or "").lower()
    achadas = []
    for apelido, marca in APELIDOS_DE_MARCA.items():
        if apelido in t and marca not in achadas:
            achadas.append(marca)
    for marca in MARCAS:
        if len(marca) >= 4 and re.search(rf"(?<![a-z]){re.escape(marca)}(?![a-z])", t) and marca not in achadas:
            achadas.append(marca)
    return achadas


def imitacao_de_marca(dominio: str) -> ImitacaoDeMarca | None:
    """
    O dominio tenta se passar por uma marca que nao e dele?

    Tres jeitos, do mais obvio ao mais sutil:
      - contem o nome da marca (`microsoft-suporte.com`, `itau.conta-segura.net`)
      - grafia a 1-2 letras de distancia, ou igual depois de desfazer as
        trocas visuais (`paypa1`, `rnicrosoft`, `arnazon`)
      - letras de alfabetos misturados (latino com cirilico, por exemplo)
    """
    original = normalizar(dominio)
    if not original or e_ip(original):
        return None
    base = registravel(original)
    rotulo = base.split(".")[0]

    alfabetos = _alfabetos(original)
    if len(alfabetos - {"DIGIT"}) > 1:
        return ImitacaoDeMarca("", "unicode", f"mistura letras de alfabetos diferentes ({', '.join(sorted(alfabetos))})")

    for marca in MARCAS:
        if oficial_da_marca(original, marca):
            return None

    for marca in MARCAS:
        if len(marca) < 4:
            continue
        if marca in original.replace("-", "").replace(".", ""):
            return ImitacaoDeMarca(marca, "contem", f"usa o nome “{marca}” num domínio que não é da marca")

    limpo = _sem_confusiveis(rotulo)
    for marca in MARCAS:
        if len(marca) < 5:
            continue
        if limpo == marca and rotulo != marca:
            return ImitacaoDeMarca(marca, "grafia", f"“{rotulo}” se lê como “{marca}” trocando letras parecidas")
        limite = 1 if len(marca) < 7 else 2
        if 0 < _distancia(rotulo, marca) <= limite:
            return ImitacaoDeMarca(marca, "grafia", f"“{rotulo}” está a {_distancia(rotulo, marca)} letra(s) de “{marca}”")
    return None


def defang(valor: str) -> str:
    """`https://mau.com/x` -> `hxxps://mau[.]com/x`: copiavel sem virar link."""
    valor = re.sub(r"^http", "hxxp", valor, flags=re.IGNORECASE)
    return valor.replace(".", "[.]").replace("@", "[@]")
