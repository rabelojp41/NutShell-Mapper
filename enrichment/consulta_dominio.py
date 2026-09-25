"""
Consulta de dominio na internet: DNS, idade e subdominios.

So roda quando pedida (`--online`), como o resto do enriquecimento. E tudo
PASSIVO - nenhuma requisicao chega ao servidor do dominio investigado:

  - DNS por DNS-over-HTTPS (Cloudflare). Perguntar ao resolvedor e o mesmo
    que o cliente de e-mail da vitima faz; o dono do dominio nao ve quem
    perguntou. Sem dependencia nova: e uma requisicao HTTPS com JSON.
  - Idade e registrador pelo RDAP (rdap.org encaminha ao registro certo).
    Dominio de phishing costuma ter dias de vida.
  - Subdominios pelos logs de Certificate Transparency (crt.sh e Cert
    Spotter). Todo
    certificado HTTPS emitido e publico; os nomes dentro dele revelam os
    subdominios que o dono ja pos no ar. Nada de forca bruta: enumerar
    nomes batendo no DNS do alvo seria reconhecimento ativo.

O que sai daqui vai para terceiros (Cloudflare, rdap.org, crt.sh, Cert Spotter): o nome
do dominio. Nunca o e-mail, nunca o conteudo.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import requests

from core import dominios

logger = logging.getLogger(__name__)

DOH = "https://cloudflare-dns.com/dns-query"
RDAP = "https://rdap.org/domain/{}"
CRTSH = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
PAGINAS_CERTSPOTTER = 5
TIMEOUT = 20
TIMEOUT_CRTSH = 45
TENTATIVAS_CRTSH = 2
ESPERA_CRTSH = 4
LIMITE_DE_SUBDOMINIOS = 500
AGENTE = {"User-Agent": "NutShellMapper/1.0"}

TIPOS_DNS = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5}


@dataclass
class ConsultaDominio:
    dominio: str
    registravel: str
    dns: dict[str, list[str]] = field(default_factory=dict)
    spf: str = ""
    dmarc: str = ""
    criado_em: str = ""
    idade_dias: int | None = None
    registrador: str = ""
    subdominios: list[str] = field(default_factory=list)
    subdominios_truncados: bool = False
    imitacao: str = ""
    observacoes: list[str] = field(default_factory=list)
    erros: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _get(sessao: requests.Session, url: str, timeout: int, **kwargs):
    try:
        resposta = sessao.get(url, timeout=timeout, **kwargs)
    except requests.RequestException as erro:
        return None, f"falha de rede: {type(erro).__name__}"
    if resposta.status_code == 404:
        return None, "não encontrado (404)"
    if not resposta.ok:
        return None, f"HTTP {resposta.status_code}"
    try:
        return resposta.json(), ""
    except ValueError:
        return None, "resposta não é JSON"


def consultar_dns(sessao: requests.Session, nome: str, tipo: str) -> tuple[list[str], str]:
    dados, erro = _get(sessao, DOH, TIMEOUT, params={"name": nome, "type": tipo},
                       headers={"accept": "application/dns-json", **AGENTE})
    if dados is None:
        return [], erro
    numero = TIPOS_DNS[tipo]
    valores = []
    for resposta in dados.get("Answer") or []:
        if resposta.get("type") == numero:
            valores.append(str(resposta.get("data", "")).strip().strip('"').replace('" "', ""))
    return valores, ""


def consultar_rdap(sessao: requests.Session, dominio: str) -> tuple[dict, str]:
    dados, erro = _get(sessao, RDAP.format(dominio), TIMEOUT, headers=AGENTE)
    if dados is None:
        return {}, erro
    saida: dict = {}
    for evento in dados.get("events") or []:
        if evento.get("eventAction") == "registration":
            saida["criado_em"] = evento.get("eventDate", "")
    for entidade in dados.get("entities") or []:
        if "registrar" in (entidade.get("roles") or []):
            for item in (entidade.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    saida["registrador"] = str(item[3])
    return saida, ""


def _nomes_validos(nomes, dominio: str) -> set[str]:
    saida = set()
    for nome in nomes:
        nome = str(nome).strip().lower().lstrip("*.")
        if nome and (nome == dominio or nome.endswith("." + dominio)) and "@" not in nome:
            saida.add(nome)
    return saida


def _subdominios_crtsh(sessao: requests.Session, dominio: str) -> tuple[set[str], str]:
    # O crt.sh vive sobrecarregado e devolve 502/503 com frequencia; uma
    # segunda tentativa as vezes passa.
    for tentativa in range(TENTATIVAS_CRTSH):
        dados, erro = _get(sessao, CRTSH, TIMEOUT_CRTSH, params={"q": f"%.{dominio}", "output": "json"}, headers=AGENTE)
        if dados is not None or not erro.startswith(("HTTP 5", "falha de rede")):
            break
        time.sleep(ESPERA_CRTSH * (tentativa + 1))
    if dados is None:
        return set(), erro
    return _nomes_validos(
        (n for c in dados for n in str(c.get("name_value", "")).splitlines()), dominio
    ), ""


def _subdominios_certspotter(sessao: requests.Session, dominio: str) -> tuple[set[str], str]:
    nomes: set[str] = set()
    depois = None
    for _pagina in range(PAGINAS_CERTSPOTTER):
        parametros = {"domain": dominio, "include_subdomains": "true", "expand": "dns_names"}
        if depois:
            parametros["after"] = depois
        dados, erro = _get(sessao, CERTSPOTTER, TIMEOUT, params=parametros, headers=AGENTE)
        if dados is None:
            return nomes, erro if not nomes else ""
        if not dados:
            break
        nomes |= _nomes_validos((n for c in dados for n in c.get("dns_names") or []), dominio)
        depois = dados[-1].get("id")
    return nomes, ""


def consultar_subdominios(sessao: requests.Session, dominio: str) -> tuple[list[str], str]:
    """
    Subdominios pelos logs de Certificate Transparency.

    Duas fontes, porque o crt.sh cai com frequencia: ele tem o historico
    inteiro (inclusive certificado vencido); o Cert Spotter responde
    melhor. Se as duas responderem, a uniao.
    """
    nomes, erro_crt = _subdominios_crtsh(sessao, dominio)
    extra, erro_cs = _subdominios_certspotter(sessao, dominio)
    nomes |= extra
    if not nomes and erro_crt and erro_cs:
        return [], f"crt.sh ({erro_crt}) e Cert Spotter ({erro_cs}) falharam"
    return sorted(nomes), ""


def consultar_dominio(dominio: str, certificados: bool = True) -> ConsultaDominio:
    """Tudo que da para saber de um dominio sem tocar o servidor dele."""
    nome = dominios.normalizar(dominio)
    if not nome or dominios.e_ip(nome) or "." not in nome:
        raise ValueError(f"domínio inválido: {dominio!r}")
    c = ConsultaDominio(dominio=nome, registravel=dominios.registravel(nome))

    imit = dominios.imitacao_de_marca(nome)
    if imit:
        c.imitacao = imit.explicacao
    if dominios.e_webmail(nome):
        c.observacoes.append("webmail gratuito: qualquer pessoa cria um endereço aqui")

    with requests.Session() as sessao:
        for tipo in ("A", "AAAA", "MX", "NS", "TXT"):
            valores, erro = consultar_dns(sessao, nome if tipo != "NS" else c.registravel, tipo)
            if erro and erro != "não encontrado (404)":
                c.erros.append(f"DNS {tipo}: {erro}")
            c.dns[tipo] = valores
        c.spf = next((t for t in c.dns.get("TXT", []) if t.lower().startswith("v=spf1")), "")
        dmarc, erro = consultar_dns(sessao, f"_dmarc.{c.registravel}", "TXT")
        c.dmarc = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), "")

        if not c.dns.get("MX") and c.dns.get("NS"):
            c.observacoes.append("sem MX: o domínio não recebe e-mail (resposta a ele se perde)")
        if not c.spf:
            c.observacoes.append("sem SPF: qualquer servidor pode enviar em nome dele")
        if not c.dmarc:
            c.observacoes.append("sem DMARC: não há política para e-mail falsificado")
        elif "p=none" in c.dmarc.replace(" ", "").lower():
            c.observacoes.append("DMARC em p=none: só monitora, não bloqueia falsificação")

        rdap, erro = consultar_rdap(sessao, c.registravel)
        sem_dns = not any(c.dns.get(t) for t in ("A", "AAAA", "MX", "NS"))
        if erro == "não encontrado (404)" and sem_dns:
            # Sem registro e sem DNS: o dominio nao existe mais. Comum em
            # phishing antigo - foi derrubado ou deixado expirar.
            c.observacoes.insert(0, "o domínio não existe mais (sem registro e sem DNS): foi derrubado ou expirou")
        elif erro == "não encontrado (404)":
            c.erros.append(f"RDAP: o registro de .{c.registravel.split('.')[-1]} não publica RDAP")
        elif erro:
            c.erros.append(f"RDAP: {erro}")
        c.registrador = rdap.get("registrador", "")
        c.criado_em = rdap.get("criado_em", "")
        if c.criado_em:
            try:
                criado = datetime.fromisoformat(c.criado_em.replace("Z", "+00:00"))
                c.idade_dias = (datetime.now(timezone.utc) - criado).days
                if c.idade_dias < 30:
                    c.observacoes.append(f"domínio registrado há {c.idade_dias} dia(s)")
                elif c.idade_dias < 180:
                    c.observacoes.append(f"domínio recente: {c.idade_dias} dias")
            except ValueError:
                pass

        if certificados:
            subs, erro = consultar_subdominios(sessao, c.registravel)
            if erro:
                c.erros.append(f"certificados: {erro}")
            c.subdominios_truncados = len(subs) > LIMITE_DE_SUBDOMINIOS
            c.subdominios = subs[:LIMITE_DE_SUBDOMINIOS]
            suspeitos = [s for s in c.subdominios if dominios.imitacao_de_marca(s.split(".")[0] + ".x")]
            if suspeitos:
                c.observacoes.append(f"subdomínios com nome de marca: {', '.join(suspeitos[:5])}")
    return c
