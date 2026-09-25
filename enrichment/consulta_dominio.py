"""
Consulta de dominio na internet: DNS, idade, certificados e subdominios.

So roda quando pedida (`--online`), como o resto do enriquecimento. E tudo
PASSIVO - nenhuma requisicao chega ao servidor do dominio investigado:

  - DNS por DNS-over-HTTPS (Cloudflare). Perguntar ao resolvedor e o mesmo
    que o cliente de e-mail da vitima faz; o dono do dominio nao ve quem
    perguntou. Sem dependencia nova: e uma requisicao HTTPS com JSON.
  - Idade e registrador pelo RDAP (rdap.org encaminha ao registro certo).
    Dominio de phishing costuma ter dias de vida.
  - Certificados e subdominios pelos logs de Certificate Transparency
    (crt.sh e Cert Spotter). Todo certificado HTTPS emitido e publico: os
    nomes dentro dele revelam os subdominios e, quando ha outro dominio no
    mesmo certificado, a infraestrutura irma. Nada de conectar no servidor
    para ler o certificado - isso avisaria o atacante - e nada de forca
    bruta de subdominio, que seria reconhecimento ativo.

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
LIMITE_DE_CERTIFICADOS = 200
# Emissores gratuitos e automaticos (ACME).
EMISSORES_GRATUITOS = ("let's encrypt", "zerossl", "google trust", "buypass", "ssl.com", "cloudflare")
# Certificados compartilhados por CDN, que juntam dominios de donos
# diferentes: o nome deles no certificado nao liga os dominios entre si.
NOMES_DE_CERTIFICADO_COMPARTILHADO = ("cloudflaressl.com", "sni.cloudflaressl.com", "incapsula.com", "akamaized.net")
AGENTE = {"User-Agent": "NutShellMapper/1.0"}

TIPOS_DNS = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5}


@dataclass
class Certificado:
    id: str
    emissor: str
    emitido_em: str
    expira_em: str
    nomes: list[str] = field(default_factory=list)
    revogado: bool = False
    fonte: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


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
    certificados: list[dict] = field(default_factory=list)
    certificados_truncados: bool = False
    primeiro_certificado: str = ""
    # False quando so o Cert Spotter respondeu: ai a lista tem apenas os
    # certificados vigentes, e o "primeiro" e so o mais antigo ainda valido.
    historico_completo: bool = False
    emissores: dict[str, int] = field(default_factory=dict)
    dominios_irmaos: list[str] = field(default_factory=list)
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


def _data(valor: str) -> str:
    """Datas do crt.sh vem sem fuso ('2023-07-01T00:00:00'); as do Cert Spotter, com Z."""
    valor = str(valor or "").strip()
    if not valor:
        return ""
    return valor if valor.endswith("Z") or "+" in valor[10:] else valor + "Z"


def _emissor_legivel(bruto: str) -> str:
    """'C=US, O=Let's Encrypt, CN=R3' -> "Let's Encrypt"."""
    for parte in str(bruto or "").split(","):
        chave, _, valor = parte.strip().partition("=")
        if chave.strip().upper() == "O" and valor:
            return valor.strip()
    return str(bruto or "").strip()


def _certificados_crtsh(sessao: requests.Session, dominio: str) -> tuple[list[Certificado], str]:
    # O crt.sh vive sobrecarregado e devolve 502/503 com frequencia; uma
    # segunda tentativa as vezes passa.
    for tentativa in range(TENTATIVAS_CRTSH):
        dados, erro = _get(sessao, CRTSH, TIMEOUT_CRTSH, params={"q": f"%.{dominio}", "output": "json"}, headers=AGENTE)
        if dados is not None or not erro.startswith(("HTTP 5", "falha de rede")):
            break
        time.sleep(ESPERA_CRTSH * (tentativa + 1))
    if dados is None:
        return [], erro
    saida = []
    for c in dados:
        saida.append(Certificado(
            id=f"crt.sh:{c.get('id', '')}",
            emissor=_emissor_legivel(c.get("issuer_name", "")),
            emitido_em=_data(c.get("not_before", "")),
            expira_em=_data(c.get("not_after", "")),
            nomes=sorted({n.strip().lower() for n in str(c.get("name_value", "")).splitlines() if n.strip()}),
            fonte="crt.sh",
        ))
    return saida, ""


def _certificados_certspotter(sessao: requests.Session, dominio: str) -> tuple[list[Certificado], str]:
    saida: list[Certificado] = []
    depois = None
    for _pagina in range(PAGINAS_CERTSPOTTER):
        parametros = [("domain", dominio), ("include_subdomains", "true"),
                      ("expand", "dns_names"), ("expand", "issuer"), ("expand", "revocation")]
        if depois:
            parametros.append(("after", depois))
        dados, erro = _get(sessao, CERTSPOTTER, TIMEOUT, params=parametros, headers=AGENTE)
        if dados is None:
            return saida, erro if not saida else ""
        if not dados:
            break
        for c in dados:
            emissor = c.get("issuer") or {}
            saida.append(Certificado(
                id=f"certspotter:{c.get('cert_sha256') or c.get('id', '')}",
                emissor=emissor.get("friendly_name") or _emissor_legivel(emissor.get("name", "")),
                emitido_em=_data(c.get("not_before", "")),
                expira_em=_data(c.get("not_after", "")),
                nomes=sorted({str(n).strip().lower() for n in c.get("dns_names") or []}),
                revogado=bool(c.get("revoked")),
                fonte="Cert Spotter",
            ))
        depois = dados[-1].get("id")
    return saida, ""


def consultar_certificados(sessao: requests.Session, dominio: str) -> tuple[list[Certificado], str]:
    """
    Certificados emitidos para o dominio, pelos logs de Certificate
    Transparency.

    Duas fontes, porque o crt.sh cai com frequencia: ele tem o historico
    inteiro (inclusive certificado vencido); o Cert Spotter responde melhor,
    mas so traz os ainda validos. Se as duas responderem, a uniao - o mesmo
    certificado visto pelas duas conta uma vez.
    """
    todos, erro_crt = _certificados_crtsh(sessao, dominio)
    extra, erro_cs = _certificados_certspotter(sessao, dominio)
    if not todos and not extra and erro_crt and erro_cs:
        return [], f"crt.sh ({erro_crt}) e Cert Spotter ({erro_cs}) falharam"
    vistos: set[tuple] = set()
    unicos: list[Certificado] = []
    for c in todos + extra:
        chave = (c.emitido_em[:10], tuple(c.nomes))
        if chave in vistos:
            continue
        vistos.add(chave)
        unicos.append(c)
    unicos.sort(key=lambda c: c.emitido_em, reverse=True)
    return unicos, ""


def consultar_subdominios(sessao: requests.Session, dominio: str) -> tuple[list[str], str]:
    certificados, erro = consultar_certificados(sessao, dominio)
    return sorted(_nomes_validos((n for c in certificados for n in c.nomes), dominio)), erro


def analisar_certificados(c: "ConsultaDominio", certificados: list[Certificado]) -> None:
    """
    O que os certificados dizem sobre a infraestrutura.

      - Quando o primeiro certificado saiu: domino de campanha costuma
        ganhar HTTPS dias antes do disparo.
      - Emissor gratuito e automatico: nao e prova de nada (metade da web
        usa Let's Encrypt), mas e o unico que o atacante usa.
      - Outros dominios no MESMO certificado: quem pos os dois nomes juntos
        controla os dois. E o pivo mais valioso daqui - revela a
        infraestrutura irma da campanha.
    """
    c.certificados = [x.to_dict() for x in certificados[:LIMITE_DE_CERTIFICADOS]]
    c.certificados_truncados = len(certificados) > LIMITE_DE_CERTIFICADOS
    if not certificados:
        return
    agora = datetime.now(timezone.utc)

    c.historico_completo = any(x.fonte == "crt.sh" for x in certificados)
    datas = [x.emitido_em for x in certificados if x.emitido_em]
    if datas:
        c.primeiro_certificado = min(datas)
        try:
            dias = (agora - datetime.fromisoformat(c.primeiro_certificado.replace("Z", "+00:00"))).days
            if dias < 30 and c.historico_completo:
                c.observacoes.append(f"primeiro certificado HTTPS emitido há {dias} dia(s): infraestrutura nova")
            elif dias < 30:
                c.observacoes.append(
                    f"o certificado vigente mais antigo tem {dias} dia(s) (sem o histórico do crt.sh, "
                    "não dá para dizer se é o primeiro)"
                )
        except ValueError:
            pass

    emissores: dict[str, int] = {}
    for x in certificados:
        emissores[x.emissor] = emissores.get(x.emissor, 0) + 1
    c.emissores = dict(sorted(emissores.items(), key=lambda kv: -kv[1]))
    if emissores and all(any(g in e.lower() for g in EMISSORES_GRATUITOS) for e in emissores):
        c.observacoes.append("só certificados gratuitos e automáticos (comum, mas é o único tipo que golpe usa)")

    irmaos: set[str] = set()
    for x in certificados:
        for nome in x.nomes:
            base = dominios.registravel(nome.lstrip("*."))
            if base and base != c.registravel and not any(base.endswith(s) for s in NOMES_DE_CERTIFICADO_COMPARTILHADO):
                irmaos.add(base)
    c.dominios_irmaos = sorted(irmaos)[:50]
    if c.dominios_irmaos:
        c.observacoes.append(
            f"{len(irmaos)} outro(s) domínio(s) no mesmo certificado: quem os pôs juntos controla os dois "
            f"({', '.join(c.dominios_irmaos[:4])}{'…' if len(irmaos) > 4 else ''})"
        )

    revogados = sum(1 for x in certificados if x.revogado)
    if revogados:
        c.observacoes.append(f"{revogados} certificado(s) revogado(s): a autoridade pode ter reagido a denúncia")

    validos = [x for x in certificados if x.expira_em and x.expira_em > agora.isoformat()[:19]]
    if not validos:
        c.observacoes.append("nenhum certificado válido hoje: o site não serve HTTPS confiável")


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
            lista, erro = consultar_certificados(sessao, c.registravel)
            if erro:
                c.erros.append(f"certificados: {erro}")
            analisar_certificados(c, lista)
            subs = sorted(_nomes_validos((n for x in lista for n in x.nomes), c.registravel))
            c.subdominios_truncados = len(subs) > LIMITE_DE_SUBDOMINIOS
            c.subdominios = subs[:LIMITE_DE_SUBDOMINIOS]
            suspeitos = [s for s in c.subdominios if dominios.imitacao_de_marca(s.split(".")[0] + ".x")]
            if suspeitos:
                c.observacoes.append(f"subdomínios com nome de marca: {', '.join(suspeitos[:5])}")
    return c
