"""
Censys: o que um IP expoe na internet.

O Censys varre a internet inteira, o tempo todo, e guarda o que cada IP
responde: portas abertas, protocolo, software, certificado TLS, DNS reverso,
sistema autonomo. Para CTI, isso diz o que o servidor do atacante E - um
painel de C2 conhecido, um servidor de e-mail montado para disparo, um proxy
- e permite pivotar pelo certificado ou pelo software.

Nada toca o alvo: consulta-se o que o Censys ja coletou.

Do WHOIS so sai o nome da organizacao e o contato de ABUSO, que e um
endereco de funcao feito para denuncia e pedido de derrubada. Contato
administrativo (nome e e-mail de funcionario do provedor) fica de fora: e
dado pessoal e nao ajuda a investigacao.

Autentica com o Personal Access Token da plataforma nova do Censys.
"""

from __future__ import annotations

import logging

from core import dominios
from enrichment.base import ClienteBase
from enrichment.reputacao import Reputacao, falha

logger = logging.getLogger(__name__)

URL_BASE = "https://api.platform.censys.io/v3/global/asset"


class CensysClient(ClienteBase):
    nome = "Censys"
    url_base = URL_BASE

    def __init__(self, token: str, timeout: int = 40):
        super().__init__(token, timeout=timeout, rate_limit_por_minuto=30)
        if token:
            self.sessao.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})

    def consultar(self, ip: str) -> Reputacao:
        if not dominios.e_ip(ip):
            return falha(self.nome, ip, "ip", "o Censys só é consultado por IP aqui")
        if not dominios.ip_publico(ip):
            return Reputacao(self.nome, ip, "ip", "sem_registro", resumo="IP privado ou reservado")
        resposta = self._requisitar(f"/host/{ip}")
        if resposta.erro:
            return falha(self.nome, ip, "ip", resposta.erro)
        referencia = f"https://platform.censys.io/hosts/{ip}"
        d = ((resposta.dados or {}).get("result") or {}).get("resource") or {}
        if not resposta.encontrado or not d:
            return Reputacao(self.nome, ip, "ip", "sem_registro", resumo="o Censys não tem dados deste IP", referencia=referencia)

        local = d.get("location") or {}
        sa = d.get("autonomous_system") or {}
        whois = d.get("whois") or {}
        organizacao = (whois.get("organization") or {}).get("name") or (whois.get("network") or {}).get("name") or ""
        abuso = sorted({c.get("email") for c in (whois.get("organization") or {}).get("abuse_contacts") or [] if c.get("email")})
        rdns = ((d.get("dns") or {}).get("reverse_dns") or {}).get("names") or (d.get("dns") or {}).get("names") or []

        servicos = []
        ameacas = []
        rotulos = set()
        for s in d.get("services") or []:
            software = [x.get("product") for x in s.get("software") or [] if x.get("product")]
            etiquetas = [x.get("value") for x in s.get("labels") or [] if x.get("value")]
            rotulos.update(etiquetas)
            for t in s.get("threats") or []:
                nome = t.get("name") if isinstance(t, dict) else str(t)
                if nome:
                    ameacas.append(nome)
            servicos.append({
                "porta": s.get("port"), "protocolo": s.get("protocol"), "transporte": s.get("transport_protocol"),
                "software": software, "rotulos": etiquetas, "visto_em": s.get("scan_time"),
                "certificado_sha256": (s.get("cert") or {}).get("fingerprint_sha256", ""),
            })

        partes = []
        if servicos:
            partes.append(f"{len(servicos)} serviço(s) exposto(s): " + ", ".join(
                f"{x['porta']}/{x['protocolo']}" + (f" ({', '.join(x['software'][:2])})" if x["software"] else "") for x in servicos[:5]))
        else:
            partes.append("nenhum serviço exposto hoje")
        if sa.get("asn"):
            partes.append(f"AS{sa['asn']} {sa.get('name') or ''}".strip())
        elif organizacao:
            partes.append(organizacao)
        lugar = ", ".join(x for x in (local.get("city"), local.get("country_code")) if x)
        if lugar:
            partes.append(lugar)
        if rdns:
            partes.append(f"DNS reverso {rdns[0]}")
        if ameacas:
            partes.append("ameaça identificada: " + ", ".join(sorted(set(ameacas))[:3]))

        return Reputacao(
            self.nome, ip, "ip", "malicioso" if ameacas else "contexto", resumo=" · ".join(partes),
            tags=sorted(rotulos)[:8] + sorted(set(ameacas))[:4],
            detalhes={"servicos": servicos[:20], "asn": sa.get("asn"), "sistema_autonomo": sa.get("name"),
                      "prefixo": sa.get("bgp_prefix"), "organizacao": organizacao, "contato_de_abuso": abuso,
                      "pais": local.get("country_code"), "cidade": local.get("city"), "dns_reverso": rdns[:5],
                      "ameacas": sorted(set(ameacas)),
                      "certificados": sorted({x["certificado_sha256"] for x in servicos if x["certificado_sha256"]})},
            referencia=referencia,
        )


def criar(config=None) -> CensysClient | None:
    from config.settings import CONFIG

    cfg = config or CONFIG
    if not cfg.enable_enrichment or not cfg.censys_api_token:
        return None
    return CensysClient(cfg.censys_api_token, timeout=max(cfg.http_timeout, 40))
