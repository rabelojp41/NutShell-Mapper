"""
AbuseIPDB: reputacao de IP por relatos da comunidade.

Administradores de rede reportam IPs que atacaram seus servidores (spam,
phishing, forca bruta, varredura). A consulta devolve a pontuacao de
confianca de abuso (0-100), quantos relatos, de quantas pessoas, em quais
categorias - e, mesmo sem relato nenhum, o contexto do IP: provedor, pais e
tipo de uso. "Data center" como origem de um e-mail que diz vir de um banco
ja e informacao.

So IP. O plano gratuito da 1000 consultas por dia.
"""

from __future__ import annotations

import logging
from collections import Counter

from core import dominios
from enrichment.base import ClienteBase
from enrichment.reputacao import Reputacao, falha

logger = logging.getLogger(__name__)

URL_BASE = "https://api.abuseipdb.com/api/v2"
JANELA_EM_DIAS = 365

CATEGORIAS = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}

TIPOS_DE_USO = {
    "Data Center/Web Hosting/Transit": "data center / hospedagem",
    "Fixed Line ISP": "provedor residencial",
    "Mobile ISP": "provedor móvel",
    "Commercial": "empresa",
    "Content Delivery Network": "CDN",
    "University/College/School": "instituição de ensino",
    "Government": "governo",
    "Military": "militar",
    "Library": "biblioteca",
    "Organization": "organização",
    "Reserved": "reservado",
    "Search Engine Spider": "robô de buscador",
}


class AbuseIPDBClient(ClienteBase):
    nome = "AbuseIPDB"
    url_base = URL_BASE

    def __init__(self, api_key: str, timeout: int = 30):
        super().__init__(api_key, timeout=timeout, rate_limit_por_minuto=60)
        if api_key:
            self.sessao.headers.update({"Key": api_key, "Accept": "application/json"})

    def consultar(self, ip: str) -> Reputacao:
        if not dominios.e_ip(ip):
            return falha(self.nome, ip, "ip", "o AbuseIPDB só consulta IP")
        if not dominios.ip_publico(ip):
            return Reputacao(self.nome, ip, "ip", "sem_registro", resumo="IP privado ou reservado: não há reputação pública")
        resposta = self._requisitar("/check", parametros={"ipAddress": ip, "maxAgeInDays": JANELA_EM_DIAS, "verbose": ""})
        if resposta.erro:
            return falha(self.nome, ip, "ip", resposta.erro)
        d = resposta.dados.get("data") or {}
        if not d:
            return falha(self.nome, ip, "ip", "resposta sem dados")

        pontuacao = int(d.get("abuseConfidenceScore") or 0)
        relatos = int(d.get("totalReports") or 0)
        pessoas = int(d.get("numDistinctUsers") or 0)
        uso = TIPOS_DE_USO.get(d.get("usageType") or "", d.get("usageType") or "uso desconhecido")
        contexto = f"{uso}, {d.get('countryName') or d.get('countryCode') or 'país desconhecido'} ({d.get('isp') or 'provedor desconhecido'})"
        if d.get("isTor"):
            contexto += ", nó de saída Tor"

        categorias = Counter(
            CATEGORIAS.get(c, f"categoria {c}") for r in d.get("reports") or [] for c in r.get("categories") or []
        )
        principais = [nome for nome, _ in categorias.most_common(5)]

        # A pontuacao, e nao a contagem bruta de relatos, decide: o proprio
        # AbuseIPDB zera a confianca de relatos que ele considera ruido - o
        # 8.8.8.8 tem centenas de relatos e pontuacao 0.
        permitido = bool(d.get("isWhitelisted"))
        if permitido:
            veredito = "sem_registro"
            contexto += ", na lista de permissões do AbuseIPDB (serviço conhecido)"
        elif pontuacao >= 75:
            veredito = "malicioso"
        elif pontuacao >= 10:
            veredito = "suspeito"
        else:
            veredito = "sem_registro"

        if relatos:
            resumo = (f"confiança de abuso {pontuacao}% · {relatos} relato(s) de {pessoas} pessoa(s) em {JANELA_EM_DIAS} dias"
                      f"{' · ' + ', '.join(principais[:3]) if principais else ''} · {contexto}")
        else:
            ultimo = (d.get("lastReportedAt") or "")[:10]
            resumo = f"nenhum relato em {JANELA_EM_DIAS} dias{f' (último em {ultimo})' if ultimo else ''} · {contexto}"

        return Reputacao(
            self.nome, ip, "ip", veredito, resumo=resumo, tags=principais,
            detalhes={"pontuacao": pontuacao, "relatos": relatos, "pessoas": pessoas, "pais": d.get("countryCode"),
                      "provedor": d.get("isp"), "dominio_do_provedor": d.get("domain"), "uso": d.get("usageType"),
                      "tor": bool(d.get("isTor")), "ultimo_relato": d.get("lastReportedAt"), "permitido": permitido,
                      "hostnames": d.get("hostnames") or [], "categorias": dict(categorias)},
            referencia=f"https://www.abuseipdb.com/check/{ip}",
        )


def criar(config=None) -> AbuseIPDBClient | None:
    from config.settings import CONFIG

    cfg = config or CONFIG
    if not cfg.enable_enrichment or not cfg.abuseipdb_api_key:
        return None
    return AbuseIPDBClient(cfg.abuseipdb_api_key, timeout=cfg.http_timeout)
