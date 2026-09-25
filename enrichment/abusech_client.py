"""
URLhaus e ThreatFox (abuse.ch).

Duas bases comunitarias, mantidas pelo mesmo projeto do MalwareBazaar e
com a mesma Auth-Key:

  - URLhaus: URLs e hosts usados para DISTRIBUIR malware. Diz se um dominio
    ou IP ja serviu payload, quantas URLs, se ainda estao no ar e com quais
    familias (tags).
  - ThreatFox: IOCs de todo tipo (C2, entrega de payload, botnet), com a
    familia do malware, o tipo de ameaca e o grau de confianca de quem
    reportou.

O que sai daqui: o indicador consultado (IP, dominio, URL, hash). Nada do
e-mail nem do artefato.
"""

from __future__ import annotations

import logging

from core import dominios
from enrichment.base import ClienteBase
from enrichment.reputacao import Reputacao, falha

logger = logging.getLogger(__name__)

URL_URLHAUS = "https://urlhaus-api.abuse.ch/v1"
URL_THREATFOX = "https://threatfox-api.abuse.ch/api/v1"


def _tipo(valor: str) -> str:
    if valor.lower().startswith(("http://", "https://")):
        return "url"
    if dominios.e_ip(valor):
        return "ip"
    if len(valor) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in valor):
        return "hash"
    return "dominio"


class URLhausClient(ClienteBase):
    nome = "URLhaus"
    url_base = URL_URLHAUS

    def __init__(self, api_key: str, timeout: int = 30):
        super().__init__(api_key, timeout=timeout, rate_limit_por_minuto=60)
        if api_key:
            self.sessao.headers["Auth-Key"] = api_key

    def consultar(self, valor: str) -> Reputacao:
        """Host (dominio ou IP) ou URL completa."""
        tipo = _tipo(valor)
        if tipo == "url":
            resposta = self._requisitar("/url/", metodo="POST", formulario={"url": valor})
        else:
            resposta = self._requisitar("/host/", metodo="POST", formulario={"host": valor})
        if resposta.erro:
            return falha(self.nome, valor, tipo, resposta.erro)
        d = resposta.dados
        if d.get("query_status") != "ok":
            return Reputacao(self.nome, valor, tipo, "sem_registro",
                             resumo="nenhuma URL de distribuição de malware registrada")

        if tipo == "url":
            no_ar = d.get("url_status") == "online"
            return Reputacao(
                self.nome, valor, tipo, "malicioso",
                resumo=f"URL de {d.get('threat', 'malware')}, {'no ar' if no_ar else 'fora do ar'}, registrada em {d.get('date_added', '?')}",
                tags=sorted(set(d.get("tags") or [])),
                detalhes={"status": d.get("url_status"), "ameaca": d.get("threat"), "registrada_em": d.get("date_added"),
                          "payloads": len(d.get("payloads") or []), "blacklists": d.get("blacklists")},
                referencia=d.get("urlhaus_reference", ""),
            )

        urls = d.get("urls") or []
        no_ar = sum(1 for u in urls if u.get("url_status") == "online")
        tags = sorted({t for u in urls for t in (u.get("tags") or []) if t})
        ameacas = sorted({u.get("threat") for u in urls if u.get("threat")})
        return Reputacao(
            self.nome, valor, tipo, "malicioso",
            resumo=(f"{d.get('url_count', len(urls))} URL(s) de malware neste host"
                    f"{f', {no_ar} ainda no ar' if no_ar else ''}; primeira vez em {d.get('firstseen', '?')}"),
            tags=tags[:12],
            detalhes={"urls": d.get("url_count"), "no_ar": no_ar, "primeira_vez": d.get("firstseen"),
                      "ameacas": ameacas, "blacklists": d.get("blacklists"),
                      "exemplos": [u.get("url") for u in urls[:5]]},
            referencia=d.get("urlhaus_reference", ""),
        )


class ThreatFoxClient(ClienteBase):
    nome = "ThreatFox"
    url_base = URL_THREATFOX

    def __init__(self, api_key: str, timeout: int = 30):
        super().__init__(api_key, timeout=timeout, rate_limit_por_minuto=60)
        if api_key:
            self.sessao.headers["Auth-Key"] = api_key

    def consultar(self, valor: str) -> Reputacao:
        tipo = _tipo(valor)
        if tipo == "hash":
            corpo = {"query": "search_hash", "hash": valor}
        else:
            corpo = {"query": "search_ioc", "search_term": valor, "exact_match": True}
        resposta = self._requisitar("/", metodo="POST", corpo_json=corpo)
        if resposta.erro:
            return falha(self.nome, valor, tipo, resposta.erro)
        d = resposta.dados
        registros = d.get("data") if d.get("query_status") == "ok" else None
        if not registros or not isinstance(registros, list):
            return Reputacao(self.nome, valor, tipo, "sem_registro", resumo="nenhum IOC registrado")

        familias = sorted({r.get("malware_printable") for r in registros if r.get("malware_printable")})
        ameacas = sorted({r.get("threat_type_desc") or r.get("threat_type") for r in registros if r.get("threat_type")})
        confianca = max(int(r.get("confidence_level") or 0) for r in registros)
        tags = sorted({t for r in registros for t in (r.get("tags") or []) if t})
        primeiro = min((r.get("first_seen") or "" for r in registros), default="")
        return Reputacao(
            self.nome, valor, tipo, "malicioso" if confianca >= 50 else "suspeito",
            resumo=(f"{', '.join(familias) or 'família não informada'} · {len(registros)} registro(s), "
                    f"confiança até {confianca}%, primeira vez em {primeiro or '?'}"),
            tags=tags[:12],
            detalhes={"familias": familias, "ameacas": ameacas, "confianca_maxima": confianca, "primeira_vez": primeiro,
                      "malpedia": sorted({r.get("malware_malpedia") for r in registros if r.get("malware_malpedia")})},
            referencia=f"https://threatfox.abuse.ch/ioc/{registros[0].get('id')}/" if registros[0].get("id") else "",
        )


def criar_urlhaus(config=None) -> URLhausClient | None:
    from config.settings import CONFIG

    cfg = config or CONFIG
    if not cfg.enable_enrichment or not cfg.malwarebazaar_api_key:
        return None
    return URLhausClient(cfg.malwarebazaar_api_key, timeout=cfg.http_timeout)


def criar_threatfox(config=None) -> ThreatFoxClient | None:
    from config.settings import CONFIG

    cfg = config or CONFIG
    if not cfg.enable_enrichment or not cfg.malwarebazaar_api_key:
        return None
    return ThreatFoxClient(cfg.malwarebazaar_api_key, timeout=cfg.http_timeout)
