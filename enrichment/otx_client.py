"""
OTX AlienVault: o que a comunidade ja publicou sobre o indicador.

Um "pulse" e um relatorio publicado no OTX (por pesquisador, empresa,
sensor de honeypot) com uma lista de indicadores. Consultar um IOC devolve
quantos pulses o citam e, deles, os adversarios, as familias de malware, as
tecnicas ATT&CK e os setores visados - o contexto que liga uma
infraestrutura isolada a uma campanha conhecida.

O OTX tambem VALIDA: dominio popular, rede de anuncios, nos de saida Tor,
falso positivo conhecido. Isso evita o alarme falso classico de um pulse
que listou google.com por engano.

Quantidade de pulses nao e gravidade: sensor de honeypot publica pulse de
todo IP que bateu nele. Por isso o resumo mostra QUEM publicou e o que
disse, e nao so o numero.
"""

from __future__ import annotations

import logging
from collections import Counter
from urllib.parse import quote

from core import dominios
from enrichment.base import ClienteBase
from enrichment.reputacao import Reputacao, falha

logger = logging.getLogger(__name__)

URL_BASE = "https://otx.alienvault.com/api/v1"
# Validacoes que dizem "isto e conhecido e legitimo".
VALIDACOES_BENIGNAS = frozenset({"whitelist", "false_positive", "majestic", "akamai", "alexa", "ad_network"})
PULSES_PARA_MALICIOSO = 3


def _secao(valor: str, tipo: str) -> tuple[str, str]:
    """(tipo na API, tipo na pagina do OTX)."""
    if tipo == "ip":
        return ("IPv6", "ip") if ":" in valor else ("IPv4", "ip")
    if tipo == "url":
        return "url", "url"
    if tipo == "hash":
        return "file", "file"
    if dominios.registravel(valor) == dominios.normalizar(valor):
        return "domain", "domain"
    return "hostname", "hostname"


class OTXClient(ClienteBase):
    nome = "OTX"
    url_base = URL_BASE

    def __init__(self, api_key: str, timeout: int = 40):
        super().__init__(api_key, timeout=timeout, rate_limit_por_minuto=60)
        if api_key:
            self.sessao.headers["X-OTX-API-KEY"] = api_key

    def consultar(self, valor: str, tipo: str = "") -> Reputacao:
        tipo = tipo or ("ip" if dominios.e_ip(valor) else "url" if "://" in valor else
                        "hash" if len(valor) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in valor) else "dominio")
        secao, pagina = _secao(valor, tipo)
        resposta = self._requisitar(f"/indicators/{secao}/{quote(valor, safe='')}/general")
        if resposta.erro:
            return falha(self.nome, valor, tipo, resposta.erro)
        if not resposta.encontrado:
            return Reputacao(self.nome, valor, tipo, "sem_registro", resumo="indicador desconhecido pelo OTX")
        d = resposta.dados
        referencia = f"https://otx.alienvault.com/indicator/{pagina}/{quote(valor, safe='')}"

        validacoes = d.get("validation") or []
        benignas = [v for v in validacoes if v.get("source") in VALIDACOES_BENIGNAS]
        info = d.get("pulse_info") or {}
        pulses = info.get("pulses") or []
        total = int(info.get("count") or len(pulses))

        adversarios = Counter(p.get("adversary") for p in pulses if p.get("adversary"))
        familias = Counter(m.get("display_name") for p in pulses for m in p.get("malware_families") or [] if m.get("display_name"))
        tecnicas = Counter(a.get("id") for p in pulses for a in p.get("attack_ids") or [] if a.get("id"))
        tags = Counter(t.lower() for p in pulses for t in p.get("tags") or [] if t)
        setores = (info.get("related") or {}).get("other", {}).get("industries") or []
        outras = [v.get("message") or v.get("name") for v in validacoes if v not in benignas]
        detalhes = {
            "pulses": total,
            "adversarios": [a for a, _ in adversarios.most_common(5)],
            "familias": [f for f, _ in familias.most_common(5)],
            "tecnicas": [t for t, _ in tecnicas.most_common(8)],
            "setores": setores[:6],
            "validacao": [v.get("message") or v.get("name") for v in validacoes],
            "ultimos_pulses": [
                {"nome": p.get("name", "")[:120], "criado": (p.get("created") or "")[:10],
                 "url": f"https://otx.alienvault.com/pulse/{p.get('id')}" if p.get("id") else ""}
                for p in sorted(pulses, key=lambda p: p.get("created") or "", reverse=True)[:5]
            ],
        }

        if benignas:
            return Reputacao(self.nome, valor, tipo, "sem_registro",
                             resumo="conhecido e legítimo para o OTX: " + "; ".join(v.get("message") or v.get("name", "") for v in benignas[:2]),
                             detalhes=detalhes, referencia=referencia)
        if not total:
            resumo = "nenhum pulse cita este indicador"
            if outras:
                resumo += " · " + "; ".join(outras[:2])
            return Reputacao(self.nome, valor, tipo, "sem_registro", resumo=resumo, detalhes=detalhes, referencia=referencia)

        partes = [f"{total} pulse(s)"]
        if detalhes["adversarios"]:
            partes.append("adversário: " + ", ".join(detalhes["adversarios"][:3]))
        if detalhes["familias"]:
            partes.append("malware: " + ", ".join(detalhes["familias"][:3]))
        if detalhes["tecnicas"]:
            partes.append("ATT&CK: " + ", ".join(detalhes["tecnicas"][:4]))
        if detalhes["ultimos_pulses"]:
            partes.append(f"mais recente em {detalhes['ultimos_pulses'][0]['criado']}")
        if outras:
            partes.append("; ".join(outras[:2]))
        forte = total >= PULSES_PARA_MALICIOSO or detalhes["adversarios"] or detalhes["familias"]
        return Reputacao(
            self.nome, valor, tipo, "malicioso" if forte else "suspeito", resumo=" · ".join(partes),
            tags=[t for t, _ in tags.most_common(8)], detalhes=detalhes, referencia=referencia,
        )


def criar(config=None) -> OTXClient | None:
    from config.settings import CONFIG

    cfg = config or CONFIG
    if not cfg.enable_enrichment or not cfg.otx_api_key:
        return None
    return OTXClient(cfg.otx_api_key, timeout=max(cfg.http_timeout, 40))
