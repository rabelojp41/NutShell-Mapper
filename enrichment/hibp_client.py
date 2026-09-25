"""
HaveIBeenPwned: vazamentos de dados, sem nunca trazer o dado vazado.

Duas consultas:

  - Catalogo por DOMINIO (gratuito, sem chave): o site desse dominio ja
    foi a origem de um vazamento? Nome, data, quantas contas e quais tipos
    de dado. Serve para o dominio da propria organizacao e para a marca que
    o golpe imita - senha de vazamento antigo e a materia-prima de golpe de
    "confirme sua conta".
  - Conta de E-MAIL (so com a chave paga): em quais vazamentos o endereco
    aparece. So para as contas do ATACANTE (Reply-To, remetente): ajuda a
    ligar a persona a outras campanhas.

O que volta e sempre nome do vazamento, data e tipo de dado. Senha, hash
ou registro de pessoa nunca: a API nao os entrega, e esta ferramenta nao os
buscaria.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from core import dominios
from enrichment.base import ClienteBase
from enrichment.reputacao import Reputacao, falha

logger = logging.getLogger(__name__)

URL_BASE = "https://haveibeenpwned.com/api/v3"


def _resumo(vazamentos: list[dict]) -> tuple[str, list[str]]:
    vazamentos = sorted(vazamentos, key=lambda v: v.get("BreachDate") or "", reverse=True)
    partes = []
    for v in vazamentos[:3]:
        contas = v.get("PwnCount")
        quantidade = f", {contas:,} contas".replace(",", ".").replace(". ", ", ", 1) if isinstance(contas, int) else ""
        partes.append(f"{v.get('Title') or v.get('Name')} ({(v.get('BreachDate') or '?')[:7]}{quantidade})")
    tipos = sorted({t for v in vazamentos for t in v.get("DataClasses") or []})
    return "; ".join(partes), tipos


class HIBPClient(ClienteBase):
    nome = "HIBP"
    url_base = URL_BASE

    def __init__(self, api_key: str = "", timeout: int = 30):
        # A chave e opcional: sem ela, so o catalogo por dominio.
        super().__init__(api_key or "catalogo", timeout=timeout, rate_limit_por_minuto=10)
        self.tem_chave = bool(api_key)
        if api_key:
            self.sessao.headers["hibp-api-key"] = api_key

    def consultar(self, valor: str) -> Reputacao:
        if "@" in valor:
            return self._conta(valor)
        return self._dominio(valor)

    def _dominio(self, valor: str) -> Reputacao:
        base = dominios.registravel(valor)
        resposta = self._requisitar("/breaches", parametros={"domain": base})
        if resposta.erro:
            return falha(self.nome, valor, "dominio", resposta.erro)
        vazamentos = resposta.dados if isinstance(resposta.dados, list) else []
        if not vazamentos:
            return Reputacao(self.nome, valor, "dominio", "sem_registro", resumo="nenhum vazamento catalogado com origem neste domínio")
        texto, tipos = _resumo(vazamentos)
        return Reputacao(
            self.nome, valor, "dominio", "contexto",
            resumo=f"o site deste domínio já vazou dados: {texto}" + (f" · tipos: {', '.join(tipos[:6])}" if tipos else ""),
            tags=tipos[:8],
            detalhes={"vazamentos": [{"nome": v.get("Title") or v.get("Name"), "data": v.get("BreachDate"), "contas": v.get("PwnCount"),
                                      "tipos": v.get("DataClasses") or [], "verificado": v.get("IsVerified")} for v in vazamentos[:10]]},
            referencia=f"https://haveibeenpwned.com/PwnedWebsites#{quote(vazamentos[0].get('Name') or '')}",
        )

    def _conta(self, valor: str) -> Reputacao:
        if not self.tem_chave:
            return falha(self.nome, valor, "email", "busca por e-mail exige a chave paga do HIBP")
        resposta = self._requisitar(f"/breachedaccount/{quote(valor)}", parametros={"truncateResponse": "false"})
        if resposta.erro:
            return falha(self.nome, valor, "email", resposta.erro)
        vazamentos = resposta.dados if isinstance(resposta.dados, list) else []
        if not vazamentos:
            return Reputacao(self.nome, valor, "email", "sem_registro", resumo="o endereço não aparece em vazamento catalogado")
        texto, tipos = _resumo(vazamentos)
        return Reputacao(
            self.nome, valor, "email", "contexto",
            resumo=f"a conta aparece em {len(vazamentos)} vazamento(s): {texto}",
            tags=tipos[:8], detalhes={"vazamentos": [v.get("Title") or v.get("Name") for v in vazamentos[:20]]},
        )


def criar(config=None) -> HIBPClient | None:
    from config.settings import CONFIG

    cfg = config or CONFIG
    if not cfg.enable_enrichment:
        return None
    return HIBPClient(cfg.hibp_api_key, timeout=cfg.http_timeout)
