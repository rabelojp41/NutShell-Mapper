"""
URLScan.io: o que ja se viu quando alguem visitou a URL.

Dois modos, com custos diferentes:

  - BUSCA (passiva, padrao): procura varreduras que outras pessoas ja
    fizeram do dominio, IP, URL ou hash. Nada e visitado. Traz a pagina que
    respondeu (titulo, IP, provedor, pais, certificado), quando foi vista
    pela ultima vez e - o pivo mais util - os OUTROS sites que carregam
    recursos desse dominio. Para um dominio de ClickFix, por exemplo, sao os
    sites comprometidos que injetam o script.

  - VARREDURA (ativa, opcional, sempre confirmada): pede ao URLScan que
    visite a URL agora. Quem acessa e a infraestrutura do URLScan, nao a sua
    maquina - o seu IP nao aparece para o atacante. Mas a visita acontece:
    link unico por vitima pode ser "queimado", e o kit pode registrar que
    foi analisado. A varredura e feita como "unlisted" (nao aparece na
    busca publica).

Ter varreduras nao e ser malicioso: metade da internet foi varrida algum
dia. Por isso o veredito aqui e "contexto", e so vira "malicioso" quando o
proprio URLScan (ou quem enviou, pelas tags) marcou como malicioso.
"""

from __future__ import annotations

import logging
import time
from collections import Counter

from core import dominios
from enrichment.base import ClienteBase
from enrichment.reputacao import Reputacao, falha

logger = logging.getLogger(__name__)

URL_BASE = "https://urlscan.io/api/v1"
RESULTADOS = 20
TAGS_MALICIOSAS = ("phish", "malicious", "malware", "clickfix", "scam", "fraud", "c2", "credential", "fakeupdate", "socgholish")
ESPERA_DA_VARREDURA = 10
TENTATIVAS_DA_VARREDURA = 9


def _consulta(valor: str, tipo: str) -> str:
    if tipo == "ip":
        return f"ip:{valor}"
    if tipo == "url":
        return f'page.url:"{valor}"'
    if tipo == "hash":
        return f"hash:{valor}"
    return f"domain:{valor}"


def _provedor(pagina: dict) -> str:
    """'AMAZON-02, US' ja traz o pais; nao repetir."""
    nome = pagina.get("asnname") or pagina.get("asn") or "provedor desconhecido"
    pais = pagina.get("country") or ""
    return nome if not pais or nome.endswith(f", {pais}") else f"{nome}, {pais}"


class URLScanClient(ClienteBase):
    nome = "URLScan"
    url_base = URL_BASE

    def __init__(self, api_key: str, timeout: int = 40):
        super().__init__(api_key, timeout=timeout, rate_limit_por_minuto=60)
        if api_key:
            self.sessao.headers["API-Key"] = api_key

    # ------------------------------------------------------------
    # Busca (passiva)
    # ------------------------------------------------------------

    def consultar(self, valor: str, tipo: str = "") -> Reputacao:
        tipo = tipo or ("ip" if dominios.e_ip(valor) else "url" if "://" in valor else
                        "hash" if len(valor) == 64 and all(c in "0123456789abcdefABCDEF" for c in valor) else "dominio")
        consulta = _consulta(valor, tipo)
        resposta = self._requisitar("/search/", parametros={"q": consulta, "size": RESULTADOS})
        if resposta.erro:
            return falha(self.nome, valor, tipo, resposta.erro)
        d = resposta.dados
        resultados = d.get("results") or []
        total = int(d.get("total") or 0)
        referencia = f"https://urlscan.io/search/#{consulta}"
        if not resultados:
            return Reputacao(self.nome, valor, tipo, "sem_registro", resumo="ninguém varreu este indicador no URLScan",
                             referencia=referencia)

        # Varredura do proprio indicador x pagina de OUTRO site que o carrega.
        alvo = dominios.registravel(valor) if tipo == "dominio" else ""
        proprias, carregam = [], []
        for x in resultados:
            t = x.get("task") or {}
            if tipo == "dominio" and alvo and dominios.registravel(t.get("domain") or "") != alvo:
                carregam.append(x)
            else:
                proprias.append(x)

        tags = Counter(tag.lower() for x in resultados for tag in (x.get("task") or {}).get("tags") or [])
        suspeitas = [t for t in tags if any(m in t for m in TAGS_MALICIOSAS)]
        maliciosas = [x for x in resultados if ((x.get("verdicts") or {}).get("overall") or {}).get("malicious")]

        partes = [f"{total} varredura(s)"]
        recente = (proprias or resultados)[0]
        pagina = recente.get("page") or {}
        tarefa = recente.get("task") or {}
        if proprias:
            partes.append(f"última em {(tarefa.get('time') or '')[:10]}")
            if pagina.get("title"):
                partes.append(f"página “{pagina['title'][:60]}”")
            if pagina.get("ip"):
                partes.append(f"{pagina['ip']} ({_provedor(pagina)})")
            if pagina.get("domain") and tarefa.get("domain") and pagina["domain"] != tarefa["domain"]:
                partes.append(f"redireciona para {pagina['domain']}")
        sites = sorted({(x.get("task") or {}).get("apexDomain") or (x.get("task") or {}).get("domain") for x in carregam} - {None})
        if sites:
            partes.append(f"{len(sites)} outro(s) site(s) carregam recursos deste domínio")
        if suspeitas:
            partes.append("tags: " + ", ".join(suspeitas[:4]))

        veredito = "malicioso" if maliciosas or suspeitas else "contexto"
        return Reputacao(
            self.nome, valor, tipo, veredito, resumo=" · ".join(partes), tags=[t for t, _ in tags.most_common(8)],
            detalhes={
                "varreduras": total,
                "ultima": tarefa.get("time"),
                "pagina": {k: pagina.get(k) for k in ("url", "domain", "title", "ip", "asn", "asnname", "country", "server",
                                                      "tlsIssuer", "tlsAgeDays", "status", "redirected")},
                "sites_que_carregam": sites[:20],
                "resultado": f"https://urlscan.io/result/{tarefa.get('uuid')}/" if tarefa.get("uuid") else "",
                "marcadas_maliciosas": len(maliciosas),
            },
            referencia=referencia,
        )

    # ------------------------------------------------------------
    # Varredura (ativa)
    # ------------------------------------------------------------

    def varrer(self, url: str, esperar: bool = True) -> Reputacao:
        """
        Pede ao URLScan que visite a URL agora, e espera o resultado.
        Quem chama e responsavel por ter confirmado com o analista.
        """
        resposta = self._requisitar("/scan/", metodo="POST", corpo_json={"url": url, "visibility": "unlisted"})
        if resposta.erro:
            return falha(self.nome, url, "url", resposta.erro)
        uuid = resposta.dados.get("uuid")
        pagina_resultado = resposta.dados.get("result") or (f"https://urlscan.io/result/{uuid}/" if uuid else "")
        if not uuid:
            return falha(self.nome, url, "url", resposta.dados.get("message") or "o URLScan não aceitou a varredura")
        if not esperar:
            return Reputacao(self.nome, url, "url", "contexto", resumo="varredura enviada; o resultado sai em até um minuto",
                             referencia=pagina_resultado, detalhes={"uuid": uuid})

        for _ in range(TENTATIVAS_DA_VARREDURA):
            time.sleep(ESPERA_DA_VARREDURA)
            r = self._requisitar(f"/result/{uuid}/")
            if r.encontrado:
                return self._interpretar_varredura(url, r.dados, pagina_resultado)
            if r.erro:
                return falha(self.nome, url, "url", r.erro)
        return Reputacao(self.nome, url, "url", "contexto", resumo="varredura enviada, mas o resultado ainda não saiu; veja na página",
                         referencia=pagina_resultado, detalhes={"uuid": uuid})

    def _interpretar_varredura(self, url: str, d: dict, referencia: str) -> Reputacao:
        veredictos = (d.get("verdicts") or {}).get("overall") or {}
        pagina = d.get("page") or {}
        listas = d.get("lists") or {}
        marcas = [m.get("name") or m.get("key") for m in veredictos.get("brands") or [] if isinstance(m, dict)] or veredictos.get("brands") or []
        partes = []
        if veredictos.get("malicious"):
            partes.append(f"MALICIOSA para o URLScan (pontuação {veredictos.get('score')})")
        if veredictos.get("categories"):
            partes.append("categorias: " + ", ".join(veredictos["categories"][:4]))
        if marcas:
            partes.append("imita: " + ", ".join(str(m) for m in marcas[:3]))
        partes.append(f"respondeu {pagina.get('url') or url} de {pagina.get('ip') or '?'} ({_provedor(pagina)})")
        if pagina.get("title"):
            partes.append(f"página “{pagina['title'][:60]}”")
        if listas.get("domains"):
            partes.append(f"{len(listas['domains'])} domínio(s) contatado(s)")
        return Reputacao(
            self.nome, url, "url", "malicioso" if veredictos.get("malicious") else "contexto", resumo=" · ".join(partes),
            tags=list(veredictos.get("categories") or [])[:6],
            detalhes={"pagina": {k: pagina.get(k) for k in ("url", "domain", "title", "ip", "asnname", "country", "server", "status")},
                      "dominios_contatados": (listas.get("domains") or [])[:30], "ips_contatados": (listas.get("ips") or [])[:30],
                      "certificados": (listas.get("certificates") or [])[:10], "marcas": marcas,
                      "captura": (d.get("task") or {}).get("screenshotURL", "")},
            referencia=referencia,
        )


def criar(config=None) -> URLScanClient | None:
    from config.settings import CONFIG

    cfg = config or CONFIG
    if not cfg.enable_enrichment or not cfg.urlscan_api_key:
        return None
    return URLScanClient(cfg.urlscan_api_key, timeout=max(cfg.http_timeout, 40))
