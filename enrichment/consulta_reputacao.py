"""
Reputacao de indicadores em todas as fontes configuradas.

Cada fonte declara que tipo de indicador sabe consultar; o orquestrador
pergunta a cada uma so o que ela entende. Fonte sem chave fica de fora sem
erro - a analise segue com as que houver.

As consultas rodam em paralelo por fonte (cada uma com o proprio limite de
taxa), porque em serie uma analise com dez indicadores e cinco fontes
levaria minutos.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable

from core import dominios
from enrichment.reputacao import Reputacao, falha

logger = logging.getLogger(__name__)

MAXIMO_DE_INDICADORES = 15


@dataclass
class Fonte:
    nome: str
    tipos: frozenset[str]
    criar: Callable[[], Any]


def fontes_disponiveis() -> list[Fonte]:
    """As fontes, na ordem em que aparecem. Criar devolve None sem chave."""
    from config.settings import CONFIG
    from enrichment import abusech_client, abuseipdb_client, censys_client, hibp_client, otx_client, urlscan_client

    # Sem chave, o HIBP so tem o catalogo por dominio; com ela, tambem conta de e-mail.
    tipos_hibp = {"dominio", "organizacao"} | ({"email"} if CONFIG.hibp_api_key else set())

    return [
        Fonte("URLhaus", frozenset({"ip", "dominio", "url"}), abusech_client.criar_urlhaus),
        Fonte("ThreatFox", frozenset({"ip", "dominio", "url", "hash"}), abusech_client.criar_threatfox),
        Fonte("MalwareBazaar", frozenset({"hash"}), abusech_client.criar_malwarebazaar),
        Fonte("YARAify", frozenset({"hash"}), abusech_client.criar_yaraify),
        Fonte("AbuseIPDB", frozenset({"ip"}), abuseipdb_client.criar),
        Fonte("OTX", frozenset({"ip", "dominio", "url", "hash"}), otx_client.criar),
        Fonte("URLScan", frozenset({"ip", "dominio", "url", "hash"}), urlscan_client.criar),
        Fonte("Censys", frozenset({"ip"}), censys_client.criar),
        Fonte("HIBP", frozenset(tipos_hibp), hibp_client.criar),
    ]


def indicadores_do_email(r: Any, diamante: Any = None) -> list[tuple[str, str]]:
    """
    O que vale consultar num e-mail: a infraestrutura do atacante. Webmail
    fica de fora (perguntar sobre gmail.com nao diz nada) e o endereco do
    atacante tambem - fonte de reputacao nao indexa e-mail.
    """
    saida: list[tuple[str, str]] = []

    def add(valor: str, tipo: str) -> None:
        if valor and (valor, tipo) not in saida:
            saida.append((valor, tipo))

    if r.origem is not None and r.origem.ip:
        add(r.origem.ip, "ip")
    if diamante is not None:
        for item in diamante.infraestrutura.itens:
            if item.tipo == "tipo 1":
                add(item.valor, "ip" if dominios.e_ip(item.valor) else "dominio")
    else:
        for i in r.identidades:
            if i.dominio and "@" in i.endereco and not dominios.e_webmail(i.dominio):
                add(dominios.registravel(i.dominio), "dominio")
    for link in r.links:
        if link.tipo in ("http", "ip", "encurtador"):
            add(link.destino, "url")
    for url in r.imagens_remotas:
        add(url, "url")
    for anexo in r.anexos:
        add(anexo.sha256, "hash")
    saida = saida[:MAXIMO_DE_INDICADORES]
    # Contas do atacante: so a fonte de vazamentos (com chave) as consulta.
    for i in r.identidades:
        if i.campo in ("Reply-To", "From") and "@" in i.endereco:
            add(i.endereco, "email")
    # O dominio de quem RECEBEU, para o catalogo de vazamentos: senha de
    # vazamento antigo da propria organizacao e materia-prima de golpe.
    for nome, valor in r.cabecalhos:
        if nome.lower() == "to":
            for pedaco in valor.replace(",", " ").split():
                pedaco = pedaco.strip("<>;\"'")
                if "@" in pedaco:
                    dominio = dominios.registravel(pedaco.rsplit("@", 1)[-1])
                    if "." in dominio and not dominios.e_webmail(dominio):
                        add(dominio, "organizacao")
    return saida


def indicadores_do_artefato(r: Any) -> list[tuple[str, str]]:
    saida: list[tuple[str, str]] = []
    sha = getattr(r, "sha256", "")
    if sha:
        saida.append((sha, "hash"))
    for ioc in getattr(r, "iocs", []):
        tipo = {"ipv4": "ip", "dominio": "dominio", "url": "url"}.get(ioc.tipo.value)
        if tipo and ioc.confianca.value != "baixa" and (ioc.valor, tipo) not in saida:
            saida.append((ioc.valor, tipo))
    return saida[:MAXIMO_DE_INDICADORES]


def consultar_reputacao(
    indicadores: list[tuple[str, str]],
    fontes: list[Fonte] | None = None,
    progresso: Callable[[str], None] | None = None,
) -> list[Reputacao]:
    """Uma Reputacao por par (fonte, indicador) que a fonte sabe consultar."""
    fontes = fontes if fontes is not None else fontes_disponiveis()
    ativas = []
    for fonte in fontes:
        try:
            cliente = fonte.criar()
        except Exception as erro:  # fabrica quebrada nao derruba as outras
            logger.warning("fonte %s indisponivel: %s", fonte.nome, erro)
            cliente = None
        if cliente is not None:
            ativas.append((fonte, cliente))

    def rodar(par) -> list[Reputacao]:
        fonte, cliente = par
        saida = []
        for valor, tipo in indicadores:
            if tipo not in fonte.tipos:
                continue
            if progresso:
                progresso(f"{fonte.nome}: {valor[:60]}")
            try:
                saida.append(cliente.consultar(valor))
            except Exception as erro:
                logger.warning("%s falhou em %s: %s", fonte.nome, valor, erro)
                saida.append(falha(fonte.nome, valor, tipo, f"falha inesperada: {type(erro).__name__}"))
        return saida

    resultados: list[Reputacao] = []
    if not ativas:
        return resultados
    with ThreadPoolExecutor(max_workers=len(ativas)) as pool:
        for lista in pool.map(rodar, ativas):
            resultados.extend(lista)
    for _, cliente in ativas:
        fechar = getattr(cliente, "fechar", None)
        if fechar:
            fechar()
    ordem = {"malicioso": 0, "suspeito": 1, "contexto": 2, "sem_registro": 3, "erro": 4}
    resultados.sort(key=lambda x: (ordem.get(x.veredito, 9), x.indicador, x.fonte))
    return resultados


def fontes_configuradas() -> list[str]:
    """Nomes das fontes com chave, para a interface dizer o que vai consultar."""
    nomes = []
    for fonte in fontes_disponiveis():
        try:
            if fonte.criar() is not None:
                nomes.append(fonte.nome)
        except Exception:
            continue
    return nomes
