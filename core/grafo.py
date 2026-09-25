"""
Grafo de pivo: os achados como nos e as relacoes entre eles como arestas.

E a forma visual do pivoting: partindo da mensagem (ou do artefato), cada
aresta e um passo que um analista daria - do remetente ao dominio dele, do
dominio aos IPs, do certificado aos dominios irmaos. Cada no e aresta sai
de um achado; nada e inferido so para o desenho ficar bonito.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

from core import dominios


@dataclass
class No:
    id: str
    rotulo: str
    tipo: str      # mensagem, artefato, endereco, dominio, ip, url, anexo, tecnica, marca, grupo
    vertice: str   # adversario, capacidade, infraestrutura, vitima, centro
    detalhe: str = ""
    destaque: bool = False


@dataclass
class Aresta:
    de: str
    para: str
    rotulo: str
    tracejada: bool = False


@dataclass
class Grafo:
    nos: list[No] = field(default_factory=list)
    arestas: list[Aresta] = field(default_factory=list)

    def no(self, id_: str, rotulo: str, tipo: str, vertice: str, detalhe: str = "", destaque: bool = False) -> str:
        chave = f"{tipo}:{id_.lower()}"
        if all(n.id != chave for n in self.nos):
            self.nos.append(No(chave, rotulo, tipo, vertice, detalhe, destaque))
        return chave

    def liga(self, de: str, para: str, rotulo: str, tracejada: bool = False) -> None:
        if de != para and all((a.de, a.para) != (de, para) for a in self.arestas):
            self.arestas.append(Aresta(de, para, rotulo, tracejada))

    def to_dict(self) -> dict:
        return asdict(self)


def _dominio(g: Grafo, nome: str, detalhe: str = "") -> str:
    base = dominios.registravel(nome)
    vertice = "infraestrutura"
    return g.no(base, base, "dominio", vertice, detalhe or ("webmail (serviço legítimo)" if dominios.e_webmail(base) else ""),
                destaque=bool(dominios.imitacao_de_marca(base)))


def grafo_do_email(r: Any, diamante: Any = None, consultas: list | None = None) -> Grafo:
    g = Grafo()
    centro = g.no("mensagem", r.assunto[:60] or "(sem assunto)", "mensagem", "centro", r.veredito, destaque=True)

    rotulos = {"From": "enviado por", "Reply-To": "respostas para", "Return-Path": "envelope", "Sender": "sender"}
    for ident in r.identidades:
        if ident.campo not in rotulos or "@" not in ident.endereco:
            continue
        n = g.no(ident.endereco, ident.endereco, "endereco", "adversario", ident.nome or ident.campo,
                 destaque=ident.campo == "Reply-To" and dominios.e_webmail(ident.dominio))
        g.liga(centro, n, rotulos[ident.campo])
        g.liga(n, _dominio(g, ident.dominio), "domínio")

    if r.origem is not None:
        ip = g.no(r.origem.ip, r.origem.ip, "ip", "infraestrutura", "servidor de origem", destaque=True)
        g.liga(centro, ip, "disparado de")
        if r.origem.de and not dominios.e_ip(r.origem.de) and "." in r.origem.de:
            g.liga(ip, _dominio(g, r.origem.de, "HELO do servidor"), "se apresentou como")

    for link in r.links:
        if link.tipo == "mailto" and "@" in link.destino:
            endereco = link.destino[7:].split("?")[0].lower()
            n = g.no(endereco, endereco, "endereco", "adversario", "destino dos botões")
            g.liga(centro, n, "botões escrevem para")
            g.liga(n, _dominio(g, link.dominio), "domínio")
        elif link.dominio and link.tipo in ("http", "encurtador"):
            g.liga(centro, _dominio(g, link.dominio), "link para")
        elif link.dominio and link.tipo == "ip":
            g.liga(centro, g.no(link.dominio, link.dominio, "ip", "infraestrutura", "link direto para IP"), "link para")
    for url in r.imagens_remotas:
        host = urlsplit(url).hostname or ""
        if host:
            g.liga(centro, _dominio(g, host, "pixel de rastreamento"), "rastreia por")

    for anexo in r.anexos:
        n = g.no(anexo.sha256, anexo.nome, "anexo", "capacidade", f"{anexo.tipo_real} · sha256 {anexo.sha256[:12]}…",
                 destaque=bool(anexo.observacoes))
        g.liga(centro, n, "anexo")

    marca = next((s.titulo.replace("Finge ser ", "") for s in r.sinais if s.codigo == "personificacao"), "")
    if marca:
        g.liga(centro, g.no(marca, marca, "marca", "vitima", "marca imitada"), "finge ser", tracejada=True)

    ttps = diamante.ttps if diamante is not None else []
    for t in ttps:
        g.liga(centro, g.no(t.tecnica, t.tecnica, "tecnica", "capacidade", t.tecnica_nome), t.tatica_nome, tracejada=True)

    for c in consultas or []:
        d = c if isinstance(c, dict) else c.to_dict()
        base = d.get("registravel") or ""
        if not base:
            continue
        n = _dominio(g, base)
        for ip in (d.get("dns") or {}).get("A", [])[:4]:
            g.liga(n, g.no(ip, ip, "ip", "infraestrutura", f"A de {base}"), "resolve para")
        for irmao in d.get("dominios_irmaos", [])[:6]:
            g.liga(n, _dominio(g, irmao, f"no mesmo certificado que {base}"), "mesmo certificado", tracejada=True)
    return g


def grafo_do_artefato(r: Any) -> Grafo:
    g = Grafo()
    nome = r.caminho.replace("\\", "/").rsplit("/", 1)[-1]
    centro = g.no("artefato", nome, "artefato", "centro", "artefato analisado", destaque=True)
    for ioc in getattr(r, "iocs", [])[:40]:
        tipo = ioc.tipo.value
        if tipo in ("ipv4", "ipv6"):
            g.liga(centro, g.no(ioc.valor, ioc.valor, "ip", "infraestrutura", ioc.confianca.value), "contém")
        elif tipo == "dominio":
            g.liga(centro, _dominio(g, ioc.valor), "contém")
        elif tipo == "url":
            host = urlsplit(ioc.valor).hostname or ""
            n = g.no(ioc.valor, ioc.valor[:48], "url", "infraestrutura", ioc.confianca.value)
            g.liga(centro, n, "contém")
            if host and dominios.e_ip(host):
                g.liga(n, g.no(host, host, "ip", "infraestrutura"), "servidor")
            elif host:
                g.liga(n, _dominio(g, host), "domínio")
    if r.mapeamento:
        for t in r.mapeamento.tecnicas:
            g.liga(centro, g.no(t.tecnica_id, t.tecnica_id, "tecnica", "capacidade", t.nome), "capacidade", tracejada=True)
    if r.atribuicao:
        for c in r.atribuicao.candidatos[:3]:
            n = g.no(c.grupo_id, c.nome, "grupo", "adversario", "repertório parecido (não é atribuição)")
            for t in c.tecnicas_em_comum[:6]:
                g.liga(n, g.no(t.tecnica_id, t.tecnica_id, "tecnica", "capacidade", t.nome), "também usa", tracejada=True)
    return g
