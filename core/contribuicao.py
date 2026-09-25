"""
Contribuicoes do analista: o que a ferramenta nao viu e uma pessoa viu.

A analise automatica traz o grosso; o analista de CTI acha o resto - um
certificado que leva a um dominio fora do escopo, um relato num canal, um
padrao que ja viu em outra campanha. Aqui esse achado entra no mesmo fluxo:

  1. O texto livre do analista e lido, e os indicadores dentro dele
     (dominio, IP, URL, e-mail, hash) sao extraidos. Os que a analise ainda
     nao tinha ficam marcados como NOVOS.
  2. A IA local (opcional) propoe onde o achado se encaixa: vertice do
     Diamond, a qual indicador existente ele se liga, que relacao e essa e
     o que a ferramenta deve pesquisar a seguir. Ela ESCOLHE, nao executa:
     so pode pedir acoes de um cardapio fechado, sobre indicadores que
     estao na nota. A proposta e conferida e o que nao bate e descartado.
  3. Sem IA, uma regra simples faz o mesmo papel (dominio e IP vao para a
     infraestrutura, e-mail para o adversario, hash para a capacidade).
  4. As acoes rodam (consulta de dominio, certificados, reputacao).
  5. Validacao, em dois modos. "Certeza": o analista garante e o achado
     entra direto, marcado como afirmado por ele. "Verificar" (padrao): so
     entra se a ferramenta achar LIGACAO CONCRETA com a analise - mesmo
     certificado, mesmo IP, mesma familia de malware, ou duas ligacoes
     fracas (servidor de nomes, servidor de e-mail, registrador). Sem isso
     fica como hipotese, listada, mas fora do Diamond e do grafo. Quem
     valida e a evidencia, nao a IA: a IA opina sobre onde encaixar, a
     ferramenta mostra se encaixa.

Tudo que entra leva a ORIGEM marcada. Num relatorio de CTI, "a ferramenta
achou", "o analista afirmou", "o analista sugeriu e a ferramenta confirmou"
sao coisas diferentes, e o leitor precisa saber qual e qual.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from core import dominios
from core.string_extractor import RE_EMAIL, RE_HASH, RE_IPV4, RE_URL, TLDS_VALIDOS

logger = logging.getLogger(__name__)

VERTICES = ("adversario", "capacidade", "infraestrutura", "vitima")
NOMES_DE_VERTICE = {"adversario": "Adversário", "capacidade": "Capacidade", "infraestrutura": "Infraestrutura", "vitima": "Vítima"}
# O que a IA pode mandar a ferramenta fazer. Nada fora disto roda.
ACOES = {
    "consultar_dominio": "DNS, idade, registrador e certificados do domínio",
    "reputacao": "reputação nas bases de inteligência configuradas (domínio, IP, URL ou hash)",
}
TIPOS_COM_REPUTACAO = frozenset({"dominio", "ip", "url", "hash"})
TAMANHO_MAXIMO_DA_NOTA = 4000
RE_DOMINIO_NOTA = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.IGNORECASE)


@dataclass
class IndicadorDaNota:
    valor: str
    tipo: str          # dominio, ip, url, email, hash
    novo: bool


@dataclass
class Acao:
    acao: str
    alvo: str
    motivo: str = ""


@dataclass
class Contribuicao:
    id: str
    texto: str
    criada_em: str
    indicadores: list[IndicadorDaNota] = field(default_factory=list)
    vertice: str = ""
    relacionado_a: str = ""
    relacao: str = ""
    tecnica: str = ""
    acoes: list[Acao] = field(default_factory=list)
    justificativa: str = ""
    # "regra" (sem IA) ou o nome do modelo que classificou.
    classificado_por: str = "regra"
    descartes: list[str] = field(default_factory=list)
    # Resultado das acoes: consultas de dominio e reputacao.
    resultados: dict = field(default_factory=lambda: {"dominios": [], "reputacao": []})
    # "verificar" (padrao): so entra na analise com evidencia de ligacao.
    # "certeza": o analista garante, e entra direto.
    modo: str = "verificar"
    # status: confirmado, nao_confirmado, nao_verificado ou afirmado (modo certeza).
    validacao: dict = field(default_factory=lambda: {"status": "", "evidencias": [], "explicacao": ""})

    @property
    def entra_na_analise(self) -> bool:
        return self.validacao.get("status") in ("confirmado", "afirmado")

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================
# Extracao
# ============================================================


def _conhecidos(r: Any, diamante: Any = None) -> set[str]:
    saida = {i.valor.lower() for i in r.iocs}
    for i in r.identidades:
        saida.update({i.endereco.lower(), i.dominio.lower(), dominios.registravel(i.dominio)})
    for l in r.links:
        saida.update({l.destino.lower(), l.dominio.lower()})
    if diamante is not None:
        for v in (diamante.adversario, diamante.capacidade, diamante.infraestrutura, diamante.vitima):
            saida.update(i.valor.lower() for i in v.itens)
    saida.discard("")
    return saida


def extrair_indicadores(texto: str, r: Any, diamante: Any = None) -> list[IndicadorDaNota]:
    conhecidos = _conhecidos(r, diamante)
    vistos: set[str] = set()
    saida: list[IndicadorDaNota] = []

    def add(valor: str, tipo: str) -> None:
        valor = valor.strip().rstrip(".,;:)]}'\"")
        if not valor or valor.lower() in vistos:
            return
        vistos.add(valor.lower())
        base = dominios.registravel(valor) if tipo == "dominio" else ""
        novo = valor.lower() not in conhecidos and (not base or base not in conhecidos)
        saida.append(IndicadorDaNota(valor, tipo, novo))

    # Aceita indicador ja "defangado" (hxxps://x[.]com), como o analista cola.
    limpo = (texto or "")[:TAMANHO_MAXIMO_DA_NOTA]
    limpo = re.sub(r"hxxp", "http", limpo, flags=re.IGNORECASE).replace("[.]", ".").replace("[@]", "@").replace("(.)", ".")
    urls = RE_URL.findall(limpo)
    for u in urls:
        add(u, "url")
    emails = RE_EMAIL.findall(limpo)
    for e in emails:
        add(e.lower(), "email")
    for h in RE_HASH.findall(limpo):
        add(h.lower(), "hash")
    for ip in RE_IPV4.findall(limpo):
        add(ip, "ip")
    ocupado = " ".join(urls + emails).lower()
    for d in RE_DOMINIO_NOTA.findall(limpo):
        d = d.lower()
        if d.rsplit(".", 1)[-1] in TLDS_VALIDOS and d not in ocupado:
            add(d, "dominio")
    return saida


# ============================================================
# Classificacao
# ============================================================


def classificar_por_regra(c: Contribuicao, r: Any) -> None:
    """Sem IA: o tipo do indicador decide o vertice; a nota decide a ligacao."""
    novos = [i for i in c.indicadores if i.novo] or c.indicadores
    tipos = {i.tipo for i in novos}
    if tipos & {"dominio", "ip", "url"}:
        c.vertice = "infraestrutura"
    elif "email" in tipos:
        c.vertice = "adversario"
    elif "hash" in tipos:
        c.vertice = "capacidade"
    else:
        c.vertice = "capacidade"
    ja_citados = [i for i in c.indicadores if not i.novo]
    if ja_citados:
        c.relacionado_a = ja_citados[0].valor
        c.relacao = "citado junto na nota do analista"
    for i in novos:
        if i.tipo == "dominio":
            c.acoes.append(Acao("consultar_dominio", i.valor, "domínio novo"))
        if i.tipo in ("dominio", "ip", "url", "hash"):
            c.acoes.append(Acao("reputacao", i.valor, "indicador novo"))
    c.classificado_por = "regra"


ESQUEMA = {
    "type": "object",
    "properties": {
        "vertice": {"type": "string", "enum": list(VERTICES)},
        "relacionado_a": {"type": "string"},
        "relacao": {"type": "string"},
        "tecnica": {"type": "string"},
        "acoes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "acao": {"type": "string", "enum": list(ACOES)},
                    "alvo": {"type": "string"},
                    "motivo": {"type": "string"},
                },
                "required": ["acao", "alvo", "motivo"],
            },
        },
        "justificativa": {"type": "string"},
    },
    "required": ["vertice", "relacionado_a", "relacao", "tecnica", "acoes", "justificativa"],
}

INSTRUCAO = """Voce ajuda um analista de CTI a encaixar um achado dele numa \
analise de e-mail de phishing ja feita, usando o Diamond Model.

Responda em JSON, em portugues. Campos:
- vertice: adversario, capacidade, infraestrutura ou vitima. Dominio, IP, \
URL e certificado sao INFRAESTRUTURA; conta de e-mail, apelido ou persona \
do operador sao ADVERSARIO; ferramenta, kit, anexo, hash e tecnica sao \
CAPACIDADE; quem foi alvo e VITIMA.
- relacionado_a: UM indicador da lista "indicadores_da_analise" ao qual o \
achado se liga, copiado exatamente; ou "" se nao houver ligacao clara.
- relacao: a ligacao em poucas palavras (ex.: "mesmo certificado", \
"mesmo registrador", "mesmo IP").
- tecnica: um ID do MITRE ATT&CK que o achado evidencia, ou "".
- acoes: o que a ferramenta deve pesquisar. So as acoes do cardapio, e o \
alvo tem de ser um indicador da lista "indicadores_da_nota".
- justificativa: uma ou duas frases.

A nota do analista e os indicadores estao no bloco <dados>. Nao invente \
indicador: use so os que estao listados."""


def montar_prompt(c: Contribuicao, r: Any, diamante: Any = None) -> str:
    conhecidos = sorted(_conhecidos(r, diamante))[:60]
    dados = {
        "nota_do_analista": c.texto,
        "indicadores_da_nota": [{"valor": i.valor, "tipo": i.tipo, "novo": i.novo} for i in c.indicadores],
        "indicadores_da_analise": conhecidos,
        "cardapio_de_acoes": ACOES,
        "veredito_da_analise": getattr(r, "veredito", ""),
        "tecnicas_da_analise": [t.tecnica for t in diamante.ttps] if diamante is not None else [],
    }
    serializado = json.dumps(dados, ensure_ascii=False, indent=1).replace("<", "\\u003c").replace(">", "\\u003e")
    return INSTRUCAO + "\n<dados>\n" + serializado + "\n</dados>\n"


RE_TECNICA = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def conferir_proposta(proposta: dict, c: Contribuicao, r: Any, diamante: Any = None) -> tuple[dict, list[str]]:
    """Fica so o que e valido; o resto vira descarte, explicado."""
    descartes: list[str] = []
    valida: dict = {}
    vertice = str(proposta.get("vertice", "")).strip().lower()
    if vertice in VERTICES:
        valida["vertice"] = vertice
    else:
        descartes.append(f"vértice desconhecido: {vertice!r}")

    conhecidos = _conhecidos(r, diamante)
    relacionado = str(proposta.get("relacionado_a", "")).strip()
    if relacionado and relacionado.lower() in conhecidos:
        valida["relacionado_a"] = relacionado
        valida["relacao"] = str(proposta.get("relacao", ""))[:120]
    elif relacionado:
        descartes.append(f"ligação com {relacionado!r}, que não está na análise")

    tecnica = str(proposta.get("tecnica", "")).strip().upper()
    if tecnica and RE_TECNICA.match(tecnica):
        valida["tecnica"] = tecnica
    elif tecnica:
        descartes.append(f"técnica inválida: {tecnica!r}")

    alvos = {i.valor.lower(): i for i in c.indicadores}
    acoes = []
    for a in proposta.get("acoes") or []:
        nome = str(a.get("acao", ""))
        alvo = str(a.get("alvo", "")).strip()
        if nome not in ACOES:
            descartes.append(f"ação fora do cardápio: {nome!r}")
        elif alvo.lower() not in alvos:
            descartes.append(f"ação sobre {alvo!r}, que não está na nota")
        elif nome == "consultar_dominio" and alvos[alvo.lower()].tipo != "dominio":
            descartes.append(f"consultar_dominio sobre {alvo!r}, que não é domínio")
        elif nome == "reputacao" and alvos[alvo.lower()].tipo not in TIPOS_COM_REPUTACAO:
            descartes.append(f"reputação de {alvo!r}: as bases não indexam {alvos[alvo.lower()].tipo}")
        elif all((x.acao, x.alvo.lower()) != (nome, alvo.lower()) for x in acoes):
            acoes.append(Acao(nome, alvos[alvo.lower()].valor, str(a.get("motivo", ""))[:160]))
    valida["acoes"] = acoes
    valida["justificativa"] = str(proposta.get("justificativa", ""))[:400]
    return valida, descartes


def classificar_com_ia(c: Contribuicao, r: Any, diamante: Any = None, modelo: str = "", progresso=None) -> bool:
    """
    Pede a proposta ao modelo local e aplica o que passar na conferencia.
    Devolve False quando a IA nao estava disponivel (e ai vale a regra).
    """
    from core.resumo_ia import MODELO_PADRAO, ClienteOllama, ErroResumoIA

    modelo = modelo or MODELO_PADRAO
    cliente = ClienteOllama(modelo=modelo)
    disponivel, motivo = cliente.disponivel()
    if not disponivel:
        c.descartes.append(f"IA indisponível ({motivo}); classificado por regra")
        return False
    try:
        bruto = cliente.gerar(montar_prompt(c, r, diamante), progresso=progresso, formato=ESQUEMA, max_tokens=600)
        proposta = json.loads(bruto)
    except (ErroResumoIA, ValueError) as erro:
        c.descartes.append(f"a IA não respondeu no formato esperado ({erro}); classificado por regra")
        return False
    valida, descartes = conferir_proposta(proposta, c, r, diamante)
    c.descartes += descartes
    if "vertice" not in valida:
        return False
    c.vertice = valida["vertice"]
    c.relacionado_a = valida.get("relacionado_a", "")
    c.relacao = valida.get("relacao", "")
    c.tecnica = valida.get("tecnica", "")
    c.acoes = valida["acoes"]
    c.justificativa = valida["justificativa"]
    c.classificado_por = modelo
    return True


# ============================================================
# Execucao e integracao
# ============================================================


def nova_contribuicao(texto: str, r: Any, diamante: Any = None, modo: str = "verificar") -> Contribuicao:
    texto = (texto or "").strip()[:TAMANHO_MAXIMO_DA_NOTA]
    if not texto:
        raise ValueError("a nota está vazia")
    if modo not in ("verificar", "certeza"):
        raise ValueError(f"modo desconhecido: {modo!r}")
    return Contribuicao(
        id=uuid.uuid4().hex[:8], texto=texto,
        criada_em=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        indicadores=extrair_indicadores(texto, r, diamante), modo=modo,
    )


def executar_acoes(c: Contribuicao, online: bool = True, progresso=None) -> None:
    """Roda as acoes escolhidas. Offline, so registra que nao rodaram."""
    if not online:
        if c.acoes:
            c.descartes.append("consultas externas desligadas: as ações não foram executadas")
        return
    from enrichment.consulta_dominio import consultar_dominio
    from enrichment.consulta_reputacao import consultar_reputacao

    tipos = {i.valor: i.tipo for i in c.indicadores}
    if c.modo == "verificar":
        # Verificar exige olhar o indicador novo, escolha a IA isso ou nao.
        for i in c.indicadores:
            if not i.novo:
                continue
            if i.tipo == "dominio" and all((a.acao, a.alvo) != ("consultar_dominio", i.valor) for a in c.acoes):
                c.acoes.append(Acao("consultar_dominio", i.valor, "necessária para verificar"))
            if i.tipo in TIPOS_COM_REPUTACAO and all((a.acao, a.alvo) != ("reputacao", i.valor) for a in c.acoes):
                c.acoes.append(Acao("reputacao", i.valor, "necessária para verificar"))
    para_reputacao = []
    for a in c.acoes:
        if a.acao == "consultar_dominio":
            if progresso:
                progresso(f"consultando {a.alvo}")
            try:
                c.resultados["dominios"].append(consultar_dominio(a.alvo, certificados=True).to_dict())
            except ValueError as erro:
                c.descartes.append(f"{a.alvo}: {erro}")
        elif a.acao == "reputacao" and tipos.get(a.alvo) in TIPOS_COM_REPUTACAO:
            para_reputacao.append((a.alvo, tipos[a.alvo]))
    if para_reputacao:
        c.resultados["reputacao"] = [x.to_dict() for x in consultar_reputacao(para_reputacao, progresso=progresso)]


def aplicar(diamante: Any, grafo: Any, contribuicoes: list[Contribuicao]) -> None:
    """Poe as contribuicoes no Diamond e no grafo, com a origem marcada."""
    from core.diamante import ItemDiamante, Pivo

    for c in contribuicoes:
        if not c.entra_na_analise:
            continue
        origem = "analista, confirmado pela ferramenta" if c.validacao.get("status") == "confirmado" else "analista"
        if c.classificado_por != "regra":
            origem += f" · classificado por {c.classificado_por}"
        vertice = getattr(diamante, c.vertice, None) if diamante is not None else None
        for ind in c.indicadores:
            if vertice is not None and ind.novo and all(i.valor.lower() != ind.valor.lower() for i in vertice.itens):
                descricao = f"[{origem}] " + (f"{c.relacao} ({c.relacionado_a})" if c.relacionado_a else c.texto[:80])
                vertice.itens.append(ItemDiamante(ind.valor, descricao, "tipo 1" if c.vertice == "infraestrutura" else ""))
        for d in c.resultados.get("dominios", []):
            for irmao in d.get("dominios_irmaos", [])[:5]:
                if diamante is not None:
                    diamante.pivos.append(Pivo("Infraestrutura", "Infraestrutura",
                                               f"(da contribuição do analista) {irmao} está no mesmo certificado que {d.get('registravel')}."))
        if grafo is None:
            continue
        ancora = None
        if c.relacionado_a:
            ancora = next((n.id for n in grafo.nos if c.relacionado_a.lower() in (n.id.split(":", 1)[-1], n.rotulo.lower())), None)
        if ancora is None:
            ancora = next((n.id for n in grafo.nos if n.vertice == "centro"), None)
        for ind in c.indicadores:
            if not ind.novo:
                continue
            tipo = {"dominio": "dominio", "ip": "ip", "url": "url", "email": "endereco", "hash": "anexo"}.get(ind.tipo, "dominio")
            no = grafo.no(ind.valor, ind.valor, tipo, c.vertice or "infraestrutura", f"informado pelo analista: {c.texto[:100]}", destaque=True)
            if ancora:
                grafo.liga(ancora, no, c.relacao or "analista", tracejada=True)
            for d in c.resultados.get("dominios", []):
                if d.get("registravel") == dominios.registravel(ind.valor):
                    for irmao in d.get("dominios_irmaos", [])[:5]:
                        grafo.liga(no, grafo.no(irmao, irmao, "dominio", "infraestrutura", f"no mesmo certificado que {ind.valor}"),
                                   "mesmo certificado", tracejada=True)


# ============================================================
# Validacao
# ============================================================

# NS e MX de provedor grande sao compartilhados por milhoes de dominios: o
# mesmo "ns.cloudflare.com" nao liga dois dominios entre si.
PROVEDORES_COMPARTILHADOS = (
    "cloudflare.com", "awsdns", "azure-dns", "googledomains.com", "domaincontrol.com", "registrar-servers.com",
    "google.com", "outlook.com", "protection.outlook.com", "googlemail.com", "zoho", "hostinger", "namecheap",
)


def _compartilhado(nome: str) -> bool:
    return any(p in nome.lower() for p in PROVEDORES_COMPARTILHADOS)


def validar(c: Contribuicao, r: Any, consultas: list | None = None, reputacao: list | None = None, online: bool = True) -> None:
    """
    Procura ligacao concreta entre os indicadores novos da nota e o que a
    analise ja tinha. Preenche c.validacao. So conta o que a ferramenta
    observou; o texto do analista e a opiniao da IA nao sao evidencia.
    """
    if c.modo == "certeza":
        c.validacao = {"status": "afirmado", "evidencias": [],
                       "explicacao": "o analista afirmou com certeza; entrou sem verificação da ferramenta"}
        return
    novos = [i for i in c.indicadores if i.novo]
    if not novos:
        c.validacao = {"status": "confirmado", "evidencias": [{"forca": "forte", "texto": "a nota só cita indicadores que já estavam na análise"}],
                       "explicacao": "nada novo a verificar"}
        return
    if not online:
        c.validacao = {"status": "nao_verificado", "evidencias": [],
                       "explicacao": "consultas externas desligadas: sem elas não há como verificar; ficou fora da análise"}
        return

    conhecidas = [x if isinstance(x, dict) else x.to_dict() for x in consultas or []]
    dominios_conhecidos = {d.get("registravel", "") for d in conhecidas}
    for i in r.identidades:
        if i.dominio and not dominios.e_webmail(i.dominio) and i.campo != "Message-ID":
            dominios_conhecidos.add(dominios.registravel(i.dominio))
    for l in r.links:
        if l.dominio and l.tipo in ("http", "encurtador"):
            dominios_conhecidos.add(dominios.registravel(l.dominio))
    dominios_conhecidos.discard("")
    ips_conhecidos = {ip for d in conhecidas for ip in (d.get("dns") or {}).get("A", [])}
    if r.origem is not None and r.origem.ip:
        ips_conhecidos.add(r.origem.ip)
    irmaos_conhecidos = {x for d in conhecidas for x in d.get("dominios_irmaos", [])}
    ns_conhecidos = {n.rstrip(".").lower() for d in conhecidas for n in (d.get("dns") or {}).get("NS", []) if not _compartilhado(n)}
    mx_conhecidos = {m.split()[-1].rstrip(".").lower() for d in conhecidas for m in (d.get("dns") or {}).get("MX", []) if not _compartilhado(m)}
    registros_conhecidos = {(d.get("registrador"), (d.get("criado_em") or "")[:7]) for d in conhecidas if d.get("registrador") and d.get("criado_em")}
    familias_conhecidas = {
        f.lower() for x in reputacao or [] for f in ((x if isinstance(x, dict) else x.to_dict()).get("detalhes") or {}).get("familias", [])
    }

    evidencias: list[dict] = []

    def ev(forca: str, texto: str) -> None:
        if all(e["texto"] != texto for e in evidencias):
            evidencias.append({"forca": forca, "texto": texto})

    novas_consultas = {d.get("registravel"): d for d in c.resultados.get("dominios", [])}
    for ind in novos:
        base = dominios.registravel(ind.valor) if ind.tipo in ("dominio", "url") else ""
        if ind.tipo == "ip" and ind.valor in ips_conhecidos:
            ev("forte", f"{ind.valor} é um IP que já aparece na análise")
        if base and base in irmaos_conhecidos:
            ev("forte", f"{base} está no mesmo certificado que um domínio da análise")
        d = novas_consultas.get(base)
        if d:
            nomes = {n.lstrip("*.").lower() for cert in d.get("certificados", []) for n in cert.get("nomes", [])}
            comuns = sorted({dominios.registravel(n) for n in nomes} & dominios_conhecidos)
            if comuns:
                ev("forte", f"o certificado de {base} também cobre {', '.join(comuns)}")
            for irmao in d.get("dominios_irmaos", []):
                if irmao in dominios_conhecidos:
                    ev("forte", f"{base} divide certificado com {irmao}, que está na análise")
            ips = set((d.get("dns") or {}).get("A", []))
            if ips & ips_conhecidos:
                ev("forte", f"{base} resolve para {', '.join(sorted(ips & ips_conhecidos))}, IP já visto na análise")
            ns = {n.rstrip(".").lower() for n in (d.get("dns") or {}).get("NS", [])} & ns_conhecidos
            if ns:
                ev("fraca", f"{base} usa o mesmo servidor de nomes ({', '.join(sorted(ns))})")
            mx = {m.split()[-1].rstrip(".").lower() for m in (d.get("dns") or {}).get("MX", [])} & mx_conhecidos
            if mx:
                ev("fraca", f"{base} usa o mesmo servidor de e-mail ({', '.join(sorted(mx))})")
            if (d.get("registrador"), (d.get("criado_em") or "")[:7]) in registros_conhecidos:
                ev("fraca", f"{base} foi registrado no mesmo registrador e no mesmo mês de um domínio da análise")
        for x in c.resultados.get("reputacao", []):
            if x.get("indicador") != ind.valor or not x.get("encontrado"):
                continue
            comuns = sorted({f.lower() for f in (x.get("detalhes") or {}).get("familias", [])} & familias_conhecidas)
            if comuns:
                ev("media", f"{x['fonte']} liga {ind.valor} à mesma família de malware ({', '.join(comuns)})")

    fortes = sum(1 for e in evidencias if e["forca"] in ("forte", "media"))
    fracas = sum(1 for e in evidencias if e["forca"] == "fraca")
    if fortes or fracas >= 2:
        c.validacao = {"status": "confirmado", "evidencias": evidencias,
                       "explicacao": "a ferramenta encontrou ligação concreta com a análise"}
    else:
        c.validacao = {"status": "nao_confirmado", "evidencias": evidencias,
                       "explicacao": ("nenhuma ligação concreta com a análise: ficou registrado como hipótese, fora do "
                                      "Diamond e do grafo. Se você tem certeza, adicione de novo no modo certeza.")}
