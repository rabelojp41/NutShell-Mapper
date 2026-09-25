"""
Pyramid of Pain (David Bianco, 2013) e a separacao IoC x IoA.

A piramide ordena os indicadores pelo quanto custa ao adversario troca-los
depois que o defensor os bloqueia:

    TTPs                    <- dificil: mudar o jeito de operar
    Ferramentas             <- desafiador: trocar/escrever a ferramenta
    Artefatos de rede/host  <- irritante: mudar um detalhe do kit
    Dominios                <- simples: registrar outro
    Enderecos IP            <- facil: trocar de servidor
    Hashes                  <- trivial: mudar um byte

Serve para priorizar a defesa: bloquear o hash de um anexo resolve esta
mensagem; detectar o PROCEDIMENTO (golpe por resposta com Reply-To em
webmail) pega a proxima campanha, com outro hash, outro IP e outro dominio.

IoC x IoA: indicador de COMPROMETIMENTO e um valor observado (o IP, o
dominio, o hash) - fica velho quando o atacante troca. Indicador de ATAQUE e
um comportamento (Reply-To desviado para webmail, marca num dominio que nao
e dela) - continua valendo na proxima campanha. Os degraus de baixo sao
IoC; o topo e IoA.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

DEGRAUS = [
    ("hash", "Hashes", "trivial", "Mudar um byte do arquivo gera outro hash."),
    ("ip", "Endereços IP", "fácil", "Trocar de servidor ou de VPS leva minutos."),
    ("dominio", "Domínios", "simples", "Registrar outro domínio custa pouco e é rápido."),
    ("artefato", "Artefatos de rede/host", "irritante", "Exige mudar um detalhe do kit: caminho, nome de anexo, assunto, cabeçalho."),
    ("ferramenta", "Ferramentas", "desafiador", "Exige trocar ou reescrever a ferramenta ou o serviço usado."),
    ("ttp", "TTPs", "difícil", "Exige mudar o jeito de operar, o que custa tempo e aprendizado."),
]
ORDEM = [d[0] for d in DEGRAUS]

# Sinais do e-mail que sao comportamento (IoA), nao valor.
SINAIS_DE_COMPORTAMENTO = {
    "golpe_por_resposta", "reply_to_desviado", "personificacao", "marca_em_webmail",
    "envelope_diferente", "link_disfarcado", "texto_oculto", "formulario", "link_perigoso",
    "dominio_imitacao", "link_imitacao",
}


@dataclass
class ItemPiramide:
    valor: str
    degrau: str
    classe: str        # "IoC" ou "IoA"
    origem: str


@dataclass
class Piramide:
    degraus: list[dict] = field(default_factory=list)
    itens: list[ItemPiramide] = field(default_factory=list)
    leitura: str = ""

    def contagem(self) -> dict[str, int]:
        return {d: sum(1 for i in self.itens if i.degrau == d) for d in ORDEM}

    def to_dict(self) -> dict:
        dados = asdict(self)
        dados["contagem"] = self.contagem()
        return dados


def _degrau_do_ioc(tipo: str) -> str:
    return {"hash": "hash", "ipv4": "ip", "ipv6": "ip", "dominio": "dominio", "url": "dominio",
            "email": "artefato", "caminho_windows": "artefato", "caminho_unc": "artefato",
            "chave_registro": "artefato", "bitcoin": "artefato", "cve": "ferramenta"}.get(tipo, "artefato")


def _leitura(p: Piramide) -> str:
    c = p.contagem()
    topo = c["ttp"] + c["ferramenta"]
    base = c["hash"] + c["ip"] + c["dominio"]
    if topo:
        return (f"{topo} indicador(es) no topo da pirâmide (comportamento e ferramenta). São eles que "
                f"sobrevivem à troca de infraestrutura: priorize detecção por eles, e use os {base} "
                "da base para bloqueio imediato.")
    if base:
        return (f"Só indicadores da base ({base}): bloqueá-los resolve esta ocorrência, mas o atacante "
                "troca em minutos. Falta comportamento observado para uma detecção durável.")
    return "Nenhum indicador classificável."


def _nova() -> Piramide:
    return Piramide(degraus=[{"id": d, "nome": n, "dor": dor, "explicacao": e} for d, n, dor, e in DEGRAUS])


def piramide_do_email(r: Any, diamante: Any = None) -> Piramide:
    p = _nova()
    vistos: set[tuple[str, str]] = set()

    def add(valor: str, degrau: str, origem: str) -> None:
        if not valor or (valor.lower(), degrau) in vistos:
            return
        vistos.add((valor.lower(), degrau))
        p.itens.append(ItemPiramide(valor, degrau, "IoA" if degrau in ("ttp", "ferramenta") else "IoC", origem))

    for i in r.iocs:
        add(i.valor, _degrau_do_ioc(i.tipo.value), i.origem)
    if len(r.assunto) >= 12:
        add(r.assunto, "artefato", "assunto da isca")
    for a in r.anexos:
        add(a.nome, "artefato", "nome do anexo")
    # Servico legitimo abusado e a "ferramenta" de uma campanha de e-mail:
    # trocar de Gmail para outro webmail exige nova conta e novo fluxo.
    from core import dominios as _d
    for ident in r.identidades:
        if ident.campo in ("Reply-To", "From") and _d.e_webmail(ident.dominio):
            add(f"conta em {ident.dominio}", "ferramenta", f"{ident.campo} em webmail")
    for s in r.sinais:
        if s.codigo in SINAIS_DE_COMPORTAMENTO:
            add(s.titulo, "ttp", "comportamento observado")
    if diamante is not None:
        for t in diamante.ttps:
            add(f"{t.tecnica} {t.tecnica_nome}", "ttp", t.tatica_nome)
    p.leitura = _leitura(p)
    return p


def piramide_do_artefato(r: Any) -> Piramide:
    p = _nova()
    vistos: set[tuple[str, str]] = set()

    def add(valor: str, degrau: str, origem: str) -> None:
        if not valor or (valor.lower(), degrau) in vistos:
            return
        vistos.add((valor.lower(), degrau))
        p.itens.append(ItemPiramide(valor, degrau, "IoA" if degrau in ("ttp", "ferramenta") else "IoC", origem))

    sha = getattr(r, "sha256", "") or ""
    if sha:
        add(sha, "hash", "artefato analisado")
    for i in getattr(r, "iocs", []):
        add(i.valor, _degrau_do_ioc(i.tipo.value), "extraído do artefato")
    if r.regra_yara is not None and r.regra_yara.valida:
        add(r.regra_yara.nome, "ferramenta", "regra YARA (detecta o kit, não um valor)")
    if r.mapeamento:
        for t in r.mapeamento.tecnicas:
            add(f"{t.tecnica_id} {t.nome}", "ttp", "capacidade observada")
    p.leitura = _leitura(p)
    return p
