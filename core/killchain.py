"""
Agrupamento das tecnicas ATT&CK nos estagios da Cyber Kill Chain.

Uma ressalva importante, porque ela muda como o resultado deve ser lido:
a Cyber Kill Chain da Lockheed Martin e o MITRE ATT&CK sao modelos
diferentes, feitos para propositos diferentes, e a traducao entre eles e
lossy por natureza.

  - A Kill Chain e linear e descreve uma intrusao do ponto de vista do
    atacante que vem de fora, do reconhecimento ate o objetivo final.
  - O ATT&CK nao e linear: e um catalogo de taticas que podem ocorrer em
    qualquer ordem, varias vezes, e varias delas nao tem lugar obvio na
    Kill Chain. "Discovery" acontece o tempo todo; "Credential Access" pode
    ser meio ou fim.

Portanto o mapeamento aqui e uma aproximacao editorial, nao uma
equivalencia formal, e cada decisao esta documentada. Ha ainda um limite
mais duro: analise estatica de um unico artefato so enxerga um recorte da
intrusao. Um downloader e so o estagio de Delivery de uma cadeia inteira
que este arquivo nao contem. Os estagios vazios, por isso, sao reportados
como "sem evidencia neste artefato", e nunca como "nao ocorreu".
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from enum import Enum

from core.mitre_mapper import ResultadoMapeamento, TecnicaMapeada
from core.string_extractor import Confianca

logger = logging.getLogger(__name__)


class Estagio(str, Enum):
    """Os sete estagios da Cyber Kill Chain, na ordem canonica."""

    RECONHECIMENTO = "Reconhecimento"
    ARMAMENTO = "Armamento"
    ENTREGA = "Entrega"
    EXPLORACAO = "Exploracao"
    INSTALACAO = "Instalacao"
    COMANDO_E_CONTROLE = "Comando e Controle"
    ACOES_NO_OBJETIVO = "Acoes no Objetivo"

    @property
    def ordem(self) -> int:
        return ORDEM_DOS_ESTAGIOS.index(self)

    @property
    def nome_original(self) -> str:
        """Nome em ingles, como na publicacao da Lockheed Martin."""
        return NOMES_EM_INGLES[self]


ORDEM_DOS_ESTAGIOS: tuple[Estagio, ...] = (
    Estagio.RECONHECIMENTO,
    Estagio.ARMAMENTO,
    Estagio.ENTREGA,
    Estagio.EXPLORACAO,
    Estagio.INSTALACAO,
    Estagio.COMANDO_E_CONTROLE,
    Estagio.ACOES_NO_OBJETIVO,
)

NOMES_EM_INGLES: dict[Estagio, str] = {
    Estagio.RECONHECIMENTO: "Reconnaissance",
    Estagio.ARMAMENTO: "Weaponization",
    Estagio.ENTREGA: "Delivery",
    Estagio.EXPLORACAO: "Exploitation",
    Estagio.INSTALACAO: "Installation",
    Estagio.COMANDO_E_CONTROLE: "Command & Control",
    Estagio.ACOES_NO_OBJETIVO: "Actions on Objectives",
}


# ============================================================
# Tatica ATT&CK -> estagio da Kill Chain
#
# Cada escolha nao obvia vem com a justificativa, porque outro analista
# poderia decidir diferente e precisa poder discordar com conhecimento de
# causa.
# ============================================================

TATICA_PARA_ESTAGIO: dict[str, Estagio] = {
    # Diretas.
    "reconnaissance": Estagio.RECONHECIMENTO,
    "resource-development": Estagio.ARMAMENTO,
    "initial-access": Estagio.ENTREGA,
    "execution": Estagio.EXPLORACAO,
    "persistence": Estagio.INSTALACAO,
    "command-and-control": Estagio.COMANDO_E_CONTROLE,
    # Escalada de privilegio e a continuacao da exploracao: o atacante ja
    # executa codigo e amplia o acesso obtido.
    "privilege-escalation": Estagio.EXPLORACAO,
    # Evasao de defesa serve para o implante sobreviver no hospedeiro, que
    # e o proposito do estagio de Instalacao. Empacotamento e ofuscacao
    # tambem poderiam ser lidos como Armamento, ja que acontecem antes da
    # entrega, mas neste framework o que se observa e o resultado no
    # hospedeiro, nao o processo de construcao.
    "defense-evasion": Estagio.INSTALACAO,
    # Descoberta e reconhecimento, porem interno: ja houve comprometimento.
    # Fica em Acoes no Objetivo por ser pos-intrusao, e nao no
    # Reconhecimento, que na Kill Chain e explicitamente externo e anterior
    # ao contato.
    "discovery": Estagio.ACOES_NO_OBJETIVO,
    # As demais sao o objetivo em si ou o caminho direto para ele.
    "credential-access": Estagio.ACOES_NO_OBJETIVO,
    "lateral-movement": Estagio.ACOES_NO_OBJETIVO,
    "collection": Estagio.ACOES_NO_OBJETIVO,
    "exfiltration": Estagio.ACOES_NO_OBJETIVO,
    "impact": Estagio.ACOES_NO_OBJETIVO,
}

# Taticas para as quais a escolha e discutivel. Registrado no resultado
# para o analista saber onde a traducao foi editorial.
TATICAS_AMBIGUAS = frozenset({"discovery", "defense-evasion", "privilege-escalation"})


# ============================================================
# Tipos
# ============================================================


@dataclass
class EstagioPreenchido:
    """Um estagio da Kill Chain com as tecnicas observadas nele."""

    estagio: Estagio
    tecnicas: list[TecnicaMapeada] = field(default_factory=list)
    # Taticas ATT&CK cuja traducao para este estagio e discutivel.
    taticas_ambiguas: list[str] = field(default_factory=list)

    @property
    def vazio(self) -> bool:
        return not self.tecnicas

    @property
    def maior_confianca(self) -> Confianca:
        """Confianca da melhor evidencia deste estagio."""
        if not self.tecnicas:
            return Confianca.BAIXA
        ordem = {Confianca.BAIXA: 1, Confianca.MEDIA: 2, Confianca.ALTA: 3}
        return max(self.tecnicas, key=lambda t: ordem[t.confianca]).confianca

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ResultadoKillChain:
    """A Kill Chain completa, com os sete estagios sempre presentes."""

    estagios: list[EstagioPreenchido] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    def por_estagio(self, estagio: Estagio) -> EstagioPreenchido:
        """Acesso direto a um estagio."""
        for e in self.estagios:
            if e.estagio is estagio:
                return e
        raise KeyError(estagio)

    @property
    def estagios_cobertos(self) -> list[Estagio]:
        """Estagios em que ha alguma evidencia."""
        return [e.estagio for e in self.estagios if not e.vazio]

    @property
    def cobertura(self) -> float:
        """Fracao dos sete estagios com evidencia (0.0 a 1.0)."""
        return len(self.estagios_cobertos) / len(ORDEM_DOS_ESTAGIOS)

    def resumo(self) -> dict:
        return {
            "estagios_cobertos": len(self.estagios_cobertos),
            "de": len(ORDEM_DOS_ESTAGIOS),
            "cobertura": round(self.cobertura, 2),
            "tecnicas": sum(len(e.tecnicas) for e in self.estagios),
        }

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================
# API
# ============================================================


def montar(mapeamento: ResultadoMapeamento) -> ResultadoKillChain:
    """
    Distribui as tecnicas mapeadas pelos estagios da Kill Chain.

    Uma tecnica com mais de uma tatica aparece em mais de um estagio: isso e
    fiel ao ATT&CK, onde T1547.001 e ao mesmo tempo persistencia e escalada
    de privilegio, e esconder isso distorceria o modelo.

    Args:
        mapeamento: saida do mitre_mapper.

    Returns:
        ResultadoKillChain com os sete estagios, inclusive os vazios.
    """
    resultado = ResultadoKillChain(
        estagios=[EstagioPreenchido(estagio=e) for e in ORDEM_DOS_ESTAGIOS]
    )
    indice = {e.estagio: e for e in resultado.estagios}

    taticas_desconhecidas: set[str] = set()

    for tecnica in mapeamento.tecnicas:
        estagios_desta_tecnica: set[Estagio] = set()

        for tatica in tecnica.taticas:
            estagio = TATICA_PARA_ESTAGIO.get(tatica)
            if estagio is None:
                taticas_desconhecidas.add(tatica)
                continue

            estagios_desta_tecnica.add(estagio)

            if tatica in TATICAS_AMBIGUAS:
                ambiguas = indice[estagio].taticas_ambiguas
                if tatica not in ambiguas:
                    ambiguas.append(tatica)

        for estagio in estagios_desta_tecnica:
            indice[estagio].tecnicas.append(tecnica)

    # Ordena cada estagio pela forca da evidencia.
    ordem = {Confianca.ALTA: 0, Confianca.MEDIA: 1, Confianca.BAIXA: 2}
    for preenchido in resultado.estagios:
        preenchido.tecnicas.sort(key=lambda t: (ordem[t.confianca], t.tecnica_id))

    # --- Avisos sobre os limites do que foi observado ---

    vazios = [e.estagio.value for e in resultado.estagios if e.vazio]
    if vazios:
        resultado.avisos.append(
            "sem evidencia neste artefato para: "
            + ", ".join(vazios)
            + ". Analise estatica de um unico arquivo cobre um recorte da "
            "intrusao; ausencia de evidencia nao e evidencia de ausencia"
        )

    if taticas_desconhecidas:
        resultado.avisos.append(
            "taticas ATT&CK sem estagio correspondente na Kill Chain: "
            + ", ".join(sorted(taticas_desconhecidas))
        )

    ambiguas_usadas = sorted(
        {t for e in resultado.estagios for t in e.taticas_ambiguas}
    )
    if ambiguas_usadas:
        resultado.avisos.append(
            "traducao editorial para: "
            + ", ".join(ambiguas_usadas)
            + ". ATT&CK e Kill Chain sao modelos distintos e a correspondencia "
            "nao e formal"
        )

    logger.info("kill chain montada: %s", resultado.resumo())
    return resultado


def resumir_em_texto(kc: ResultadoKillChain) -> str:
    """Rendericao em texto, usada no CLI e no relatorio."""
    linhas: list[str] = []

    for preenchido in kc.estagios:
        estagio = preenchido.estagio
        cabecalho = f"{estagio.ordem + 1}. {estagio.value} ({estagio.nome_original})"

        if preenchido.vazio:
            linhas.append(f"{cabecalho}: sem evidencia neste artefato")
            continue

        linhas.append(f"{cabecalho}: {len(preenchido.tecnicas)} tecnica(s)")
        for t in preenchido.tecnicas:
            linhas.append(f"     [{t.confianca.value:5}] {t.tecnica_id}  {t.nome}")

    return "\n".join(linhas)
