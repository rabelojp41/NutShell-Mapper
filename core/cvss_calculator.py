"""
Calculo de score CVSS 3.1.

Entra em cena quando o artefato explora uma CVE conhecida: o CVSS quantifica
a severidade daquela vulnerabilidade, o que da ao relatorio uma medida
comparavel entre casos.

O calculo em si e delegado a biblioteca `cvss`, que implementa a
especificacao do FIRST. Reimplementar a formula na mao seria pedir erro de
arredondamento silencioso - a especificacao 3.1 tem regras de arredondamento
proprias que diferem da 3.0. O que este modulo acrescenta e a camada em
volta: validacao com mensagem util, construcao de vetor a partir de
componentes, traducao das metricas para portugues e a distincao entre os
tres tipos de score.

Sobre os tres scores, que sao frequentemente confundidos:
  - Base          : caracteristicas intrinsecas e imutaveis da falha.
  - Temporal      : ajusta pela maturidade do exploit e disponibilidade de
                    correcao. Muda com o tempo.
  - Ambiental     : ajusta pelo contexto de quem sofre. So quem opera o
                    ambiente pode preencher.
O que a NVD publica e o Base. Um relatorio que cita "o CVSS e 9.8" quase
sempre esta falando do Base, e vale dizer isso explicitamente.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from enum import Enum

from cvss import CVSS3
from cvss.exceptions import CVSS3MalformedError

logger = logging.getLogger(__name__)


RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class Severidade(str, Enum):
    """Faixas qualitativas definidas pela especificacao CVSS 3.1."""

    NENHUMA = "Nenhuma"
    BAIXA = "Baixa"
    MEDIA = "Media"
    ALTA = "Alta"
    CRITICA = "Critica"

    @classmethod
    def de_score(cls, score: float) -> "Severidade":
        """Converte o score numerico na faixa qualitativa oficial."""
        if score == 0.0:
            return cls.NENHUMA
        if score < 4.0:
            return cls.BAIXA
        if score < 7.0:
            return cls.MEDIA
        if score < 9.0:
            return cls.ALTA
        return cls.CRITICA


# Metricas base, com os valores aceitos e a traducao de cada um.
# Serve para validar o vetor e para o relatorio ficar legivel em portugues.
METRICAS_BASE: dict[str, tuple[str, dict[str, str]]] = {
    "AV": (
        "Vetor de Ataque",
        {
            "N": "Rede",
            "A": "Rede adjacente",
            "L": "Local",
            "P": "Físico",
        },
    ),
    "AC": ("Complexidade do Ataque", {"L": "Baixa", "H": "Alta"}),
    "PR": (
        "Privilégios Necessários",
        {"N": "Nenhum", "L": "Baixos", "H": "Altos"},
    ),
    "UI": ("Interação do Usuário", {"N": "Nenhuma", "R": "Necessária"}),
    "S": ("Escopo", {"U": "Inalterado", "C": "Alterado"}),
    "C": ("Confidencialidade", {"H": "Alto", "L": "Baixo", "N": "Nenhum"}),
    "I": ("Integridade", {"H": "Alto", "L": "Baixo", "N": "Nenhum"}),
    "A": ("Disponibilidade", {"H": "Alto", "L": "Baixo", "N": "Nenhum"}),
}

ORDEM_DAS_METRICAS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Metricas temporais, opcionais.
METRICAS_TEMPORAIS: dict[str, tuple[str, dict[str, str]]] = {
    "E": (
        "Maturidade do Exploit",
        {
            "X": "Não definida",
            "U": "Não comprovado",
            "P": "Prova de conceito",
            "F": "Funcional",
            "H": "Alta",
        },
    ),
    "RL": (
        "Nível de Correção",
        {
            "X": "Não definido",
            "O": "Correção oficial",
            "T": "Correção temporária",
            "W": "Contorno",
            "U": "Indisponível",
        },
    ),
    "RC": (
        "Confiança no Relato",
        {
            "X": "Não definida",
            "U": "Desconhecida",
            "R": "Razoável",
            "C": "Confirmada",
        },
    ),
}


@dataclass
class MetricaLegivel:
    """Uma metrica do vetor, traduzida."""

    sigla: str
    nome: str
    valor: str
    valor_legivel: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ResultadoCVSS:
    """Scores e a leitura do vetor."""

    vetor: str
    versao: str = "3.1"

    score_base: float = 0.0
    severidade_base: Severidade = Severidade.NENHUMA

    # Presentes apenas quando o vetor traz metricas temporais.
    score_temporal: float | None = None
    severidade_temporal: Severidade | None = None

    # Presentes apenas quando o vetor traz metricas ambientais.
    score_ambiental: float | None = None
    severidade_ambiental: Severidade | None = None

    metricas: list[MetricaLegivel] = field(default_factory=list)
    cve: str = ""
    avisos: list[str] = field(default_factory=list)

    @property
    def score_efetivo(self) -> float:
        """
        O score mais especifico disponivel.

        Ambiental > temporal > base: cada um refina o anterior com mais
        contexto.
        """
        if self.score_ambiental is not None:
            return self.score_ambiental
        if self.score_temporal is not None:
            return self.score_temporal
        return self.score_base

    @property
    def severidade_efetiva(self) -> Severidade:
        return Severidade.de_score(self.score_efetivo)

    def resumo(self) -> dict:
        return {
            "cve": self.cve,
            "vetor": self.vetor,
            "base": self.score_base,
            "temporal": self.score_temporal,
            "ambiental": self.score_ambiental,
            "severidade": self.severidade_efetiva.value,
        }

    def to_dict(self) -> dict:
        return asdict(self)


class ErroCVSS(ValueError):
    """Vetor CVSS invalido ou incompleto."""


# ============================================================
# Construcao e normalizacao do vetor
# ============================================================


def montar_vetor(
    av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
) -> str:
    """
    Monta um vetor CVSS 3.1 a partir das oito metricas base.

    Args:
        av: Attack Vector - N, A, L ou P.
        ac: Attack Complexity - L ou H.
        pr: Privileges Required - N, L ou H.
        ui: User Interaction - N ou R.
        s: Scope - U ou C.
        c: Confidentiality - H, L ou N.
        i: Integrity - H, L ou N.
        a: Availability - H, L ou N.

    Returns:
        O vetor no formato "CVSS:3.1/AV:N/AC:L/...".

    Raises:
        ErroCVSS: algum valor nao pertence ao dominio da metrica.
    """
    valores = dict(zip(ORDEM_DAS_METRICAS, (av, ac, pr, ui, s, c, i, a)))
    partes: list[str] = []

    for sigla in ORDEM_DAS_METRICAS:
        valor = (valores[sigla] or "").strip().upper()
        nome, aceitos = METRICAS_BASE[sigla]

        if valor not in aceitos:
            raise ErroCVSS(
                f"{nome} ({sigla}): '{valor}' inválido. "
                f"Aceitos: {', '.join(f'{k} ({v})' for k, v in aceitos.items())}"
            )
        partes.append(f"{sigla}:{valor}")

    return "CVSS:3.1/" + "/".join(partes)


def _normalizar(vetor: str) -> str:
    """
    Aceita vetor sem o prefixo de versao.

    Fonte publica frequentemente publica so "AV:N/AC:L/...". Completar o
    prefixo aqui evita obrigar quem chama a lembrar disso.
    """
    vetor = vetor.strip()
    if not vetor:
        raise ErroCVSS("vetor vazio")
    if not vetor.upper().startswith("CVSS:"):
        return f"CVSS:3.1/{vetor}"
    return vetor


def _traduzir(vetor: str) -> list[MetricaLegivel]:
    """Converte cada par sigla:valor do vetor para descricao em portugues."""
    metricas: list[MetricaLegivel] = []
    conhecidas = {**METRICAS_BASE, **METRICAS_TEMPORAIS}

    for parte in vetor.split("/"):
        if ":" not in parte or parte.upper().startswith("CVSS"):
            continue

        sigla, _, valor = parte.partition(":")
        sigla, valor = sigla.strip().upper(), valor.strip().upper()

        if sigla not in conhecidas:
            continue  # metrica ambiental ou desconhecida: nao traduzida

        nome, aceitos = conhecidas[sigla]
        metricas.append(
            MetricaLegivel(
                sigla=sigla,
                nome=nome,
                valor=valor,
                valor_legivel=aceitos.get(valor, valor),
            )
        )

    return metricas


# ============================================================
# API principal
# ============================================================


def calcular(vetor: str, cve: str = "") -> ResultadoCVSS:
    """
    Calcula os scores CVSS 3.1 a partir de um vetor.

    Args:
        vetor: o vetor completo ou apenas as metricas ("AV:N/AC:L/...").
        cve: identificador da CVE, apenas registrado no resultado.

    Returns:
        ResultadoCVSS com os scores disponiveis e a leitura do vetor.

    Raises:
        ErroCVSS: vetor malformado ou com metrica invalida.
    """
    normalizado = _normalizar(vetor)

    try:
        c = CVSS3(normalizado)
    except CVSS3MalformedError as erro:
        raise ErroCVSS(f"vetor CVSS inválido: {erro}") from erro
    except Exception as erro:  # a lib levanta tipos variados para entrada ruim
        raise ErroCVSS(f"não foi possível interpretar o vetor: {erro}") from erro

    base, temporal, ambiental = c.scores()

    resultado = ResultadoCVSS(
        vetor=c.clean_vector(),
        score_base=float(base),
        severidade_base=Severidade.de_score(float(base)),
        metricas=_traduzir(normalizado),
        cve=cve.upper().strip(),
    )

    # A biblioteca sempre devolve os tres scores; sem metricas temporais ou
    # ambientais no vetor, eles apenas repetem o base. Reporta-los como se
    # fossem calculados daria falsa impressao de refinamento.
    vetor_maiusculo = normalizado.upper()
    if any(f"/{m}:" in vetor_maiusculo for m in METRICAS_TEMPORAIS):
        resultado.score_temporal = float(temporal)
        resultado.severidade_temporal = Severidade.de_score(float(temporal))

    if any(f"/{m}:" in vetor_maiusculo for m in ("CR", "IR", "AR", "MAV", "MAC",
                                                 "MPR", "MUI", "MS", "MC", "MI", "MA")):
        resultado.score_ambiental = float(ambiental)
        resultado.severidade_ambiental = Severidade.de_score(float(ambiental))

    if cve and not RE_CVE.match(cve.strip()):
        resultado.avisos.append(
            f"'{cve}' não está no formato CVE-AAAA-NNNN e não foi validado"
        )

    if resultado.score_temporal is None and resultado.score_ambiental is None:
        resultado.avisos.append(
            "apenas o score base foi calculado: o vetor não traz métricas "
            "temporais nem ambientais. Este é o score que a NVD publica"
        )

    logger.info("CVSS calculado: %s", resultado.resumo())
    return resultado


def calcular_de_componentes(
    av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str,
    cve: str = "",
) -> ResultadoCVSS:
    """Atalho: monta o vetor a partir das metricas e calcula."""
    return calcular(montar_vetor(av, ac, pr, ui, s, c, i, a), cve=cve)


def resumir_em_texto(resultado: ResultadoCVSS) -> str:
    """Rendericao em texto, para o CLI e o relatorio."""
    linhas: list[str] = []

    if resultado.cve:
        linhas.append(f"CVE    : {resultado.cve}")
    linhas.append(f"Vetor  : {resultado.vetor}")
    linhas.append(
        f"Base   : {resultado.score_base:.1f} ({resultado.severidade_base.value})"
    )

    if resultado.score_temporal is not None:
        linhas.append(
            f"Temporal: {resultado.score_temporal:.1f} "
            f"({resultado.severidade_temporal.value})"
        )
    if resultado.score_ambiental is not None:
        linhas.append(
            f"Ambiental: {resultado.score_ambiental:.1f} "
            f"({resultado.severidade_ambiental.value})"
        )

    linhas.append("")
    linhas.append("Métricas:")
    for m in resultado.metricas:
        linhas.append(f"  {m.sigla:3} {m.nome:26} {m.valor_legivel}")

    for aviso in resultado.avisos:
        linhas.append(f"\naviso: {aviso}")

    return "\n".join(linhas)
