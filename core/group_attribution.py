"""
Cruzamento das tecnicas observadas com os grupos catalogados no ATT&CK.

LEIA ISTO ANTES DE USAR O RESULTADO.

Isto nao e atribuicao. Atribuicao, no sentido de inteligencia, combina
infraestrutura, telemetria, temporalidade, vitimologia, linguagem, erros
operacionais e frequentemente fontes que nao sao tecnicas. Sobreposicao de
tecnicas ATT&CK e um sinal fraco entre muitos, e sozinha nao sustenta
conclusao nenhuma.

O que este modulo entrega e: "os grupos cujo repertorio publicamente
documentado e mais compativel com o que foi observado neste artefato". Isso
serve para orientar pesquisa - por onde comecar a procurar - e nao para
afirmar autoria.

Tres vieses estruturais que o resultado carrega e que nao podem ser
corrigidos por calculo nenhum:

  1. Repertorio grande vence. Um grupo com 200 tecnicas documentadas
     intersecta quase qualquer artefato. Grupos muito estudados (APT29,
     Lazarus) aparecem mais porque foram mais pesquisados, nao porque sao
     mais provaveis. A pontuacao abaixo tenta compensar isso, mas so em
     parte.
  2. Tecnica comum nao discrimina. "Injecao de processo" e usada por
     praticamente todo mundo; saber que o artefato injeta nao restringe
     nada. Por isso cada tecnica e ponderada pelo inverso de quantos
     grupos a usam, no mesmo espirito do IDF.
  3. O ATT&CK so documenta o que foi publicado. Grupo sem relatorio
     publico simplesmente nao existe aqui, e o verdadeiro autor pode ser
     um deles.

Por isso a saida e uma lista ordenada com a evidencia exposta, nunca um
veredito unico, e o nivel de confianca maximo possivel e deliberadamente
limitado.
"""

from __future__ import annotations

import logging
import math
from dataclasses import asdict, dataclass, field

from core.mitre_mapper import MitreAttack, ResultadoMapeamento
from core.string_extractor import Confianca

logger = logging.getLogger(__name__)


# Abaixo desta pontuacao o grupo nao e reportado: e ruido estatistico.
PONTUACAO_MINIMA = 0.15

# Quantos grupos reportar no maximo.
MAXIMO_DE_GRUPOS = 10

# Numero minimo de tecnicas em comum para o grupo ser considerado.
# Uma unica tecnica coincidente nao significa nada.
MINIMO_DE_TECNICAS_EM_COMUM = 2

# Sub-tecnica observada casando com a tecnica-pai do grupo (ou o contrario)
# conta, mas vale menos que um casamento exato.
PESO_CASAMENTO_PARCIAL = 0.5


@dataclass
class TecnicaEmComum:
    """Uma tecnica que tanto o artefato quanto o grupo apresentam."""

    tecnica_id: str
    nome: str
    # True quando o casamento foi exato; False quando foi via tecnica-pai.
    exato: bool
    # Quantos grupos do ATT&CK usam esta tecnica. Quanto menor, mais ela
    # discrimina.
    grupos_que_usam: int
    # Peso desta tecnica na pontuacao final.
    peso: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GrupoCandidato:
    """Um intrusion-set compativel com o que foi observado."""

    grupo_id: str  # G0016
    nome: str  # APT29
    aliases: list[str] = field(default_factory=list)
    url: str = ""

    tecnicas_em_comum: list[TecnicaEmComum] = field(default_factory=list)
    # Total de tecnicas que o grupo tem documentadas no ATT&CK.
    tecnicas_do_grupo: int = 0

    # Quanto do que observamos o grupo cobre (0.0 a 1.0).
    cobertura: float = 0.0
    # Quanto do repertorio do grupo aparece aqui (0.0 a 1.0). Baixo indica
    # que o grupo e grande e a sobreposicao pode ser coincidencia.
    especificidade: float = 0.0
    # Pontuacao final, ja ponderada pela raridade das tecnicas.
    pontuacao: float = 0.0

    confianca: Confianca = Confianca.BAIXA
    observacoes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ResultadoAtribuicao:
    """Saida do modulo."""

    candidatos: list[GrupoCandidato] = field(default_factory=list)
    # Tecnicas observadas que nenhum grupo catalogado usa.
    tecnicas_sem_grupo: list[str] = field(default_factory=list)
    total_de_grupos_avaliados: int = 0
    avisos: list[str] = field(default_factory=list)
    # Repetido aqui para acompanhar o resultado onde quer que ele va.
    ressalva: str = (
        "Sobreposicao de tecnicas ATT&CK nao e atribuicao. O resultado "
        "indica quais grupos tem repertorio documentado compativel com o "
        "artefato, o que serve para orientar pesquisa, nunca para afirmar "
        "autoria."
    )

    @property
    def melhor(self) -> GrupoCandidato | None:
        return self.candidatos[0] if self.candidatos else None

    def resumo(self) -> dict:
        return {
            "candidatos": len(self.candidatos),
            "avaliados": self.total_de_grupos_avaliados,
            "melhor": self.melhor.nome if self.melhor else None,
            "pontuacao": round(self.melhor.pontuacao, 3) if self.melhor else 0.0,
        }

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================
# Indice de grupos
# ============================================================


def _indexar_grupos(attack: MitreAttack) -> dict[str, set[str]]:
    """
    Monta o indice grupo -> conjunto de tecnicas.

    Percorre as relacoes "uses" do bundle uma unica vez. Fazer uma consulta
    por tecnica seria O(tecnicas x objetos) e o bundle real tem dezenas de
    milhares de objetos.
    """
    if attack._dados is None:
        return {}

    objetos = attack._dados.get("objects", [])
    por_stix_id = {o.get("id"): o for o in objetos}

    def attack_id_de(obj: dict) -> str:
        for referencia in obj.get("external_references", []):
            if referencia.get("source_name") == "mitre-attack":
                return referencia.get("external_id", "")
        return ""

    indice: dict[str, set[str]] = {}

    for obj in objetos:
        if (
            obj.get("type") != "relationship"
            or obj.get("relationship_type") != "uses"
        ):
            continue

        origem = por_stix_id.get(obj.get("source_ref"))
        alvo = por_stix_id.get(obj.get("target_ref"))

        if not origem or not alvo:
            continue
        if origem.get("type") != "intrusion-set" or alvo.get("type") != "attack-pattern":
            continue

        grupo_id = attack_id_de(origem)
        tecnica_id = attack_id_de(alvo)
        if grupo_id and tecnica_id:
            indice.setdefault(grupo_id, set()).add(tecnica_id)

    return indice


def _frequencia_das_tecnicas(indice: dict[str, set[str]]) -> dict[str, int]:
    """Quantos grupos usam cada tecnica."""
    frequencia: dict[str, int] = {}
    for tecnicas in indice.values():
        for t in tecnicas:
            frequencia[t] = frequencia.get(t, 0) + 1
    return frequencia


def _peso_por_raridade(tecnica_id: str, frequencia: dict[str, int], total: int) -> float:
    """
    Peso da tecnica pelo inverso da sua frequencia entre os grupos.

    Mesma ideia do IDF: tecnica que todo mundo usa nao ajuda a distinguir
    ninguem. Normalizado para a faixa 0.0-1.0, onde 1.0 e uma tecnica que
    so um grupo usa.
    """
    usos = frequencia.get(tecnica_id, 0)
    if usos <= 0 or total <= 0:
        return 0.0
    return math.log(1 + total / usos) / math.log(1 + total)


def _casar(
    observadas: set[str],
    do_grupo: set[str],
) -> list[tuple[str, bool]]:
    """
    Casa as tecnicas observadas com as do grupo.

    Devolve [(tecnica_id, exato)]. O casamento parcial cobre o caso comum de
    o ATT&CK documentar o grupo na tecnica-pai (T1055) enquanto a analise
    identificou a sub-tecnica (T1055.012), e vice-versa. Ignorar isso
    perderia sobreposicao real.
    """
    casamentos: list[tuple[str, bool]] = []
    pais_do_grupo = {t.split(".")[0] for t in do_grupo}

    for tecnica in observadas:
        if tecnica in do_grupo:
            casamentos.append((tecnica, True))
        elif tecnica.split(".")[0] in pais_do_grupo:
            casamentos.append((tecnica, False))

    return casamentos


def _confianca_de(candidato: GrupoCandidato) -> Confianca:
    """
    Nivel de confianca do candidato.

    O teto e MEDIA de proposito. Nenhuma sobreposicao de tecnicas, por
    melhor que seja, justifica confianca alta em atribuicao - isso exigiria
    evidencia de outra natureza, que este framework nao tem.
    """
    exatos = sum(1 for t in candidato.tecnicas_em_comum if t.exato)

    if candidato.pontuacao >= 0.45 and exatos >= 3:
        return Confianca.MEDIA
    return Confianca.BAIXA


def atribuir(
    mapeamento: ResultadoMapeamento,
    attack: MitreAttack | None,
    maximo: int = MAXIMO_DE_GRUPOS,
) -> ResultadoAtribuicao:
    """
    Lista os grupos cujo repertorio e compativel com as tecnicas observadas.

    Args:
        mapeamento: saida do mitre_mapper.
        attack: STIX carregado. Sem ele nao ha o que cruzar, e o resultado
            volta vazio com o aviso correspondente.
        maximo: quantos candidatos reportar.

    Returns:
        ResultadoAtribuicao ordenado por pontuacao decrescente.
    """
    resultado = ResultadoAtribuicao()

    if attack is None or not attack.carregado:
        resultado.avisos.append(
            "STIX do ATT&CK nao carregado: atribuicao de grupo requer o "
            "bundle oficial, que contem os intrusion-sets"
        )
        return resultado

    observadas = {t.tecnica_id for t in mapeamento.tecnicas}
    if not observadas:
        resultado.avisos.append("nenhuma tecnica foi mapeada: nada a cruzar")
        return resultado

    nomes_observados = {t.tecnica_id: t.nome for t in mapeamento.tecnicas}

    indice = _indexar_grupos(attack)
    resultado.total_de_grupos_avaliados = len(indice)

    if not indice:
        resultado.avisos.append(
            "o bundle carregado nao contem relacoes grupo-tecnica"
        )
        return resultado

    frequencia = _frequencia_das_tecnicas(indice)
    total_de_grupos = len(indice)

    # Peso total do que foi observado, usado para normalizar a cobertura.
    peso_observado = sum(
        _peso_por_raridade(t, frequencia, total_de_grupos) for t in observadas
    ) or 1.0

    for grupo_id, tecnicas_do_grupo in indice.items():
        casamentos = _casar(observadas, tecnicas_do_grupo)

        if len(casamentos) < MINIMO_DE_TECNICAS_EM_COMUM:
            continue

        em_comum: list[TecnicaEmComum] = []
        peso_acumulado = 0.0

        for tecnica_id, exato in casamentos:
            peso_base = _peso_por_raridade(tecnica_id, frequencia, total_de_grupos)
            peso = peso_base if exato else peso_base * PESO_CASAMENTO_PARCIAL
            peso_acumulado += peso

            em_comum.append(
                TecnicaEmComum(
                    tecnica_id=tecnica_id,
                    nome=nomes_observados.get(tecnica_id, ""),
                    exato=exato,
                    grupos_que_usam=frequencia.get(tecnica_id, 0),
                    peso=round(peso, 4),
                )
            )

        obj = attack.objeto(grupo_id) or {}

        candidato = GrupoCandidato(
            grupo_id=grupo_id,
            nome=obj.get("name", grupo_id),
            aliases=list(obj.get("aliases", [])),
            tecnicas_em_comum=sorted(em_comum, key=lambda t: -t.peso),
            tecnicas_do_grupo=len(tecnicas_do_grupo),
            cobertura=round(peso_acumulado / peso_observado, 4),
            especificidade=round(len(casamentos) / len(tecnicas_do_grupo), 4),
        )

        for referencia in obj.get("external_references", []):
            if referencia.get("source_name") == "mitre-attack" and referencia.get("url"):
                candidato.url = referencia["url"]
                break

        # A pontuacao e a media geometrica entre cobertura e especificidade.
        # A media geometrica, e nao a aritmetica, porque ela pune o
        # desequilibrio: um grupo enorme que cobre tudo o que vimos mas do
        # qual vimos 2% do repertorio nao deve pontuar como um grupo cujo
        # repertorio inteiro e compativel.
        candidato.pontuacao = round(
            math.sqrt(candidato.cobertura * candidato.especificidade), 4
        )
        candidato.confianca = _confianca_de(candidato)

        # --- Observacoes que contextualizam o numero ---
        if candidato.tecnicas_do_grupo > 100:
            candidato.observacoes.append(
                f"grupo com repertorio grande ({candidato.tecnicas_do_grupo} "
                "tecnicas documentadas): tende a intersectar qualquer artefato"
            )
        if candidato.especificidade < 0.05:
            candidato.observacoes.append(
                "menos de 5% do repertorio do grupo aparece aqui: "
                "sobreposicao pode ser coincidencia"
            )
        if all(not t.exato for t in candidato.tecnicas_em_comum):
            candidato.observacoes.append(
                "todos os casamentos foram via tecnica-pai, nenhum exato"
            )

        if candidato.pontuacao >= PONTUACAO_MINIMA:
            resultado.candidatos.append(candidato)

    resultado.candidatos.sort(key=lambda c: -c.pontuacao)
    resultado.candidatos = resultado.candidatos[:maximo]

    # Tecnicas que nenhum grupo catalogado usa: ou sao muito novas, ou o
    # artefato nao se parece com nada documentado.
    usadas_por_alguem = set(frequencia)
    resultado.tecnicas_sem_grupo = sorted(observadas - usadas_por_alguem)

    if resultado.tecnicas_sem_grupo:
        resultado.avisos.append(
            "tecnicas observadas que nenhum grupo do ATT&CK tem documentadas: "
            + ", ".join(resultado.tecnicas_sem_grupo)
        )

    if len(observadas) < 5:
        resultado.avisos.append(
            f"apenas {len(observadas)} tecnicas observadas: base estreita "
            "demais para qualquer comparacao significativa"
        )

    logger.info("atribuicao concluida: %s", resultado.resumo())
    return resultado


def resumir_em_texto(resultado: ResultadoAtribuicao) -> str:
    """Rendericao em texto, para o CLI e o relatorio."""
    linhas = [resultado.ressalva, ""]

    if not resultado.candidatos:
        linhas.append("Nenhum grupo com sobreposicao significativa.")
        for aviso in resultado.avisos:
            linhas.append(f"  aviso: {aviso}")
        return "\n".join(linhas)

    for i, c in enumerate(resultado.candidatos, 1):
        linhas.append(
            f"{i}. {c.nome} ({c.grupo_id})  pontuacao {c.pontuacao:.3f}  "
            f"[{c.confianca.value}]"
        )
        linhas.append(
            f"     cobertura {c.cobertura:.2f} | especificidade "
            f"{c.especificidade:.2f} | {len(c.tecnicas_em_comum)} de "
            f"{c.tecnicas_do_grupo} tecnicas do grupo"
        )
        if c.aliases:
            linhas.append(f"     aliases: {', '.join(c.aliases[:6])}")
        for t in c.tecnicas_em_comum[:5]:
            marca = "=" if t.exato else "~"
            linhas.append(
                f"     {marca} {t.tecnica_id:10} peso {t.peso:.3f} "
                f"(usada por {t.grupos_que_usam} grupos)"
            )
        for obs in c.observacoes:
            linhas.append(f"     ! {obs}")
        linhas.append("")

    for aviso in resultado.avisos:
        linhas.append(f"aviso: {aviso}")

    return "\n".join(linhas)
