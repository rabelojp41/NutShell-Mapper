"""
Exportacao de indicadores em formato consumivel por outras ferramentas.

O relatorio serve para uma pessoa ler. Mas um indicador so vira defesa
quando chega a um bloqueio, a uma regra de SIEM ou a uma plataforma de
compartilhamento - e para isso ele precisa sair daqui em formato que a
maquina do outro lado entenda.

Tres formatos, cada um para um destino:

  - CSV       : o denominador comum. Abre em planilha, importa em qualquer
                SIEM, cola numa lista de bloqueio. Feio e universal.
  - STIX 2.1  : o padrao de compartilhamento de CTI (OASIS). E o que MISP,
                OpenCTI e feeds comerciais falam entre si.
  - MISP      : JSON de evento, para quem usa MISP direto.

O QUE E EXPORTADO, E O QUE NAO E

So indicadores de confianca ALTA e MEDIA saem por padrao. Os de confianca
baixa existem para o analista julgar - alimentar um bloqueio automatico com
"1.1.0.14, provavel numero de versao" produziria incidente, nao defesa. O
filtro e ajustavel, mas o padrao e conservador de proposito.

Indicador de caminho de arquivo e chave de registro nao viram padrao STIX
de rede: eles descrevem o hospedeiro, nao trafego, e um bloqueio de borda
nao faz nada com eles. Continuam no CSV, que e descritivo, e viram
observacao no STIX.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core.string_extractor import IOC, Confianca, TipoIOC

logger = logging.getLogger(__name__)


# Confianca minima para um indicador ser exportado. Baixa fica de fora:
# ela existe para o analista olhar, nao para alimentar bloqueio automatico.
CONFIANCA_MINIMA_PADRAO = Confianca.MEDIA

_PESO = {Confianca.ALTA: 3, Confianca.MEDIA: 2, Confianca.BAIXA: 1}

# Tipo de IOC -> como ele se expressa num padrao STIX.
# Os que descrevem o hospedeiro (caminho, chave de registro) nao tem padrao
# de rede util e ficam de fora do STIX, com aviso.
PADRAO_STIX = {
    TipoIOC.IPV4: "[ipv4-addr:value = '{valor}']",
    TipoIOC.IPV6: "[ipv6-addr:value = '{valor}']",
    TipoIOC.DOMINIO: "[domain-name:value = '{valor}']",
    TipoIOC.URL: "[url:value = '{valor}']",
    TipoIOC.EMAIL: "[email-addr:value = '{valor}']",
    TipoIOC.BITCOIN: "[x-cryptocurrency-wallet:address = '{valor}']",
}

# Hash nao entra no mapa acima porque o padrao depende do valor, nao do
# tipo: o extrator classifica MD5, SHA1 e SHA256 todos como TipoIOC.HASH, e
# e o comprimento que diz qual e qual. Exportar um SHA256 rotulado como MD5
# faz o MISP recusar o atributo na importacao - ele valida o valor contra o
# tipo declarado - e faz o padrao STIX nunca casar.
ALGORITMO_POR_COMPRIMENTO = {32: "md5", 40: "sha1", 64: "sha256"}

# Nome do algoritmo como o STIX 2.1 o escreve (hifenizado) e como o MISP o
# escreve (nome do tipo de atributo).
HASH_STIX = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}


def _algoritmo_do_hash(valor: str) -> str | None:
    """Deduz o algoritmo pelo comprimento. None quando nao reconhece."""
    return ALGORITMO_POR_COMPRIMENTO.get(len(valor.strip()))

# Tipo de IOC -> tipo de atributo no MISP.
ATRIBUTO_MISP = {
    TipoIOC.IPV4: ("ip-dst", "Network activity"),
    TipoIOC.IPV6: ("ip-dst", "Network activity"),
    TipoIOC.DOMINIO: ("domain", "Network activity"),
    TipoIOC.URL: ("url", "Network activity"),
    TipoIOC.EMAIL: ("email-src", "Network activity"),
    TipoIOC.CAMINHO_WINDOWS: ("filename", "Artifacts dropped"),
    TipoIOC.CAMINHO_UNC: ("filename", "Artifacts dropped"),
    TipoIOC.CHAVE_REGISTRO: ("regkey", "Persistence mechanism"),
    # TipoIOC.HASH e resolvido em _algoritmo_do_hash: o tipo do atributo
    # depende do comprimento do valor, nao do tipo do IOC.
    TipoIOC.BITCOIN: ("btc", "Financial fraud"),
    TipoIOC.CVE: ("vulnerability", "External analysis"),
}


class ErroExportacao(Exception):
    """Nao foi possivel exportar os indicadores."""


@dataclass
class ResultadoExportacao:
    """O que foi exportado, e o que ficou de fora."""

    caminho: Path
    formato: str
    exportados: int = 0
    # Indicadores descartados pelo filtro de confianca.
    descartados_por_confianca: int = 0
    # Indicadores sem representacao no formato de destino.
    sem_representacao: list[str] = None

    def __post_init__(self):
        if self.sem_representacao is None:
            self.sem_representacao = []

    def to_dict(self) -> dict:
        return {
            "caminho": str(self.caminho),
            "formato": self.formato,
            "exportados": self.exportados,
            "descartados_por_confianca": self.descartados_por_confianca,
            "sem_representacao": self.sem_representacao,
        }


def _filtrar(
    iocs: list[IOC], confianca_minima: Confianca
) -> tuple[list[IOC], int]:
    """Aplica o corte de confianca. Devolve (aceitos, quantos sairam)."""
    minimo = _PESO[confianca_minima]
    aceitos = [i for i in iocs if _PESO[i.confianca] >= minimo]
    return aceitos, len(iocs) - len(aceitos)


def _agora() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ============================================================
# CSV
# ============================================================


def exportar_csv(
    resultado,
    destino: str | Path,
    confianca_minima: Confianca = CONFIANCA_MINIMA_PADRAO,
) -> ResultadoExportacao:
    """
    Exporta em CSV.

    O formato mais burro e o mais util: abre em planilha, importa em
    qualquer SIEM, cola numa lista de bloqueio. Leva todos os tipos de
    indicador, inclusive os que nao tem padrao STIX.
    """
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)

    iocs, descartados = _filtrar(resultado.iocs, confianca_minima)

    with destino.open("w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.writer(arquivo)
        escritor.writerow(
            [
                "valor",
                "tipo",
                "confianca",
                "observacao",
                "origem_string",
                "tipo_de_string",
                "artefato_sha256",
                "artefato_nome",
                "analisado_em",
            ]
        )
        for i in iocs:
            escritor.writerow(
                [
                    i.valor,
                    i.tipo.value,
                    i.confianca.value,
                    i.observacao,
                    # A string de origem da o contexto: sem ela, um
                    # indicador isolado nao e verificavel por quem recebe.
                    i.origem[:200],
                    i.tipo_string.value,
                    resultado.sha256,
                    Path(resultado.caminho).name,
                    resultado.iniciado_em,
                ]
            )

    logger.info("CSV com %d indicadores em %s", len(iocs), destino)
    return ResultadoExportacao(
        caminho=destino,
        formato="csv",
        exportados=len(iocs),
        descartados_por_confianca=descartados,
    )


# ============================================================
# STIX 2.1
# ============================================================


def exportar_stix(
    resultado,
    destino: str | Path,
    confianca_minima: Confianca = CONFIANCA_MINIMA_PADRAO,
) -> ResultadoExportacao:
    """
    Exporta como bundle STIX 2.1.

    E o formato que MISP, OpenCTI e feeds comerciais trocam entre si. O
    bundle sai com um objeto por indicador, mais um `malware` descrevendo o
    artefato analisado e as relacoes entre eles - assim quem recebe sabe
    que os indicadores vieram todos da mesma amostra, e nao de uma lista
    solta.
    """
    try:
        from stix2 import (
            Bundle,
            ExternalReference,
            Indicator,
            Malware,
            Relationship,
            Vulnerability,
        )
    except ImportError as erro:
        raise ErroExportacao(
            f"a biblioteca stix2 nao esta disponivel ({erro})"
        ) from erro

    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)

    iocs, descartados = _filtrar(resultado.iocs, confianca_minima)
    nome = Path(resultado.caminho).name

    # O artefato como objeto proprio. "is_family=False" porque isto e uma
    # amostra especifica, nao uma familia de malware - e a analise estatica
    # nao afirma sequer que seja malicioso.
    artefato = Malware(
        name=f"Artefato analisado: {nome}",
        is_family=False,
        description=(
            f"Amostra SHA256 {resultado.sha256}. Indicadores extraidos por "
            "analise estatica com o RabMapper. A presenca de um indicador "
            "descreve o que foi encontrado no arquivo, nao comportamento "
            "observado em execucao."
        ),
    )

    objetos = [artefato]
    sem_representacao: list[str] = []

    for i in iocs:
        # CVE nao e um Indicator: indicador e padrao que se procura em
        # telemetria, e um numero de CVE nao se "detecta" numa rede. O STIX
        # tem um objeto proprio para isso, e usa-lo e o que faz o bundle
        # ser entendido corretamente por quem importa.
        if i.tipo is TipoIOC.CVE:
            vulnerabilidade = Vulnerability(
                name=i.valor,
                description=(
                    "Vulnerabilidade referenciada pelo artefato. A referencia "
                    "nao estabelece que o artefato explore a falha."
                ),
                external_references=[
                    ExternalReference(source_name="cve", external_id=i.valor)
                ],
            )
            objetos.append(vulnerabilidade)
            objetos.append(
                Relationship(
                    # "targets" e a relacao correta: o artefato mira a
                    # falha. "uses" implicaria exploracao comprovada, que a
                    # analise estatica nao estabelece.
                    relationship_type="targets",
                    source_ref=artefato.id,
                    target_ref=vulnerabilidade.id,
                    description="CVE citada nas strings do artefato",
                )
            )
            continue

        if i.tipo is TipoIOC.HASH:
            algoritmo = _algoritmo_do_hash(i.valor)
            if algoritmo is None:
                sem_representacao.append(
                    f"{i.tipo.value}: {i.valor} (comprimento nao reconhecido)"
                )
                continue
            # O STIX escreve o nome do algoritmo entre aspas dentro do
            # padrao, e ele e case-sensitive na forma hifenizada.
            modelo = (
                "[file:hashes.'" + HASH_STIX[algoritmo] + "' = '{valor}']"
            )
        else:
            modelo = PADRAO_STIX.get(i.tipo)

        if modelo is None:
            sem_representacao.append(f"{i.tipo.value}: {i.valor}")
            continue

        # Aspas simples no valor quebrariam o padrao STIX.
        valor = i.valor.replace("'", "\\'")

        indicador = Indicator(
            name=f"{i.tipo.value}: {i.valor[:60]}",
            pattern=modelo.format(valor=valor),
            pattern_type="stix",
            valid_from=_agora(),
            description=(
                f"Confianca da extracao: {i.confianca.value}."
                + (f" {i.observacao}" if i.observacao else "")
                + f" Encontrado em string do tipo {i.tipo_string.value}."
            ),
            # O STIX tem um campo de confianca de 0 a 100. O mapeamento e
            # grosseiro de proposito: a escala daqui tem tres niveis, e
            # fingir precisao maior seria inventar.
            confidence={Confianca.ALTA: 85, Confianca.MEDIA: 50}.get(i.confianca, 15),
            labels=["malicious-activity"],
        )
        objetos.append(indicador)
        objetos.append(
            Relationship(
                relationship_type="indicates",
                source_ref=indicador.id,
                target_ref=artefato.id,
            )
        )

    bundle = Bundle(objects=objetos, allow_custom=True)
    destino.write_text(bundle.serialize(indent=2), encoding="utf-8")

    quantidade = sum(1 for o in objetos if o.type in ("indicator", "vulnerability"))
    logger.info("STIX com %d indicadores em %s", quantidade, destino)

    return ResultadoExportacao(
        caminho=destino,
        formato="stix",
        exportados=quantidade,
        descartados_por_confianca=descartados,
        sem_representacao=sem_representacao,
    )


# ============================================================
# MISP
# ============================================================


def exportar_misp(
    resultado,
    destino: str | Path,
    confianca_minima: Confianca = CONFIANCA_MINIMA_PADRAO,
) -> ResultadoExportacao:
    """
    Exporta como evento MISP.

    Formato de importacao direta no MISP. O evento sai com
    `to_ids: false` para os indicadores de confianca media: `to_ids` marca
    um atributo como pronto para virar regra de deteccao automatica, e so
    o que tem confianca alta merece isso sem revisao humana.
    """
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)

    iocs, descartados = _filtrar(resultado.iocs, confianca_minima)
    nome = Path(resultado.caminho).name

    atributos = []
    sem_representacao: list[str] = []

    # O hash do proprio artefato entra como atributo, e e o unico que
    # identifica a amostra de forma inequivoca.
    if resultado.sha256:
        atributos.append(
            {
                "type": "sha256",
                "category": "Payload delivery",
                "value": resultado.sha256,
                "to_ids": True,
                "comment": f"Artefato analisado: {nome}",
            }
        )

    for i in iocs:
        if i.tipo is TipoIOC.HASH:
            algoritmo = _algoritmo_do_hash(i.valor)
            if algoritmo is None:
                sem_representacao.append(
                    f"{i.tipo.value}: {i.valor} (comprimento nao reconhecido)"
                )
                continue
            mapeado = (algoritmo, "Payload delivery")
        else:
            mapeado = ATRIBUTO_MISP.get(i.tipo)

        if mapeado is None:
            sem_representacao.append(f"{i.tipo.value}: {i.valor}")
            continue

        tipo_misp, categoria = mapeado
        atributos.append(
            {
                "type": tipo_misp,
                "category": categoria,
                "value": i.valor,
                # So confianca alta vira regra automatica sem revisao.
                "to_ids": i.confianca is Confianca.ALTA,
                "comment": (
                    f"confianca {i.confianca.value}"
                    + (f" — {i.observacao}" if i.observacao else "")
                ),
            }
        )

    evento = {
        "Event": {
            "info": f"RabMapper — analise estatica de {nome}",
            "date": (resultado.iniciado_em or _agora())[:10],
            # 2 = "Possibly false" na escala do MISP. Analise estatica
            # automatizada nao justifica nivel maior sem revisao humana.
            "analysis": "1",
            "threat_level_id": "3",
            "published": False,
            "Attribute": atributos,
            "Tag": [
                {"name": 'rabmapper:origem="analise-estatica"'},
                {"name": 'estimative-language:confidence-in-analytic-judgment="moderate"'},
            ],
        }
    }

    destino.write_text(
        json.dumps(evento, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    logger.info("evento MISP com %d atributos em %s", len(atributos), destino)
    return ResultadoExportacao(
        caminho=destino,
        formato="misp",
        exportados=len(atributos),
        descartados_por_confianca=descartados,
        sem_representacao=sem_representacao,
    )


FORMATOS = {
    "csv": exportar_csv,
    "stix": exportar_stix,
    "misp": exportar_misp,
}


def exportar(
    resultado,
    diretorio: str | Path,
    formatos: list[str] | None = None,
    confianca_minima: Confianca = CONFIANCA_MINIMA_PADRAO,
    nome_base: str = "",
) -> dict[str, ResultadoExportacao]:
    """
    Exporta os indicadores nos formatos pedidos.

    Args:
        resultado: saida do pipeline.
        diretorio: onde gravar.
        formatos: entre "csv", "stix" e "misp". Padrao: apenas CSV.
        confianca_minima: corte. O padrao deixa de fora a confianca baixa.
        nome_base: nome dos arquivos, sem extensao.

    Returns:
        formato -> ResultadoExportacao. Formato que falhou nao aparece.
    """
    formatos = formatos or ["csv"]
    diretorio = Path(diretorio)

    if not nome_base:
        nome_base = Path(resultado.caminho).stem
        if resultado.sha256:
            nome_base = f"{nome_base}_{resultado.sha256[:8]}"

    extensao = {"csv": "csv", "stix": "json", "misp": "json"}
    sufixo = {"csv": "", "stix": "_stix", "misp": "_misp"}

    saidas: dict[str, ResultadoExportacao] = {}

    for formato in formatos:
        chave = formato.lower().strip()
        funcao = FORMATOS.get(chave)

        if funcao is None:
            logger.warning("formato de exportacao desconhecido: %s", formato)
            continue

        caminho = diretorio / f"{nome_base}{sufixo[chave]}.{extensao[chave]}"
        try:
            saidas[chave] = funcao(resultado, caminho, confianca_minima)
        except Exception as erro:
            # Falta do stix2 nao pode impedir a exportacao do CSV.
            logger.error("falha ao exportar %s: %s", chave, erro)

    return saidas
