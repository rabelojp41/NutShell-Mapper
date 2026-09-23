"""
Geracao do relatorio de analise em PDF, DOCX, Markdown e JSON.

O relatorio e o produto final: e o que alguem que nao rodou a ferramenta vai
ler. Por isso duas escolhas editoriais atravessam o modulo inteiro:

  1. O que nao foi analisado aparece. Etapa que falhou, consulta que nao foi
     feita, STIX que nao carregou - tudo vira secao visivel. Relatorio que
     omite o que faltou passa impressao de completude que ele nao tem, e
     quem le nao consegue calibrar a confianca.

  2. Evidencia acompanha conclusao. Nenhuma tecnica ATT&CK aparece sem o
     que a disparou; nenhum grupo aparece sem a ressalva de que
     sobreposicao de tecnicas nao e atribuicao. O relatorio descreve o que
     foi observado, nao o que se concluiu.

Formatos:
  - JSON     : a saida completa, para automacao e para reprocessar depois.
  - Markdown : legivel no terminal e no GitHub, sem dependencia.
  - PDF      : via ReportLab, para anexar em ticket ou enviar.
  - DOCX     : via python-docx, para quem precisa editar o texto depois.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core.pipeline import ResultadoAnalise
from core.string_extractor import Confianca

logger = logging.getLogger(__name__)


# Quantos itens de cada lista longa entram no relatorio. Despejar 400
# strings num PDF nao ajuda ninguem a ler.
LIMITE_IOCS = 60
LIMITE_STRINGS = 40
LIMITE_ACHADOS = 30
LIMITE_DETECCOES_VT = 15

# Cores por nivel de confianca, usadas no PDF.
COR_POR_CONFIANCA = {
    Confianca.ALTA: "#b3261e",
    Confianca.MEDIA: "#b35c00",
    Confianca.BAIXA: "#5f6368",
}


class ErroRelatorio(Exception):
    """Nao foi possivel gerar o relatorio."""


@dataclass
class Secao:
    """Uma secao do relatorio, ja montada como texto."""

    titulo: str
    linhas: list[str]

    @property
    def vazia(self) -> bool:
        return not self.linhas


# ============================================================
# Montagem do conteudo (independente do formato de saida)
# ============================================================


def _sim_nao(valor: bool) -> str:
    return "sim" if valor else "não"


def _data_legivel(iso: str) -> str:
    """Converte ISO 8601 para algo que se le num relatorio."""
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%d/%m/%Y %H:%M UTC")
    except ValueError:
        return iso


def _tabela(cabecalho: list[str], linhas: list[list[str]]) -> list[str]:
    """Monta uma tabela em Markdown."""
    if not linhas:
        return []
    saida = ["| " + " | ".join(cabecalho) + " |"]
    saida.append("|" + "|".join(["---"] * len(cabecalho)) + "|")
    for linha in linhas:
        celulas = [str(c).replace("|", "\\|").replace("\n", " ") for c in linha]
        saida.append("| " + " | ".join(celulas) + " |")
    return saida


def _secao_identificacao(r: ResultadoAnalise) -> Secao:
    linhas = ["### Artefato", ""]
    caminho = Path(r.caminho)

    dados = [
        ["Arquivo", caminho.name],
        ["Tamanho", f"{r.extracao.tamanho_bytes:,} bytes" if r.extracao else "-"],
        ["SHA256", r.extracao.sha256 if r.extracao else "-"],
        ["MD5", r.extracao.md5 if r.extracao else "-"],
    ]

    if r.info_pe and r.info_pe.e_pe:
        dados.extend(
            [
                ["Formato", f"PE {r.info_pe.tipo} {r.info_pe.arquitetura}"],
                ["Imphash", r.info_pe.imphash or "-"],
                ["Compilado em", _data_legivel(r.info_pe.timestamp_compilacao)],
            ]
        )
    elif r.info_pe:
        dados.append(["Formato", f"não é PE ({r.info_pe.erro})"])

    dados.extend(
        [
            ["Analisado em", _data_legivel(r.iniciado_em)],
            ["Duração", f"{r.duracao_segundos:.1f}s"],
        ]
    )

    linhas.extend(_tabela(["Campo", "Valor"], dados))

    if r.info_pe and r.info_pe.e_pe and r.info_pe.timestamp_compilacao:
        linhas += [
            "",
            "> O timestamp de compilação é frequentemente falsificado por "
            "malware. Vale como indício, não como fato.",
        ]

    return Secao("Identificação", linhas)


def _secao_sumario(r: ResultadoAnalise) -> Secao:
    """Sumario executivo: o que foi observado, em uma tela."""
    linhas = ["### Sumário", ""]
    resumo = r.resumo()

    dados = [
        ["Strings extraídas", resumo["strings"]],
        ["IOCs identificados", resumo["iocs"]],
        ["Achados de desofuscação", resumo["achados_desofuscacao"]],
        ["Técnicas ATT&CK", resumo["tecnicas"]],
        ["Regra YARA válida", _sim_nao(resumo["yara_valida"])],
    ]

    if r.mapeamento:
        altas = r.mapeamento.com_confianca_minima(Confianca.ALTA)
        dados.append(["Técnicas de alta confiança", len(altas)])
    if r.kill_chain:
        dados.append(
            [
                "Estágios da Kill Chain cobertos",
                f"{len(r.kill_chain.estagios_cobertos)} de 7",
            ]
        )
    if r.virustotal:
        arquivo = next((v for v in r.virustotal if v.tipo == "arquivo"), None)
        if arquivo:
            dados.append(["VirusTotal (hash)", arquivo.resumo_de_deteccao])
    if r.cvss:
        dados.append(
            [
                "CVSS",
                f"{r.cvss.score_efetivo:.1f} ({r.cvss.severidade_efetiva.value})",
            ]
        )

    linhas.extend(_tabela(["Indicador", "Valor"], dados))

    if r.extracao and not r.extracao.usou_floss:
        linhas += [
            "",
            "> O FLOSS não foi usado nesta análise. Apenas strings estáticas "
            "foram recuperadas; strings montadas em runtime (stack, tight, "
            "decoded) não aparecem.",
        ]

    return Secao("Sumário", linhas)


def _secao_iocs(r: ResultadoAnalise) -> Secao:
    iocs = r.iocs
    if not iocs:
        return Secao("Indicadores", ["### Indicadores", "", "Nenhum IOC identificado."])

    linhas = ["### Indicadores de comprometimento", ""]

    ordem = {Confianca.ALTA: 0, Confianca.MEDIA: 1, Confianca.BAIXA: 2}
    ordenados = sorted(iocs, key=lambda i: (ordem[i.confianca], i.tipo.value, i.valor))

    dados = [
        [i.confianca.value, i.tipo.value, i.valor[:90], i.observacao[:60] or "-"]
        for i in ordenados[:LIMITE_IOCS]
    ]
    linhas.extend(_tabela(["Confiança", "Tipo", "Valor", "Observação"], dados))

    if len(ordenados) > LIMITE_IOCS:
        linhas += ["", f"_({len(ordenados) - LIMITE_IOCS} indicadores omitidos; "
                       "a saída JSON traz todos.)_"]

    linhas += [
        "",
        "> A confiança reflete quão inequívoco é o formato e o contexto do "
        "indicador, não se ele é malicioso. Um domínio de alta confiança é um "
        "domínio bem identificado, que pode ser perfeitamente legítimo.",
    ]

    return Secao("Indicadores", linhas)


def _secao_desofuscacao(r: ResultadoAnalise) -> Secao:
    if r.desofuscacao is None:
        return Secao("Desofuscação", [])

    linhas = ["### Desofuscação", ""]

    if not r.desofuscacao.achados:
        linhas += [
            f"Nenhuma ofuscação detectada em {r.desofuscacao.candidatos_avaliados} "
            "candidatos avaliados.",
        ]
        return Secao("Desofuscação", linhas)

    dados = [
        [f"{a.pontuacao:.2f}", a.cadeia, a.original[:40], a.decodificado[:70]]
        for a in r.desofuscacao.achados[:LIMITE_ACHADOS]
    ]
    linhas.extend(_tabela(["Nota", "Cadeia", "Original", "Decodificado"], dados))

    if r.desofuscacao.iocs_revelados:
        linhas += ["", "**IOCs que só existiam atrás da ofuscação:**", ""]
        linhas.extend(
            _tabela(
                ["Tipo", "Valor"],
                [[i.tipo.value, i.valor[:90]] for i in r.desofuscacao.iocs_revelados],
            )
        )

    return Secao("Desofuscação", linhas)


def _secao_pe(r: ResultadoAnalise) -> Secao:
    if not r.info_pe or not r.info_pe.e_pe:
        return Secao("PE", [])

    linhas = ["### Estrutura do PE", "", "**Seções:**", ""]

    dados = [
        [
            s.nome,
            f"{s.entropia:.2f}",
            f"{s.tamanho_bruto:,}",
            ("X" if s.executavel else "") + ("W" if s.gravavel else "") or "-",
            "alta entropia" if s.alta_entropia else "",
        ]
        for s in r.info_pe.secoes
    ]
    linhas.extend(_tabela(["Seção", "Entropia", "Tamanho", "Flags", "Nota"], dados))

    if r.info_pe.imports:
        linhas += ["", "**DLLs importadas:** " + ", ".join(sorted(r.info_pe.imports))]
        linhas += [f"", f"Total de {len(r.info_pe.todas_as_apis())} funções importadas."]

    if r.info_pe.indicios:
        linhas += ["", "**Observações estruturais:**", ""]
        linhas.extend(f"- {d}" for d in r.info_pe.indicios)

    return Secao("PE", linhas)


def _secao_mitre(r: ResultadoAnalise) -> Secao:
    if r.mapeamento is None:
        return Secao("ATT&CK", [])

    linhas = ["### Técnicas MITRE ATT&CK", ""]

    if not r.mapeamento.tecnicas:
        linhas.append("Nenhuma técnica foi identificada com evidência suficiente.")
        return Secao("ATT&CK", linhas)

    fonte = (
        f"STIX oficial (versão {r.mapeamento.versao_attack})"
        if r.mapeamento.fonte == "stix"
        else "catálogo local (STIX não carregado)"
    )
    linhas += [f"Fonte dos metadados: {fonte}.", ""]

    for t in r.mapeamento.tecnicas:
        linhas.append(f"**{t.tecnica_id} — {t.nome}**  `[{t.confianca.value}]`")
        if t.descricao:
            linhas.append(f"  {t.descricao}")
        linhas.append(f"  Táticas: {', '.join(t.taticas)}")
        linhas.append("  Evidência:")
        for e in t.evidencias[:6]:
            linhas.append(f"    - {e.tipo.value}: `{e.trecho[:100]}`")
        linhas.append("")

    linhas += [
        "> Uma técnica listada significa que a **capacidade** foi observada no "
        "artefato, não que ela é efetivamente usada. Importar "
        "`CreateRemoteThread` prova que a função está na tabela de imports.",
    ]

    return Secao("ATT&CK", linhas)


def _secao_killchain(r: ResultadoAnalise) -> Secao:
    if r.kill_chain is None:
        return Secao("Kill Chain", [])

    linhas = ["### Cyber Kill Chain", ""]

    for estagio in r.kill_chain.estagios:
        nome = f"{estagio.estagio.ordem + 1}. {estagio.estagio.value}"
        if estagio.vazio:
            linhas.append(f"**{nome}** — sem evidência neste artefato")
        else:
            ids = ", ".join(f"`{t.tecnica_id}`" for t in estagio.tecnicas)
            linhas.append(f"**{nome}** — {ids}")

    linhas += [
        "",
        f"Cobertura: {len(r.kill_chain.estagios_cobertos)} de 7 estágios.",
        "",
        "> ATT&CK e Cyber Kill Chain são modelos diferentes e a tradução entre "
        "eles é aproximada. Estágio sem evidência significa que este artefato "
        "não mostra sinal dele, e não que a etapa não ocorreu na intrusão.",
    ]

    return Secao("Kill Chain", linhas)


def _secao_atribuicao(r: ResultadoAnalise) -> Secao:
    if r.atribuicao is None:
        return Secao("Atribuição", [])

    linhas = ["### Grupos com repertório compatível", "", f"> {r.atribuicao.ressalva}", ""]

    if not r.atribuicao.candidatos:
        linhas.append("Nenhum grupo com sobreposição significativa.")
        for aviso in r.atribuicao.avisos:
            linhas.append(f"- {aviso}")
        return Secao("Atribuição", linhas)

    dados = [
        [
            c.nome,
            c.grupo_id,
            f"{c.pontuacao:.3f}",
            f"{c.cobertura:.2f}",
            f"{c.especificidade:.2f}",
            f"{len(c.tecnicas_em_comum)}/{c.tecnicas_do_grupo}",
        ]
        for c in r.atribuicao.candidatos
    ]
    linhas.extend(
        _tabela(
            ["Grupo", "ID", "Pontuação", "Cobertura", "Especificidade", "Técnicas"],
            dados,
        )
    )

    for c in r.atribuicao.candidatos:
        if c.observacoes:
            linhas += ["", f"**{c.nome}:**"]
            linhas.extend(f"- {o}" for o in c.observacoes)

    return Secao("Atribuição", linhas)


def _secao_yara(r: ResultadoAnalise) -> Secao:
    if r.regra_yara is None:
        return Secao("YARA", [])

    linhas = ["### Regra YARA", ""]

    dados = [
        ["Compila", _sim_nao(r.regra_yara.compila)],
        ["Casa com a amostra", _sim_nao(r.regra_yara.casa_com_a_amostra)],
        ["Strings usadas", len(r.regra_yara.strings_usadas)],
        ["Limiar para casar", r.regra_yara.minimo_para_casar],
    ]
    if r.regra_yara.falsos_positivos:
        dados.append(["Falsos positivos", len(r.regra_yara.falsos_positivos)])

    linhas.extend(_tabela(["Validação", "Resultado"], dados))

    if r.regra_yara.avisos:
        linhas += ["", "**Avisos:**", ""]
        linhas.extend(f"- {a}" for a in r.regra_yara.avisos)

    linhas += ["", "```yara", r.regra_yara.texto.rstrip(), "```"]
    return Secao("YARA", linhas)


def _secao_cvss(r: ResultadoAnalise) -> Secao:
    if r.cvss is None:
        return Secao("CVSS", [])

    linhas = ["### Score CVSS 3.1", ""]

    dados = [["Vetor", r.cvss.vetor]]
    if r.cvss.cve:
        dados.insert(0, ["CVE", r.cvss.cve])
    dados.append(
        ["Base", f"{r.cvss.score_base:.1f} ({r.cvss.severidade_base.value})"]
    )
    if r.cvss.score_temporal is not None:
        dados.append(
            ["Temporal", f"{r.cvss.score_temporal:.1f} "
                        f"({r.cvss.severidade_temporal.value})"]
        )
    if r.cvss.score_ambiental is not None:
        dados.append(
            ["Ambiental", f"{r.cvss.score_ambiental:.1f} "
                          f"({r.cvss.severidade_ambiental.value})"]
        )

    linhas.extend(_tabela(["Campo", "Valor"], dados))
    linhas += ["", "**Leitura do vetor:**", ""]
    linhas.extend(
        _tabela(
            ["Métrica", "Valor"],
            [[m.nome, m.valor_legivel] for m in r.cvss.metricas],
        )
    )

    return Secao("CVSS", linhas)


def _secao_enriquecimento(r: ResultadoAnalise) -> Secao:
    # A NVD precisa entrar nesta condicao junto com os outros. Ela nao exige
    # chave de API, entao e comum ser a UNICA fonte com resultado - e quando
    # a condicao olhava so para VirusTotal e Shodan, a secao inteira era
    # descartada e levava junto a ressalva de que o score CVSS descreve a
    # vulnerabilidade citada, nao este arquivo. O relatorio saia com "10.0"
    # em destaque e sem nada explicando o numero, exatamente para quem nao
    # tem chave nenhuma configurada.
    if not r.virustotal and not r.shodan and not r.nvd:
        if not r.opcoes.enriquecer:
            return Secao(
                "Enriquecimento",
                [
                    "### Enriquecimento externo",
                    "",
                    "Não executado. Nenhum dado deste artefato foi enviado a "
                    "serviço de terceiros.",
                ],
            )
        return Secao("Enriquecimento", [])

    linhas = ["### Enriquecimento externo", ""]

    # --- VirusTotal ---
    if r.virustotal:
        linhas += ["**VirusTotal**", ""]
        dados = [
            [
                v.tipo,
                v.indicador[:60],
                v.resumo_de_deteccao,
                v.familia_sugerida or v.pais or "-",
                v.erro[:40] or "-",
            ]
            for v in r.virustotal
        ]
        linhas.extend(
            _tabela(["Tipo", "Indicador", "Detecção", "Contexto", "Erro"], dados)
        )

        arquivo = next((v for v in r.virustotal if v.tipo == "arquivo"), None)
        if arquivo and arquivo.deteccoes:
            linhas += ["", "Detecções por motor:", ""]
            itens = list(arquivo.deteccoes.items())[:LIMITE_DETECCOES_VT]
            linhas.extend(_tabela(["Motor", "Nome"], [[k, v] for k, v in itens]))

        for v in r.virustotal:
            for obs in v.observacoes:
                linhas.append(f"- `{v.indicador[:40]}`: {obs}")
        linhas.append("")

    # --- NVD ---
    if r.nvd:
        linhas += ["**NVD (vulnerabilidades citadas pelo artefato)**", ""]
        dados = [
            [
                n.cve,
                n.resumo,
                n.versao_cvss or "-",
                n.publicada_em or "-",
                (n.descricao[:70] + "...") if len(n.descricao) > 70 else (n.descricao or "-"),
            ]
            for n in r.nvd
        ]
        linhas.extend(
            _tabela(["CVE", "CVSS", "Versão", "Publicada", "Descrição"], dados)
        )
        linhas += [
            "",
            "> O artefato apenas REFERENCIA estas vulnerabilidades. Se ele as "
            "explora, e com que sucesso, a análise estática não determina - o "
            "score descreve a falha, não este arquivo.",
            "",
        ]

    # --- Shodan ---
    if r.shodan:
        linhas += ["**Shodan**", ""]
        dados = [
            [
                s.ip,
                s.resumo,
                ", ".join(str(p) for p in s.portas[:10]) or "-",
                s.organizacao[:30] or "-",
                s.pais or "-",
            ]
            for s in r.shodan
        ]
        linhas.extend(_tabela(["IP", "Estado", "Portas", "Organização", "País"], dados))

        for s in r.shodan:
            for obs in s.observacoes:
                linhas.append(f"- `{s.ip}`: {obs}")

    return Secao("Enriquecimento", linhas)


def _secao_resumo_ia(r: ResultadoAnalise) -> Secao:
    """
    Resumo em linguagem natural, gerado por LLM local.

    Vem depois do sumario de numeros e antes das secoes de evidencia: e
    apoio a leitura, nao fonte. Toda afirmacao verificavel dele foi
    conferida contra os achados, e o que nao tem respaldo aparece listado
    logo abaixo do texto - nunca escondido, porque esconder impediria o
    analista de ver o erro.
    """
    if r.resumo_ia is None:
        return Secao("Resumo por IA", [])

    linhas = ["### Leitura assistida por IA", ""]

    if not r.resumo_ia.gerado:
        linhas.append(
            f"Não gerado: {r.resumo_ia.erro or 'motivo desconhecido'}"
        )
        return Secao("Resumo por IA", linhas)

    linhas += [r.resumo_ia.texto, "", f"> {r.resumo_ia.ressalva}"]

    if r.resumo_ia.invencoes:
        linhas += [
            "",
            "**Afirmações do texto acima sem respaldo nos achados:**",
            "",
        ]
        linhas.extend(f"- `{i.valor}` ({i.tipo}) — {i.explicacao}" for i in r.resumo_ia.invencoes)
        linhas += [
            "",
            "> Estas afirmações foram detectadas automaticamente comparando o "
            "texto com o que a análise observou. Desconsidere-as.",
        ]

    return Secao("Resumo por IA", linhas)


def _secao_limitacoes(r: ResultadoAnalise) -> Secao:
    """
    O que nao foi analisado.

    Esta secao e obrigatoria e nunca fica vazia: se nada falhou, ela diz
    isso. Relatorio que omite o que faltou passa impressao de completude que
    ele nao tem.
    """
    linhas = ["### Limitações desta análise", ""]

    linhas += [
        "Esta é uma análise **estática**: o artefato não foi executado. "
        "Comportamento que só se manifesta em execução - tráfego real de "
        "rede, payload baixado, código desempacotado em memória - não está "
        "coberto aqui.",
        "",
    ]

    if r.erros:
        linhas += ["**Etapas que falharam:**", ""]
        linhas.extend(f"- {e}" for e in r.erros)
        linhas.append("")

    if r.cancelado:
        linhas += ["**A análise foi cancelada antes de terminar.**", ""]

    avisos = r.todos_os_avisos()
    if avisos:
        linhas += ["**Avisos das etapas:**", ""]
        linhas.extend(f"- {a}" for a in dict.fromkeys(avisos))
        linhas.append("")

    if not r.erros and not avisos and not r.cancelado:
        linhas += ["Todas as etapas solicitadas foram concluídas sem aviso.", ""]

    return Secao("Limitações", linhas)


def montar_markdown(r: ResultadoAnalise) -> str:
    """Monta o relatorio completo em Markdown."""
    nome = Path(r.caminho).name

    partes = [
        f"# Relatório de análise — {nome}",
        "",
        f"_Gerado pelo Nut-Shell Mapper em {_data_legivel(r.concluido_em or r.iniciado_em)}_",
        "",
    ]

    secoes = [
        _secao_sumario(r),
        _secao_resumo_ia(r),
        _secao_identificacao(r),
        _secao_iocs(r),
        _secao_desofuscacao(r),
        _secao_pe(r),
        _secao_mitre(r),
        _secao_killchain(r),
        _secao_atribuicao(r),
        _secao_yara(r),
        _secao_cvss(r),
        _secao_enriquecimento(r),
        _secao_limitacoes(r),
    ]

    for secao in secoes:
        if not secao.vazia:
            partes.extend(secao.linhas)
            partes.append("")

    return "\n".join(partes)


# ============================================================
# Saidas
# ============================================================


def salvar_json(r: ResultadoAnalise, destino: str | Path) -> Path:
    """Grava a saida completa em JSON, sem nenhum corte."""
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(
        json.dumps(r.to_dict(), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    logger.info("JSON salvo em %s", destino)
    return destino


def salvar_markdown(r: ResultadoAnalise, destino: str | Path) -> Path:
    """Grava o relatorio em Markdown."""
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(montar_markdown(r), encoding="utf-8")
    logger.info("Markdown salvo em %s", destino)
    return destino


def salvar_pdf(r: ResultadoAnalise, destino: str | Path) -> Path:
    """
    Grava o relatorio em PDF, via ReportLab.

    O Markdown e convertido para os elementos do ReportLab. A conversao e
    intencionalmente simples - tabela, paragrafo, bloco de codigo e citacao -
    porque o relatorio nao precisa de mais do que isso e um conversor
    completo de Markdown seria outro projeto.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table,
            TableStyle,
        )
    except ImportError as erro:
        raise ErroRelatorio(
            f"ReportLab não está instalado ({erro}); "
            "rode: pip install reportlab"
        ) from erro

    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)

    estilos = getSampleStyleSheet()
    estilo_titulo = ParagraphStyle(
        "TituloRab", parent=estilos["Title"], fontSize=18, spaceAfter=4
    )
    estilo_h = ParagraphStyle(
        "H2Rab", parent=estilos["Heading2"], fontSize=13, spaceBefore=12, spaceAfter=6
    )
    estilo_corpo = ParagraphStyle(
        "CorpoRab", parent=estilos["BodyText"], fontSize=9, leading=12, alignment=TA_LEFT
    )
    estilo_nota = ParagraphStyle(
        "NotaRab", parent=estilo_corpo, fontSize=8, textColor=colors.HexColor("#5f6368"),
        leftIndent=8, borderPadding=4,
    )
    estilo_codigo = ParagraphStyle(
        "CodigoRab", parent=estilos["Code"], fontSize=7, leading=8.5
    )

    documento = SimpleDocTemplate(
        str(destino),
        pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Nut-Shell Mapper — {Path(r.caminho).name}",
        author="Nut-Shell Mapper",
    )

    elementos: list = []
    linhas = montar_markdown(r).splitlines()
    i = 0

    def escapar(texto: str) -> str:
        """Escapa o que o mini-HTML do ReportLab interpretaria."""
        return (
            texto.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )

    def formatar(texto: str) -> str:
        """Converte a enfase do Markdown para as tags do ReportLab."""
        import re as _re

        texto = escapar(texto)
        texto = _re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", texto)
        texto = _re.sub(r"`(.+?)`", r"<font face='Courier'>\1</font>", texto)
        texto = _re.sub(r"_(.+?)_", r"<i>\1</i>", texto)
        return texto

    while i < len(linhas):
        linha = linhas[i]

        if not linha.strip():
            i += 1
            continue

        # --- Titulos ---
        if linha.startswith("# "):
            elementos.append(Paragraph(escapar(linha[2:]), estilo_titulo))
            i += 1
            continue
        if linha.startswith("### "):
            elementos.append(Paragraph(escapar(linha[4:]), estilo_h))
            i += 1
            continue

        # --- Bloco de codigo ---
        if linha.startswith("```"):
            i += 1
            bloco = []
            while i < len(linhas) and not linhas[i].startswith("```"):
                bloco.append(linhas[i])
                i += 1
            i += 1
            elementos.append(
                Preformatted("\n".join(bloco), estilo_codigo, maxLineLength=110)
            )
            elementos.append(Spacer(1, 6))
            continue

        # --- Tabela ---
        if linha.startswith("|"):
            bruto = []
            while i < len(linhas) and linhas[i].startswith("|"):
                bruto.append(linhas[i])
                i += 1

            celulas = [
                [c.strip() for c in l.strip().strip("|").split("|")]
                for l in bruto
                if not set(l.replace("|", "").strip()) <= {"-", " "}
            ]
            if celulas:
                largura = documento.width
                colunas = max(len(l) for l in celulas)
                # Normaliza o numero de colunas: linha curta quebraria a Table.
                celulas = [l + [""] * (colunas - len(l)) for l in celulas]

                dados = [
                    [Paragraph(formatar(c), estilo_corpo) for c in linha_]
                    for linha_ in celulas
                ]
                tabela = Table(dados, colWidths=[largura / colunas] * colunas)
                tabela.setStyle(
                    TableStyle(
                        [
                            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c4c7c5")),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0ee")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                            ("TOPPADDING", (0, 0), (-1, -1), 2),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                        ]
                    )
                )
                elementos.append(tabela)
                elementos.append(Spacer(1, 8))
            continue

        # --- Citacao (as ressalvas do relatorio) ---
        if linha.startswith("> "):
            bloco = []
            while i < len(linhas) and linhas[i].startswith("> "):
                bloco.append(linhas[i][2:])
                i += 1
            elementos.append(Paragraph(formatar(" ".join(bloco)), estilo_nota))
            elementos.append(Spacer(1, 6))
            continue

        # --- Paragrafo comum ou item de lista ---
        texto = linha
        if texto.startswith("- "):
            texto = "• " + texto[2:]
        elementos.append(Paragraph(formatar(texto), estilo_corpo))
        i += 1

    documento.build(elementos)
    logger.info("PDF salvo em %s", destino)
    return destino


def salvar_docx(r: ResultadoAnalise, destino: str | Path) -> Path:
    """Grava o relatorio em DOCX, via python-docx."""
    try:
        from docx import Document
        from docx.shared import Pt
    except ImportError as erro:
        raise ErroRelatorio(
            f"python-docx não está instalado ({erro}); "
            "rode: pip install python-docx"
        ) from erro

    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)

    documento = Document()
    linhas = montar_markdown(r).splitlines()
    i = 0

    def sem_marcacao(texto: str) -> str:
        return texto.replace("**", "").replace("`", "")

    while i < len(linhas):
        linha = linhas[i]

        if not linha.strip():
            i += 1
            continue

        if linha.startswith("# "):
            documento.add_heading(linha[2:], level=0)
            i += 1
            continue
        if linha.startswith("### "):
            documento.add_heading(linha[4:], level=1)
            i += 1
            continue

        if linha.startswith("```"):
            i += 1
            bloco = []
            while i < len(linhas) and not linhas[i].startswith("```"):
                bloco.append(linhas[i])
                i += 1
            i += 1
            paragrafo = documento.add_paragraph()
            trecho = paragrafo.add_run("\n".join(bloco))
            trecho.font.name = "Consolas"
            trecho.font.size = Pt(7)
            continue

        if linha.startswith("|"):
            bruto = []
            while i < len(linhas) and linhas[i].startswith("|"):
                bruto.append(linhas[i])
                i += 1

            celulas = [
                [c.strip() for c in l.strip().strip("|").split("|")]
                for l in bruto
                if not set(l.replace("|", "").strip()) <= {"-", " "}
            ]
            if celulas:
                colunas = max(len(l) for l in celulas)
                tabela = documento.add_table(rows=0, cols=colunas)
                tabela.style = "Light Grid Accent 1"
                for linha_ in celulas:
                    linha_ = linha_ + [""] * (colunas - len(linha_))
                    celulas_docx = tabela.add_row().cells
                    for coluna, valor in enumerate(linha_):
                        celulas_docx[coluna].text = sem_marcacao(valor)
            continue

        if linha.startswith("> "):
            bloco = []
            while i < len(linhas) and linhas[i].startswith("> "):
                bloco.append(linhas[i][2:])
                i += 1
            paragrafo = documento.add_paragraph(sem_marcacao(" ".join(bloco)))
            paragrafo.style = "Intense Quote"
            continue

        if linha.startswith("- "):
            documento.add_paragraph(sem_marcacao(linha[2:]), style="List Bullet")
            i += 1
            continue

        documento.add_paragraph(sem_marcacao(linha))
        i += 1

    documento.save(str(destino))
    logger.info("DOCX salvo em %s", destino)
    return destino


# Formato -> funcao que o grava.
FORMATOS = {
    "json": salvar_json,
    "md": salvar_markdown,
    "markdown": salvar_markdown,
    "pdf": salvar_pdf,
    "docx": salvar_docx,
}


def gerar(
    r: ResultadoAnalise,
    diretorio: str | Path,
    formatos: list[str] | None = None,
    nome_base: str = "",
) -> dict[str, Path]:
    """
    Gera o relatorio nos formatos pedidos.

    Args:
        r: resultado do pipeline.
        diretorio: onde gravar.
        formatos: lista entre "json", "md", "pdf", "docx". Padrao: md e json.
        nome_base: nome dos arquivos, sem extensao. Padrao: nome do artefato
            mais os 8 primeiros caracteres do SHA256, o que evita sobrescrever
            a analise anterior de um arquivo homonimo.

    Returns:
        formato -> caminho gravado. Formato que falhou nao aparece; o erro
        vai para o log e para os avisos do resultado.
    """
    formatos = formatos or ["md", "json"]
    diretorio = Path(diretorio)

    if not nome_base:
        nome_base = Path(r.caminho).stem
        if r.sha256:
            nome_base = f"{nome_base}_{r.sha256[:8]}"

    gerados: dict[str, Path] = {}

    for formato in formatos:
        chave = formato.lower().strip()
        funcao = FORMATOS.get(chave)

        if funcao is None:
            logger.warning("formato desconhecido: %s", formato)
            r.avisos.append(f"formato de relatório desconhecido: {formato}")
            continue

        extensao = "md" if chave == "markdown" else chave
        try:
            gerados[chave] = funcao(r, diretorio / f"{nome_base}.{extensao}")
        except Exception as erro:
            # Falta do ReportLab nao pode impedir a geracao do Markdown.
            logger.error("falha ao gerar %s: %s", chave, erro)
            r.avisos.append(f"não foi possível gerar o relatório {chave}: {erro}")

    return gerados
