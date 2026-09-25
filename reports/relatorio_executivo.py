"""
Relatorio executivo em PDF da analise de e-mail.

Escrito para duas leituras. A primeira pagina e para quem decide: o que e,
quao grave, o que fazer - em linguagem de gestor. O resto e para quem vai
agir: Diamond Model, TTPs, Pyramid of Pain, grafo de pivo e as evidencias
completas, para o relatorio se sustentar sozinho numa auditoria.

As recomendacoes sao da ferramenta, nao da IA: saem direto dos achados, e
cada uma aponta o indicador em que se apoia. O texto da IA aparece como
resumo de apoio, com a ressalva e as invencoes detectadas - nunca sem elas.

Todo indicador vai "defangado" (hxxps://golpe[.]com): o PDF circula por
e-mail, e um link clicavel dentro dele seria o proprio golpe de novo.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import dominios

logger = logging.getLogger(__name__)

TINTA = "#1d1f26"
TINTA_2 = "#4a4f5c"
TINTA_3 = "#7d8392"
LINHA = "#dfe1e6"
FUNDO_SUAVE = "#f5f5f8"
ACENTO = "#6c5ce7"
ACENTO_SUAVE = "#eeebfd"
COR_GRAVIDADE = {"alta": "#d93f45", "media": "#c98a1b", "baixa": "#7d8596"}

FONTES = [
    ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
]
# Sem fonte Unicode, a Helvetica padrao nao tem estes glifos.
TROCAS_SEM_UNICODE = {"→": "->", "←": "<-", "≠": "!=", "≥": ">=", "≤": "<=", "✓": "ok"}


class ErroRelatorioExecutivo(Exception):
    pass


def _registrar_fontes() -> tuple[str, str, bool]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    for normal, negrito in FONTES:
        if Path(normal).exists() and Path(negrito).exists():
            try:
                pdfmetrics.registerFont(TTFont("NSCorpo", normal))
                pdfmetrics.registerFont(TTFont("NSNegrito", negrito))
                return "NSCorpo", "NSNegrito", True
            except Exception:
                logger.debug("fonte %s nao carregou", normal, exc_info=True)
    return "Helvetica", "Helvetica-Bold", False


# ============================================================
# Conteudo calculado
# ============================================================


def recomendacoes(r: Any, diamante: Any = None) -> list[tuple[str, str]]:
    """(acao, em que se apoia). Da mais urgente para a menos."""
    saida: list[tuple[str, str]] = []
    codigos = {s.codigo for s in r.sinais}
    ident = {i.campo: i for i in r.identidades if "@" in i.endereco}
    reply = ident.get("Reply-To")
    mailtos = sorted({l.destino[7:].split("?")[0].lower() for l in r.links if l.tipo == "mailto" and "@" in l.destino})

    if r.pontuacao < 30:
        saida.append(("Tratar como suspeito de baixo risco: confirmar com o remetente por outro canal antes de agir.",
                      f"pontuação {r.pontuacao}/100"))
    if "golpe_por_resposta" in codigos or (reply and dominios.e_webmail(reply.dominio)):
        contas = sorted({reply.endereco} if reply else set()) or mailtos
        contas = sorted(set(contas) | set(mailtos))
        saida.append(("Não responder. Bloquear no gateway de e-mail o envio para " + ", ".join(dominios.defang(c) for c in contas)
                      + " e denunciar a conta ao provedor, o que corta o canal de retorno do golpe.",
                      "Reply-To / botões mailto"))
    dominios_tipo1 = []
    if diamante is not None:
        dominios_tipo1 = [i.valor for i in diamante.infraestrutura.itens if i.tipo == "tipo 1" and not dominios.e_ip(i.valor)]
    if dominios_tipo1:
        saida.append(("Bloquear no gateway de e-mail, no proxy e no DNS os domínios " + ", ".join(dominios.defang(d) for d in dominios_tipo1[:6]) + ".",
                      "infraestrutura do adversário (tipo 1)"))
    if r.origem is not None:
        saida.append((f"Bloquear o servidor de origem {dominios.defang(r.origem.ip)} no gateway e buscar outras mensagens vindas dele.",
                      "primeiro salto externo (Received)"))
    saida.append(("Varrer as caixas de entrada da organização com a regra YARA da campanha e pelo assunto "
                  f"“{r.assunto[:60]}”, e remover as cópias encontradas.", "regra YARA da campanha"))
    if any(l.tipo in ("http", "ip", "encurtador") for l in r.links):
        saida.append(("Procurar nos logs de proxy e DNS acessos aos domínios dos links: quem acessou pode ter digitado a senha.",
                      "links no corpo"))
    if r.anexos:
        saida.append(("Bloquear os hashes dos anexos no antivírus/EDR e procurar os arquivos nas estações.",
                      ", ".join(a.nome for a in r.anexos[:3])))
    if codigos & {"personificacao", "marca_em_webmail", "dominio_imitacao"}:
        saida.append(("Se alguém respondeu ou clicou: trocar a senha da conta imitada, revisar o MFA e as sessões ativas.",
                      "personificação de marca"))
    saida.append(("Usar esta mensagem como exemplo em conscientização: o formato se repete em outras campanhas.",
                  "comportamento (topo da Pyramid of Pain)"))
    return saida


def resumo_sem_ia(r: Any, diamante: Any = None) -> str:
    """Texto executivo montado pela ferramenta, quando a IA nao gerou."""
    marca = next((s.titulo.replace("Finge ser ", "") for s in r.sinais if s.codigo == "personificacao"), "")
    partes = [f"Veredito: {r.veredito.lower()} ({r.pontuacao}/100)."]
    if marca:
        partes.append(f"A mensagem se passa por {marca}.")
    if diamante is not None:
        partes.append(f"Método: {diamante.meta.get('Metodologia', '')}.")
    altas = [s.titulo for s in r.sinais if s.gravidade == "alta"]
    if altas:
        partes.append("Sinais mais graves: " + "; ".join(altas[:4]) + ".")
    return " ".join(partes)


# ============================================================
# Desenhos
# ============================================================


def _texto_curto(texto: str, limite: int) -> str:
    return texto if len(texto) <= limite else texto[: limite - 1] + "…"


def desenho_diamante(diamante: Any, largura: float, fonte: str, negrito: str):
    """O diamante com os quatro vertices e os itens principais de cada um."""
    from reportlab.graphics.shapes import Drawing, Line, Polygon, String
    from reportlab.lib import colors

    altura = 250
    d = Drawing(largura, altura)
    cx, cy = largura / 2, altura / 2
    rx, ry = 70, 70
    topo, direita, baixo, esquerda = (cx, cy + ry), (cx + rx, cy), (cx, cy - ry), (cx - rx, cy)
    d.add(Polygon([*topo, *direita, *baixo, *esquerda], fillColor=colors.HexColor(ACENTO_SUAVE),
                  strokeColor=colors.HexColor(ACENTO), strokeWidth=1.2))
    # Eixos: social-politico (vertical) e tecnico (horizontal).
    d.add(Line(*topo, *baixo, strokeColor=colors.HexColor(ACENTO), strokeDashArray=[3, 3], strokeWidth=0.6))
    d.add(Line(*esquerda, *direita, strokeColor=colors.HexColor(ACENTO), strokeDashArray=[3, 3], strokeWidth=0.6))
    d.add(String(cx + 4, cy + 3, "eixo social", fontName=fonte, fontSize=6, fillColor=colors.HexColor(TINTA_3)))
    d.add(String(cx - 60, cy - 9, "eixo técnico", fontName=fonte, fontSize=6, fillColor=colors.HexColor(TINTA_3)))

    def bloco(vertice, x, y, alinhamento):
        itens = [_texto_curto(i.valor, 38) for i in vertice.itens[:4]]
        linhas = [vertice.nome] + (itens or ["(nada observado)"])
        for k, linha in enumerate(linhas):
            d.add(String(x, y - k * 10, linha, fontName=negrito if k == 0 else fonte,
                         fontSize=9 if k == 0 else 7, textAnchor=alinhamento,
                         fillColor=colors.HexColor(TINTA if k == 0 else TINTA_2)))

    bloco(diamante.adversario, cx, altura - 8, "middle")
    bloco(diamante.capacidade, cx + rx + 10, cy + 20, "start")
    bloco(diamante.infraestrutura, cx - rx - 10, cy + 20, "end")
    bloco(diamante.vitima, cx, cy - ry - 14, "middle")
    return d


def desenho_piramide(piramide: Any, largura: float, fonte: str, negrito: str):
    from reportlab.graphics.shapes import Drawing, Polygon, String
    from reportlab.lib import colors

    degraus = list(reversed(piramide.degraus))  # topo primeiro
    contagem = piramide.contagem()
    altura_degrau = 26
    altura = altura_degrau * len(degraus) + 6
    d = Drawing(largura, altura)
    base_larg = largura * 0.42
    x0 = 10
    tons = ["#3f2fb8", "#5344d3", "#6c5ce7", "#8b7cf6", "#ab9ff9", "#cbc3fb"]
    for k, deg in enumerate(degraus):
        topo_y = altura - k * altura_degrau
        base_y = topo_y - altura_degrau + 2
        larg_topo = base_larg * (k) / len(degraus)
        larg_base = base_larg * (k + 1) / len(degraus)
        cx = x0 + base_larg / 2
        d.add(Polygon([cx - larg_topo / 2, topo_y, cx + larg_topo / 2, topo_y,
                       cx + larg_base / 2, base_y, cx - larg_base / 2, base_y],
                      fillColor=colors.HexColor(tons[k]), strokeColor=colors.white, strokeWidth=1))
        n = contagem.get(deg["id"], 0)
        d.add(String(x0 + base_larg + 14, base_y + 8, f"{deg['nome']}", fontName=negrito, fontSize=8.5,
                     fillColor=colors.HexColor(TINTA)))
        d.add(String(x0 + base_larg + 134, base_y + 8, f"{n} · {deg['dor']}", fontName=fonte,
                     fontSize=8, fillColor=colors.HexColor(TINTA_2 if n else TINTA_3)))
    return d


def desenho_grafo(grafo: Any, largura: float, fonte: str, negrito: str):
    """Layout radial: a mensagem no centro, primeiro anel os vizinhos, segundo anel o resto."""
    from reportlab.graphics.shapes import Circle, Drawing, Line, String
    from reportlab.lib import colors

    altura = 330
    d = Drawing(largura, altura)
    cx, cy = largura / 2, altura / 2
    nos = {n.id: n for n in grafo.nos}
    centro = next((n.id for n in grafo.nos if n.vertice == "centro"), None)
    if centro is None:
        return d
    vizinhos = list(dict.fromkeys(a.para for a in grafo.arestas if a.de == centro))
    pos = {centro: (cx, cy)}
    angulos: dict[str, float] = {}
    for k, id_ in enumerate(vizinhos):
        angulos[id_] = 2 * math.pi * k / max(1, len(vizinhos))
        pos[id_] = (cx + 95 * 1.6 * math.cos(angulos[id_]), cy + 95 * math.sin(angulos[id_]))
    # O anel de fora fica ao lado do no de que ele deriva: o dominio perto
    # do endereco que o usa. Distribuir por igual cruzaria as linhas.
    filhos: dict[str, list[str]] = {}
    for a in grafo.arestas:
        if a.de in angulos and a.para not in pos and a.para != centro:
            filhos.setdefault(a.de, [])
            if all(a.para not in f for f in filhos.values()):
                filhos[a.de].append(a.para)
    passo = 2 * math.pi / max(1, len(vizinhos))
    for pai, ids in filhos.items():
        for k, id_ in enumerate(ids):
            ang = angulos[pai] + (k - (len(ids) - 1) / 2) * min(0.35, passo / max(1, len(ids)))
            pos[id_] = (cx + 150 * 1.55 * math.cos(ang), cy + 148 * math.sin(ang))
    soltos = [n.id for n in grafo.nos if n.id not in pos]
    for k, id_ in enumerate(soltos):
        ang = 2 * math.pi * k / max(1, len(soltos)) + 0.2
        pos[id_] = (cx + 150 * 1.55 * math.cos(ang), cy + 148 * math.sin(ang))
    cores = {"endereco": "#d93f45", "dominio": "#6c5ce7", "ip": "#c98a1b", "tecnica": "#2f8f6b",
             "anexo": "#d93f45", "marca": "#7d8596", "mensagem": TINTA, "artefato": TINTA,
             "url": "#6c5ce7", "grupo": "#7d8596"}
    for a in grafo.arestas:
        if a.de in pos and a.para in pos:
            d.add(Line(*pos[a.de], *pos[a.para], strokeColor=colors.HexColor(LINHA), strokeWidth=0.8,
                       strokeDashArray=[2, 2] if a.tracejada else None))
    for id_, (x, y) in pos.items():
        n = nos[id_]
        raio = 7 if n.vertice == "centro" else 4.5
        d.add(Circle(x, y, raio, fillColor=colors.HexColor(cores.get(n.tipo, TINTA_2)),
                     strokeColor=colors.white, strokeWidth=1.2 if n.destaque else 0.5))
        d.add(String(x, y - raio - 8, _texto_curto(n.rotulo, 30), fontName=negrito if n.destaque else fonte,
                     fontSize=6.5, textAnchor="middle", fillColor=colors.HexColor(TINTA if n.destaque else TINTA_2)))
    return d


# ============================================================
# Documento
# ============================================================


def salvar_pdf_email(
    r: Any,
    destino: str | Path,
    diamante: Any = None,
    piramide: Any = None,
    grafo: Any = None,
    resumo_ia: Any = None,
    regra_yara: Any = None,
    consultas: list | None = None,
    reputacao: list | None = None,
) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as erro:
        raise ErroRelatorioExecutivo(f"ReportLab não está instalado ({erro}); rode: pip install reportlab") from erro

    fonte, negrito, unicode_ok = _registrar_fontes()
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)

    def limpo(texto: Any) -> str:
        t = str(texto if texto is not None else "")
        if not unicode_ok:
            for a, b in TROCAS_SEM_UNICODE.items():
                t = t.replace(a, b)
        return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def estilo(nome, **kw):
        base = dict(fontName=fonte, fontSize=9.5, leading=13.5, textColor=colors.HexColor(TINTA), alignment=TA_LEFT)
        base.update(kw)
        return ParagraphStyle(nome, **base)

    s_titulo = estilo("titulo", fontName=negrito, fontSize=21, leading=25)
    s_sub = estilo("sub", fontSize=11, leading=15, textColor=colors.HexColor(TINTA_2))
    s_h = estilo("h", fontName=negrito, fontSize=13, leading=17, spaceBefore=14, spaceAfter=6)
    s_corpo = estilo("corpo")
    s_peq = estilo("peq", fontSize=8, leading=11, textColor=colors.HexColor(TINTA_3))
    s_cel = estilo("cel", fontSize=8, leading=10.5)
    s_cel_n = estilo("celn", fontName=negrito, fontSize=8, leading=10.5)
    s_mono = estilo("mono", fontName="Courier", fontSize=7, leading=9)

    def tabela(linhas, larguras, cabecalho=True):
        dados = [[Paragraph(limpo(c), s_cel_n if (cabecalho and i == 0) else s_cel) for c in l] for i, l in enumerate(linhas)]
        t = Table(dados, colWidths=larguras, repeatRows=1 if cabecalho else 0)
        estilo_t = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(LINHA)),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        if cabecalho:
            estilo_t.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(FUNDO_SUAVE)))
        t.setStyle(TableStyle(estilo_t))
        return t

    agora = datetime.now(timezone.utc)
    documento = SimpleDocTemplate(
        str(destino), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=22 * mm, bottomMargin=18 * mm,
        title=f"Relatório executivo — {Path(r.caminho).name}", author="Nut-Shell Mapper",
    )
    largura = documento.width

    def moldura(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor(TINTA))
        canvas.rect(0, A4[1] - 12 * mm, A4[0], 12 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont(negrito, 9)
        canvas.drawString(18 * mm, A4[1] - 7.5 * mm, "Nut-Shell Mapper")
        canvas.setFont(fonte, 8)
        canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 7.5 * mm, "Relatório executivo · análise de e-mail")
        canvas.setFillColor(colors.HexColor(TINTA_3))
        canvas.drawString(18 * mm, 10 * mm, f"Gerado em {agora.strftime('%d/%m/%Y %H:%M')} UTC · sha256 do e-mail {r.sha256[:16]}…")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"página {doc.page}")
        canvas.restoreState()

    el: list = []
    cor = COR_GRAVIDADE["alta" if r.pontuacao >= 60 else "media" if r.pontuacao >= 30 else "baixa"]

    # --- Pagina 1: para quem decide ---
    el.append(Paragraph("Análise de e-mail suspeito", s_titulo))
    el.append(Spacer(1, 4))
    el.append(Paragraph(limpo(r.assunto or "(sem assunto)"), s_sub))
    de = next((i for i in r.identidades if i.campo == "From" and "@" in i.endereco), None)
    if de:
        el.append(Paragraph(limpo(f"De: {de.nome + ' ' if de.nome else ''}<{dominios.defang(de.endereco)}> · {r.data}"), s_peq))
    el.append(Spacer(1, 10))
    veredito = Table(
        [[Paragraph(f"<font color='{cor}'><b>{limpo(r.veredito)}</b></font>", estilo("v", fontName=negrito, fontSize=15, leading=19)),
          Paragraph(f"<font color='{cor}'><b>{r.pontuacao}</b></font><font size=9 color='{TINTA_3}'>/100</font>",
                    estilo("p", fontName=negrito, fontSize=22, leading=24, alignment=2))],
         [Paragraph(limpo(f"{len(r.sinais)} sinais · técnicas " + (", ".join(t['id'] for t in r.tecnicas) or "—")
                          + f" · SPF {r.autenticacao.spf or '?'} · DKIM {r.autenticacao.dkim or '?'} · DMARC {r.autenticacao.dmarc or '?'}"), s_peq), ""]],
        colWidths=[largura * 0.75, largura * 0.25],
    )
    veredito.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(FUNDO_SUAVE)),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(cor)),
        ("SPAN", (0, 1), (1, 1)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    el.append(veredito)

    el.append(Paragraph("Resumo executivo", s_h))
    if resumo_ia is not None and getattr(resumo_ia, "gerado", False):
        for paragrafo in [p for p in resumo_ia.texto.split("\n") if p.strip()]:
            el.append(Paragraph(limpo(paragrafo), s_corpo))
            el.append(Spacer(1, 4))
        el.append(Paragraph(limpo(resumo_ia.ressalva), s_peq))
        for inv in resumo_ia.invencoes:
            el.append(Paragraph(limpo(f"Não confere com a análise: {inv}"), estilo("inv", fontSize=8, textColor=colors.HexColor(COR_GRAVIDADE['alta']))))
    else:
        el.append(Paragraph(limpo(resumo_sem_ia(r, diamante)), s_corpo))
        motivo = getattr(resumo_ia, "erro", "") if resumo_ia is not None else "não solicitado"
        el.append(Paragraph(limpo(f"Resumo por IA não gerado ({motivo}); texto montado pela ferramenta a partir dos achados."), s_peq))

    el.append(Paragraph("O que fazer agora", s_h))
    for k, (acao, base) in enumerate(recomendacoes(r, diamante), 1):
        el.append(Paragraph(f"<b>{k}.</b> {limpo(acao)} <font size=7.5 color='{TINTA_3}'>({limpo(base)})</font>", s_corpo))
        el.append(Spacer(1, 3))

    el.append(Paragraph("Por que é suspeito", s_h))
    ordem = {"alta": 0, "media": 1, "baixa": 2}
    linhas = [["Gravidade", "Sinal", "Evidência", "ATT&CK"]]
    for s in sorted(r.sinais, key=lambda x: ordem[x.gravidade]):
        linhas.append([{"alta": "Alta", "media": "Média", "baixa": "Baixa"}[s.gravidade], s.titulo, dominios.defang(s.detalhe) if "://" in s.detalhe else s.detalhe, s.tecnica or "—"])
    el.append(tabela(linhas, [largura * 0.1, largura * 0.25, largura * 0.53, largura * 0.12]))

    # --- Diamond, TTPs, piramide ---
    if diamante is not None:
        el.append(PageBreak())
        el.append(Paragraph("Diamond Model", s_h))
        el.append(desenho_diamante(diamante, largura, fonte, negrito))
        meta = [[k, v] for k, v in diamante.meta.items()]
        meta += [["Eixo social-político", diamante.eixo_social], ["Eixo técnico", diamante.eixo_tecnico]]
        el.append(tabela(meta, [largura * 0.22, largura * 0.78], cabecalho=False))
        linhas = [["Vértice", "Item", "Descrição"]]
        for v in (diamante.adversario, diamante.capacidade, diamante.infraestrutura, diamante.vitima):
            for i in v.itens:
                valor = dominios.defang(i.valor) if ("." in i.valor and " " not in i.valor) else i.valor
                linhas.append([v.nome, valor, (f"[{i.tipo}] " if i.tipo else "") + i.descricao])
        el.append(Spacer(1, 8))
        el.append(tabela(linhas, [largura * 0.16, largura * 0.36, largura * 0.48]))

        el.append(Paragraph("TTPs: tática, técnica e procedimento", s_h))
        linhas = [["Tática", "Técnica", "Procedimento (como este adversário fez)"]]
        for t in diamante.ttps:
            evid = f" Evidência: {t.evidencias[0]}" if t.evidencias else ""
            linhas.append([t.tatica_nome, f"{t.tecnica} {t.tecnica_nome}", t.procedimento + evid])
        el.append(tabela(linhas, [largura * 0.18, largura * 0.27, largura * 0.55]))

    if piramide is not None:
        bloco = [Paragraph("Pyramid of Pain", s_h), desenho_piramide(piramide, largura, fonte, negrito), Spacer(1, 4),
                 Paragraph(limpo(piramide.leitura), s_corpo)]
        ioa = [i for i in piramide.itens if i.classe == "IoA"]
        if ioa:
            bloco.append(Spacer(1, 4))
            bloco.append(Paragraph(limpo("Indicadores de ataque (comportamento, sobrevivem à troca de infraestrutura): "
                                         + "; ".join(i.valor for i in ioa[:8])), s_peq))
        el.append(KeepTogether(bloco))

    if grafo is not None and grafo.nos:
        el.append(PageBreak())
        el.append(Paragraph("Grafo de pivô", s_h))
        el.append(Paragraph("Cada ligação é um passo de investigação: do remetente ao domínio, do domínio aos IPs e aos "
                            "domínios que dividem o mesmo certificado. Linhas tracejadas são relações de comportamento.", s_peq))
        el.append(desenho_grafo(grafo, largura, fonte, negrito))
    if diamante is not None and diamante.pivos:
        el.append(Paragraph("Próximos pivôs", s_h))
        for p in diamante.pivos:
            el.append(Paragraph(limpo(f"{p.de} → {p.para}: {p.acao}"), s_corpo))
            el.append(Spacer(1, 2))

    # --- Evidencias ---
    el.append(PageBreak())
    el.append(Paragraph("Evidências", s_h))
    if r.saltos:
        linhas = [["#", "De", "IP", "Para", "Quando"]]
        for s in r.saltos:
            marca = " (origem)" if r.origem is not None and s.ordem == r.origem.ordem else ""
            linhas.append([str(s.ordem), s.de + marca, s.ip, s.por, s.quando[:19].replace("T", " ")])
        el.append(Paragraph("Caminho da mensagem", s_cel_n))
        el.append(tabela(linhas, [largura * 0.05, largura * 0.3, largura * 0.17, largura * 0.3, largura * 0.18]))
        el.append(Spacer(1, 8))
    linhas = [["Tipo", "Indicador (defangado)", "Onde", "Confiança"]]
    for i in r.iocs:
        linhas.append([i.tipo.value, dominios.defang(i.valor), i.origem, i.confianca.value])
    el.append(Paragraph("Indicadores", s_cel_n))
    el.append(tabela(linhas, [largura * 0.1, largura * 0.5, largura * 0.28, largura * 0.12]))

    if reputacao:
        itens = [x if isinstance(x, dict) else x.to_dict() for x in reputacao]
        rotulo = {"malicioso": "Malicioso", "suspeito": "Suspeito", "sem_registro": "Sem registro", "erro": "Falhou"}
        el.append(Spacer(1, 8))
        el.append(Paragraph("Reputação em bases de inteligência", s_cel_n))
        linhas = [["Fonte", "Indicador", "Veredito", "O que a fonte diz"]]
        for x in itens:
            linhas.append([x["fonte"], dominios.defang(x["indicador"]), rotulo.get(x["veredito"], x["veredito"]),
                           (x["resumo"] or x["erro"]) + (f" · tags: {', '.join(x['tags'][:6])}" if x.get("tags") else "")])
        el.append(tabela(linhas, [largura * 0.13, largura * 0.33, largura * 0.13, largura * 0.41]))
        el.append(Paragraph(limpo("“Sem registro” não é “limpo”: infraestrutura de phishing costuma viver dias e nunca "
                                  "chegar a base nenhuma."), s_peq))

    for c in consultas or []:
        d = c if isinstance(c, dict) else c.to_dict()
        el.append(Spacer(1, 8))
        el.append(Paragraph(limpo(f"Domínio {d.get('registravel')}"), s_cel_n))
        linhas = [["Registro", (d.get("criado_em") or "—")[:10] + (f" ({d['idade_dias']} dias)" if d.get("idade_dias") is not None else "") + (f" · {d['registrador']}" if d.get("registrador") else "")],
                  ["DNS A / MX", ", ".join((d.get("dns") or {}).get("A", [])[:4]) + " / " + ", ".join((d.get("dns") or {}).get("MX", [])[:2])],
                  ["SPF / DMARC", (d.get("spf") or "—") + " / " + (d.get("dmarc") or "—")],
                  ["Certificados", f"{len(d.get('certificados', []))} · emissores: " + ", ".join(d.get("emissores", {}) or ["—"])
                   + (f" · irmãos: {', '.join(d.get('dominios_irmaos', [])[:5])}" if d.get("dominios_irmaos") else "")]]
        for o in d.get("observacoes", []):
            linhas.append(["Observação", o])
        el.append(tabela(linhas, [largura * 0.18, largura * 0.82], cabecalho=False))

    if regra_yara is not None and getattr(regra_yara, "texto", ""):
        el.append(Paragraph("Regra YARA da campanha", s_h))
        situacao = "válida: compila, casa com o e-mail e não casa com um e-mail comum" if regra_yara.valida and not regra_yara.falsos_positivos else "não validada"
        el.append(Paragraph(limpo(f"Regra {situacao}."), s_peq))
        el.append(Preformatted(regra_yara.texto, s_mono, maxLineLength=118))

    el.append(Paragraph("Método e limites", s_h))
    for texto in (
        "Análise estática: nenhum link foi acessado, nenhuma imagem remota foi carregada e nenhum anexo foi aberto.",
        "A autenticação (SPF/DKIM/DMARC) foi lida do cabeçalho mais alto, escrito pelo servidor que entregou a mensagem; os de baixo podem ter sido forjados.",
        "O Diamond Model descreve personas e infraestrutura observadas. Não há atribuição a um grupo: o operador real é desconhecido.",
        "O resumo por IA foi gerado por modelo local e conferido contra os achados; é texto de apoio, não evidência.",
    ):
        el.append(Paragraph(limpo("• " + texto), s_peq))

    documento.build(el, onFirstPage=moldura, onLaterPages=moldura)
    logger.info("relatório executivo salvo em %s", destino)
    return destino
