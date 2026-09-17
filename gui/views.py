"""
Construcao das abas de resultado da interface.

Cada funcao recebe o ResultadoAnalise e devolve um widget pronto. Ficam
separadas da janela principal porque sao a maior parte do codigo da
interface e nao tem nada a ver com o ciclo de vida da aplicacao.

A apresentacao segue a mesma regra do relatorio: evidencia acompanha
conclusao. Tecnica ATT&CK aparece com o que a disparou; grupo aparece com a
ressalva de que sobreposicao nao e atribuicao; estagio vazio da Kill Chain
diz "sem evidencia neste artefato", nunca "nao ocorreu".
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.string_extractor import Confianca

# ============================================================
# Cores
#
# Os tokens vivem em gui/estilo.py; aqui ficam apenas os atalhos que as
# abas usam. A indirecao existe para os testes poderem trocar o tema com
# monkeypatch sem mexer na aplicacao inteira.
# ============================================================

from gui.estilo import NOTA, paleta, tema_escuro  # noqa: E402


def cor_confianca(confianca: Confianca) -> QColor:
    """Cor da confianca, adequada ao tema em vigor."""
    p = ESCURO_OU_CLARO()
    return QColor({
        Confianca.ALTA: p.alta,
        Confianca.MEDIA: p.media,
        Confianca.BAIXA: p.baixa,
    }[confianca])


def ESCURO_OU_CLARO():
    """Paleta em vigor, resolvida pelo tema deste modulo."""
    from gui.estilo import CLARO, ESCURO

    return ESCURO if tema_escuro() else CLARO


def cor_secundaria() -> str:
    """Cinza de texto secundario que funciona nos dois temas."""
    return ESCURO_OU_CLARO().texto_fraco


def fundo_de_nota() -> str:
    """Realce translucido: escurece fundo claro e clareia fundo escuro."""
    return ESCURO_OU_CLARO().realce


FONTE_MONO = "Consolas, 'Courier New', monospace"


# ============================================================
# Blocos reutilizaveis
# ============================================================


def _pagina(*widgets: QWidget) -> QWidget:
    """Empilha widgets numa pagina de aba."""
    pagina = QWidget()
    layout = QVBoxLayout(pagina)
    layout.setContentsMargins(12, 12, 12, 12)
    layout.setSpacing(10)
    for w in widgets:
        layout.addWidget(w)
    return pagina


def _nota(texto: str) -> QLabel:
    """Ressalva em destaque discreto, como as citacoes do relatorio."""
    rotulo = QLabel(texto)
    rotulo.setWordWrap(True)
    # O estilo vem da folha central, por objectName: assim a aparencia da
    # ressalva e a mesma em toda aba, sem repetir CSS.
    rotulo.setObjectName(NOTA)
    return rotulo


def _texto_mono(conteudo: str) -> QPlainTextEdit:
    campo = QPlainTextEdit()
    campo.setPlainText(conteudo)
    campo.setReadOnly(True)
    fonte = QFont("Consolas")
    fonte.setStyleHint(QFont.Monospace)
    fonte.setPointSize(9)
    campo.setFont(fonte)
    campo.setLineWrapMode(QPlainTextEdit.NoWrap)
    return campo


def _tabela(cabecalho: list[str], linhas: list[list[str]]) -> QTableWidget:
    """Tabela somente leitura, com a ultima coluna esticando."""
    tabela = QTableWidget(len(linhas), len(cabecalho))
    tabela.setHorizontalHeaderLabels(cabecalho)
    tabela.setEditTriggers(QAbstractItemView.NoEditTriggers)
    tabela.setSelectionBehavior(QAbstractItemView.SelectRows)
    tabela.setAlternatingRowColors(True)
    tabela.verticalHeader().setVisible(False)

    for i, linha in enumerate(linhas):
        for j, valor in enumerate(linha):
            tabela.setItem(i, j, QTableWidgetItem(str(valor)))

    cabecalho_h = tabela.horizontalHeader()
    for j in range(len(cabecalho) - 1):
        cabecalho_h.setSectionResizeMode(j, QHeaderView.ResizeToContents)
    cabecalho_h.setSectionResizeMode(len(cabecalho) - 1, QHeaderView.Stretch)

    return tabela


def _colorir_por_confianca(tabela: QTableWidget, coluna: int) -> None:
    """Pinta a coluna de confianca com a cor correspondente."""
    for i in range(tabela.rowCount()):
        item = tabela.item(i, coluna)
        if item is None:
            continue
        for confianca in Confianca:
            if item.text() == confianca.value:
                item.setForeground(cor_confianca(confianca))
                fonte = item.font()
                fonte.setBold(confianca is Confianca.ALTA)
                item.setFont(fonte)
                break


def _vazio(mensagem: str) -> QWidget:
    rotulo = QLabel(mensagem)
    rotulo.setAlignment(Qt.AlignCenter)
    rotulo.setStyleSheet(
        f"QLabel {{ color: {cor_secundaria()}; padding: 32px; font-size: 13px; }}"
    )
    return _pagina(rotulo)


# ============================================================
# Abas
# ============================================================


def aba_resumo(r) -> QWidget:
    resumo = r.resumo()
    linhas = [
        ["Arquivo", Path(r.caminho).name],
        ["SHA256", r.sha256 or "-"],
        ["MD5", r.extracao.md5 if r.extracao else "-"],
        ["Tamanho", f"{r.extracao.tamanho_bytes:,} bytes" if r.extracao else "-"],
        ["Duracao", f"{resumo['duracao']}s"],
        ["Strings extraidas", resumo["strings"]],
        ["IOCs identificados", resumo["iocs"]],
        ["Achados de desofuscacao", resumo["achados_desofuscacao"]],
        ["Tecnicas ATT&CK", resumo["tecnicas"]],
        ["Regra YARA valida", "sim" if resumo["yara_valida"] else "nao"],
    ]

    if r.info_pe and r.info_pe.e_pe:
        linhas.insert(4, ["Formato", f"PE {r.info_pe.tipo} {r.info_pe.arquitetura}"])
        linhas.insert(5, ["Imphash", r.info_pe.imphash or "-"])
    if r.kill_chain:
        linhas.append(
            ["Estagios da Kill Chain", f"{len(r.kill_chain.estagios_cobertos)} de 7"]
        )
    if r.cvss:
        linhas.append(
            ["CVSS", f"{r.cvss.score_efetivo:.1f} ({r.cvss.severidade_efetiva.value})"]
        )
    if r.erros:
        linhas.append(["Etapas que falharam", len(r.erros)])

    widgets: list[QWidget] = [_tabela(["Campo", "Valor"], linhas)]

    if r.extracao and not r.extracao.usou_floss:
        widgets.append(
            _nota(
                "O FLOSS nao foi usado nesta analise. Apenas strings estaticas "
                "foram recuperadas; strings montadas em runtime (stack, tight, "
                "decoded) nao aparecem."
            )
        )

    widgets.append(
        _nota(
            "Analise estatica: o artefato nao foi executado. Comportamento que "
            "so se manifesta em execucao nao esta coberto aqui."
        )
    )

    return _pagina(*widgets)


def aba_iocs(r) -> QWidget:
    iocs = r.iocs
    if not iocs:
        return _vazio("Nenhum indicador identificado.")

    ordem = {Confianca.ALTA: 0, Confianca.MEDIA: 1, Confianca.BAIXA: 2}
    ordenados = sorted(iocs, key=lambda i: (ordem[i.confianca], i.tipo.value, i.valor))

    tabela = _tabela(
        ["Confianca", "Tipo", "Valor", "Observacao"],
        [
            [i.confianca.value, i.tipo.value, i.valor, i.observacao or ""]
            for i in ordenados
        ],
    )
    _colorir_por_confianca(tabela, 0)

    return _pagina(
        tabela,
        _nota(
            "A confianca reflete quao inequivoco e o formato e o contexto do "
            "indicador, e nao se ele e malicioso. Um dominio de alta confianca "
            "e um dominio bem identificado, que pode ser legitimo."
        ),
    )


def aba_strings(r) -> QWidget:
    if not r.extracao or not r.extracao.strings:
        return _vazio("Nenhuma string extraida.")

    linhas = [
        [
            s.tipo.value,
            s.encoding,
            hex(s.endereco) if s.endereco is not None else "-",
            s.valor,
        ]
        for s in r.extracao.strings
    ]
    tabela = _tabela(["Origem", "Encoding", "Endereco", "String"], linhas)

    resumo = r.extracao.resumo()
    cabecalho = QLabel(
        f"static: {resumo['static']}  |  stack: {resumo['stack']}  |  "
        f"tight: {resumo['tight']}  |  decoded: {resumo['decoded']}"
    )

    return _pagina(cabecalho, tabela)


def aba_desofuscacao(r) -> QWidget:
    if r.desofuscacao is None:
        return _vazio("A etapa de desofuscacao nao foi executada.")

    if not r.desofuscacao.achados:
        return _vazio(
            f"Nenhuma ofuscacao detectada em "
            f"{r.desofuscacao.candidatos_avaliados} candidatos avaliados."
        )

    tabela = _tabela(
        ["Nota", "Cadeia", "Original", "Decodificado"],
        [
            [f"{a.pontuacao:.2f}", a.cadeia, a.original, a.decodificado]
            for a in r.desofuscacao.achados
        ],
    )

    widgets: list[QWidget] = [tabela]

    if r.desofuscacao.iocs_revelados:
        widgets.append(QLabel("<b>IOCs que so existiam atras da ofuscacao:</b>"))
        widgets.append(
            _tabela(
                ["Tipo", "Valor"],
                [[i.tipo.value, i.valor] for i in r.desofuscacao.iocs_revelados],
            )
        )

    return _pagina(*widgets)


def aba_pe(r) -> QWidget:
    if not r.info_pe or not r.info_pe.e_pe:
        motivo = r.info_pe.erro if r.info_pe else "a etapa nao foi executada"
        return _vazio(f"O artefato nao e um PE ({motivo}).")

    widgets: list[QWidget] = [QLabel("<b>Secoes</b>")]

    tabela = _tabela(
        ["Secao", "Entropia", "Tam. bruto", "Tam. virtual", "Flags", "Nota"],
        [
            [
                s.nome,
                f"{s.entropia:.3f}",
                f"{s.tamanho_bruto:,}",
                f"{s.tamanho_virtual:,}",
                ("X" if s.executavel else "") + ("W" if s.gravavel else "") or "-",
                "alta entropia" if s.alta_entropia else "",
            ]
            for s in r.info_pe.secoes
        ],
    )
    widgets.append(tabela)

    if r.info_pe.imports:
        widgets.append(
            QLabel(
                f"<b>Imports</b> — {len(r.info_pe.imports)} DLLs, "
                f"{len(r.info_pe.todas_as_apis())} funcoes"
            )
        )
        arvore = QTreeWidget()
        arvore.setHeaderLabels(["DLL / funcao"])
        for dll, funcoes in sorted(r.info_pe.imports.items()):
            no = QTreeWidgetItem(arvore, [f"{dll}  ({len(funcoes)})"])
            for funcao in sorted(funcoes):
                QTreeWidgetItem(no, [funcao])
        widgets.append(arvore)

    if r.info_pe.indicios:
        widgets.append(QLabel("<b>Observacoes estruturais</b>"))
        widgets.append(_texto_mono("\n".join(f"- {d}" for d in r.info_pe.indicios)))

    return _pagina(*widgets)


def aba_mitre(r) -> QWidget:
    if r.mapeamento is None:
        return _vazio("O mapeamento ATT&CK nao foi executado.")
    if not r.mapeamento.tecnicas:
        return _vazio("Nenhuma tecnica identificada com evidencia suficiente.")

    arvore = QTreeWidget()
    arvore.setHeaderLabels(["Tecnica", "Confianca", "Taticas"])
    arvore.setAlternatingRowColors(True)

    for t in r.mapeamento.tecnicas:
        no = QTreeWidgetItem(
            arvore,
            [f"{t.tecnica_id}  {t.nome}", t.confianca.value, ", ".join(t.taticas)],
        )
        no.setForeground(1, cor_confianca(t.confianca))

        if t.descricao:
            QTreeWidgetItem(no, [t.descricao, "", ""])
        # A evidencia fica sempre visivel junto da tecnica.
        evidencias = QTreeWidgetItem(no, ["Evidencia", "", ""])
        for e in t.evidencias:
            QTreeWidgetItem(evidencias, [e.trecho, e.tipo.value, ""])
        evidencias.setExpanded(True)

        if t.url:
            QTreeWidgetItem(no, [t.url, "", ""])

    arvore.expandToDepth(0)
    for coluna in range(3):
        arvore.resizeColumnToContents(coluna)

    fonte = (
        f"STIX oficial (versao {r.mapeamento.versao_attack})"
        if r.mapeamento.fonte == "stix"
        else "catalogo local — o STIX oficial nao foi carregado"
    )

    return _pagina(
        QLabel(f"Fonte dos metadados: {fonte}"),
        arvore,
        _nota(
            "Uma tecnica listada significa que a capacidade foi observada no "
            "artefato, e nao que ela e efetivamente usada. Importar "
            "CreateRemoteThread prova que a funcao esta na tabela de imports."
        ),
    )


def aba_killchain(r) -> QWidget:
    if r.kill_chain is None:
        return _vazio("A Kill Chain nao foi montada.")

    arvore = QTreeWidget()
    arvore.setHeaderLabels(["Estagio", "Tecnicas"])

    for estagio in r.kill_chain.estagios:
        rotulo = f"{estagio.estagio.ordem + 1}. {estagio.estagio.value}"
        if estagio.vazio:
            no = QTreeWidgetItem(arvore, [rotulo, "sem evidencia neste artefato"])
            no.setForeground(1, QColor("#9aa0a6"))
            continue

        no = QTreeWidgetItem(arvore, [rotulo, f"{len(estagio.tecnicas)} tecnica(s)"])
        for t in estagio.tecnicas:
            filho = QTreeWidgetItem(no, [f"{t.tecnica_id}  {t.nome}", t.confianca.value])
            filho.setForeground(1, cor_confianca(t.confianca))
        no.setExpanded(True)

    arvore.resizeColumnToContents(0)

    return _pagina(
        QLabel(
            f"<b>Cobertura:</b> {len(r.kill_chain.estagios_cobertos)} de 7 estagios"
        ),
        arvore,
        _nota(
            "ATT&CK e Cyber Kill Chain sao modelos diferentes e a traducao "
            "entre eles e aproximada. Estagio sem evidencia significa que este "
            "artefato nao mostra sinal dele, e nao que a etapa nao ocorreu."
        ),
    )


def aba_atribuicao(r) -> QWidget:
    if r.atribuicao is None:
        return _vazio("A atribuicao nao foi executada.")

    ressalva = _nota(r.atribuicao.ressalva)

    if not r.atribuicao.candidatos:
        motivos = "\n".join(f"- {a}" for a in r.atribuicao.avisos)
        return _pagina(
            ressalva,
            QLabel("Nenhum grupo com sobreposicao significativa."),
            _texto_mono(motivos) if motivos else QLabel(""),
        )

    tabela = _tabela(
        ["Grupo", "ID", "Pontuacao", "Cobertura", "Especificidade", "Tecnicas", "Aliases"],
        [
            [
                c.nome,
                c.grupo_id,
                f"{c.pontuacao:.3f}",
                f"{c.cobertura:.2f}",
                f"{c.especificidade:.2f}",
                f"{len(c.tecnicas_em_comum)}/{c.tecnicas_do_grupo}",
                ", ".join(c.aliases[:4]),
            ]
            for c in r.atribuicao.candidatos
        ],
    )

    observacoes = [
        f"{c.nome}: {o}" for c in r.atribuicao.candidatos for o in c.observacoes
    ]

    widgets: list[QWidget] = [ressalva, tabela]
    if observacoes:
        widgets.append(QLabel("<b>Ressalvas por candidato</b>"))
        widgets.append(_texto_mono("\n".join(f"- {o}" for o in observacoes)))

    return _pagina(*widgets)


def aba_yara(r) -> QWidget:
    if r.regra_yara is None:
        return _vazio("A regra YARA nao foi gerada.")

    estado = (
        "valida: compila e casa com a amostra"
        if r.regra_yara.valida
        else "INVALIDA — nao use sem revisar"
    )

    widgets: list[QWidget] = [
        QLabel(
            f"<b>{r.regra_yara.nome}</b> — {estado} "
            f"({len(r.regra_yara.strings_usadas)} strings, "
            f"limiar {r.regra_yara.minimo_para_casar})"
        )
    ]

    if r.regra_yara.avisos:
        widgets.append(_nota("\n".join(f"• {a}" for a in r.regra_yara.avisos)))

    widgets.append(_texto_mono(r.regra_yara.texto))

    if r.regra_yara.strings_usadas:
        widgets.append(QLabel("<b>Por que cada string foi escolhida</b>"))
        widgets.append(
            _tabela(
                ["Nota", "Origem", "String", "Motivo"],
                [
                    [f"{c.pontuacao:.2f}", c.origem.value, c.valor, c.motivo]
                    for c in r.regra_yara.strings_usadas
                ],
            )
        )

    return _pagina(*widgets)


def aba_enriquecimento(r) -> QWidget:
    if not r.virustotal and not r.shodan:
        if not r.opcoes.enriquecer:
            return _vazio(
                "Enriquecimento externo nao executado.\n\n"
                "Nenhum dado deste artefato foi enviado a servico de terceiros."
            )
        return _vazio("Nenhuma consulta externa retornou dado.")

    widgets: list[QWidget] = []

    if r.virustotal:
        widgets.append(QLabel("<b>VirusTotal</b>"))
        widgets.append(
            _tabela(
                ["Tipo", "Indicador", "Deteccao", "Contexto", "Erro"],
                [
                    [
                        v.tipo,
                        v.indicador,
                        v.resumo_de_deteccao,
                        v.familia_sugerida or v.pais or "",
                        v.erro,
                    ]
                    for v in r.virustotal
                ],
            )
        )

        arquivo = next((v for v in r.virustotal if v.tipo == "arquivo"), None)
        if arquivo and arquivo.deteccoes:
            widgets.append(QLabel("<b>Deteccoes por motor</b>"))
            widgets.append(
                _tabela(
                    ["Motor", "Nome"],
                    [[k, v] for k, v in sorted(arquivo.deteccoes.items())],
                )
            )

    if r.nvd:
        widgets.append(QLabel("<b>NVD — vulnerabilidades citadas</b>"))
        widgets.append(
            _tabela(
                ["CVE", "CVSS", "Versao", "Publicada", "Descricao"],
                [
                    [n.cve, n.resumo, n.versao_cvss, n.publicada_em, n.descricao]
                    for n in r.nvd
                ],
            )
        )
        widgets.append(
            _nota(
                "O artefato apenas REFERENCIA estas vulnerabilidades. Se ele "
                "as explora, e com que sucesso, a analise estatica nao "
                "determina - o score descreve a falha, nao este arquivo."
            )
        )

    if r.shodan:
        widgets.append(QLabel("<b>Shodan</b>"))
        widgets.append(
            _tabela(
                ["IP", "Estado", "Portas", "Organizacao", "Pais", "CVEs"],
                [
                    [
                        s.ip,
                        s.resumo,
                        ", ".join(str(p) for p in s.portas),
                        s.organizacao,
                        s.pais,
                        ", ".join(s.vulnerabilidades[:5]),
                    ]
                    for s in r.shodan
                ],
            )
        )

    observacoes = [
        f"{v.indicador}: {o}" for v in r.virustotal for o in v.observacoes
    ] + [f"{s.ip}: {o}" for s in r.shodan for o in s.observacoes]

    if observacoes:
        widgets.append(QLabel("<b>Como ler estes resultados</b>"))
        widgets.append(_texto_mono("\n".join(f"- {o}" for o in observacoes)))

    return _pagina(*widgets)


def aba_resumo_ia(r) -> QWidget:
    """
    Resumo em linguagem natural, gerado pelo LLM local.

    O texto aparece sempre que foi gerado - inclusive quando contem
    invencao. Esconder impediria o analista de ver o erro; o que nao pode
    e ele aparecer sem o aviso do que foi inventado, entao a lista de
    afirmacoes sem respaldo fica logo abaixo, em destaque.
    """
    if r.resumo_ia is None:
        return _vazio(
            """Resumo por IA nao foi solicitado.

Marque a opcao no painel a esquerda para gerar. O modelo roda localmente
via Ollama: nenhum dado sai desta maquina."""
        )

    if not r.resumo_ia.gerado:
        return _vazio(
            f"""Resumo por IA nao gerado.

{r.resumo_ia.erro}"""
        )

    texto = QLabel(r.resumo_ia.texto)
    texto.setWordWrap(True)
    texto.setTextInteractionFlags(Qt.TextSelectableByMouse)
    texto.setStyleSheet("QLabel { line-height: 165%; padding: 4px; }")

    widgets: list[QWidget] = [texto, _nota(r.resumo_ia.ressalva)]

    if r.resumo_ia.invencoes:
        alerta = QLabel(
            f"<b>{len(r.resumo_ia.invencoes)} afirmacao(oes) do texto acima "
            "nao correspondem a nenhum achado desta analise.</b><br>"
            "Foram detectadas comparando o texto com o que foi observado. "
            "Desconsidere-as."
        )
        alerta.setWordWrap(True)
        alerta.setStyleSheet(
            f"QLabel {{ color: {ESCURO_OU_CLARO().perigo};"
            f" background: {fundo_de_nota()}; border-left: 3px solid"
            f" {ESCURO_OU_CLARO().perigo}; padding: 8px 12px; }}"
        )
        widgets.append(alerta)
        widgets.append(
            _tabela(
                ["Tipo", "Valor citado", "Por que nao confere"],
                [[i.tipo, i.valor, i.explicacao] for i in r.resumo_ia.invencoes],
            )
        )

    rodape = QLabel(
        f"Gerado por {r.resumo_ia.modelo} em "
        f"{r.resumo_ia.duracao_segundos:.1f}s, localmente."
    )
    rodape.setStyleSheet(f"QLabel {{ color: {cor_secundaria()}; font-size: 11px; }}")
    widgets.append(rodape)

    return _pagina(*widgets)


def aba_limitacoes(r) -> QWidget:
    """
    O que nao foi analisado.

    Aba fixa, nunca escondida: se nada falhou, ela diz isso. Interface que
    so mostra achado passa impressao de completude que a analise nao tem.
    """
    partes = [
        "Esta e uma analise ESTATICA: o artefato nao foi executado.",
        "Comportamento que so se manifesta em execucao - trafego real de rede,",
        "payload baixado, codigo desempacotado em memoria - nao esta coberto.",
        "",
    ]

    if r.cancelado:
        partes += ["A ANALISE FOI CANCELADA ANTES DE TERMINAR.", ""]

    if r.erros:
        partes.append("Etapas que falharam:")
        partes += [f"  ! {e}" for e in r.erros]
        partes.append("")

    avisos = list(dict.fromkeys(r.todos_os_avisos()))
    if avisos:
        partes.append("Avisos das etapas:")
        partes += [f"  - {a}" for a in avisos]
    elif not r.erros and not r.cancelado:
        partes.append("Todas as etapas solicitadas foram concluidas sem aviso.")

    return _pagina(_texto_mono("\n".join(partes)))


# Ordem das abas na janela. A de limitacoes fica por ultimo, mas sempre
# existe.
ABAS = (
    ("Resumo", aba_resumo),
    ("Indicadores", aba_iocs),
    ("Strings", aba_strings),
    ("Desofuscacao", aba_desofuscacao),
    ("PE", aba_pe),
    ("ATT&&CK", aba_mitre),
    ("Kill Chain", aba_killchain),
    ("Atribuicao", aba_atribuicao),
    ("YARA", aba_yara),
    ("Enriquecimento", aba_enriquecimento),
    ("Resumo IA", aba_resumo_ia),
    ("Limitacoes", aba_limitacoes),
)
