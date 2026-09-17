"""
Sistema de estilo da interface.

Concentra num lugar so as decisoes visuais: cores, espacamento, raio de
borda e tipografia. Espalhar `setStyleSheet` por widget, como estava antes,
garante que a interface va divergindo de si mesma a cada tela nova.

Duas restricoes moldam tudo aqui:

  1. O Windows pode estar em tema claro ou escuro, e o Qt herda a escolha.
     Cor fixa clara some no escuro e vice-versa, entao existem duas paletas
     e a escolha e feita na inicializacao, a partir da paleta do sistema.

  2. A interface e de analise, nao de marketing. A cor carrega significado -
     vermelho e confianca alta, cinza e ressalva - e por isso o uso e
     contido: se tudo tem cor, nada chama atencao.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


# ============================================================
# Tokens
# ============================================================


@dataclass(frozen=True)
class Paleta:
    """As cores de um tema."""

    # Superficies, da mais ao fundo para a mais a frente.
    fundo: str
    superficie: str
    superficie_alta: str
    borda: str
    borda_suave: str

    # Texto.
    texto: str
    texto_fraco: str
    texto_apagado: str

    # Acao e estado.
    destaque: str
    destaque_fraco: str
    destaque_texto: str

    # Semantica de analise.
    alta: str
    media: str
    baixa: str
    perigo: str
    sucesso: str

    # Realce translucido, que funciona sobre qualquer fundo.
    realce: str
    selecao: str


ESCURO = Paleta(
    # Fundo quase preto com desvio para o roxo, em vez de cinza neutro. A
    # diferenca e sutil por pixel e enorme no conjunto: o olho le a tela
    # inteira como tendo uma cor, nao como cinza escuro qualquer.
    fundo="#0f0c17",
    superficie="#171325",
    superficie_alta="#1f1930",
    borda="#3d2f5c",
    borda_suave="#2a2140",
    # Texto com o mesmo desvio quente, para nao brigar com o fundo.
    texto="#e9e4f5",
    texto_fraco="#a99cc7",
    texto_apagado="#6f6490",
    # Roxo neon. Saturado o bastante para parecer emitir luz sobre um fundo
    # escuro, e claro o bastante para texto branco em cima dele passar em
    # contraste.
    destaque="#a855f7",
    destaque_fraco="rgba(168, 85, 247, 0.18)",
    destaque_texto="#ffffff",
    # Os tres niveis de confianca diferem em LUMINOSIDADE, e nao so em
    # matiz (194 / 135 / 112). Isso importa porque a distincao entre alta e
    # media e a informacao mais importante da ferramenta: se ela depender
    # so da cor, quem tem dificuldade de distinguir vermelho e verde perde
    # o dado. Na primeira versao desta paleta o rosa e o laranja tinham
    # luminosidade identica - um teste pegou.
    alta="#ff85b0",
    media="#e09b2d",
    baixa="#655b85",
    # O perigo continua no rosa neon saturado: ele aparece sozinho, sem
    # precisar ser comparado com outro nivel.
    perigo="#ff4d8f",
    sucesso="#3ce8b0",
    realce="rgba(168, 85, 247, 0.09)",
    selecao="rgba(168, 85, 247, 0.28)",
)

CLARO = Paleta(
    # O tema claro segue a mesma familia roxa, mas o neon nao funciona sobre
    # fundo claro - ele some. Aqui o roxo e fechado e saturado, para manter
    # a identidade sem perder contraste.
    fundo="#f7f5fb",
    superficie="#ffffff",
    superficie_alta="#faf8fd",
    borda="#d8cfe8",
    borda_suave="#e9e3f2",
    texto="#1c1526",
    texto_fraco="#584a6e",
    texto_apagado="#857a99",
    destaque="#7c3aed",
    destaque_fraco="rgba(124, 58, 237, 0.10)",
    destaque_texto="#ffffff",
    alta="#c2185b",
    media="#b26a00",
    baixa="#6f6685",
    perigo="#b3123f",
    sucesso="#00795c",
    realce="rgba(124, 58, 237, 0.06)",
    selecao="rgba(124, 58, 237, 0.16)",
)


# Escala de espacamento. Multiplos de 4 mantem o alinhamento vertical
# consistente sem precisar ajustar valor por valor.
ESPACO = {"xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24}

RAIO = 6
RAIO_PEQUENO = 4

# Nomes de objeto usados para variar o estilo de um mesmo widget. Definir
# como constante evita erro de digitacao silencioso: um objectName errado
# nao quebra nada, so nao aplica o estilo.
BOTAO_PRIMARIO = "botaoPrimario"
BOTAO_PERIGO = "botaoPerigo"
TITULO = "tituloApp"
SUBTITULO = "subtituloApp"
NOTA = "notaRessalva"
AVISO = "avisoRisco"
CABECALHO_SECAO = "cabecalhoSecao"


# ============================================================
# Tema em vigor
# ============================================================


def tema_escuro() -> bool:
    """Descobre se a aplicacao esta em tema escuro, pela paleta do sistema."""
    app = QApplication.instance()
    if app is None:
        return False
    return app.palette().color(QPalette.Window).lightness() < 128


def paleta() -> Paleta:
    """A paleta correspondente ao tema em vigor."""
    return ESCURO if tema_escuro() else CLARO


def cor(nome: str) -> QColor:
    """Um token de cor como QColor, para uso em item de tabela ou arvore."""
    return QColor(getattr(paleta(), nome))


# ============================================================
# Folha de estilo
# ============================================================


def folha_de_estilo() -> str:
    """
    Monta o QSS da aplicacao inteira a partir da paleta em vigor.

    Aplicado uma vez na QApplication, vale para todos os widgets, inclusive
    os criados depois - o que importa aqui, ja que as abas de resultado so
    nascem quando a analise termina.
    """
    p = paleta()
    e = ESPACO

    return f"""
/* ---------- Base ---------- */
/*
   Nao pintar fundo no seletor QWidget generico. Ele atinge TODO widget,
   inclusive QCheckBox e QLabel, que passam a desenhar um retangulo com a
   cor de fundo da janela por cima do card mais claro em que estao - o
   efeito e uma caixa escura atras de cada checkbox. Cor de fundo so onde
   ela e realmente desejada.
*/
QWidget {{
    color: {p.texto};
    font-size: 13px;
}}

QMainWindow, QDialog, QScrollArea > QWidget > QWidget {{
    background-color: {p.fundo};
}}

/* Widgets que apenas se apoiam no fundo de quem os contem. */
QLabel, QCheckBox, QRadioButton, QGroupBox::title {{
    background: transparent;
}}

QToolTip {{
    background-color: {p.superficie_alta};
    color: {p.texto};
    border: 1px solid {p.borda};
    border-radius: {RAIO_PEQUENO}px;
    padding: {e['sm']}px;
}}

/* ---------- Tipografia ---------- */
QLabel#{TITULO} {{
    font-size: 26px;
    font-weight: 700;
    color: {p.destaque};
    letter-spacing: 3px;
}}

QLabel#{SUBTITULO} {{
    font-size: 12px;
    color: {p.texto_fraco};
}}

QLabel#{CABECALHO_SECAO} {{
    font-size: 10px;
    font-weight: 700;
    color: {p.destaque};
    letter-spacing: 2px;
    padding-top: {e['sm']}px;
}}

/* Ressalva: fundo translucido funciona sobre claro e sobre escuro. */
QLabel#{NOTA} {{
    background-color: {p.realce};
    color: {p.texto_fraco};
    border-left: 3px solid {p.borda};
    border-radius: {RAIO_PEQUENO}px;
    padding: {e['sm']}px {e['md']}px;
}}

QLabel#{AVISO} {{
    color: {p.perigo};
    font-size: 11px;
    padding: {e['xs']}px 0;
}}

/* ---------- Agrupadores ---------- */
QGroupBox {{
    background-color: {p.superficie};
    border: 1px solid {p.borda_suave};
    border-top: 1px solid {p.borda};
    border-radius: {RAIO}px;
    margin-top: {e['md']}px;
    padding: {e['md']}px {e['sm']}px {e['sm']}px {e['sm']}px;
    font-weight: 600;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: {e['md']}px;
    padding: 0 {e['sm']}px;
    color: {p.destaque};
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
}}

/* ---------- Botoes ---------- */
QPushButton {{
    background-color: {p.superficie_alta};
    color: {p.texto};
    border: 1px solid {p.borda};
    border-radius: {RAIO_PEQUENO}px;
    padding: {e['sm']}px {e['md']}px;
    min-height: 18px;
}}

QPushButton:hover:enabled {{
    background-color: {p.realce};
    border-color: {p.destaque};
}}

QPushButton:pressed:enabled {{
    background-color: {p.selecao};
}}

QPushButton:disabled {{
    color: {p.texto_apagado};
    border-color: {p.borda_suave};
    background-color: transparent;
}}

QPushButton#{BOTAO_PRIMARIO} {{
    background-color: {p.destaque};
    color: {p.destaque_texto};
    border: none;
    font-weight: 600;
    padding: {e['md']}px;
}}

QPushButton#{BOTAO_PRIMARIO} {{
    letter-spacing: 1px;
    text-transform: uppercase;
    font-size: 12px;
}}

QPushButton#{BOTAO_PRIMARIO}:hover:enabled {{
    background-color: #c77dff;
    border: none;
}}

QPushButton#{BOTAO_PRIMARIO}:disabled {{
    background-color: {p.borda_suave};
    color: {p.texto_apagado};
}}

QPushButton#{BOTAO_PERIGO} {{
    border-color: {p.perigo};
    color: {p.perigo};
}}

/* ---------- Campos ---------- */
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {{
    background-color: {p.fundo};
    color: {p.texto};
    border: 1px solid {p.borda};
    border-radius: {RAIO_PEQUENO}px;
    padding: {e['sm']}px;
    selection-background-color: {p.selecao};
}}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {{
    border-color: {p.destaque};
}}

QLineEdit::placeholder {{
    color: {p.texto_apagado};
}}

QComboBox::drop-down {{
    border: none;
    width: 20px;
}}

QComboBox QAbstractItemView {{
    background-color: {p.superficie_alta};
    border: 1px solid {p.borda};
    selection-background-color: {p.selecao};
    outline: none;
}}

/* ---------- Caixas de selecao ---------- */
QCheckBox {{
    spacing: {e['sm']}px;
    padding: {e['xs']}px 0;
}}

/*
   O indicador marcado usa um SVG embutido com o "check" desenhado. Sem
   isso, dar background-color ao ::indicator substitui o desenho nativo do
   Qt e o resultado e um quadrado azul solido, sem marca nenhuma - o
   usuario ve "ligado" pela cor, mas perde o simbolo que torna o estado
   obvio.
*/
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {p.borda};
    border-radius: {RAIO_PEQUENO}px;
    background-color: {p.fundo};
}}

QCheckBox::indicator:hover {{
    border-color: {p.destaque};
}}

QCheckBox::indicator:checked {{
    background-color: {p.destaque};
    border-color: {p.destaque};
    image: url("data:image/svg+xml;utf8,\
<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' \
viewBox='0 0 16 16'><path d='M3.5 8.5l3 3 6-7' fill='none' \
stroke='white' stroke-width='2' stroke-linecap='round' \
stroke-linejoin='round'/></svg>");
}}

/* ---------- Abas ---------- */
QTabWidget::pane {{
    background-color: {p.superficie};
    border: 1px solid {p.borda_suave};
    border-radius: {RAIO}px;
    top: -1px;
}}

QTabBar::tab {{
    background: transparent;
    color: {p.texto_fraco};
    border: none;
    border-bottom: 2px solid transparent;
    padding: {e['sm']}px {e['md']}px;
    margin-right: {e['xs']}px;
}}

QTabBar::tab:hover {{
    color: {p.texto};
}}

QTabBar::tab:selected {{
    color: {p.destaque};
    border-bottom: 3px solid {p.destaque};
    background: {p.destaque_fraco};
    font-weight: 700;
}}

/* ---------- Tabelas ---------- */
QTableWidget, QTreeWidget {{
    background-color: {p.superficie};
    alternate-background-color: {p.superficie_alta};
    color: {p.texto};
    border: 1px solid {p.borda_suave};
    border-radius: {RAIO}px;
    gridline-color: transparent;
    outline: none;
}}

QTableWidget::item, QTreeWidget::item {{
    padding: {e['sm']}px {e['xs']}px;
    border: none;
}}

QTableWidget::item:selected, QTreeWidget::item:selected {{
    background-color: {p.selecao};
    color: {p.texto};
}}

QHeaderView::section {{
    background-color: {p.superficie_alta};
    color: {p.destaque};
    border: none;
    border-bottom: 2px solid {p.borda};
    padding: {e['sm']}px;
    font-weight: 700;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

QTreeWidget::branch {{
    background: transparent;
}}

/* ---------- Progresso ---------- */
QProgressBar {{
    background-color: {p.borda_suave};
    border: none;
    border-radius: 3px;
    height: 6px;
    text-align: center;
    color: transparent;
}}

QProgressBar::chunk {{
    background-color: {p.destaque};
    border-radius: 3px;
}}

/* ---------- Rolagem ---------- */
QScrollArea {{
    border: none;
    background: transparent;
}}

QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: {p.borda};
    border-radius: 5px;
    min-height: 28px;
}}

QScrollBar::handle:vertical:hover {{
    background: {p.destaque};
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}

QScrollBar::handle:horizontal {{
    background: {p.borda};
    border-radius: 5px;
    min-width: 28px;
}}

QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0;
    width: 0;
}}

QScrollBar::add-page, QScrollBar::sub-page {{
    background: transparent;
}}

/* ---------- Menu e barra de estado ---------- */
QMenuBar {{
    background-color: {p.fundo};
    border-bottom: 1px solid {p.borda_suave};
    padding: {e['xs']}px;
}}

QMenuBar::item {{
    padding: {e['xs']}px {e['md']}px;
    border-radius: {RAIO_PEQUENO}px;
}}

QMenuBar::item:selected {{
    background-color: {p.realce};
}}

QMenu {{
    background-color: {p.superficie_alta};
    border: 1px solid {p.borda};
    border-radius: {RAIO_PEQUENO}px;
    padding: {e['xs']}px;
}}

QMenu::item {{
    padding: {e['sm']}px {e['lg']}px;
    border-radius: {RAIO_PEQUENO}px;
}}

QMenu::item:selected {{
    background-color: {p.selecao};
}}

QStatusBar {{
    background-color: {p.superficie};
    border-top: 1px solid {p.borda_suave};
    color: {p.texto_fraco};
}}

QStatusBar::item {{
    border: none;
}}

/* ---------- Divisor ---------- */
QSplitter::handle {{
    background-color: {p.borda_suave};
    width: 1px;
}}

QSplitter::handle:hover {{
    background-color: {p.destaque};
}}
"""


def aplicar(app: QApplication) -> None:
    """Aplica a folha de estilo a aplicacao inteira."""
    app.setStyleSheet(folha_de_estilo())
