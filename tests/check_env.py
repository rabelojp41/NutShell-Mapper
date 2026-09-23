"""
Verificacao de ambiente do Nut-Shell Mapper.

Confirma que todas as dependencias criticas importam de fato antes de o
pipeline ser executado. Falha cedo e com mensagem clara e melhor do que
quebrar no meio de uma analise.

Uso:
    python -m tests.check_env
"""

import importlib
import sys

# (modulo_importavel, rotulo exibido, e_critico)
DEPENDENCIAS = [
    ("floss", "flare-floss (extracao de strings)", True),
    ("binary2strings", "  backend C++ do FLOSS", True),
    ("vivisect", "  emulador do FLOSS", True),
    ("pefile", "pefile (parsing PE)", True),
    ("yara", "yara-python (regras YARA)", True),
    ("mitreattack.stix20", "mitreattack-python (ATT&CK)", True),
    ("cvss", "cvss (scoring CVSS)", True),
    ("requests", "requests (clients de API)", True),
    ("dotenv", "python-dotenv (.env)", True),
    ("reportlab", "reportlab (relatorio PDF)", False),
    ("docx", "python-docx (relatorio DOCX)", False),
    ("PySide6.QtWidgets", "PySide6 (interface grafica)", False),
]

VERSAO_MINIMA = (3, 10)
VERSAO_MAXIMA = (3, 11)  # exclusivo: 3.11+ nao tem wheel de binary2strings


def _versao(modulo) -> str:
    """Extrai a versao do modulo, se ele expuser uma."""
    for atributo in ("__version__", "VERSION", "version"):
        valor = getattr(modulo, atributo, None)
        if isinstance(valor, str):
            return valor
    return ""


def verificar_python() -> bool:
    """Alerta se o interpretador nao for 3.10.x."""
    atual = sys.version_info[:2]
    print(f"Python: {sys.version.split()[0]}")
    if not (VERSAO_MINIMA <= atual < VERSAO_MAXIMA):
        print(
            f"  [AVISO] Esperado Python 3.10.x. O flare-floss depende de\n"
            f"          binary2strings, que so tem wheel para cp310 no Windows."
        )
        return False
    return True


def verificar_dependencias() -> tuple[int, int]:
    """Importa cada dependencia e devolve (falhas_criticas, falhas_opcionais)."""
    criticas = opcionais = 0
    print()
    for nome, rotulo, e_critico in DEPENDENCIAS:
        try:
            modulo = importlib.import_module(nome)
        except Exception as erro:  # ImportError, DLL faltando, etc.
            if e_critico:
                criticas += 1
                marca = "[FALHA]"
            else:
                opcionais += 1
                marca = "[OPC.] "
            print(f"  {marca} {rotulo:38} {type(erro).__name__}: {erro}")
        else:
            print(f"  [OK]    {rotulo:38} {_versao(modulo)}")
    return criticas, opcionais


def main() -> int:
    python_ok = verificar_python()
    criticas, opcionais = verificar_dependencias()

    total = len(DEPENDENCIAS)
    print(f"\n{total - criticas - opcionais}/{total} dependencias OK")

    if criticas:
        print(f"{criticas} dependencia(s) critica(s) faltando.")
        print("Rode: pip install -r requirements.txt")
        return 1
    if opcionais:
        print(f"{opcionais} dependencia(s) opcional(is) faltando "
              "(relatorios/GUI ficam indisponiveis).")
    if not python_ok:
        return 2
    print("Ambiente pronto.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
