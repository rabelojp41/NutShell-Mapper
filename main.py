"""
RabMapper - interface de linha de comando.

Orquestra o pipeline completo de analise de artefatos. A logica de analise
esta em core/pipeline.py; aqui ficam apenas o parsing de argumentos e a
apresentacao no terminal, para que a GUI possa usar exatamente o mesmo
pipeline sem depender deste arquivo.

Uso:
    python main.py analisar amostra.bin
    python main.py analisar amostra.bin --relatorio pdf md --enriquecer
    python main.py config
    python main.py cvss "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    python main.py atualizar-attack
    python main.py gui
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

logger = logging.getLogger("rabmapper")


# ============================================================
# Apresentacao
# ============================================================

LARGURA = 72


def _titulo(texto: str) -> None:
    print()
    print("=" * LARGURA)
    print(f" {texto}")
    print("=" * LARGURA)


def _secao(texto: str) -> None:
    print(f"\n--- {texto} " + "-" * max(0, LARGURA - len(texto) - 6))


def _barra_de_progresso(estagio, mensagem: str, fracao: float) -> None:
    """Progresso numa linha so, reescrita a cada etapa."""
    preenchido = int(fracao * 30)
    barra = "#" * preenchido + "." * (30 - preenchido)
    rotulo = (mensagem or estagio.value)[:34].ljust(34)
    fim = "\n" if fracao >= 1.0 else ""
    print(f"\r  [{barra}] {fracao * 100:3.0f}%  {rotulo}", end=fim, flush=True)


def _imprimir_resultado(r) -> None:
    """Resumo da analise no terminal."""
    from core.string_extractor import Confianca

    _titulo(f"Analise: {Path(r.caminho).name}")

    resumo = r.resumo()
    print(f"  SHA256    : {r.sha256}")
    print(f"  Duracao   : {resumo['duracao']}s")
    print(f"  Strings   : {resumo['strings']}")
    print(f"  IOCs      : {resumo['iocs']}")
    print(f"  Tecnicas  : {resumo['tecnicas']}")
    print(f"  YARA      : {'valida' if resumo['yara_valida'] else 'nao gerada'}")

    # --- IOCs ---
    iocs = r.iocs
    if iocs:
        _secao("Indicadores")
        ordem = {Confianca.ALTA: 0, Confianca.MEDIA: 1, Confianca.BAIXA: 2}
        for i in sorted(iocs, key=lambda x: (ordem[x.confianca], x.tipo.value))[:25]:
            observacao = f"  <- {i.observacao}" if i.observacao else ""
            print(f"  [{i.confianca.value:5}] {i.tipo.value:16} {i.valor[:60]}{observacao}")
        if len(iocs) > 25:
            print(f"  ... e mais {len(iocs) - 25} (veja a saida JSON)")

    # --- Desofuscacao ---
    if r.desofuscacao and r.desofuscacao.achados:
        _secao("Desofuscacao")
        for a in r.desofuscacao.achados[:10]:
            print(f"  [{a.pontuacao:.2f}] {a.cadeia}")
            print(f"         -> {a.decodificado[:60]!r}")

    # --- ATT&CK ---
    if r.mapeamento and r.mapeamento.tecnicas:
        _secao("Tecnicas MITRE ATT&CK")
        for t in r.mapeamento.tecnicas:
            print(f"  [{t.confianca.value:5}] {t.tecnica_id:10} {t.nome[:44]}")
            if t.evidencias:
                print(f"           evidencia: {t.evidencias[0]}")

    # --- Kill Chain ---
    if r.kill_chain:
        from core.killchain import resumir_em_texto

        _secao("Cyber Kill Chain")
        for linha in resumir_em_texto(r.kill_chain).splitlines():
            print(f"  {linha}")

    # --- Atribuicao ---
    if r.atribuicao and r.atribuicao.candidatos:
        from core.group_attribution import resumir_em_texto

        _secao("Grupos com repertorio compativel")
        for linha in resumir_em_texto(r.atribuicao).splitlines():
            print(f"  {linha}")

    # --- CVSS ---
    if r.cvss:
        from core.cvss_calculator import resumir_em_texto

        _secao("CVSS")
        for linha in resumir_em_texto(r.cvss).splitlines():
            print(f"  {linha}")

    # --- Enriquecimento ---
    if r.virustotal:
        _secao("VirusTotal")
        for v in r.virustotal:
            estado = v.erro or v.resumo_de_deteccao
            print(f"  {v.tipo:8} {v.indicador[:46]:48} {estado}")
    if r.shodan:
        _secao("Shodan")
        for s in r.shodan:
            portas = ", ".join(str(p) for p in s.portas[:8]) or "-"
            print(f"  {s.ip:16} {s.resumo:24} portas: {portas}")

    # --- O que faltou ---
    if r.erros:
        _secao("Etapas que falharam")
        for e in r.erros:
            print(f"  ! {e}")

    avisos = list(dict.fromkeys(r.todos_os_avisos()))
    if avisos:
        _secao("Avisos")
        for a in avisos:
            print(f"  - {a}")


# ============================================================
# Comandos
# ============================================================


def comando_analisar(args: argparse.Namespace) -> int:
    from core.pipeline import OpcoesAnalise, analisar
    from reports import report_generator

    caminho = Path(args.arquivo)
    if not caminho.is_file():
        print(f"erro: arquivo nao encontrado: {caminho}", file=sys.stderr)
        return 1

    opcoes = OpcoesAnalise(
        usar_floss=not args.sem_floss,
        tamanho_minimo_de_string=args.min_string,
        timeout_floss=args.timeout_floss,
        gerar_yara=not args.sem_yara,
        maximo_de_strings_yara=args.strings_yara,
        amostras_benignas=args.benigno or [],
        usar_stix=not args.sem_stix,
        baixar_stix_se_faltar=not args.offline,
        vetor_cvss=args.cvss or "",
        cve=args.cve or "",
        enriquecer=args.enriquecer,
        maximo_de_consultas=args.max_consultas,
    )

    if args.enriquecer:
        print(
            "\n  Enriquecimento habilitado: hashes e indicadores deste artefato\n"
            "  serao enviados ao VirusTotal e ao Shodan. Quem opera esses\n"
            "  servicos vera o que voce esta investigando."
        )

    _titulo(f"Analisando {caminho.name}")
    resultado = analisar(
        caminho, opcoes, progresso=None if args.quieto else _barra_de_progresso
    )

    _imprimir_resultado(resultado)

    # --- Regra YARA ---
    if resultado.regra_yara and resultado.regra_yara.valida:
        destino = Path(args.saida) / f"{caminho.stem}_{resultado.sha256[:8]}.yar"
        try:
            from core.yara_generator import salvar

            salvar(resultado.regra_yara, destino)
            print(f"\n  Regra YARA : {destino}")
        except Exception as erro:
            print(f"\n  regra YARA nao foi salva: {erro}", file=sys.stderr)

    # --- Relatorios ---
    if args.relatorio:
        gerados = report_generator.gerar(resultado, args.saida, args.relatorio)
        if gerados:
            _secao("Relatorios")
            for formato, destino in gerados.items():
                print(f"  {formato:8} {destino}")

    print()
    return 0 if resultado.concluido else 2


def comando_config(_args: argparse.Namespace) -> int:
    """Mostra o estado da configuracao, com as chaves mascaradas."""
    from config.settings import CAMINHO_ENV_EXEMPLO, CONFIG

    _titulo("Configuracao")
    for chave, valor in CONFIG.diagnostico().items():
        print(f"  {chave:16}: {valor}")

    if CONFIG.avisos:
        _secao("Avisos")
        for aviso in CONFIG.avisos:
            print(f"  - {aviso}")

    if not CONFIG.env_encontrado:
        print(f"\n  Template disponivel em: {CAMINHO_ENV_EXEMPLO}")

    _secao("Ambiente")
    import subprocess

    # O subprocesso escreve direto no terminal, enquanto os prints acima
    # ficam no buffer do Python. Sem o flush, a saida sai fora de ordem.
    sys.stdout.flush()

    codigo = subprocess.call(
        [sys.executable, "-m", "tests.check_env"], cwd=str(Path(__file__).parent)
    )
    return codigo


def comando_cvss(args: argparse.Namespace) -> int:
    from core.cvss_calculator import ErroCVSS, calcular, resumir_em_texto

    try:
        resultado = calcular(args.vetor, args.cve or "")
    except ErroCVSS as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1

    _titulo("CVSS 3.1")
    print(resumir_em_texto(resultado))
    print()
    return 0


def comando_atualizar_attack(args: argparse.Namespace) -> int:
    from core.mitre_mapper import CAMINHO_CACHE_PADRAO, ErroMitre, MitreAttack

    caminho = Path(args.cache) if args.cache else CAMINHO_CACHE_PADRAO
    attack = MitreAttack(caminho)

    _titulo("Atualizando o MITRE ATT&CK")
    print(f"  Cache  : {caminho}")
    print(f"  Estado : {'presente' if attack.cache_existe else 'ausente'}")
    print("  Baixando o bundle STIX (~45 MB)...")

    try:
        attack.baixar(forcar=args.forcar)
        attack.carregar(baixar_se_faltar=False)
    except ErroMitre as erro:
        print(f"\nerro: {erro}", file=sys.stderr)
        return 1

    print(f"\n  Versao do ATT&CK : {attack.versao or 'desconhecida'}")
    print(f"  Objetos indexados: {len(attack._por_id)}")
    for aviso in attack.avisos:
        print(f"  aviso: {aviso}")
    print()
    return 0


def comando_gui(_args: argparse.Namespace) -> int:
    try:
        from gui.app import main as gui_main
    except ImportError as erro:
        print(
            f"erro: nao foi possivel carregar a interface grafica ({erro}).\n"
            "Instale as dependencias: pip install PySide6",
            file=sys.stderr,
        )
        return 1
    return gui_main()


# ============================================================
# CLI
# ============================================================


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rabmapper",
        description="RabMapper - analise estatica de artefatos e threat intelligence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exemplos:\n"
            "  python main.py analisar amostra.bin\n"
            "  python main.py analisar amostra.bin --relatorio pdf md\n"
            "  python main.py analisar amostra.bin --enriquecer\n"
            "  python main.py config\n"
            "  python main.py gui\n"
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log detalhado")
    sub = parser.add_subparsers(dest="comando", required=True)

    # --- analisar ---
    p = sub.add_parser("analisar", help="analisa um artefato")
    p.add_argument("arquivo", help="caminho do artefato")
    p.add_argument(
        "-o", "--saida", default="output", help="diretorio de saida (padrao: output)"
    )
    p.add_argument(
        "-r", "--relatorio", nargs="*", default=[],
        choices=["md", "json", "pdf", "docx"],
        help="formatos de relatorio a gerar",
    )
    p.add_argument("--sem-floss", action="store_true",
                   help="usa apenas o extrator nativo (mais rapido)")
    p.add_argument("--sem-yara", action="store_true", help="nao gera regra YARA")
    p.add_argument("--sem-stix", action="store_true",
                   help="usa so o catalogo local de tecnicas")
    p.add_argument("--offline", action="store_true",
                   help="nao baixa o STIX se ele faltar")
    p.add_argument("--min-string", type=int, default=4,
                   help="tamanho minimo de string (padrao: 4)")
    p.add_argument("--timeout-floss", type=int, default=300,
                   help="limite do FLOSS em segundos (padrao: 300)")
    p.add_argument("--strings-yara", type=int, default=20,
                   help="quantas strings entram na regra (padrao: 20)")
    p.add_argument("--benigno", action="append",
                   help="arquivo legitimo para testar falso positivo da regra "
                        "(pode repetir)")
    p.add_argument("--cvss", help="vetor CVSS 3.1, quando o artefato explora uma CVE")
    p.add_argument("--cve", help="identificador da CVE")
    p.add_argument(
        "--enriquecer", action="store_true",
        help="consulta VirusTotal e Shodan. ATENCAO: envia os indicadores "
             "deste artefato a servicos de terceiros",
    )
    p.add_argument("--max-consultas", type=int, default=20,
                   help="teto de consultas externas (padrao: 20)")
    p.add_argument("-q", "--quieto", action="store_true", help="sem barra de progresso")
    p.set_defaults(funcao=comando_analisar)

    # --- config ---
    p = sub.add_parser("config", help="mostra a configuracao e verifica o ambiente")
    p.set_defaults(funcao=comando_config)

    # --- cvss ---
    p = sub.add_parser("cvss", help="calcula um score CVSS 3.1")
    p.add_argument("vetor", help='vetor, ex: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"')
    p.add_argument("--cve", help="identificador da CVE")
    p.set_defaults(funcao=comando_cvss)

    # --- atualizar-attack ---
    p = sub.add_parser("atualizar-attack", help="baixa o bundle STIX do MITRE ATT&CK")
    p.add_argument("--cache", help="caminho alternativo do cache")
    p.add_argument("--forcar", action="store_true", help="baixa mesmo com cache valido")
    p.set_defaults(funcao=comando_atualizar_attack)

    # --- gui ---
    p = sub.add_parser("gui", help="abre a interface grafica")
    p.set_defaults(funcao=comando_gui)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = construir_parser().parse_args(argv)

    from config.settings import configurar_logging

    # No terminal o padrao e silencioso: a barra de progresso e o log
    # competem pela mesma linha, e o que o usuario precisa saber ja esta
    # na secao de avisos do resultado. -v mostra tudo.
    configurar_logging("DEBUG" if args.verbose else "WARNING")

    try:
        return args.funcao(args)
    except KeyboardInterrupt:
        print("\n\ninterrompido pelo usuario", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
