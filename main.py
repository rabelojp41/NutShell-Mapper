"""
Nut-Shell Mapper - interface de linha de comando.

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
import gc
import logging
import subprocess
import sys
from pathlib import Path

# Desliga o coletor ciclico do Python para o processo inteiro, antes de
# qualquer modulo pesado ser importado (todos os outros - core.pipeline,
# enrichment, gui - sao importados sob demanda dentro de cada comando).
#
# O pipeline combina varias extensoes nativas no mesmo processo - pefile,
# yara-python, PySide6/Qt, pyzipper - e essa combinacao corrompe memoria em
# algum ponto ainda nao isolado. O sintoma e um "access violation" que
# aparece sempre dentro de uma coleta de lixo, mas em locais diferentes a
# cada execucao: o coletor ciclico e o detonador, nao a causa - ele so
# acontece de ser o primeiro a tocar a memoria corrompida. Reproduzido de
# forma confiavel na suite de testes; desligar o coletor eliminou o crash
# de forma consistente em execucoes repetidas.
#
# Seguro para este programa: CLI e GUI sao, cada analise, um processo ou
# uma sessao de duracao limitada, e a contagem de referencia do CPython
# continua liberando a esmagadora maioria dos objetos normalmente. So fica
# sem coletar um ciclo de referencia genuino, que este projeto praticamente
# nao cria - Qt QObject com parent e gerenciado pela arvore C++ do proprio
# Qt, nao pelo coletor do Python.
gc.disable()

logger = logging.getLogger("nutshell")


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

    # --- Resumo por IA ---
    if r.resumo_ia is not None:
        from core.resumo_ia import resumir_em_texto

        _secao("Leitura assistida por IA")
        for linha in resumir_em_texto(r.resumo_ia).splitlines():
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
        formato=args.formato,
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
        resumo_ia=args.resumo_ia,
        modelo_ia=args.modelo_ia,
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

    # --- Exportacao de indicadores ---
    if args.exportar_iocs:
        from core.string_extractor import Confianca
        from reports import ioc_export

        minima = {
            "alta": Confianca.ALTA,
            "media": Confianca.MEDIA,
            "baixa": Confianca.BAIXA,
        }[args.confianca_minima]

        saidas = ioc_export.exportar(
            resultado, args.saida, args.exportar_iocs, confianca_minima=minima
        )
        if saidas:
            _secao("Indicadores exportados")
            for formato, s in saidas.items():
                print(f"  {formato:6} {s.exportados:3} indicadores  {s.caminho}")
                if s.descartados_por_confianca:
                    print(f"         {s.descartados_por_confianca} abaixo de "
                          f"'{args.confianca_minima}' ficaram de fora")
                for item in s.sem_representacao:
                    print(f"         sem representacao no formato: {item}")

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


def comando_bazaar(args: argparse.Namespace) -> int:
    """Consulta um hash no MalwareBazaar e, opcionalmente, baixa a amostra."""
    from config.settings import CONFIG
    from enrichment import malwarebazaar_client
    from enrichment.malwarebazaar_client import ErroMalwareBazaar

    cliente = malwarebazaar_client.criar(CONFIG)
    if cliente is None:
        print(
            "erro: Auth-Key do MalwareBazaar nao configurada, ou "
            "enriquecimento desabilitado no .env.\n"
            "A chave e obtida em auth.abuse.ch e vale para todos os servicos "
            "do abuse.ch.",
            file=sys.stderr,
        )
        return 1

    with cliente:
        _titulo(f"MalwareBazaar — {args.hash[:24]}")
        resultado = cliente.consultar_hash(args.hash)

        if resultado.erro:
            print(f"erro: {resultado.erro}", file=sys.stderr)
            return 1

        if not resultado.encontrado:
            print(f"  {resultado.resumo}")
            for o in resultado.observacoes:
                print(f"  obs: {o}")
            return 0

        print(f"  Familia      : {resultado.familia or '-'}")
        print(f"  Tags         : {', '.join(resultado.tags) or '-'}")
        print(f"  Tipo         : {resultado.tipo} {resultado.formato} "
              f"{resultado.arquitetura}".rstrip())
        print(f"  Tamanho      : {resultado.tamanho_bytes:,} bytes")
        print(f"  Entrega      : {resultado.metodo_de_entrega or '-'}")
        print(f"  Visto em     : {resultado.primeira_vez_visto} por "
              f"{resultado.reportado_por} ({resultado.pais_de_origem})")
        print(f"  SHA256       : {resultado.sha256}")
        print(f"  MD5          : {resultado.md5}")
        print(f"  Senha do ZIP : {resultado.senha_do_arquivo}")

        if resultado.regras_yara:
            _secao(f"Regras YARA da comunidade ({len(resultado.regras_yara)})")
            for nome in resultado.regras_yara[:10]:
                print(f"  - {nome}")

        if resultado.fontes_externas:
            _secao("Analises em outros servicos")
            print("  " + ", ".join(resultado.fontes_externas))

        for o in resultado.observacoes:
            print(f"\n  obs: {o}")

        if not args.baixar:
            print()
            return 0

        # --- Download ---
        _secao("Download da amostra")
        print(
            "  ATENCAO: isto traz malware para esta maquina.\n"
            "  O arquivo sera gravado como ZIP cifrado, sem descompactar.\n"
            "  Faca isto apenas em ambiente isolado, com snapshot.\n"
        )

        if not args.sim:
            try:
                confirmacao = input("  Continuar? [s/N] ").strip().lower()
            except EOFError:
                confirmacao = ""
            if confirmacao not in ("s", "sim", "y", "yes"):
                print("  cancelado.")
                return 0

        destino = Path(args.saida) if args.saida else CONFIG.samples_dir
        try:
            amostra = cliente.baixar_amostra(
                resultado.sha256 or args.hash, destino
            )
        except ErroMalwareBazaar as erro:
            print(f"erro: {erro}", file=sys.stderr)
            return 1

        print(f"\n  Salvo em : {amostra.caminho}")
        print(f"  Tamanho  : {amostra.tamanho_bytes:,} bytes")
        print(f"  Senha    : {amostra.senha}")
        for aviso in amostra.avisos:
            print(f"  aviso: {aviso}")
        print(
            "\n  Para analisar, descompacte em VM isolada (7-Zip, senha "
            f"'{amostra.senha}') e rode:\n"
            "    python main.py analisar <arquivo>"
        )

    print()
    return 0


def comando_gui(args: argparse.Namespace) -> int:
    try:
        if getattr(args, "classica", False):
            from gui.app import main as gui_main
        else:
            from gui.janela_web import main as gui_main
    except ImportError as erro:
        print(
            f"erro: nao foi possivel carregar a interface grafica ({erro}).\n"
            "Instale as dependencias: pip install PySide6",
            file=sys.stderr,
        )
        return 1
    return gui_main()


def _imprimir_dominio(c) -> None:
    print(f"  Domínio      : {c.dominio}  (registrável: {c.registravel})")
    if c.imitacao:
        print(f"  ! Imitação   : {c.imitacao}")
    if c.criado_em:
        idade = f" ({c.idade_dias} dias)" if c.idade_dias is not None else ""
        print(f"  Registrado em: {c.criado_em[:10]}{idade}  {c.registrador}")
    for tipo in ("A", "AAAA", "MX", "NS"):
        if c.dns.get(tipo):
            print(f"  {tipo:5}        : {', '.join(c.dns[tipo][:6])}")
    print(f"  SPF          : {c.spf or '(nenhum)'}")
    print(f"  DMARC        : {c.dmarc or '(nenhum)'}")
    if c.subdominios:
        extra = " (lista truncada)" if c.subdominios_truncados else ""
        print(f"  Subdomínios  : {len(c.subdominios)} nos logs de certificados{extra}")
        for nome in c.subdominios[:30]:
            print(f"                 {nome}")
        if len(c.subdominios) > 30:
            print(f"                 ... e mais {len(c.subdominios) - 30}")
    for obs in c.observacoes:
        print(f"  - {obs}")
    for erro in c.erros:
        print(f"  (falhou) {erro}")


def _imprimir_reputacao(reputacao) -> None:
    from core.dominios import defang

    rotulos = {"malicioso": "MALICIOSO", "suspeito": "suspeito", "sem_registro": "sem registro", "erro": "falhou"}
    for x in reputacao:
        print(f"  [{rotulos.get(x.veredito, x.veredito):12}] {x.fonte:10} {defang(x.indicador)[:60]}")
        if x.veredito in ("malicioso", "suspeito"):
            print(f"  {'':27}{x.resumo}")
            if x.tags:
                print(f"  {'':27}tags: {', '.join(x.tags[:8])}")
        elif x.veredito == "erro":
            print(f"  {'':27}{x.erro}")
    encontrados = sum(1 for x in reputacao if x.encontrado)
    print(f"\n  {encontrados} registro(s) em bases de inteligência. \"Sem registro\" não é \"limpo\": "
          "infraestrutura de phishing costuma viver dias e nunca chegar a base nenhuma.")


def comando_email(args: argparse.Namespace) -> int:
    import json

    from core.analise_email import ErroEmail, analisar_email
    from urllib.parse import urlsplit

    from core.dominios import defang, e_webmail, registravel

    caminho = Path(args.arquivo)
    if not caminho.is_file():
        print(f"erro: arquivo nao encontrado: {caminho}", file=sys.stderr)
        return 1
    try:
        r = analisar_email(caminho)
    except ErroEmail as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1

    _titulo(f"E-mail: {caminho.name}")
    print(f"  Assunto   : {r.assunto}")
    print(f"  Data      : {r.data}")
    for ident in r.identidades:
        if ident.campo != "Message-ID":
            nome = f'"{ident.nome}" ' if ident.nome else ""
            print(f"  {ident.campo:10}: {nome}<{ident.endereco}>")
    print(f"\n  Veredito  : {r.veredito} ({r.pontuacao}/100)")

    _secao("Caminho da mensagem (do remetente até você)")
    for salto in r.saltos:
        atraso = f" +{salto.atraso_segundos:.0f}s" if salto.atraso_segundos else ""
        marca = "  <- origem" if r.origem is salto else ""
        print(f"  {salto.ordem}. {salto.de or '?'} [{salto.ip or '-'}] -> {salto.por or '?'}{atraso}{marca}")
    if r.origem is not None:
        print(f"\n  Servidor de origem: {r.origem.ip} ({r.origem.de_reverso or r.origem.de or 'sem nome'})")

    a = r.autenticacao
    _secao("Autenticação")
    print(f"  SPF {a.spf or '?'}   DKIM {a.dkim or '?'}   DMARC {a.dmarc or '?'}"
          f"   (envelope: {a.dominio_envelope or '-'})")

    _secao(f"Sinais ({len(r.sinais)})")
    ordem = {"alta": 0, "media": 1, "baixa": 2}
    for sinal in sorted(r.sinais, key=lambda x: ordem[x.gravidade]):
        tecnica = f"  [{sinal.tecnica}]" if sinal.tecnica else ""
        print(f"  [{sinal.gravidade:5}] {sinal.titulo}{tecnica}")
        print(f"          {sinal.detalhe}")

    if r.links:
        _secao(f"Links ({len(r.links)}) - nenhum foi acessado")
        for link in r.links[:20]:
            print(f"  {link.tipo:10} {defang(link.destino)[:90]}")
            for obs in link.observacoes:
                print(f"             - {obs}")
    if r.anexos:
        _secao(f"Anexos ({len(r.anexos)}) - nenhum foi aberto")
        for anexo in r.anexos:
            print(f"  {anexo.nome}  {anexo.tamanho} bytes  {anexo.tipo_real}")
            print(f"    sha256 {anexo.sha256}")
            for obs in anexo.observacoes:
                print(f"    - {obs}")
    if r.tecnicas:
        _secao("MITRE ATT&CK")
        for t in r.tecnicas:
            print(f"  {t['id']:10} {t['nome']}")
    _secao(f"Indicadores ({len(r.iocs)}), já sem risco de clique")
    for i in r.iocs:
        print(f"  [{i.confianca.value:5}] {i.tipo.value:8} {defang(i.valor)[:80]}  ({i.origem})")

    consultas = []
    if args.online:
        from enrichment.consulta_dominio import consultar_dominio

        alvos = []
        candidatos = [x.dominio for x in r.identidades if x.campo != "Message-ID"]
        candidatos += [l.dominio for l in r.links if l.tipo in ("http", "encurtador")]
        candidatos += [urlsplit(u).hostname or "" for u in r.imagens_remotas]
        for d in candidatos:
            base = registravel(d) if d else ""
            if base and not e_webmail(base) and base not in alvos:
                alvos.append(base)
        print("\n  Consultando domínios (DNS, RDAP, certificados). Só o nome do domínio sai daqui.")
        for alvo in alvos[:6]:
            _secao(f"Domínio {alvo}")
            try:
                c = consultar_dominio(alvo, certificados=True)
            except ValueError as erro:
                print(f"  {erro}")
                continue
            consultas.append(c.to_dict())
            _imprimir_dominio(c)

    # --- Diamond Model, TTPs e Pyramid of Pain: calculo local, sempre ---
    from core.diamante import diamante_do_email
    from core.piramide import piramide_do_email

    reputacao = []
    if args.online:
        from enrichment.consulta_reputacao import consultar_reputacao, fontes_configuradas, indicadores_do_email

        fontes = fontes_configuradas()
        indicadores = indicadores_do_email(r, diamante_do_email(r, consultas))
        if fontes and indicadores:
            _secao(f"Reputação ({', '.join(fontes)})")
            print(f"  Consultando {len(indicadores)} indicador(es) do atacante. Só o indicador sai daqui.\n")
            reputacao = consultar_reputacao(indicadores)
            _imprimir_reputacao(reputacao)

    diamante = diamante_do_email(r, consultas, reputacao)
    piramide = piramide_do_email(r, diamante)
    _secao("Diamond Model")
    for vertice in (diamante.adversario, diamante.capacidade, diamante.infraestrutura, diamante.vitima):
        print(f"  {vertice.nome}")
        for item in vertice.itens[:6]:
            tipo = f"[{item.tipo}] " if item.tipo else ""
            print(f"    - {tipo}{defang(item.valor) if '.' in item.valor and ' ' not in item.valor else item.valor}  ({item.descricao})")
    print(f"\n  Eixo social : {diamante.eixo_social}")
    print(f"  Eixo técnico: {diamante.eixo_tecnico}")
    _secao("TTPs (tática -> técnica -> procedimento)")
    for t in diamante.ttps:
        print(f"  {t.tatica_nome:26} {t.tecnica:10} {t.tecnica_nome}")
        print(f"  {'':26} {t.procedimento}")
    _secao("Pyramid of Pain")
    contagem = piramide.contagem()
    for d in reversed(piramide.degraus):
        print(f"  {d['nome']:24} {contagem[d['id']]:3}   (dor: {d['dor']})")
    print(f"\n  {piramide.leitura}")
    if diamante.pivos:
        _secao("Próximos pivôs")
        for pivo in diamante.pivos:
            print(f"  {pivo.de} -> {pivo.para}: {pivo.acao}")

    saida = Path(args.saida)
    if args.json or args.exportar_iocs or args.yara or args.pdf or args.navigator:
        saida.mkdir(parents=True, exist_ok=True)

    regra = None
    if args.yara or args.pdf:
        from core.yara_email import gerar_regra_email

        regra = gerar_regra_email(r, caminho)
    if args.yara:
        _secao("Regra YARA da campanha")
        if regra.texto:
            print(regra.texto)
        situacao = "válida (compila, casa com o e-mail e não casa com um e-mail comum)" if regra.valida and not regra.falsos_positivos else "NÃO validada"
        print(f"  Regra {situacao}")
        for aviso in regra.avisos:
            print(f"  - {aviso}")
        if regra.texto:
            destino_yara = saida / f"{regra.nome}.yar"
            destino_yara.write_text(regra.texto, encoding="utf-8")
            print(f"  Salva em {destino_yara}")

    resumo = None
    if args.ia:
        from core.ia_email import gerar_resumo_email

        _secao(f"Resumo por IA ({args.modelo_ia}, local)")
        print("  Gerando... a primeira chamada carrega o modelo na GPU e pode levar um a dois minutos.")
        resumo = gerar_resumo_email(r, diamante, consultas, reputacao, modelo=args.modelo_ia)
        if resumo.gerado:
            print()
            for linha in resumo.texto.splitlines():
                print(f"  {linha}")
            print(f"\n  {resumo.ressalva}")
            for inv in resumo.invencoes:
                print(f"  ! não confere: {inv}")
        else:
            print(f"  Não gerado: {resumo.erro}")
        for aviso in resumo.avisos:
            print(f"  - {aviso}")

    if args.navigator:
        from reports.navigator import salvar_layer

        destino_layer = salvar_layer(f"E-mail: {r.assunto[:60]}", diamante.ttps,
                                     saida / f"{caminho.stem}_{r.sha256[:8]}_navigator.json",
                                     f"Técnicas observadas no e-mail {caminho.name} ({r.veredito}).")
        print(f"\n  Layer do ATT&CK Navigator: {destino_layer}")
    if args.pdf:
        from core.grafo import grafo_do_email
        from reports.relatorio_executivo import ErroRelatorioExecutivo, salvar_pdf_email

        try:
            destino_pdf = salvar_pdf_email(
                r, saida / f"{caminho.stem}_{r.sha256[:8]}_executivo.pdf", diamante, piramide,
                grafo_do_email(r, diamante, consultas), resumo, regra, consultas, reputacao,
            )
            print(f"  Relatório executivo (PDF): {destino_pdf}")
        except ErroRelatorioExecutivo as erro:
            print(f"  PDF não gerado: {erro}", file=sys.stderr)
    if args.json:
        destino = saida / f"{caminho.stem}_{r.sha256[:8]}_email.json"
        dados = r.to_dict()
        dados["dominios"] = consultas
        dados["reputacao"] = [x.to_dict() for x in reputacao]
        dados["diamante"] = diamante.to_dict()
        dados["piramide"] = piramide.to_dict()
        if resumo is not None:
            dados["resumo_ia"] = resumo.to_dict()
        destino.write_text(json.dumps(dados, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n  JSON: {destino}")
    if args.exportar_iocs:
        from core.string_extractor import Confianca
        from reports import ioc_export

        minima = {"alta": Confianca.ALTA, "media": Confianca.MEDIA, "baixa": Confianca.BAIXA}[args.confianca_minima]
        for formato, s in ioc_export.exportar(r, saida, args.exportar_iocs, confianca_minima=minima).items():
            print(f"  {formato:6} {s.exportados:3} indicadores  {s.caminho}")
    print()
    return 0


def comando_dominio(args: argparse.Namespace) -> int:
    import json

    from enrichment.consulta_dominio import consultar_dominio

    _titulo(f"Domínio: {args.dominio}")
    print("  Consulta passiva: DNS (Cloudflare), RDAP e logs de certificados (crt.sh, Cert Spotter).")
    print("  Nenhuma requisição vai ao servidor do domínio.\n")
    try:
        c = consultar_dominio(args.dominio, certificados=not args.sem_subdominios)
    except ValueError as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    _imprimir_dominio(c)
    if args.json:
        destino = Path(args.saida)
        destino.mkdir(parents=True, exist_ok=True)
        arquivo = destino / f"dominio_{c.registravel}.json"
        arquivo.write_text(json.dumps(c.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n  JSON: {arquivo}")
    print()
    return 0


def comando_instalar_ia(args: argparse.Namespace) -> int:
    """Baixa o modelo do Hugging Face, confere o SHA256 e registra no Ollama."""
    from core import modelo_hf

    modelo = modelo_hf.QWEN
    pasta = Path(args.pasta) if args.pasta else modelo_hf.pasta_padrao()
    _titulo(f"Instalando {modelo.nome_ollama}")
    print(f"  Origem : {modelo.pagina}")
    print(f"  Arquivo: {modelo.arquivo} ({modelo.tamanho / 2**30:.1f} GB)")
    print(f"  SHA256 : {modelo.sha256}")
    print(f"  Pasta  : {pasta}\n")

    ultimo = [""]

    def progresso(etapa: str, fracao: float) -> None:
        rotulo = {"baixando": "Baixando", "conferindo": "Conferindo SHA256", "registrando": "Registrando no Ollama"}[etapa]
        if etapa != ultimo[0] and ultimo[0]:
            print()
        ultimo[0] = etapa
        print(f"\r  {rotulo:22} {fracao * 100:5.1f}%", end="", flush=True)

    try:
        modelo_hf.instalar(modelo, pasta, manter_gguf=args.manter_gguf, progresso=progresso)
    except (modelo_hf.ErroInstalacao, OSError) as erro:
        print(f"\nerro: {erro}", file=sys.stderr)
        return 1
    print(f"\n\n  Pronto. O modelo {modelo.nome_ollama} já é o padrão do resumo e da revisão por IA.\n")
    return 0


def comando_atalho(args: argparse.Namespace) -> int:
    """Cria o atalho com icone na Area de Trabalho e no Menu Iniciar."""
    try:
        from PySide6.QtGui import QGuiApplication

        from gui import icone
    except ImportError as erro:
        print(f"erro: PySide6 indisponivel ({erro})", file=sys.stderr)
        return 1

    aplicacao = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841
    if not icone.CAMINHO_ICO.exists():
        icone.gerar_ico()
    try:
        criados = icone.criar_atalhos()
    except (OSError, subprocess.SubprocessError) as erro:
        print(f"erro: nao foi possivel criar o atalho ({erro})", file=sys.stderr)
        return 1
    for lnk in criados:
        print(f"  atalho criado: {lnk}")
    return 0


# ============================================================
# CLI
# ============================================================


def construir_parser() -> argparse.ArgumentParser:
    # Leve: so constantes. O nome do modelo tem uma unica fonte.
    from core.resumo_ia import MODELO_PADRAO

    parser = argparse.ArgumentParser(
        prog="nutshell",
        description="Nut-Shell Mapper - analise estatica de artefatos e threat intelligence.",
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

    # O mesmo -v aceito depois do subcomando. Por padrao o argparse so
    # aceitaria "main.py -v analisar x", e "main.py analisar x -v" daria
    # erro - um tropeco comum. SUPPRESS faz o valor do subcomando so
    # sobrescrever o global quando a flag for realmente informada ali.
    comum = argparse.ArgumentParser(add_help=False)
    comum.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS,
        help="log detalhado",
    )

    sub = parser.add_subparsers(dest="comando", required=True)

    # --- analisar ---
    p = sub.add_parser("analisar", help="analisa um artefato", parents=[comum])
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
    p.add_argument(
        "--formato", choices=["auto", "pe", "sc32", "sc64"], default="auto",
        help="formato do artefato. Em auto, arquivo sem cabecalho de PE e "
             "tentado como shellcode nas duas arquiteturas",
    )
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
    p.add_argument(
        "--resumo-ia", action="store_true",
        help="gera um resumo executivo com LLM local via Ollama. Roda em "
             "localhost: nenhum dado sai da maquina",
    )
    p.add_argument(
        "--modelo-ia", default=MODELO_PADRAO,
        help=f"modelo do Ollama a usar (padrao: {MODELO_PADRAO})",
    )
    p.add_argument(
        "--exportar-iocs", nargs="*", default=[], choices=["csv", "stix", "misp"],
        help="exporta os indicadores para alimentar SIEM, MISP ou bloqueio",
    )
    p.add_argument(
        "--confianca-minima", choices=["alta", "media", "baixa"], default="media",
        help="corte da exportacao de indicadores (padrao: media). 'baixa' "
             "inclui os duvidosos, que nao servem para bloqueio automatico",
    )
    p.add_argument("-q", "--quieto", action="store_true", help="sem barra de progresso")
    p.set_defaults(funcao=comando_analisar)

    # --- config ---
    p = sub.add_parser(
        "config", help="mostra a configuracao e verifica o ambiente",
        parents=[comum],
    )
    p.set_defaults(funcao=comando_config)

    # --- cvss ---
    p = sub.add_parser("cvss", help="calcula um score CVSS 3.1", parents=[comum])
    p.add_argument("vetor", help='vetor, ex: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"')
    p.add_argument("--cve", help="identificador da CVE")
    p.set_defaults(funcao=comando_cvss)

    # --- atualizar-attack ---
    p = sub.add_parser(
        "atualizar-attack", help="baixa o bundle STIX do MITRE ATT&CK",
        parents=[comum],
    )
    p.add_argument("--cache", help="caminho alternativo do cache")
    p.add_argument("--forcar", action="store_true", help="baixa mesmo com cache valido")
    p.set_defaults(funcao=comando_atualizar_attack)

    # --- bazaar ---
    p = sub.add_parser(
        "bazaar", help="consulta um hash no MalwareBazaar", parents=[comum]
    )
    p.add_argument("hash", help="MD5, SHA1 ou SHA256 da amostra")
    p.add_argument(
        "--baixar", action="store_true",
        help="baixa a amostra como ZIP cifrado. ATENCAO: traz malware para "
             "esta maquina; use apenas em ambiente isolado",
    )
    p.add_argument(
        "-o", "--saida",
        help="diretorio onde salvar (padrao: SAMPLES_DIR do .env)",
    )
    p.add_argument(
        "--sim", action="store_true",
        help="nao pergunta antes de baixar (para automacao)",
    )
    p.set_defaults(funcao=comando_bazaar)

    # --- gui ---
    p = sub.add_parser("gui", help="abre a interface grafica", parents=[comum])
    p.add_argument(
        "--classica",
        action="store_true",
        help="abre a interface antiga, em Qt puro, no lugar da nova",
    )
    p.set_defaults(funcao=comando_gui)

    # --- email ---
    p = sub.add_parser(
        "email",
        help="analisa um e-mail (.eml): cabeçalhos, origem, autenticação, links e anexos",
        parents=[comum],
    )
    p.add_argument("arquivo", help="arquivo .eml")
    p.add_argument(
        "--online", action="store_true",
        help="consulta DNS, idade e registrador dos domínios envolvidos (só o nome do domínio sai daqui)",
    )
    p.add_argument("--json", action="store_true", help="salva o resultado completo em JSON")
    p.add_argument("--yara", action="store_true", help="gera e valida uma regra YARA da campanha")
    p.add_argument("--ia", action="store_true", help="resumo executivo pela IA local (Ollama), conferido contra os achados")
    p.add_argument("--modelo-ia", default=MODELO_PADRAO, help=f"modelo do Ollama (padrao: {MODELO_PADRAO})")
    p.add_argument("--pdf", action="store_true", help="relatório executivo em PDF (Diamond, TTPs, pirâmide, grafo, YARA)")
    p.add_argument("--navigator", action="store_true", help="exporta a layer do ATT&CK Navigator")
    p.add_argument("-o", "--saida", default="output", help="diretorio de saida (padrao: output)")
    p.add_argument("--exportar-iocs", nargs="*", default=[], choices=["csv", "stix", "misp"])
    p.add_argument("--confianca-minima", choices=["alta", "media", "baixa"], default="media")
    p.set_defaults(funcao=comando_email)

    # --- dominio ---
    p = sub.add_parser(
        "dominio",
        help="DNS, idade, registrador e subdomínios de um domínio, de forma passiva",
        parents=[comum],
    )
    p.add_argument("dominio", help="ex.: exemplo.com")
    p.add_argument("--sem-subdominios", action="store_true", help="não consulta os logs de certificados")
    p.add_argument("--json", action="store_true", help="salva o resultado em JSON")
    p.add_argument("-o", "--saida", default="output", help="diretorio de saida (padrao: output)")
    p.set_defaults(funcao=comando_dominio)

    # --- instalar-ia ---
    p = sub.add_parser(
        "instalar-ia",
        help="baixa o modelo de IA padrao (Qwen3.5-9B) do Hugging Face e registra no Ollama",
        parents=[comum],
    )
    p.add_argument("--pasta", help="onde baixar o GGUF (padrao: ao lado de OLLAMA_MODELS)")
    p.add_argument("--manter-gguf", action="store_true", help="nao apaga o GGUF depois de registrar")
    p.set_defaults(funcao=comando_instalar_ia)

    # --- atalho ---
    p = sub.add_parser(
        "atalho",
        help="cria o atalho com icone na Area de Trabalho e no Menu Iniciar (Windows)",
        parents=[comum],
    )
    p.set_defaults(funcao=comando_atalho)

    return parser


def _verificar_interpretador() -> int:
    """
    Confere que as dependencias estao disponiveis antes de qualquer import.

    O erro mais comum de quem clona o projeto e rodar `python main.py` com o
    interpretador do sistema em vez do ambiente virtual. O sintoma e um
    ModuleNotFoundError cru, que nao diz o que fazer - e nem sempre o
    modulo faltando e obvio o suficiente para a pessoa ligar uma coisa a
    outra.

    Returns:
        0 quando esta tudo certo, ou um codigo de erro apos explicar.
    """
    raiz = Path(__file__).resolve().parent

    try:
        import dotenv  # noqa: F401  (so serve de sentinela)
    except ImportError:
        pass
    else:
        # Dependencias presentes; so avisa se a versao estiver fora da faixa.
        if sys.version_info[:2] != (3, 10):
            print(
                f"aviso: rodando em Python {sys.version_info.major}."
                f"{sys.version_info.minor}; o projeto e testado em 3.10.\n",
                file=sys.stderr,
            )
        return 0

    # --- Dependencias ausentes: descobrir o porque e dizer o que fazer ---
    nome = "python.exe" if sys.platform == "win32" else "python"
    venv = raiz / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / nome

    print(
        "erro: as dependencias do Nut-Shell Mapper nao estao disponiveis neste "
        "interpretador.\n",
        file=sys.stderr,
    )
    print(f"  Interpretador em uso : {sys.executable}", file=sys.stderr)
    print(
        f"  Versao               : {sys.version_info.major}."
        f"{sys.version_info.minor}.{sys.version_info.micro}\n",
        file=sys.stderr,
    )

    if venv.exists():
        print(
            "  O ambiente virtual do projeto existe, mas nao e o que esta "
            "rodando.\n"
            "  Use um dos dois:\n\n"
            f"    {venv} main.py ...\n\n"
            "  ou ative o ambiente antes:\n\n"
            f"    {raiz / '.venv' / 'Scripts' / 'activate'}\n",
            file=sys.stderr,
        )
    else:
        print(
            "  O ambiente virtual ainda nao foi criado. O projeto exige "
            "Python 3.10\n"
            "  (o flare-floss depende de binary2strings, que so tem wheel "
            "cp310 no Windows):\n\n"
            "    py -3.10 -m venv .venv\n"
            "    .venv\\Scripts\\activate\n"
            "    pip install -r requirements.txt\n",
            file=sys.stderr,
        )

    return 3


def main(argv: list[str] | None = None) -> int:
    codigo = _verificar_interpretador()
    if codigo:
        return codigo

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
