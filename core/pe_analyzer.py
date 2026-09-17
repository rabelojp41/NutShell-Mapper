"""
Parsing de binarios PE (Portable Executable).

Modulo compartilhado: o yara_generator usa os imports e as secoes de alta
entropia para montar a regra, e o mitre_mapper mapeia as mesmas API calls
para tecnicas ATT&CK. Manter isso num lugar so evita duas implementacoes
divergentes de "quais funcoes este binario importa".

O que sai daqui e descritivo, nao conclusivo. "Secao com entropia 7.9" e um
fato; "esta empacotado com UPX" seria uma conclusao, e cabe ao analista.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pefile

from core.deobfuscator import entropia_shannon

logger = logging.getLogger(__name__)


def _neutralizar_gc_collect_do_pefile() -> None:
    """
    Remove o gc.collect() incondicional que o pefile roda ao fechar um PE.

    O metodo pefile.PE._close_data() termina com um `gc.collect()` que
    executa sempre - mesmo quando nao ha mmap nenhum para liberar. Esse
    metodo tambem e chamado automaticamente pelo proprio __init__ do
    pefile quando o parse falha (`except: self.close(); raise`), entao ele
    dispara mesmo em arquivo que nem chega a ser um PE valido.

    Este modulo nunca abre PE por caminho (sempre por `data=`), entao
    self.__from_file nunca e True e o unico mmap que esse metodo poderia
    fechar nunca existe - o gc.collect() e puro custo, sem beneficio
    nenhum, em 100% dos casos daqui.

    O custo nao e so desempenho: uma colheita completa e sincrona,
    disparada de dentro do tratamento de excecao de uma extensao C,
    interagindo com outras extensoes nativas no mesmo processo (Qt, yara,
    pyzipper), produziu um crash intermitente por corrupcao de heap
    (access violation dentro do proprio gc.collect()) - reproduzido de
    forma confiavel ao rodar a suite de testes da GUI, que analisa muitos
    artefatos sinteticos nao-PE.

    O patch preserva o comportamento de fechar um mmap real, para o caso
    (que nao ocorre neste modulo, mas pode ocorrer se pefile for usado
    para outra coisa no mesmo processo) de alguem abrir um PE por
    caminho: a colheita roda normalmente quando ha de fato um mmap.
    """
    original = pefile.PE._close_data

    def _close_data_sem_gc_desnecessario(self):
        import mmap as _mmap

        tem_mmap = getattr(self, "_PE__from_file", None) is True and (
            isinstance(getattr(self, "__data__", None), _mmap.mmap)
        )
        if tem_mmap:
            original(self)
        # Sem mmap para fechar, nao ha razao para forcar uma colheita
        # completa - o ciclo normal de coleta do Python da conta do resto.

    pefile.PE._close_data = _close_data_sem_gc_desnecessario


_neutralizar_gc_collect_do_pefile()


# Acima disso a secao esta comprimida, cifrada ou empacotada. 7.0 e o valor
# usado pela maioria das ferramentas de triagem; texto e codigo normal
# raramente passam de 6.5.
ENTROPIA_SECAO_ALTA = 7.0

# Secoes com nome fora do padrao sao sinal de empacotador.
NOMES_DE_SECAO_COMUNS = frozenset(
    {
        ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata",
        ".rsrc", ".reloc", ".tls", ".debug", ".didat", ".sdata", ".xdata",
        "CODE", "DATA", "BSS", "INIT", "PAGE",
    }
)


@dataclass(frozen=True)
class Secao:
    """Uma secao do PE."""

    nome: str
    endereco_virtual: int
    tamanho_virtual: int
    tamanho_bruto: int
    entropia: float
    executavel: bool
    gravavel: bool

    @property
    def alta_entropia(self) -> bool:
        """Indica compressao, cifragem ou empacotamento."""
        return self.entropia >= ENTROPIA_SECAO_ALTA

    @property
    def nome_incomum(self) -> bool:
        """Nome fora do conjunto que compiladores normais produzem."""
        return self.nome not in NOMES_DE_SECAO_COMUNS

    @property
    def gravavel_e_executavel(self) -> bool:
        """
        Combinacao classica de codigo automodificavel ou desempacotador.

        Compilador legitimo praticamente nunca produz secao W+X.
        """
        return self.gravavel and self.executavel


@dataclass
class InfoPE:
    """Tudo que foi extraido do cabecalho PE."""

    e_pe: bool = False
    # Motivo de nao ter sido possivel parsear, quando e_pe e False.
    erro: str = ""

    arquitetura: str = ""
    tipo: str = ""  # EXE, DLL, SYS
    timestamp_compilacao: str = ""
    # Hash da tabela de imports. Mesmo compilador + mesma ordem de imports
    # produzem o mesmo imphash: e uma das melhores pistas de familia.
    imphash: str = ""

    # dll (minusculo) -> funcoes importadas
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    secoes: list[Secao] = field(default_factory=list)
    # Tipos de recurso embutidos (RT_RCDATA costuma esconder payload).
    tipos_de_recurso: list[str] = field(default_factory=list)

    # Observacoes objetivas, sem concluir nada.
    indicios: list[str] = field(default_factory=list)

    def todas_as_apis(self) -> list[str]:
        """Todas as funcoes importadas, sem separar por DLL."""
        return [funcao for funcoes in self.imports.values() for funcao in funcoes]

    def importa(self, funcao: str) -> bool:
        """Se o binario importa determinada API (sem diferenciar maiuscula)."""
        alvo = funcao.lower()
        return any(f.lower() == alvo for f in self.todas_as_apis())

    def secoes_suspeitas(self) -> list[Secao]:
        """Secoes que merecem atencao: alta entropia, nome incomum ou W+X."""
        return [
            s
            for s in self.secoes
            if s.alta_entropia or s.nome_incomum or s.gravavel_e_executavel
        ]

    def resumo(self) -> dict:
        return {
            "e_pe": self.e_pe,
            "arquitetura": self.arquitetura,
            "tipo": self.tipo,
            "dlls": len(self.imports),
            "apis": len(self.todas_as_apis()),
            "secoes": len(self.secoes),
            "secoes_suspeitas": len(self.secoes_suspeitas()),
            "indicios": len(self.indicios),
        }

    def to_dict(self) -> dict:
        return asdict(self)


def _formatar_timestamp(bruto: int) -> str:
    """
    Converte o TimeDateStamp do PE para ISO 8601.

    O valor e frequentemente falsificado por malware, entao vale como
    indicio e nao como fato - por isso ele so e registrado, nunca usado
    para decidir nada.
    """
    try:
        return datetime.fromtimestamp(bruto, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def _ler_secoes(pe: pefile.PE) -> list[Secao]:
    """Extrai as secoes com entropia calculada sobre os bytes brutos."""
    secoes: list[Secao] = []

    for s in pe.sections:
        nome = s.Name.rstrip(b"\x00").decode("ascii", "replace")
        dados = s.get_data()
        caracteristicas = s.Characteristics

        secoes.append(
            Secao(
                nome=nome,
                endereco_virtual=s.VirtualAddress,
                tamanho_virtual=s.Misc_VirtualSize,
                tamanho_bruto=s.SizeOfRawData,
                entropia=round(entropia_shannon(dados), 3),
                executavel=bool(caracteristicas & 0x20000000),  # MEM_EXECUTE
                gravavel=bool(caracteristicas & 0x80000000),  # MEM_WRITE
            )
        )

    return secoes


def _ler_imports(pe: pefile.PE) -> dict[str, list[str]]:
    """
    Extrai a tabela de imports.

    Funcao importada apenas por ordinal (sem nome) vira "ordinal_N": o numero
    ainda identifica a funcao dentro daquela DLL, e algumas, como ws2_32, sao
    quase sempre importadas assim.
    """
    imports: dict[str, list[str]] = {}

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entrada in pe.DIRECTORY_ENTRY_IMPORT:
        dll = (entrada.dll or b"").decode("ascii", "replace").lower()
        if not dll:
            continue

        funcoes = imports.setdefault(dll, [])
        for simbolo in entrada.imports:
            if simbolo.name:
                funcoes.append(simbolo.name.decode("ascii", "replace"))
            elif simbolo.ordinal is not None:
                funcoes.append(f"ordinal_{simbolo.ordinal}")

    return imports


def _ler_exports(pe: pefile.PE) -> list[str]:
    """Funcoes exportadas (relevante em DLL maliciosa)."""
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return []

    return [
        s.name.decode("ascii", "replace")
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols
        if s.name
    ]


def _ler_tipos_de_recurso(pe: pefile.PE) -> list[str]:
    """Tipos de recurso embutidos. RT_RCDATA costuma carregar payload."""
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return []

    tipos: set[str] = set()
    for entrada in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entrada.name is not None:
            tipos.add(str(entrada.name))
        elif entrada.id is not None:
            tipos.add(pefile.RESOURCE_TYPE.get(entrada.id, f"id_{entrada.id}"))

    return sorted(tipos)


def _levantar_indicios(info: InfoPE) -> list[str]:
    """
    Registra observacoes objetivas sobre o cabecalho.

    Cada item e um fato verificavel, nao um veredito. "Nenhuma DLL
    importada" e um fato; "esta empacotado" seria conclusao.
    """
    indicios: list[str] = []

    for s in info.secoes:
        if s.alta_entropia:
            indicios.append(
                f"secao '{s.nome}' com entropia {s.entropia} "
                f"(>= {ENTROPIA_SECAO_ALTA}): comprimida, cifrada ou empacotada"
            )
        if s.nome_incomum:
            indicios.append(f"secao '{s.nome}' com nome fora do padrao de compilador")
        if s.gravavel_e_executavel:
            indicios.append(
                f"secao '{s.nome}' e gravavel e executavel (W+X): "
                "codigo automodificavel ou desempacotador"
            )
        # Secao declarada muito maior na memoria do que no arquivo indica
        # espaco reservado para desempacotar em runtime.
        if s.tamanho_bruto == 0 and s.tamanho_virtual > 0:
            indicios.append(
                f"secao '{s.nome}' sem dado no arquivo mas com {s.tamanho_virtual} "
                "bytes reservados em memoria"
            )

    if not info.imports:
        indicios.append(
            "nenhuma DLL importada: tabela de imports destruida ou "
            "resolvida em runtime"
        )
    elif len(info.todas_as_apis()) < 10:
        indicios.append(
            f"apenas {len(info.todas_as_apis())} funcoes importadas: "
            "poucas para um programa funcional, sugere resolucao dinamica"
        )

    if "RT_RCDATA" in info.tipos_de_recurso:
        indicios.append("recurso RT_RCDATA presente: pode conter payload embutido")

    return indicios


def analisar(caminho: str | Path) -> InfoPE:
    """
    Analisa o cabecalho PE de um arquivo.

    Nao levanta excecao para arquivo nao-PE: devolve InfoPE(e_pe=False) com
    o motivo. O pipeline precisa seguir mesmo quando o artefato e um script,
    um documento ou um dump de memoria.
    """
    caminho = Path(caminho)

    try:
        dados = caminho.read_bytes()
    except OSError as erro:
        return InfoPE(e_pe=False, erro=f"nao foi possivel ler o arquivo: {erro}")

    # Confere o magic "MZ" antes de chamar o pefile. Quando __parse__ falha,
    # o proprio __init__ do pefile roda "except: self.close(); raise", e
    # close() chama gc.collect() de forma incondicional - uma colheita
    # completa e sincrona, disparada de dentro do tratamento de excecao do
    # C extension. Em combinacao com outras extensoes nativas no mesmo
    # processo (Qt, yara, pyzipper), isso produziu um crash intermitente
    # por corrupcao de heap (access violation dentro do proprio
    # gc.collect()), reproduzido de forma confiavel rodando a suite de
    # testes da GUI - que analisa muitos artefatos sinteticos nao-PE.
    # A grande maioria dos artefatos que chegam aqui (script, shellcode,
    # documento, texto) nem comeca com "MZ", entao filtrar isso aqui evita
    # entrar no caminho perigoso do pefile na esmagadora maioria dos casos,
    # sem mudar nada do que e reportado - e o mesmo InvalidPE de sempre.
    if dados[:2] != b"MZ":
        return InfoPE(e_pe=False, erro="DOS Header magic not found.")

    try:
        # Passa os bytes em vez do caminho: com um caminho, o pefile mapeia
        # o arquivo em memoria (mmap), cujo ciclo de vida tambem e fonte de
        # corrupcao de heap. O arquivo inteiro ja foi lido pelo
        # string_extractor de qualquer forma.
        pe = pefile.PE(data=dados, fast_load=False)
    except pefile.PEFormatError as erro:
        logger.debug("%s tem magic MZ mas nao e um PE valido: %s", caminho, erro)
        return InfoPE(e_pe=False, erro=str(erro))

    try:
        cabecalho = pe.FILE_HEADER
        opcional = pe.OPTIONAL_HEADER

        if opcional.Magic == 0x20B:
            arquitetura = "x64"
        elif opcional.Magic == 0x10B:
            arquitetura = "x86"
        else:
            arquitetura = f"desconhecida (0x{opcional.Magic:x})"

        if cabecalho.Characteristics & 0x2000:
            tipo = "DLL"
        elif cabecalho.Characteristics & 0x1000:
            tipo = "SYS"
        else:
            tipo = "EXE"

        info = InfoPE(
            e_pe=True,
            arquitetura=arquitetura,
            tipo=tipo,
            timestamp_compilacao=_formatar_timestamp(cabecalho.TimeDateStamp),
            imphash=pe.get_imphash(),
            imports=_ler_imports(pe),
            exports=_ler_exports(pe),
            secoes=_ler_secoes(pe),
            tipos_de_recurso=_ler_tipos_de_recurso(pe),
        )
        info.indicios = _levantar_indicios(info)
    finally:
        # Nao chamamos pe.close() aqui de proposito. Ele so tem trabalho a
        # fazer quando o PE foi aberto a partir de um caminho (mmap para
        # fechar); como usamos `data=`, nao ha mmap nenhum. Mas o close()
        # do pefile chama gc.collect() de forma incondicional, MESMO
        # quando nao ha nada para fechar - e uma colheita completa e
        # sincrona a cada arquivo analisado e cara e, em combinacao com
        # outras extensoes nativas no mesmo processo (Qt, yara, pyzipper),
        # foi a causa de um crash intermitente por corrupcao de heap
        # (access violation dentro do proprio gc.collect()). O objeto `pe`
        # e liberado normalmente pela contagem de referencia do Python
        # quando sai de escopo, sem precisar de gc.collect() forcado.
        del pe

    logger.info("PE analisado: %s", info.resumo())
    return info
