"""
Mapeamento de comportamentos para tecnicas MITRE ATT&CK.

Duas camadas, deliberadamente separadas:

  1. Catalogo de regras (offline, sempre disponivel)
     Liga sinais observaveis - API importada, string, indicio do PE,
     ofuscacao detectada - a tecnicas ATT&CK. E aqui que mora o
     conhecimento de dominio do modulo, e ele nao depende de rede.

  2. Enriquecimento STIX (online, opcional)
     Carrega o bundle oficial do ATT&CK para confirmar o ID, trazer a
     descricao canonica, as taticas corretas e as mitigacoes, alem de
     habilitar a atribuicao de grupos no group_attribution.

O pipeline funciona sem a camada 2. Sem ela o resultado traz os nomes do
catalogo local, que podem ficar defasados em relacao a versao atual do
ATT&CK - e isso e sinalizado explicitamente no resultado, em vez de
passar despercebido.

Aviso sobre o que este modulo *nao* faz: importar CreateRemoteThread nao
prova injecao de processo. Prova que a capacidade esta presente no binario.
Toda saida daqui e "capacidade observada", com a evidencia anexada para o
analista julgar - nunca "o malware faz X".
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Sequence

from core.deobfuscator import ResultadoDesofuscacao
from core.pe_analyzer import InfoPE
from core.string_extractor import Confianca, ResultadoExtracao

logger = logging.getLogger(__name__)


# Bundle oficial do ATT&CK Enterprise, mantido pela propria MITRE.
URL_STIX_ENTERPRISE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# O ATT&CK e atualizado algumas vezes por ano; um mes de cache e folgado.
VALIDADE_DO_CACHE = timedelta(days=30)

CAMINHO_CACHE_PADRAO = Path("data/mitre_cache/enterprise-attack.json")

# Peso somado minimo para uma tecnica ser reportada. Sem este piso, um unico
# sinal fraco ja gerava tecnica: GetTickCount (peso 0.2) esta em quase todo
# binario compilado com MSVC e sozinho fazia aparecer "evasao de sandbox".
PESO_MINIMO_PARA_REPORTAR = 0.3


# ============================================================
# Tipos
# ============================================================


class TipoSinal(str, Enum):
    """De onde veio a evidencia. A ordem reflete o quanto ela pesa."""

    # Funcao na tabela de imports do PE: evidencia forte, dificil de forjar
    # sem intencao.
    API = "api_importada"
    # Indicio estrutural do PE (secao W+X, alta entropia).
    PE = "indicio_pe"
    # Conteudo revelado pela desofuscacao: o malware se deu ao trabalho de
    # esconder, o que reforca a intencao.
    DESOFUSCADO = "conteudo_desofuscado"
    # Texto literal no binario: mais fraco, pode ser dado inerte.
    STRING = "string"


@dataclass(frozen=True)
class Sinal:
    """Um padrao observavel que aponta para uma tecnica."""

    tipo: TipoSinal
    padrao: str
    # Peso de 0.0 a 1.0. Sinal generico pesa pouco de proposito.
    peso: float = 0.5
    # Quando True, `padrao` e tratado como expressao regular.
    regex: bool = False


@dataclass(frozen=True)
class RegraTecnica:
    """Liga um conjunto de sinais a uma tecnica ATT&CK."""

    tecnica_id: str
    nome: str
    taticas: tuple[str, ...]
    sinais: tuple[Sinal, ...]
    descricao: str = ""
    # Quantos sinais distintos sao necessarios. Tecnicas cujos sinais
    # isolados sao ambiguos exigem mais de um.
    minimo_de_sinais: int = 1

    @property
    def e_subtecnica(self) -> bool:
        return "." in self.tecnica_id

    @property
    def tecnica_pai(self) -> str:
        return self.tecnica_id.split(".")[0]


@dataclass(frozen=True)
class Evidencia:
    """O que exatamente disparou a regra."""

    tipo: TipoSinal
    padrao: str
    # Trecho concreto encontrado, para o analista conferir.
    trecho: str

    def __str__(self) -> str:
        return f"{self.tipo.value}: {self.trecho}"


@dataclass
class TecnicaMapeada:
    """Uma tecnica ATT&CK observada no artefato."""

    tecnica_id: str
    nome: str
    taticas: list[str]
    evidencias: list[Evidencia] = field(default_factory=list)
    confianca: Confianca = Confianca.MEDIA
    descricao: str = ""
    # URL na base do ATT&CK, util no relatorio.
    url: str = ""
    # True quando os dados vieram do STIX oficial, e nao do catalogo local.
    confirmada_no_stix: bool = False

    @property
    def e_subtecnica(self) -> bool:
        return "." in self.tecnica_id

    @property
    def tecnica_pai(self) -> str:
        return self.tecnica_id.split(".")[0]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ResultadoMapeamento:
    """Saida do modulo."""

    tecnicas: list[TecnicaMapeada] = field(default_factory=list)
    # Origem dos metadados: "stix" ou "catalogo_local".
    fonte: str = "catalogo_local"
    versao_attack: str = ""
    avisos: list[str] = field(default_factory=list)

    def ids(self) -> list[str]:
        """IDs das tecnicas, na ordem em que foram reportadas."""
        return [t.tecnica_id for t in self.tecnicas]

    def por_tatica(self) -> dict[str, list[TecnicaMapeada]]:
        """Agrupa as tecnicas por tatica ATT&CK."""
        agrupado: dict[str, list[TecnicaMapeada]] = {}
        for t in self.tecnicas:
            for tatica in t.taticas:
                agrupado.setdefault(tatica, []).append(t)
        return agrupado

    def com_confianca_minima(self, minima: Confianca) -> list[TecnicaMapeada]:
        """Filtra por nivel de confianca."""
        ordem = {Confianca.BAIXA: 1, Confianca.MEDIA: 2, Confianca.ALTA: 3}
        return [t for t in self.tecnicas if ordem[t.confianca] >= ordem[minima]]

    def resumo(self) -> dict:
        return {
            "tecnicas": len(self.tecnicas),
            "subtecnicas": sum(1 for t in self.tecnicas if t.e_subtecnica),
            "taticas": len(self.por_tatica()),
            "alta_confianca": len(self.com_confianca_minima(Confianca.ALTA)),
            "fonte": self.fonte,
        }

    def to_dict(self) -> dict:
        return asdict(self)


class ErroMitre(Exception):
    """Falha ao obter ou carregar os dados do ATT&CK."""


# ============================================================
# Catalogo de regras
#
# Cada entrada liga sinais concretos a uma tecnica. Os pesos foram
# atribuidos pela especificidade do sinal: "CreateRemoteThread" praticamente
# so aparece em injecao de processo, enquanto "GetComputerNameA" aparece em
# software legitimo o tempo todo.
# ============================================================


def _api(nome: str, peso: float = 0.7) -> Sinal:
    return Sinal(TipoSinal.API, nome, peso)


def _str(padrao: str, peso: float = 0.4) -> Sinal:
    return Sinal(TipoSinal.STRING, padrao, peso)


def _re(padrao: str, peso: float = 0.5) -> Sinal:
    return Sinal(TipoSinal.STRING, padrao, peso, regex=True)


def _pe(padrao: str, peso: float = 0.6) -> Sinal:
    return Sinal(TipoSinal.PE, padrao, peso)


CATALOGO: tuple[RegraTecnica, ...] = (
    # ---------- Execution ----------
    RegraTecnica(
        "T1059.001", "Command and Scripting Interpreter: PowerShell",
        ("execution",),
        (
            _str("powershell.exe", 0.6),
            _re(r"-enc(odedcommand)?\b", 0.7),
            _re(r"-nop\b|-noprofile\b", 0.6),
            _re(r"\b(iex|invoke-expression)\b", 0.7),
            _str("DownloadString", 0.7),
            _re(r"-w\s+hidden|-windowstyle\s+hidden", 0.7),
        ),
        "Execucao via PowerShell, frequentemente com comando codificado.",
    ),
    RegraTecnica(
        "T1059.003", "Command and Scripting Interpreter: Windows Command Shell",
        ("execution",),
        (_str("cmd.exe", 0.5), _re(r"cmd(\.exe)?\s+/c\b", 0.7), _str("ComSpec", 0.4)),
        "Execucao de comandos via interpretador do Windows.",
    ),
    RegraTecnica(
        "T1106", "Native API",
        ("execution",),
        (_api("NtCreateThreadEx", 0.7), _api("ZwCreateThreadEx", 0.7),
         _api("NtCreateSection", 0.6), _api("RtlCreateUserThread", 0.7)),
        "Chamadas diretas a API nativa, contornando a camada Win32.",
    ),

    # ---------- Persistence ----------
    RegraTecnica(
        "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys",
        ("persistence", "privilege-escalation"),
        (
            _re(r"CurrentVersion\\\\?Run(Once)?\b", 0.9),
            _str("Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0.9),
            _api("RegSetValueExA", 0.4),
            _api("RegSetValueExW", 0.4),
        ),
        "Persistencia por chave Run do registro.",
    ),
    RegraTecnica(
        "T1053.005", "Scheduled Task/Job: Scheduled Task",
        ("execution", "persistence", "privilege-escalation"),
        (_str("schtasks", 0.8), _str("TaskScheduler", 0.6),
         _str("ITaskService", 0.7), _re(r"/create\s+/tn", 0.8)),
        "Persistencia por tarefa agendada.",
    ),
    RegraTecnica(
        "T1543.003", "Create or Modify System Process: Windows Service",
        ("persistence", "privilege-escalation"),
        (_api("CreateServiceA", 0.8), _api("CreateServiceW", 0.8),
         _api("OpenSCManagerA", 0.6), _api("OpenSCManagerW", 0.6),
         _api("StartServiceA", 0.6), _str("sc.exe create", 0.7)),
        "Persistencia por servico do Windows.",
        minimo_de_sinais=2,
    ),

    # ---------- Privilege Escalation / Defense Evasion ----------
    RegraTecnica(
        "T1055", "Process Injection",
        ("defense-evasion", "privilege-escalation"),
        (
            _api("WriteProcessMemory", 0.8),
            _api("CreateRemoteThread", 0.9),
            _api("VirtualAllocEx", 0.8),
            _api("QueueUserAPC", 0.8),
            _api("SetThreadContext", 0.7),
            _api("OpenProcess", 0.3),
        ),
        "Escrita de codigo na memoria de outro processo.",
        minimo_de_sinais=2,
    ),
    RegraTecnica(
        "T1055.012", "Process Injection: Process Hollowing",
        ("defense-evasion", "privilege-escalation"),
        (_api("NtUnmapViewOfSection", 0.9), _api("ZwUnmapViewOfSection", 0.9),
         _api("SetThreadContext", 0.5), _api("ResumeThread", 0.3)),
        "Substituicao da imagem de um processo suspenso.",
        minimo_de_sinais=2,
    ),
    RegraTecnica(
        "T1055.001", "Process Injection: Dynamic-link Library Injection",
        ("defense-evasion", "privilege-escalation"),
        (_api("LoadLibraryA", 0.2), _api("CreateRemoteThread", 0.6),
         _api("VirtualAllocEx", 0.5), _api("GetModuleHandleA", 0.2)),
        "Carga de DLL no espaco de endereco de outro processo.",
        minimo_de_sinais=3,
    ),
    RegraTecnica(
        "T1027", "Obfuscated Files or Information",
        ("defense-evasion",),
        (
            _pe("alta_entropia", 0.7),
            Sinal(TipoSinal.DESOFUSCADO, "qualquer", 0.6),
        ),
        "Conteudo ofuscado ou codificado para dificultar a analise.",
    ),
    RegraTecnica(
        "T1027.002", "Obfuscated Files or Information: Software Packing",
        ("defense-evasion",),
        (
            _pe("alta_entropia", 0.6),
            _pe("nome_de_secao_incomum", 0.6),
            _pe("secao_wx", 0.7),
            _pe("poucos_imports", 0.6),
            _re(r"^(UPX[0-9!]|\.aspack|\.themida|\.vmp\d|\.petite|MPRESS)", 0.9),
        ),
        "Binario empacotado: codigo real so existe apos desempacotar.",
        minimo_de_sinais=2,
    ),
    RegraTecnica(
        "T1140", "Deobfuscate/Decode Files or Information",
        ("defense-evasion",),
        (
            Sinal(TipoSinal.DESOFUSCADO, "qualquer", 0.7),
            _api("CryptStringToBinaryA", 0.7),
            _api("CryptStringToBinaryW", 0.7),
        ),
        "Rotina propria de decodificacao do conteudo embutido.",
    ),
    RegraTecnica(
        "T1622", "Debugger Evasion",
        ("defense-evasion", "discovery"),
        (_api("IsDebuggerPresent", 0.5), _api("CheckRemoteDebuggerPresent", 0.8),
         _api("NtQueryInformationProcess", 0.5), _api("OutputDebugStringA", 0.3)),
        "Verificacao da presenca de depurador.",
    ),
    RegraTecnica(
        "T1497.001", "Virtualization/Sandbox Evasion: System Checks",
        ("defense-evasion", "discovery"),
        (
            _re(r"\b(vmware|virtualbox|vbox|qemu|xen|sandboxie|cuckoo)\b", 0.8),
            _str("SbieDll.dll", 0.9),
            _str("VBoxService", 0.9),
            _api("GetTickCount", 0.2),
        ),
        "Deteccao de ambiente virtualizado ou de sandbox.",
    ),
    RegraTecnica(
        "T1070.004", "Indicator Removal: File Deletion",
        ("defense-evasion",),
        (_api("DeleteFileA", 0.4), _api("DeleteFileW", 0.4),
         _api("SHFileOperationW", 0.5), _re(r"del\s+/f\s+/q", 0.7)),
        "Remocao de arquivos para apagar rastro.",
        minimo_de_sinais=2,
    ),
    RegraTecnica(
        "T1218.011", "System Binary Proxy Execution: Rundll32",
        ("defense-evasion",),
        (_str("rundll32", 0.8),),
        "Execucao de codigo atraves do rundll32.exe.",
    ),
    RegraTecnica(
        "T1218.010", "System Binary Proxy Execution: Regsvr32",
        ("defense-evasion",),
        (_str("regsvr32", 0.8), _re(r"/i:.*scrobj\.dll", 0.9)),
        "Execucao de codigo atraves do regsvr32.exe.",
    ),
    RegraTecnica(
        "T1112", "Modify Registry",
        ("defense-evasion",),
        (_api("RegSetValueExA", 0.5), _api("RegSetValueExW", 0.5),
         _api("RegCreateKeyExA", 0.4), _api("RegDeleteValueA", 0.5)),
        "Alteracao de chaves do registro.",
        minimo_de_sinais=2,
    ),

    # ---------- Credential Access ----------
    RegraTecnica(
        "T1056.001", "Input Capture: Keylogging",
        ("collection", "credential-access"),
        (_api("SetWindowsHookExA", 0.8), _api("SetWindowsHookExW", 0.8),
         _api("GetAsyncKeyState", 0.8), _api("GetKeyboardState", 0.6),
         _api("RegisterRawInputDevices", 0.5)),
        "Captura de teclas digitadas.",
    ),
    RegraTecnica(
        "T1555.003", "Credentials from Password Stores: Web Browsers",
        ("credential-access",),
        (
            _str("Login Data", 0.8),
            _str("logins.json", 0.8),
            _str("Local State", 0.6),
            _re(r"\\(Chrome|Edge|Firefox|Opera|Brave)\\User Data", 0.8),
            _str("key4.db", 0.9),
        ),
        "Leitura de credenciais salvas em navegadores.",
    ),
    RegraTecnica(
        "T1003.001", "OS Credential Dumping: LSASS Memory",
        ("credential-access",),
        (_str("lsass.exe", 0.9), _api("MiniDumpWriteDump", 0.8),
         _str("sekurlsa", 0.9)),
        "Extracao de credenciais da memoria do LSASS.",
    ),

    # ---------- Discovery ----------
    RegraTecnica(
        "T1082", "System Information Discovery",
        ("discovery",),
        (_api("GetSystemInfo", 0.4), _api("GetVersionExA", 0.4),
         _api("GetComputerNameA", 0.4), _api("GetComputerNameW", 0.4),
         _str("systeminfo", 0.5)),
        "Coleta de informacoes do sistema.",
        minimo_de_sinais=2,
    ),
    RegraTecnica(
        "T1057", "Process Discovery",
        ("discovery",),
        (_api("CreateToolhelp32Snapshot", 0.7), _api("Process32First", 0.7),
         _api("Process32Next", 0.7), _api("EnumProcesses", 0.7),
         _str("tasklist", 0.5)),
        "Enumeracao dos processos em execucao.",
    ),
    RegraTecnica(
        "T1083", "File and Directory Discovery",
        ("discovery",),
        (_api("FindFirstFileA", 0.4), _api("FindFirstFileW", 0.4),
         _api("FindNextFileA", 0.4), _api("FindNextFileW", 0.4)),
        "Varredura do sistema de arquivos.",
        minimo_de_sinais=2,
    ),
    RegraTecnica(
        "T1033", "System Owner/User Discovery",
        ("discovery",),
        (_api("GetUserNameA", 0.5), _api("GetUserNameW", 0.5), _str("whoami", 0.6)),
        "Identificacao do usuario atual.",
    ),
    RegraTecnica(
        "T1016", "System Network Configuration Discovery",
        ("discovery",),
        (_api("GetAdaptersInfo", 0.6), _api("GetAdaptersAddresses", 0.6),
         _str("ipconfig", 0.6), _api("GetNetworkParams", 0.5)),
        "Leitura da configuracao de rede.",
    ),
    RegraTecnica(
        "T1010", "Application Window Discovery",
        ("discovery",),
        (_api("EnumWindows", 0.5), _api("GetForegroundWindow", 0.6),
         _api("GetWindowTextA", 0.5), _api("GetWindowTextW", 0.5)),
        "Enumeracao de janelas abertas.",
        minimo_de_sinais=2,
    ),

    # ---------- Collection ----------
    RegraTecnica(
        "T1113", "Screen Capture",
        ("collection",),
        (_api("BitBlt", 0.7), _api("CreateCompatibleBitmap", 0.6),
         _api("GetDC", 0.3), _api("CreateCompatibleDC", 0.5)),
        "Captura de tela.",
        minimo_de_sinais=2,
    ),
    RegraTecnica(
        "T1115", "Clipboard Data",
        ("collection",),
        (_api("OpenClipboard", 0.7), _api("GetClipboardData", 0.8)),
        "Leitura da area de transferencia.",
    ),
    RegraTecnica(
        "T1123", "Audio Capture",
        ("collection",),
        (_api("waveInOpen", 0.8), _api("waveInStart", 0.8)),
        "Captura de audio do microfone.",
    ),
    RegraTecnica(
        "T1560", "Archive Collected Data",
        ("collection",),
        (_str("RAR!", 0.5), _api("RtlCompressBuffer", 0.6),
         _re(r"\b(7za?|rar|zip)\.(exe|dll)\b", 0.5)),
        "Compactacao dos dados antes da exfiltracao.",
    ),

    # ---------- Command and Control ----------
    RegraTecnica(
        "T1071.001", "Application Layer Protocol: Web Protocols",
        ("command-and-control",),
        (
            _api("InternetOpenA", 0.6), _api("InternetOpenUrlA", 0.7),
            _api("HttpSendRequestA", 0.7), _api("WinHttpOpen", 0.6),
            _api("WinHttpSendRequest", 0.7),
            _re(r"^(GET|POST)\s+/", 0.5),
            _str("User-Agent:", 0.4),
        ),
        "Comunicacao com o C2 por HTTP ou HTTPS.",
    ),
    RegraTecnica(
        "T1105", "Ingress Tool Transfer",
        ("command-and-control",),
        (_api("URLDownloadToFileA", 0.9), _api("URLDownloadToFileW", 0.9),
         _api("InternetReadFile", 0.6), _api("WinHttpReadData", 0.6),
         _str("certutil -urlcache", 0.8)),
        "Download de ferramenta ou estagio adicional.",
    ),
    RegraTecnica(
        "T1571", "Non-Standard Port",
        ("command-and-control",),
        (_re(r"https?://[^\s/]+:(?!80|443|8080)\d{2,5}", 0.7),),
        "C2 em porta fora do padrao do protocolo.",
    ),
    RegraTecnica(
        "T1132.001", "Data Encoding: Standard Encoding",
        ("command-and-control",),
        (Sinal(TipoSinal.DESOFUSCADO, "base64", 0.6),),
        "Dado codificado em Base64 no canal de comando.",
    ),
    RegraTecnica(
        "T1095", "Non-Application Layer Protocol",
        ("command-and-control",),
        (_api("WSASocketA", 0.6), _api("socket", 0.4),
         _api("connect", 0.3), _api("send", 0.2)),
        "Comunicacao direta por socket, sem protocolo de aplicacao.",
        minimo_de_sinais=3,
    ),

    # ---------- Impact ----------
    RegraTecnica(
        "T1486", "Data Encrypted for Impact",
        ("impact",),
        (
            _api("CryptEncrypt", 0.8), _api("CryptGenKey", 0.7),
            _api("BCryptEncrypt", 0.8), _api("CryptAcquireContextA", 0.4),
            _re(r"\b(your files|seus arquivos).{0,30}(encrypted|criptografados)", 0.9),
            _re(r"\.(locked|encrypted|crypt|crypted|enc)\b", 0.6),
            _re(r"README.*DECRYPT|HOW.TO.DECRYPT", 0.9),
        ),
        "Cifragem de dados da vitima (ransomware).",
    ),
    RegraTecnica(
        "T1490", "Inhibit System Recovery",
        ("impact",),
        (
            _re(r"vssadmin.{0,20}delete.{0,20}shadows", 0.95),
            _str("wbadmin delete catalog", 0.95),
            _re(r"bcdedit.{0,30}recoveryenabled\s+no", 0.95),
            _str("Win32_ShadowCopy", 0.8),
        ),
        "Destruicao de copias de sombra e pontos de restauracao.",
    ),
    RegraTecnica(
        "T1489", "Service Stop",
        ("impact",),
        (_re(r"net\s+stop\b", 0.6), _api("ControlService", 0.5),
         _re(r"taskkill\s+/f", 0.6)),
        "Parada de servicos, tipica antes de cifrar dados.",
    ),

    # ---------- Exfiltration ----------
    RegraTecnica(
        "T1041", "Exfiltration Over C2 Channel",
        ("exfiltration",),
        (_api("HttpSendRequestA", 0.4), _api("InternetWriteFile", 0.7),
         _re(r"(POST|PUT)\s+/(upload|gate|submit|data)", 0.7)),
        "Envio dos dados coletados pelo proprio canal de C2.",
        minimo_de_sinais=2,
    ),
)


# Indice para busca rapida por ID.
CATALOGO_POR_ID: dict[str, RegraTecnica] = {r.tecnica_id: r for r in CATALOGO}


# ============================================================
# Casamento de sinais
# ============================================================


def _apis_do_artefato(info_pe: InfoPE | None) -> dict[str, str]:
    """APIs importadas, indexadas em minusculo para busca sem case."""
    if not info_pe or not info_pe.e_pe:
        return {}
    return {api.lower(): api for api in info_pe.todas_as_apis()}


def _indicios_do_pe(info_pe: InfoPE | None) -> dict[str, str]:
    """
    Traduz os indicios estruturais do PE para os rotulos usados no catalogo.

    Devolve rotulo -> trecho de evidencia.
    """
    if not info_pe or not info_pe.e_pe:
        return {}

    indicios: dict[str, str] = {}

    for s in info_pe.secoes:
        if s.alta_entropia:
            indicios.setdefault(
                "alta_entropia", f"secao '{s.nome}' com entropia {s.entropia}"
            )
        if s.nome_incomum:
            indicios.setdefault(
                "nome_de_secao_incomum", f"secao '{s.nome}' fora do padrao"
            )
        if s.gravavel_e_executavel:
            indicios.setdefault("secao_wx", f"secao '{s.nome}' e W+X")

    if len(info_pe.todas_as_apis()) < 10:
        indicios["poucos_imports"] = (
            f"apenas {len(info_pe.todas_as_apis())} funcoes importadas"
        )

    return indicios


def _casar_sinal(
    sinal: Sinal,
    apis: dict[str, str],
    indicios: dict[str, str],
    textos: Sequence[str],
    nomes_de_secao: Sequence[str],
    tecnicas_de_ofuscacao: set[str],
) -> Evidencia | None:
    """Verifica se um sinal ocorre no artefato. Devolve a evidencia ou None."""

    if sinal.tipo is TipoSinal.API:
        # Casa tambem as variantes A/W e Nt/Zw, que sao a mesma funcao.
        alvo = sinal.padrao.lower()
        for candidato in (alvo, alvo + "a", alvo + "w"):
            if candidato in apis:
                return Evidencia(TipoSinal.API, sinal.padrao, apis[candidato])
        return None

    if sinal.tipo is TipoSinal.PE:
        if sinal.regex:
            # Padroes de nome de secao (UPX0, .themida, ...).
            padrao = re.compile(sinal.padrao, re.IGNORECASE)
            for nome in nomes_de_secao:
                if padrao.search(nome):
                    return Evidencia(TipoSinal.PE, sinal.padrao, f"secao '{nome}'")
            return None
        if sinal.padrao in indicios:
            return Evidencia(TipoSinal.PE, sinal.padrao, indicios[sinal.padrao])
        return None

    if sinal.tipo is TipoSinal.DESOFUSCADO:
        if sinal.padrao == "qualquer" and tecnicas_de_ofuscacao:
            return Evidencia(
                TipoSinal.DESOFUSCADO,
                sinal.padrao,
                f"ofuscacao detectada: {', '.join(sorted(tecnicas_de_ofuscacao))}",
            )
        if sinal.padrao in tecnicas_de_ofuscacao:
            return Evidencia(
                TipoSinal.DESOFUSCADO, sinal.padrao, f"tecnica {sinal.padrao} detectada"
            )
        return None

    # TipoSinal.STRING
    if sinal.regex:
        padrao = re.compile(sinal.padrao, re.IGNORECASE)
        for texto in textos:
            m = padrao.search(texto)
            if m:
                return Evidencia(TipoSinal.STRING, sinal.padrao, texto[:120])
        return None

    alvo = sinal.padrao.lower()
    for texto in textos:
        if alvo in texto.lower():
            return Evidencia(TipoSinal.STRING, sinal.padrao, texto[:120])
    return None


def _confianca_de(evidencias: list[Evidencia], pesos: list[float]) -> Confianca:
    """
    Converte as evidencias em nivel de confianca.

    O criterio pondera quantidade e qualidade: duas evidencias fracas nao
    valem uma forte, e uma API especifica (peso alto) sozinha ja e mais
    convincente que tres strings genericas.
    """
    if not evidencias:
        return Confianca.BAIXA

    soma = sum(pesos)
    tem_api = any(e.tipo is TipoSinal.API for e in evidencias)

    if soma >= 1.5 or (tem_api and soma >= 0.8 and len(evidencias) >= 2):
        return Confianca.ALTA
    if soma >= 0.7:
        return Confianca.MEDIA
    return Confianca.BAIXA


def mapear(
    extracao: ResultadoExtracao,
    desofuscacao: ResultadoDesofuscacao | None = None,
    info_pe: InfoPE | None = None,
    attack: "MitreAttack | None" = None,
) -> ResultadoMapeamento:
    """
    Mapeia o artefato para tecnicas ATT&CK.

    Args:
        extracao: saida do string_extractor.
        desofuscacao: saida do deobfuscator (opcional).
        info_pe: saida do pe_analyzer (opcional, mas melhora muito).
        attack: instancia carregada do STIX, para enriquecer e confirmar os
            IDs. Sem ela, os metadados vem do catalogo local.

    Returns:
        ResultadoMapeamento com as tecnicas e as evidencias de cada uma.
    """
    resultado = ResultadoMapeamento()

    apis = _apis_do_artefato(info_pe)
    indicios = _indicios_do_pe(info_pe)
    nomes_de_secao = [s.nome for s in info_pe.secoes] if info_pe else []

    textos = list(extracao.valores_unicos())
    tecnicas_de_ofuscacao: set[str] = set()
    if desofuscacao:
        textos.extend(a.decodificado for a in desofuscacao.achados)
        tecnicas_de_ofuscacao = {
            t.value for a in desofuscacao.achados for t in a.tecnicas
        }

    if not info_pe or not info_pe.e_pe:
        resultado.avisos.append(
            "artefato nao e um PE: o mapeamento usou apenas strings, sem a "
            "tabela de imports, que e a evidencia mais forte"
        )

    for regra in CATALOGO:
        evidencias: list[Evidencia] = []
        pesos: list[float] = []

        for sinal in regra.sinais:
            evidencia = _casar_sinal(
                sinal, apis, indicios, textos, nomes_de_secao, tecnicas_de_ofuscacao
            )
            if evidencia is not None:
                evidencias.append(evidencia)
                pesos.append(sinal.peso)

        if len(evidencias) < regra.minimo_de_sinais:
            continue

        # Descarta o que so casou por sinal fraco e generico.
        if sum(pesos) < PESO_MINIMO_PARA_REPORTAR:
            continue

        tecnica = TecnicaMapeada(
            tecnica_id=regra.tecnica_id,
            nome=regra.nome,
            taticas=list(regra.taticas),
            evidencias=evidencias,
            confianca=_confianca_de(evidencias, pesos),
            descricao=regra.descricao,
            url=f"https://attack.mitre.org/techniques/"
            f"{regra.tecnica_id.replace('.', '/')}/",
        )

        if attack is not None:
            attack.enriquecer(tecnica)

        resultado.tecnicas.append(tecnica)

    # Ordena por confianca e depois por ID, para o relatorio ficar estavel.
    ordem = {Confianca.ALTA: 0, Confianca.MEDIA: 1, Confianca.BAIXA: 2}
    resultado.tecnicas.sort(key=lambda t: (ordem[t.confianca], t.tecnica_id))

    if attack is not None:
        resultado.fonte = "stix"
        resultado.versao_attack = attack.versao
        nao_confirmadas = [
            t.tecnica_id for t in resultado.tecnicas if not t.confirmada_no_stix
        ]
        if nao_confirmadas:
            resultado.avisos.append(
                "tecnicas do catalogo local ausentes no STIX carregado "
                f"(possivelmente descontinuadas): {', '.join(nao_confirmadas)}"
            )
    else:
        resultado.avisos.append(
            "STIX oficial nao carregado: nomes e taticas vem do catalogo "
            "local e podem estar defasados em relacao a versao atual do ATT&CK"
        )

    logger.info("mapeamento ATT&CK concluido: %s", resultado.resumo())
    return resultado


# ============================================================
# Camada STIX
# ============================================================


class MitreAttack:
    """
    Acesso ao bundle STIX oficial do ATT&CK, com cache em disco.

    O bundle tem cerca de 45 MB, entao e baixado uma vez e reaproveitado.
    O cache e considerado velho depois de VALIDADE_DO_CACHE, mas um cache
    velho ainda e usado quando nao ha rede - dado defasado e melhor que
    nenhum, desde que o usuario saiba.
    """

    def __init__(self, caminho_cache: str | Path = CAMINHO_CACHE_PADRAO):
        self.caminho_cache = Path(caminho_cache)
        self.versao = ""
        self._dados = None
        self._por_id: dict[str, dict] = {}
        self.avisos: list[str] = []

    # --- Cache ---

    @property
    def cache_existe(self) -> bool:
        return self.caminho_cache.is_file() and self.caminho_cache.stat().st_size > 0

    @property
    def cache_vencido(self) -> bool:
        """True se o cache existe mas passou da validade."""
        if not self.cache_existe:
            return True
        idade = datetime.now(timezone.utc) - datetime.fromtimestamp(
            self.caminho_cache.stat().st_mtime, tz=timezone.utc
        )
        return idade > VALIDADE_DO_CACHE

    def baixar(self, forcar: bool = False, timeout: int = 300) -> Path:
        """
        Baixa o bundle STIX, se necessario.

        Args:
            forcar: baixa mesmo com cache valido.
            timeout: limite da requisicao em segundos.

        Raises:
            ErroMitre: falha de rede e nenhum cache utilizavel.
        """
        if self.cache_existe and not self.cache_vencido and not forcar:
            logger.debug("cache do ATT&CK valido: %s", self.caminho_cache)
            return self.caminho_cache

        import requests

        logger.info("baixando o bundle STIX do ATT&CK (~45 MB)...")
        self.caminho_cache.parent.mkdir(parents=True, exist_ok=True)
        temporario = self.caminho_cache.with_suffix(".parcial")

        try:
            resposta = requests.get(URL_STIX_ENTERPRISE, timeout=timeout, stream=True)
            resposta.raise_for_status()

            # Grava num arquivo temporario e so entao substitui: uma queda
            # no meio do download deixaria um cache corrompido que falharia
            # de forma confusa na proxima execucao.
            with temporario.open("wb") as destino:
                for bloco in resposta.iter_content(chunk_size=1 << 16):
                    destino.write(bloco)

            temporario.replace(self.caminho_cache)
            logger.info(
                "bundle salvo em %s (%.1f MB)",
                self.caminho_cache,
                self.caminho_cache.stat().st_size / 1024 / 1024,
            )

        except Exception as erro:  # rede, DNS, HTTP, disco
            temporario.unlink(missing_ok=True)

            if self.cache_existe:
                self.avisos.append(
                    f"nao foi possivel atualizar o ATT&CK ({erro}); "
                    "usando o cache existente, possivelmente defasado"
                )
                logger.warning("%s", self.avisos[-1])
                return self.caminho_cache

            raise ErroMitre(
                f"falha ao baixar o bundle STIX e nao ha cache local: {erro}"
            ) from erro

        return self.caminho_cache

    # --- Carga ---

    def carregar(self, baixar_se_faltar: bool = True) -> "MitreAttack":
        """
        Carrega o bundle em memoria e indexa por ID do ATT&CK.

        A indexacao e feita direto sobre o JSON, sem a MitreAttackData, para
        o carregamento ficar previsivel e rapido: o que este modulo precisa
        e apenas a busca por ID, e a biblioteca completa custa varios
        segundos so para montar o grafo de relacionamentos.

        Raises:
            ErroMitre: cache ausente ou JSON invalido.
        """
        if not self.cache_existe:
            if not baixar_se_faltar:
                raise ErroMitre(
                    f"cache do ATT&CK nao encontrado em {self.caminho_cache}. "
                    "Rode MitreAttack().baixar() ou passe baixar_se_faltar=True"
                )
            self.baixar()

        try:
            with self.caminho_cache.open(encoding="utf-8") as arquivo:
                self._dados = json.load(arquivo)
        except (json.JSONDecodeError, OSError) as erro:
            raise ErroMitre(
                f"cache do ATT&CK invalido ({erro}); apague {self.caminho_cache} "
                "e baixe de novo"
            ) from erro

        objetos = self._dados.get("objects", [])
        for obj in objetos:
            for referencia in obj.get("external_references", []):
                if referencia.get("source_name") == "mitre-attack":
                    identificador = referencia.get("external_id")
                    if identificador:
                        self._por_id[identificador] = obj
                    break

        # A versao fica no objeto x-mitre-collection do proprio bundle.
        for obj in objetos:
            if obj.get("type") == "x-mitre-collection":
                self.versao = obj.get("x_mitre_version", "")
                break

        logger.info(
            "ATT&CK carregado: %d objetos indexados, versao %s",
            len(self._por_id),
            self.versao or "desconhecida",
        )
        return self

    # --- Consulta ---

    @property
    def carregado(self) -> bool:
        return bool(self._por_id)

    def objeto(self, attack_id: str) -> dict | None:
        """Objeto STIX de um ID do ATT&CK (T1055, G0016, S0154...)."""
        return self._por_id.get(attack_id)

    def enriquecer(self, tecnica: TecnicaMapeada) -> TecnicaMapeada:
        """
        Sobrepoe os dados do catalogo local com os do STIX oficial.

        As evidencias e a confianca sao nossas e nao se alteram; o que vem
        do STIX e a identidade da tecnica: nome canonico, taticas e URL.
        """
        obj = self.objeto(tecnica.tecnica_id)
        if obj is None:
            return tecnica

        tecnica.confirmada_no_stix = True
        tecnica.nome = obj.get("name", tecnica.nome)

        taticas = [
            fase.get("phase_name", "")
            for fase in obj.get("kill_chain_phases", [])
            if fase.get("kill_chain_name") == "mitre-attack"
        ]
        if taticas:
            tecnica.taticas = taticas

        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            tecnica.descricao = f"[DESCONTINUADA NO ATT&CK] {tecnica.descricao}"

        for referencia in obj.get("external_references", []):
            if referencia.get("source_name") == "mitre-attack" and referencia.get("url"):
                tecnica.url = referencia["url"]
                break

        return tecnica

    def grupos_que_usam(self, tecnica_id: str) -> list[dict]:
        """
        Intrusion-sets que usam a tecnica, segundo o STIX.

        Usado pelo group_attribution. Percorre as relacoes "uses" que
        apontam do grupo para a tecnica.
        """
        alvo = self.objeto(tecnica_id)
        if alvo is None or self._dados is None:
            return []

        stix_id = alvo.get("id")
        grupos: list[dict] = []
        objetos = self._dados.get("objects", [])
        por_stix_id = {o.get("id"): o for o in objetos}

        for obj in objetos:
            if (
                obj.get("type") == "relationship"
                and obj.get("relationship_type") == "uses"
                and obj.get("target_ref") == stix_id
            ):
                origem = por_stix_id.get(obj.get("source_ref"))
                if origem and origem.get("type") == "intrusion-set":
                    grupos.append(origem)

        return grupos


def carregar_attack(
    caminho_cache: str | Path = CAMINHO_CACHE_PADRAO,
    baixar_se_faltar: bool = True,
) -> MitreAttack | None:
    """
    Tenta carregar o ATT&CK, devolvendo None em vez de levantar excecao.

    O pipeline deve seguir sem o STIX; a ausencia vira aviso no relatorio,
    nao interrupcao da analise.
    """
    try:
        return MitreAttack(caminho_cache).carregar(baixar_se_faltar=baixar_se_faltar)
    except ErroMitre as erro:
        logger.warning("ATT&CK indisponivel: %s", erro)
        return None
