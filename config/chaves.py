"""
Chaves de API pela interface, sem abrir o .env num editor.

O .env continua sendo o unico lugar onde as chaves moram - a interface so
escreve nele. Assim a regra do projeto nao muda: chave nunca vai para o
codigo nem para o Git (o .env e ignorado), e quem prefere editar o arquivo
a mao continua podendo.

Tres cuidados que este modulo existe para garantir:

  - A chave nunca volta para a pagina. O estado diz so "configurada" ou
    "nao configurada"; nem mascarada ela sai daqui.
  - O valor nao injeta nada no .env. Uma "chave" com quebra de linha
    viraria uma segunda variavel (ENABLE_ENRICHMENT=false, por exemplo);
    por isso so passam caracteres que chaves de verdade usam.
  - So as variaveis do catalogo podem ser gravadas. A pagina nao escolhe
    um nome qualquer para escrever no arquivo.

A escrita e atomica (arquivo temporario + os.replace): uma queda no meio
nao deixa o .env pela metade, com as outras chaves perdidas.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Callable

from config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Chave:
    variavel: str
    nome: str
    descricao: str
    # Fontes que passam a funcionar com esta chave.
    libera: tuple[str, ...]
    # Onde o analista cria a chave.
    onde_obter: str
    gratuita: bool = True
    observacao: str = ""


CATALOGO: tuple[Chave, ...] = (
    Chave(
        "VIRUSTOTAL_API_KEY", "VirusTotal",
        "Reputação de hash, IP, domínio e URL em cerca de 70 motores de antivírus.",
        ("VirusTotal",), "https://www.virustotal.com/gui/my-apikey",
        observacao="O plano gratuito permite 4 consultas por minuto.",
    ),
    Chave(
        "SHODAN_API_KEY", "Shodan",
        "Portas, serviços e banners dos IPs encontrados.",
        ("Shodan",), "https://account.shodan.io/",
    ),
    Chave(
        "MALWAREBAZAAR_API_KEY", "abuse.ch",
        "Uma chave só vale para as quatro bases do abuse.ch.",
        ("MalwareBazaar", "URLhaus", "ThreatFox", "YARAify"), "https://auth.abuse.ch/",
    ),
    Chave(
        "ABUSEIPDB_API_KEY", "AbuseIPDB",
        "Relatos de abuso de um IP, provedor e país.",
        ("AbuseIPDB",), "https://www.abuseipdb.com/account/api",
    ),
    Chave(
        "OTX_API_KEY", "OTX AlienVault",
        "Pulses da comunidade: adversários, famílias e técnicas ATT&CK.",
        ("OTX",), "https://otx.alienvault.com/api",
    ),
    Chave(
        "URLSCAN_API_KEY", "URLScan.io",
        "Varreduras anteriores de domínios e URLs, e a varredura ativa sob confirmação.",
        ("URLScan",), "https://urlscan.io/user/profile/",
    ),
    Chave(
        "CENSYS_API_TOKEN", "Censys",
        "O que um IP expõe na internet e o contato de abuso do provedor.",
        ("Censys",), "https://platform.censys.io/",
        observacao="Use o Personal Access Token, não o API ID e Secret antigos.",
    ),
    Chave(
        "HIBP_API_KEY", "HaveIBeenPwned",
        "Vazamentos em que as contas do atacante aparecem.",
        ("HIBP (contas)",), "https://haveibeenpwned.com/API/Key", gratuita=False,
        observacao="Paga. Sem ela, o catálogo de vazamentos por domínio continua funcionando.",
    ),
)

POR_VARIAVEL = {c.variavel: c for c in CATALOGO}

# O que uma chave de API de verdade usa: letras, digitos e poucos
# simbolos. Fica de fora tudo que muda o sentido de uma linha do .env -
# espaco, quebra de linha, #, aspas, barra invertida, $ (interpolacao do
# python-dotenv).
FORMATO_DA_CHAVE = re.compile(r"[A-Za-z0-9_\-.:+/=]{8,512}")


class ErroDeChave(ValueError):
    """Pedido recusado; a mensagem pode ser mostrada ao analista."""


# ------------------------------------------------------------
# Leitura do estado
# ------------------------------------------------------------


def _valores_no_arquivo(caminho: Path) -> dict[str, str]:
    """Variavel -> valor, como estao escritas no .env (sem interpretar)."""
    valores = {}
    if not caminho.is_file():
        return valores
    for linha in caminho.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _LINHA.match(linha)
        if m:
            valores[m.group("nome")] = _sem_comentario(m.group("valor"))
    return valores


_LINHA = re.compile(r"^\s*(?:export\s+)?(?P<nome>[A-Z][A-Z0-9_]*)\s*=(?P<valor>.*)$")


def _sem_comentario(valor: str) -> str:
    valor = re.split(r"\s+#", valor, maxsplit=1)[0].strip()
    return valor.strip("'\"")


def _preenchida(valor: str) -> bool:
    return bool(valor) and not valor.startswith("#") and valor.lower() not in settings.PLACEHOLDERS


def estado(caminho: Path | None = None) -> dict:
    """
    O que a pagina pode saber: quais chaves existem e de onde vieram.

    "origem" separa a chave gravada no .env da que veio de uma variavel de
    ambiente do sistema. A diferenca importa: a do sistema vence o .env na
    proxima abertura, entao substituir por aqui nao teria efeito duradouro.
    """
    caminho = caminho or settings.CAMINHO_ENV
    no_arquivo = _valores_no_arquivo(caminho)
    chaves = []
    for c in CATALOGO:
        arquivo = _preenchida(no_arquivo.get(c.variavel, ""))
        ambiente = _preenchida(os.environ.get(c.variavel, "").strip())
        chaves.append({
            "variavel": c.variavel,
            "nome": c.nome,
            "descricao": c.descricao,
            "libera": list(c.libera),
            "onde_obter": c.onde_obter,
            "gratuita": c.gratuita,
            "observacao": c.observacao,
            "configurada": arquivo or ambiente,
            "origem": "arquivo" if arquivo else ("ambiente" if ambiente else ""),
        })
    return {
        "chaves": chaves,
        "configuradas": sum(1 for c in chaves if c["configurada"]),
        "total": len(chaves),
        "env_encontrado": caminho.is_file(),
        "caminho_env": str(caminho),
        "enriquecimento_habilitado": settings.CONFIG.enable_enrichment,
    }


# ------------------------------------------------------------
# Escrita
# ------------------------------------------------------------


def _validar(variavel: str, valor: str | None) -> str:
    if variavel not in POR_VARIAVEL:
        raise ErroDeChave("variável desconhecida")
    if valor is None:
        return ""
    valor = valor.strip()
    if not FORMATO_DA_CHAVE.fullmatch(valor):
        # A mensagem nunca repete o valor: ele e segredo mesmo quando invalido.
        raise ErroDeChave(
            "isso não parece uma chave de API: use só letras, números e - _ . : + / =, "
            "sem espaços, entre 8 e 512 caracteres"
        )
    if valor.lower() in settings.PLACEHOLDERS:
        raise ErroDeChave("esse é o texto de exemplo, não uma chave")
    return valor


def _linhas_iniciais(caminho: Path) -> list[str]:
    if caminho.is_file():
        return caminho.read_text(encoding="utf-8", errors="replace").splitlines()
    # Sem .env: parte do modelo, que ja traz os comentarios de cada chave.
    # Os valores de exemplo dele contam como ausentes (PLACEHOLDERS).
    if settings.CAMINHO_ENV_EXEMPLO.is_file():
        return settings.CAMINHO_ENV_EXEMPLO.read_text(encoding="utf-8").splitlines()
    return ["# Nut-Shell Mapper - chaves de API (nunca commitar este arquivo)"]


def _gravar(caminho: Path, variavel: str, valor: str) -> None:
    linhas = _linhas_iniciais(caminho)
    novas, gravou = [], False
    for linha in linhas:
        m = _LINHA.match(linha)
        if not m or m.group("nome") != variavel:
            novas.append(linha)
            continue
        if gravou:
            # Variavel repetida: a segunda linha venceria a primeira na
            # leitura. Fica uma so.
            continue
        # Mantem o comentario da linha (o link de onde obter a chave).
        comentario = re.search(r"\s+#.*$", m.group("valor"))
        novas.append(f"{variavel}={valor}" + (f"         {comentario.group(0).strip()}" if comentario else ""))
        gravou = True
    if not gravou:
        if novas and novas[-1].strip():
            novas.append("")
        novas.append(f"{variavel}={valor}")

    caminho.parent.mkdir(parents=True, exist_ok=True)
    descritor, temporario = tempfile.mkstemp(prefix=".env.", suffix=".tmp", dir=caminho.parent)
    try:
        with os.fdopen(descritor, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(novas) + "\n")
        os.replace(temporario, caminho)
    except BaseException:
        Path(temporario).unlink(missing_ok=True)
        raise


def _aplicar_na_sessao(variavel: str, valor: str, caminho: Path) -> None:
    """
    A chave nova vale ja, sem reiniciar o programa.

    O CONFIG e atualizado NO LUGAR, campo a campo: modulos que ja fizeram
    `from config.settings import CONFIG` guardam o objeto, e trocar a
    referencia do modulo deixaria esses com a configuracao velha.
    """
    # Vazio (e nao ausente) de proposito: o load_dotenv nao sobrescreve
    # variavel que ja existe no ambiente, entao a chave removida nao volta.
    os.environ[variavel] = valor
    novo = settings.carregar(caminho)
    for f in fields(novo):
        setattr(settings.CONFIG, f.name, getattr(novo, f.name))


def salvar(variavel: str, valor: str, caminho: Path | None = None) -> dict:
    valor = _validar(variavel, valor)
    caminho = caminho or settings.CAMINHO_ENV
    _gravar(caminho, variavel, valor)
    _aplicar_na_sessao(variavel, valor, caminho)
    logger.info("chave %s gravada em %s", variavel, caminho)
    return estado(caminho)


def remover(variavel: str, caminho: Path | None = None) -> dict:
    _validar(variavel, None)
    caminho = caminho or settings.CAMINHO_ENV
    if caminho.is_file():
        _gravar(caminho, variavel, "")
    _aplicar_na_sessao(variavel, "", caminho)
    logger.info("chave %s removida de %s", variavel, caminho)
    return estado(caminho)


# ------------------------------------------------------------
# Teste da chave
# ------------------------------------------------------------
#
# Cada teste bate num endpoint que exige a chave e, sempre que o servico
# tem um, num endpoint da propria conta - assim nenhum indicador de
# analise sai da maquina so para conferir credencial. Onde nao ha, a
# consulta e de um valor publico e inofensivo (8.8.8.8, example.com).


@dataclass(frozen=True)
class _Teste:
    url_base: str
    caminho: str
    cabecalho: str = ""           # nome do cabecalho que leva a chave
    prefixo: str = ""             # "Bearer " etc.
    parametro: str = ""           # chave na query string (Shodan)
    metodo: str = "GET"
    parametros: tuple = ()
    formulario: tuple = ()
    espera: int = 20              # segundos


TESTES: dict[str, _Teste] = {
    "VIRUSTOTAL_API_KEY": _Teste("https://www.virustotal.com/api/v3", "/popular_threat_categories", "x-apikey"),
    "SHODAN_API_KEY": _Teste("https://api.shodan.io", "/api-info", parametro="key"),
    "MALWAREBAZAAR_API_KEY": _Teste("https://urlhaus-api.abuse.ch/v1", "/host/", "Auth-Key", metodo="POST",
                                    formulario=(("host", "example.com"),)),
    "ABUSEIPDB_API_KEY": _Teste("https://api.abuseipdb.com/api/v2", "/check", "Key",
                                parametros=(("ipAddress", "8.8.8.8"), ("maxAgeInDays", "1"))),
    "OTX_API_KEY": _Teste("https://otx.alienvault.com/api/v1", "/pulses/subscribed", "X-OTX-API-KEY",
                          parametros=(("limit", "1"),), espera=45),
    "URLSCAN_API_KEY": _Teste("https://urlscan.io", "/user/quotas/", "API-Key"),
    "CENSYS_API_TOKEN": _Teste("https://api.platform.censys.io/v3/global/asset", "/host/8.8.8.8", "Authorization", prefixo="Bearer "),
    "HIBP_API_KEY": _Teste("https://haveibeenpwned.com/api/v3", "/subscription/status", "hibp-api-key"),
}


def _requisitar_teste(nome: str, teste: _Teste, valor: str):
    from enrichment.base import ClienteBase

    cliente = ClienteBase(valor, timeout=max(settings.CONFIG.http_timeout, teste.espera), tentativas=1)
    cliente.nome = nome
    cliente.url_base = teste.url_base
    if teste.cabecalho:
        cliente.sessao.headers[teste.cabecalho] = teste.prefixo + valor
    parametros = dict(teste.parametros)
    if teste.parametro:
        parametros[teste.parametro] = valor
    try:
        return cliente._requisitar(teste.caminho, parametros=parametros or None, metodo=teste.metodo,
                                   formulario=dict(teste.formulario) or None)
    finally:
        cliente.fechar()


def testar(variavel: str, requisitar: Callable | None = None) -> dict:
    """
    Pergunta ao servico se a chave gravada e aceita.

    Devolve {variavel, valida, mensagem}. valida e None quando nao deu para
    saber (rede fora, consultas desabilitadas): falha de rede nao e chave
    errada, e dizer "invalida" nesse caso mandaria o analista trocar uma
    chave boa.
    """
    c = POR_VARIAVEL.get(variavel)
    if c is None:
        raise ErroDeChave("variável desconhecida")
    valor = os.environ.get(variavel, "").strip()
    if not _preenchida(valor):
        return {"variavel": variavel, "valida": False, "mensagem": "nenhuma chave configurada"}
    if not settings.CONFIG.enable_enrichment:
        return {"variavel": variavel, "valida": None,
                "mensagem": "consultas externas desligadas no .env (ENABLE_ENRICHMENT=false)"}

    resposta = (requisitar or _requisitar_teste)(c.nome, TESTES[variavel], valor)
    erro = resposta.erro or ""
    dados = resposta.dados if isinstance(resposta.dados, dict) else {}
    # O abuse.ch pode responder 200 dizendo que a chave nao existe.
    if dados.get("query_status") in ("unknown_auth_key", "invalid_auth_key"):
        erro = "chave rejeitada pelo abuse.ch"
    if not erro:
        return {"variavel": variavel, "valida": True, "mensagem": _detalhe_da_conta(variavel, dados)}
    # O URLScan recusa chave malformada com 400, e nao 401.
    rejeitada = "rejeitada" in erro or "HTTP 401" in erro or "HTTP 403" in erro or "invalid api key" in erro.lower()
    return {"variavel": variavel, "valida": False if rejeitada else None, "mensagem": erro[:200]}


def _detalhe_da_conta(variavel: str, dados: dict) -> str:
    """Um detalhe util da resposta, quando ha: plano, cota restante."""
    try:
        if variavel == "SHODAN_API_KEY" and "plan" in dados:
            return f"aceita · plano {dados.get('plan')}, {dados.get('query_credits', '?')} créditos de busca"
        if variavel == "HIBP_API_KEY" and dados.get("SubscriptionName"):
            return f"aceita · assinatura {dados['SubscriptionName']}"
        if variavel == "URLSCAN_API_KEY":
            dia = (dados.get("limits") or {}).get("private", {}).get("day") or {}
            if dia:
                return f"aceita · {dia.get('remaining', '?')} varreduras restantes hoje"
    except (AttributeError, TypeError):
        pass
    return "aceita pelo serviço"
