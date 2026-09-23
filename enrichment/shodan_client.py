"""
Client do Shodan.

Consulta os IPs extraidos do artefato: portas abertas, servicos, banners,
certificados e vulnerabilidades conhecidas do host. A pergunta que o modulo
responde e "este endereco tem cara de infraestrutura de C2 ativa?".

O que o resultado significa, e o que ele nao significa:

  - O Shodan varre a internet periodicamente, entao o dado tem data. Um
    host listado pode ter sido desligado ontem; um host ausente pode estar
    ativo e simplesmente nao ter sido varrido ainda. Por isso a data da
    ultima atualizacao acompanha todo resultado.
  - Portas abertas conhecidas de framework ofensivo (Cobalt Strike em 50050,
    Metasploit em 4444) sao indicio util, mas qualquer um pode abrir
    qualquer porta. O modulo sinaliza, nao conclui.
  - IP compartilhado, atras de CDN ou de hospedagem popular, descreve a
    infraestrutura do provedor e nao a do adversario. Isso e sinalizado.

Consultar IP privado nao faz sentido: o Shodan varre a internet publica. O
modulo pula esses enderecos para nao gastar cota a toa.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import asdict, dataclass, field

from core.string_extractor import IOC, TipoIOC
from enrichment.base import TENTATIVAS_PADRAO, ClienteBase, RespostaEnriquecimento

logger = logging.getLogger(__name__)


URL_BASE = "https://api.shodan.io"

# Portas associadas a framework de pos-exploracao ou acesso remoto.
# A presenca e indicio, nunca prova: qualquer servico pode usar qualquer porta.
PORTAS_DE_INTERESSE: dict[int, str] = {
    1080: "proxy SOCKS",
    1337: "porta comum em backdoor",
    3389: "RDP exposto",
    4444: "porta padrão de handler do Metasploit",
    4445: "porta comum de handler do Metasploit",
    5555: "ADB ou backdoor",
    5900: "VNC exposto",
    6666: "porta comum em IRC bot",
    6667: "IRC, historicamente usado para C2 de botnet",
    8080: "HTTP alternativo, comum em painel de C2",
    8443: "HTTPS alternativo, comum em painel de C2",
    9001: "porta comum de relé Tor",
    50050: "porta padrão do team server do Cobalt Strike",
}

# Provedores cuja infraestrutura e compartilhada: o que se ve e o provedor,
# nao necessariamente o adversario.
PROVEDORES_COMPARTILHADOS = (
    "cloudflare", "amazon", "aws", "google", "microsoft", "azure",
    "akamai", "fastly", "digitalocean", "linode", "ovh", "hetzner",
    "vultr", "contabo", "namecheap", "godaddy",
)


@dataclass
class ServicoExposto:
    """Um servico encontrado no host."""

    porta: int
    protocolo: str = "tcp"
    produto: str = ""
    versao: str = ""
    # Primeiras linhas do banner, o suficiente para identificar sem poluir.
    banner: str = ""
    # Motivo pelo qual esta porta chamou atencao, se chamou.
    observacao: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ResultadoShodan:
    """Leitura do que o Shodan devolveu sobre um IP."""

    ip: str

    consultado: bool = False
    encontrado: bool = False
    erro: str = ""

    # --- Identificacao do host ---
    pais: str = ""
    cidade: str = ""
    organizacao: str = ""
    asn: str = ""
    provedor: str = ""
    hostnames: list[str] = field(default_factory=list)

    # --- Exposicao ---
    portas: list[int] = field(default_factory=list)
    servicos: list[ServicoExposto] = field(default_factory=list)
    # CVEs que o Shodan associa aos servicos encontrados.
    vulnerabilidades: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # Quando o Shodan viu este host pela ultima vez.
    ultima_atualizacao: str = ""

    observacoes: list[str] = field(default_factory=list)

    @property
    def portas_de_interesse(self) -> list[ServicoExposto]:
        """Servicos em portas associadas a ferramenta ofensiva."""
        return [s for s in self.servicos if s.observacao]

    @property
    def infraestrutura_compartilhada(self) -> bool:
        """True quando o host esta em provedor de infraestrutura compartilhada."""
        alvo = f"{self.organizacao} {self.provedor}".lower()
        return any(p in alvo for p in PROVEDORES_COMPARTILHADOS)

    @property
    def resumo(self) -> str:
        if not self.consultado:
            return "não consultado"
        if not self.encontrado:
            return "sem registro no Shodan"
        return f"{len(self.portas)} porta(s) aberta(s)"

    def to_dict(self) -> dict:
        return asdict(self)


def ip_e_consultavel(ip: str) -> tuple[bool, str]:
    """
    Decide se vale consultar o Shodan para este endereco.

    O Shodan varre a internet publica: perguntar por 192.168.1.1 ou
    127.0.0.1 gasta cota e nao devolve nada util.

    Returns:
        (consultavel, motivo). O motivo explica a recusa, quando houver.
    """
    try:
        endereco = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False, f"'{ip}' não é um endereço IP válido"

    if endereco.is_private:
        return False, "endereço privado (RFC 1918): fora do alcance do Shodan"
    if endereco.is_loopback:
        return False, "loopback"
    if endereco.is_link_local:
        return False, "link-local (APIPA)"
    if endereco.is_multicast:
        return False, "multicast"
    if endereco.is_reserved or endereco.is_unspecified:
        return False, "faixa reservada"

    return True, ""


class ShodanClient(ClienteBase):
    """Consultas a API do Shodan."""

    nome = "Shodan"
    url_base = URL_BASE

    def __init__(
        self,
        api_key: str,
        timeout: int = 30,
        rate_limit_por_minuto: int = 60,
        tentativas: int = TENTATIVAS_PADRAO,
    ):
        super().__init__(api_key, timeout, rate_limit_por_minuto, tentativas)

    def consultar_ip(self, ip: str) -> ResultadoShodan:
        """
        Consulta um IP no Shodan.

        Enderecos privados e reservados sao recusados antes da requisicao.
        """
        ip = ip.strip()
        resultado = ResultadoShodan(ip=ip)

        consultavel, motivo = ip_e_consultavel(ip)
        if not consultavel:
            resultado.erro = motivo
            resultado.observacoes.append(f"consulta pulada: {motivo}")
            return resultado

        # A chave do Shodan vai na query string. O sanitizador da classe base
        # remove esse valor de qualquer log ou mensagem de erro.
        resposta = self._requisitar(
            f"/shodan/host/{ip}",
            parametros={"key": self._api_key, "minify": "false"},
        )
        return self._interpretar(resposta, resultado)

    def consultar_iocs(
        self, iocs: list[IOC], maximo: int = 20
    ) -> list[ResultadoShodan]:
        """
        Consulta os IPs presentes na lista de IOCs.

        Args:
            iocs: saida do string_extractor ou do deobfuscator.
            maximo: teto de consultas.

        Returns:
            Um ResultadoShodan por IP consultado, na ordem de confianca.
        """
        ordem = {"alta": 0, "media": 1, "baixa": 2}
        candidatos = [
            i for i in sorted(iocs, key=lambda x: ordem.get(x.confianca.value, 3))
            if i.tipo is TipoIOC.IPV4
        ]

        resultados: list[ResultadoShodan] = []
        vistos: set[str] = set()

        for ioc in candidatos:
            if len(resultados) >= maximo:
                break
            if ioc.valor in vistos:
                continue
            consultavel, _ = ip_e_consultavel(ioc.valor)
            if not consultavel:
                continue
            vistos.add(ioc.valor)
            resultados.append(self.consultar_ip(ioc.valor))

        return resultados

    def _interpretar(
        self, resposta: RespostaEnriquecimento, resultado: ResultadoShodan
    ) -> ResultadoShodan:
        resultado.consultado = resposta.consultado
        resultado.encontrado = resposta.encontrado
        resultado.erro = resposta.erro

        if not resposta.util:
            if resposta.consultado and not resposta.encontrado:
                resultado.observacoes.append(
                    "sem registro no Shodan. O host pode não ter serviço "
                    "exposto, estar atrás de firewall, ou simplesmente ainda "
                    "não ter sido varrido"
                )
            return resultado

        dados = resposta.dados

        resultado.pais = dados.get("country_name", "") or ""
        resultado.cidade = dados.get("city", "") or ""
        resultado.organizacao = dados.get("org", "") or ""
        resultado.provedor = dados.get("isp", "") or ""
        asn = dados.get("asn")
        resultado.asn = str(asn) if asn else ""
        resultado.hostnames = list(dados.get("hostnames", []) or [])
        resultado.portas = sorted(dados.get("ports", []) or [])
        resultado.vulnerabilidades = sorted(dados.get("vulns", []) or [])
        resultado.tags = list(dados.get("tags", []) or [])
        resultado.ultima_atualizacao = dados.get("last_update", "") or ""

        for servico in dados.get("data", []) or []:
            porta = int(servico.get("port", 0) or 0)
            banner = (servico.get("data", "") or "").strip()

            resultado.servicos.append(
                ServicoExposto(
                    porta=porta,
                    protocolo=servico.get("transport", "tcp") or "tcp",
                    produto=servico.get("product", "") or "",
                    versao=servico.get("version", "") or "",
                    # Banner inteiro polui o relatorio; as primeiras linhas
                    # ja identificam o servico.
                    banner="\n".join(banner.splitlines()[:3])[:300],
                    observacao=PORTAS_DE_INTERESSE.get(porta, ""),
                )
            )

        resultado.servicos.sort(key=lambda s: s.porta)

        # --- Observacoes que contextualizam o achado ---

        de_interesse = resultado.portas_de_interesse
        if de_interesse:
            resultado.observacoes.append(
                "portas associadas a ferramenta ofensiva: "
                + ", ".join(f"{s.porta} ({s.observacao})" for s in de_interesse)
                + ". Indício, não prova: qualquer serviço pode usar qualquer porta"
            )

        if resultado.infraestrutura_compartilhada:
            resultado.observacoes.append(
                f"host em infraestrutura compartilhada ({resultado.organizacao}): "
                "o que se observa descreve o provedor, não necessariamente o "
                "operador do artefato"
            )

        if resultado.vulnerabilidades:
            resultado.observacoes.append(
                f"{len(resultado.vulnerabilidades)} CVE(s) associadas aos "
                "serviços expostos"
            )

        if resultado.ultima_atualizacao:
            resultado.observacoes.append(
                f"dado da varredura de {resultado.ultima_atualizacao[:10]}: "
                "o Shodan varre periodicamente, o estado atual pode ser outro"
            )

        return resultado


def criar(config=None) -> ShodanClient | None:
    """
    Cria o client a partir das configuracoes.

    Returns:
        O client, ou None quando o enriquecimento esta desabilitado ou a
        chave nao foi configurada.
    """
    if config is None:
        from config.settings import CONFIG as config

    if not config.shodan_habilitado:
        logger.info("Shodan desabilitado ou sem chave: consultas serão puladas")
        return None

    return ShodanClient(
        api_key=config.shodan_api_key,
        timeout=config.http_timeout,
    )
