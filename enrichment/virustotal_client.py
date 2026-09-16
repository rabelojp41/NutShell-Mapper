"""
Client do VirusTotal (API v3).

Consulta por hash, IP, dominio e URL. Traz deteccoes dos antivirus,
primeira e ultima vez que o artefato foi visto, tags e rotulo de familia.

DUAS DECISOES DE PRIVACIDADE, deliberadas:

1. Este modulo NAO envia arquivo para o VirusTotal, e nao ha funcao para
   isso. Consultar por hash e uma pergunta; enviar o arquivo e uma
   publicacao. Amostra enviada ao VT fica disponivel para os assinantes do
   servico, e se o artefato veio de um cliente, de um incidente interno ou
   contem dado sensivel, esse envio e um vazamento - irreversivel, porque
   nao ha como retirar depois. A decisao de publicar uma amostra e do
   analista e da organizacao, nunca de uma ferramenta automatizada.

2. Um hash consultado tambem e informacao. Quem opera o VirusTotal ve quais
   hashes foram procurados e quando. Em investigacao sensivel, isso pode
   sinalizar ao adversario que ele foi detectado. O modulo nao impede a
   consulta, mas registra o fato para que a escolha seja consciente.

O numero de deteccoes tambem nao e um veredito. Software legitimo pouco
conhecido acumula falso positivo de motor heuristico, e malware novo comeca
com zero deteccoes. O que o resultado traz e "quantos motores apontaram o
que", com os nomes, e nao "isto e malicioso".
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from core.string_extractor import IOC, TipoIOC
from enrichment.base import TENTATIVAS_PADRAO, ClienteBase, RespostaEnriquecimento

logger = logging.getLogger(__name__)


URL_BASE = "https://www.virustotal.com/api/v3"

# Acima desta fracao de motores apontando, o consenso e forte.
FRACAO_CONSENSO_FORTE = 0.25


@dataclass
class ResultadoVirusTotal:
    """Leitura do que o VirusTotal devolveu sobre um indicador."""

    indicador: str
    tipo: str  # arquivo, ip, dominio, url

    consultado: bool = False
    encontrado: bool = False
    erro: str = ""

    # --- Deteccao ---
    maliciosos: int = 0
    suspeitos: int = 0
    inofensivos: int = 0
    nao_detectados: int = 0
    total_de_motores: int = 0
    # Motor -> nome da deteccao, apenas dos que apontaram algo.
    deteccoes: dict[str, str] = field(default_factory=dict)

    # --- Contexto ---
    # Rotulo de familia sugerido pelo proprio VT a partir do consenso.
    familia_sugerida: str = ""
    primeira_vez_visto: str = ""
    ultima_analise: str = ""
    nomes_conhecidos: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    reputacao: int = 0

    # --- Especifico de IP e dominio ---
    pais: str = ""
    asn: str = ""
    proprietario_do_as: str = ""

    observacoes: list[str] = field(default_factory=list)

    @property
    def taxa_de_deteccao(self) -> float:
        """Fracao dos motores que apontaram algo (0.0 a 1.0)."""
        if not self.total_de_motores:
            return 0.0
        return (self.maliciosos + self.suspeitos) / self.total_de_motores

    @property
    def consenso_forte(self) -> bool:
        """
        True quando uma parcela substancial dos motores concorda.

        Um ou dois motores apontando costuma ser falso positivo heuristico;
        um quarto deles concordando e outra conversa.
        """
        return self.taxa_de_deteccao >= FRACAO_CONSENSO_FORTE and self.maliciosos >= 5

    @property
    def resumo_de_deteccao(self) -> str:
        if not self.consultado:
            return "nao consultado"
        if not self.encontrado:
            return "nao consta no VirusTotal"
        return f"{self.maliciosos + self.suspeitos}/{self.total_de_motores}"

    def to_dict(self) -> dict:
        return asdict(self)


def _data_iso(carimbo: int | None) -> str:
    """Converte carimbo Unix do VT para ISO 8601."""
    if not carimbo:
        return ""
    try:
        return datetime.fromtimestamp(int(carimbo), tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError, TypeError):
        return ""


class VirusTotalClient(ClienteBase):
    """Consultas ao VirusTotal v3."""

    nome = "VirusTotal"
    url_base = URL_BASE

    def __init__(
        self,
        api_key: str,
        timeout: int = 30,
        rate_limit_por_minuto: int = 4,
        tentativas: int = TENTATIVAS_PADRAO,
    ):
        # O padrao de 4/min corresponde ao plano gratuito. Estourar devolve
        # 429 para tudo que vier depois, entao e melhor esperar antes.
        super().__init__(api_key, timeout, rate_limit_por_minuto, tentativas)

        # A API v3 autentica pelo cabecalho x-apikey. Definir na sessao faz
        # valer para toda requisicao, sem depender de cada metodo lembrar de
        # passar - foi o que faltava, e o resultado era 401 em tudo.
        if api_key:
            self.sessao.headers["x-apikey"] = api_key

    # ----- Consultas -----

    def consultar_hash(self, valor: str) -> ResultadoVirusTotal:
        """
        Consulta um arquivo por hash (MD5, SHA1 ou SHA256).

        Nao envia o arquivo: apenas pergunta se o hash e conhecido.
        """
        valor = valor.strip().lower()
        resultado = ResultadoVirusTotal(indicador=valor, tipo="arquivo")

        if not self._hash_valido(valor):
            resultado.erro = (
                f"'{valor}' nao e um hash MD5, SHA1 ou SHA256 valido"
            )
            return resultado

        resultado.observacoes.append(
            "consulta por hash: o arquivo nao foi enviado ao VirusTotal"
        )

        resposta = self._requisitar(f"/files/{valor}")
        return self._interpretar_arquivo(resposta, resultado)

    def consultar_ip(self, ip: str) -> ResultadoVirusTotal:
        """Consulta um endereco IP."""
        resultado = ResultadoVirusTotal(indicador=ip, tipo="ip")
        resposta = self._requisitar(f"/ip_addresses/{ip.strip()}")
        return self._interpretar_rede(resposta, resultado)

    def consultar_dominio(self, dominio: str) -> ResultadoVirusTotal:
        """Consulta um dominio."""
        resultado = ResultadoVirusTotal(indicador=dominio, tipo="dominio")
        resposta = self._requisitar(f"/domains/{dominio.strip().lower()}")
        return self._interpretar_rede(resposta, resultado)

    def consultar_url(self, url: str) -> ResultadoVirusTotal:
        """
        Consulta uma URL.

        A API v3 identifica URL pelo seu Base64 URL-safe sem preenchimento.
        """
        import base64

        resultado = ResultadoVirusTotal(indicador=url, tipo="url")
        identificador = (
            base64.urlsafe_b64encode(url.strip().encode()).decode().rstrip("=")
        )
        resposta = self._requisitar(f"/urls/{identificador}")
        return self._interpretar_rede(resposta, resultado)

    def consultar_iocs(
        self,
        iocs: list[IOC],
        maximo: int = 20,
        pular_privados: bool = True,
    ) -> list[ResultadoVirusTotal]:
        """
        Consulta em lote os IOCs extraidos do artefato.

        Args:
            iocs: saida do string_extractor ou do deobfuscator.
            maximo: teto de consultas. No plano gratuito, 20 consultas ja
                sao 5 minutos de espera por causa do limite de taxa.
            pular_privados: ignora IOC de faixa privada. O VirusTotal nao
                tem nada util sobre 192.168.1.1, e a consulta so gastaria
                cota.

        Returns:
            Um ResultadoVirusTotal por IOC consultado.
        """
        consultaveis = {
            TipoIOC.IPV4: self.consultar_ip,
            TipoIOC.DOMINIO: self.consultar_dominio,
            TipoIOC.URL: self.consultar_url,
        }

        # Prioriza os IOCs de maior confianca: a cota e escassa.
        ordem = {"alta": 0, "media": 1, "baixa": 2}
        candidatos = [
            i for i in sorted(iocs, key=lambda x: ordem.get(x.confianca.value, 3))
            if i.tipo in consultaveis
        ]

        resultados: list[ResultadoVirusTotal] = []
        vistos: set[str] = set()

        for ioc in candidatos:
            if len(resultados) >= maximo:
                break
            if ioc.valor in vistos:
                continue
            if pular_privados and "RFC 1918" in ioc.observacao:
                continue
            vistos.add(ioc.valor)
            resultados.append(consultaveis[ioc.tipo](ioc.valor))

        if len(candidatos) > maximo:
            logger.info(
                "%d IOCs consultaveis, %d consultados (limite)",
                len(candidatos), maximo,
            )

        return resultados

    # ----- Interpretacao -----

    @staticmethod
    def _hash_valido(valor: str) -> bool:
        if len(valor) not in (32, 40, 64):
            return False
        return all(c in "0123456789abcdef" for c in valor)

    @staticmethod
    def _aplicar_estatisticas(
        atributos: dict, resultado: ResultadoVirusTotal
    ) -> None:
        """Preenche a contagem de motores a partir de last_analysis_stats."""
        stats = atributos.get("last_analysis_stats", {}) or {}
        resultado.maliciosos = int(stats.get("malicious", 0) or 0)
        resultado.suspeitos = int(stats.get("suspicious", 0) or 0)
        resultado.inofensivos = int(stats.get("harmless", 0) or 0)
        resultado.nao_detectados = int(stats.get("undetected", 0) or 0)
        resultado.total_de_motores = sum(
            int(v or 0) for v in stats.values() if isinstance(v, (int, float))
        )

        for motor, analise in (atributos.get("last_analysis_results") or {}).items():
            if (analise or {}).get("category") in ("malicious", "suspicious"):
                nome = analise.get("result") or analise.get("category", "")
                resultado.deteccoes[motor] = nome

    def _interpretar_arquivo(
        self, resposta: RespostaEnriquecimento, resultado: ResultadoVirusTotal
    ) -> ResultadoVirusTotal:
        resultado.consultado = resposta.consultado
        resultado.encontrado = resposta.encontrado
        resultado.erro = resposta.erro

        if not resposta.util:
            if resposta.consultado and not resposta.encontrado:
                resultado.observacoes.append(
                    "hash desconhecido pelo VirusTotal. Pode ser amostra nova, "
                    "artefato interno ou binario legitimo pouco distribuido - "
                    "ausencia nao indica nada por si so"
                )
            return resultado

        atributos = (resposta.dados.get("data") or {}).get("attributes", {}) or {}

        self._aplicar_estatisticas(atributos, resultado)

        resultado.familia_sugerida = (
            (atributos.get("popular_threat_classification") or {})
            .get("suggested_threat_label", "")
        )
        resultado.primeira_vez_visto = _data_iso(atributos.get("first_submission_date"))
        resultado.ultima_analise = _data_iso(atributos.get("last_analysis_date"))
        resultado.nomes_conhecidos = list(atributos.get("names", [])[:10])
        resultado.tags = list(atributos.get("tags", []))
        resultado.reputacao = int(atributos.get("reputation", 0) or 0)

        # --- Leitura honesta do numero de deteccoes ---
        if resultado.maliciosos == 0 and resultado.total_de_motores:
            resultado.observacoes.append(
                "conhecido pelo VirusTotal e sem deteccoes. Malware recente "
                "costuma comecar assim"
            )
        elif 0 < resultado.maliciosos <= 3:
            resultado.observacoes.append(
                f"apenas {resultado.maliciosos} motor(es) apontaram, de "
                f"{resultado.total_de_motores}. Deteccao isolada e "
                "frequentemente falso positivo heuristico"
            )
        elif resultado.consenso_forte:
            resultado.observacoes.append(
                f"consenso forte: {resultado.maliciosos} de "
                f"{resultado.total_de_motores} motores"
            )

        return resultado

    def _interpretar_rede(
        self, resposta: RespostaEnriquecimento, resultado: ResultadoVirusTotal
    ) -> ResultadoVirusTotal:
        resultado.consultado = resposta.consultado
        resultado.encontrado = resposta.encontrado
        resultado.erro = resposta.erro

        if not resposta.util:
            return resultado

        atributos = (resposta.dados.get("data") or {}).get("attributes", {}) or {}

        self._aplicar_estatisticas(atributos, resultado)

        resultado.reputacao = int(atributos.get("reputation", 0) or 0)
        resultado.pais = atributos.get("country", "") or ""
        asn = atributos.get("asn")
        resultado.asn = str(asn) if asn is not None else ""
        resultado.proprietario_do_as = atributos.get("as_owner", "") or ""
        resultado.tags = list(atributos.get("tags", []))
        resultado.ultima_analise = _data_iso(atributos.get("last_analysis_date"))

        if resultado.maliciosos == 0 and resultado.total_de_motores:
            resultado.observacoes.append(
                "nenhum motor marcou este indicador como malicioso"
            )

        return resultado


def criar(config=None) -> VirusTotalClient | None:
    """
    Cria o client a partir das configuracoes.

    Returns:
        O client, ou None quando o enriquecimento esta desabilitado ou a
        chave nao foi configurada. O pipeline trata None como "pular".
    """
    if config is None:
        from config.settings import CONFIG as config

    if not config.virustotal_habilitado:
        logger.info("VirusTotal desabilitado ou sem chave: consultas serao puladas")
        return None

    return VirusTotalClient(
        api_key=config.virustotal_api_key,
        timeout=config.http_timeout,
        rate_limit_por_minuto=config.virustotal_rate_limit,
    )
