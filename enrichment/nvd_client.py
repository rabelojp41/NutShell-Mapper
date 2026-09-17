"""
Client da NVD (National Vulnerability Database, do NIST).

Resolve uma lacuna de usabilidade: o vetor CVSS era campo manual, o que
obrigava o analista a saber o vetor de cor ou ir procurar. Mas o CVSS
descreve uma VULNERABILIDADE, nao um artefato - nao ha como calcula-lo a
partir de um binario. O que da para fazer, e que faltava, e:

  1. Detectar referencia a CVE nas strings do artefato (isso e offline,
     feito pelo string_extractor).
  2. Buscar aqui o vetor oficial daquela CVE.

Assim o campo se preenche sozinho quando faz sentido, e fica vazio quando
nao faz - em vez de exigir que o usuario invente um vetor para um PDF
qualquer.

A API e publica e nao exige chave. Sem chave o NIST limita a 5 requisicoes
por janela de 30 segundos; com chave, 50. O limitador padrao deste modulo
respeita o limite sem chave, que e o caso comum.

Uma ressalva sobre o dado: o CVSS que vem daqui e o score BASE publicado
pelo NIST para a vulnerabilidade. Ele nao diz nada sobre este artefato
especifico - apenas que o artefato menciona uma falha com aquela
severidade. Se o binario realmente explora a falha, se explora com
sucesso, ou se so cita o numero num comentario, isso a analise estatica
nao determina, e o relatorio precisa deixar claro.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field

from enrichment.base import TENTATIVAS_PADRAO, ClienteBase

logger = logging.getLogger(__name__)


URL_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Sem chave, o NIST permite 5 requisicoes por 30 segundos. Convertido para
# o limitador por minuto do ClienteBase, com folga.
LIMITE_SEM_CHAVE_POR_MINUTO = 8


@dataclass
class ResultadoNVD:
    """O que a NVD sabe sobre uma CVE."""

    cve: str

    consultado: bool = False
    encontrado: bool = False
    erro: str = ""

    # Vetor CVSS, na melhor versao disponivel (prefere 3.1 sobre 3.0).
    vetor: str = ""
    versao_cvss: str = ""
    score_base: float = 0.0
    severidade: str = ""

    descricao: str = ""
    publicada_em: str = ""
    modificada_em: str = ""
    # Produtos afetados, quando a NVD os lista de forma legivel.
    referencias: list[str] = field(default_factory=list)

    observacoes: list[str] = field(default_factory=list)

    @property
    def resumo(self) -> str:
        if not self.consultado:
            return "nao consultado"
        if not self.encontrado:
            return "nao consta na NVD"
        if not self.vetor:
            return "sem vetor CVSS publicado"
        return f"{self.score_base:.1f} ({self.severidade})"

    def to_dict(self) -> dict:
        return asdict(self)


class NVDClient(ClienteBase):
    """Consulta de CVE na NVD."""

    nome = "NVD"
    url_base = URL_BASE

    def __init__(
        self,
        api_key: str = "",
        timeout: int = 30,
        rate_limit_por_minuto: int = LIMITE_SEM_CHAVE_POR_MINUTO,
        tentativas: int = TENTATIVAS_PADRAO,
    ):
        # Diferente dos outros clients, a chave e opcional: a API publica
        # funciona sem ela, so com limite menor.
        super().__init__(api_key or "sem-chave", timeout, rate_limit_por_minuto,
                         tentativas)
        if api_key:
            self.sessao.headers["apiKey"] = api_key
        self._tem_chave = bool(api_key)

    def consultar(self, cve: str) -> ResultadoNVD:
        """
        Busca uma CVE pelo identificador.

        Args:
            cve: no formato CVE-AAAA-NNNN.
        """
        cve = cve.strip().upper()
        resultado = ResultadoNVD(cve=cve)

        import re

        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            resultado.erro = f"'{cve}' nao esta no formato CVE-AAAA-NNNN"
            return resultado

        # A URL base ja e o endpoint completo; o ClienteBase concatena um
        # caminho, entao aqui ele fica vazio.
        resposta = self._requisitar("", parametros={"cveId": cve})

        resultado.consultado = resposta.consultado
        resultado.erro = resposta.erro

        if not resposta.util:
            return resultado

        return self._interpretar(resposta.dados, resultado)

    def _interpretar(self, corpo: dict, resultado: ResultadoNVD) -> ResultadoNVD:
        vulnerabilidades = corpo.get("vulnerabilities") or []
        if not vulnerabilidades:
            resultado.encontrado = False
            resultado.observacoes.append(
                "CVE nao consta na NVD. Pode ser identificador reservado, "
                "recem-atribuido ou invalido"
            )
            return resultado

        cve = vulnerabilidades[0].get("cve", {})
        resultado.encontrado = True

        resultado.publicada_em = (cve.get("published") or "")[:10]
        resultado.modificada_em = (cve.get("lastModified") or "")[:10]

        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                resultado.descricao = d.get("value", "")
                break

        # Prefere CVSS 3.1; cai para 3.0 e depois para 2.0, que e bem mais
        # antigo e usa escala diferente - por isso a versao acompanha o
        # score, para o relatorio nao comparar coisas incomparaveis.
        metricas = cve.get("metrics", {}) or {}
        for chave, versao in (
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ):
            entradas = metricas.get(chave) or []
            if not entradas:
                continue
            dados = entradas[0].get("cvssData", {}) or {}
            resultado.vetor = dados.get("vectorString", "")
            resultado.versao_cvss = versao
            resultado.score_base = float(dados.get("baseScore") or 0.0)
            resultado.severidade = (
                dados.get("baseSeverity")
                or entradas[0].get("baseSeverity")
                or ""
            )
            break

        resultado.referencias = [
            r.get("url", "") for r in (cve.get("references") or [])[:5] if r.get("url")
        ]

        if not resultado.vetor:
            resultado.observacoes.append(
                "a NVD conhece esta CVE mas ainda nao publicou vetor CVSS"
            )
        elif resultado.versao_cvss == "2.0":
            resultado.observacoes.append(
                "apenas CVSS 2.0 disponivel: a escala difere da 3.x e os "
                "scores nao sao comparaveis diretamente"
            )

        # A ressalva que impede a leitura errada do numero.
        resultado.observacoes.append(
            "este score descreve a vulnerabilidade, nao este artefato. O "
            "artefato apenas referencia a CVE; se ele a explora, e com que "
            "sucesso, a analise estatica nao determina"
        )

        return resultado


def criar(config=None) -> NVDClient | None:
    """
    Cria o client.

    A NVD nao exige chave, entao o unico motivo para nao criar o client e o
    enriquecimento estar desabilitado.
    """
    if config is None:
        from config.settings import CONFIG as config

    if not config.enable_enrichment:
        logger.info("NVD pulada: enriquecimento desabilitado")
        return None

    return NVDClient(
        api_key=getattr(config, "nvd_api_key", ""),
        timeout=config.http_timeout,
    )
