"""
Configuracao central do Nut-Shell Mapper.

Carrega o .env e expoe as configuracoes como um objeto tipado, em vez de
espalhar os.getenv pelo codigo. Duas razoes praticas: o erro de digitar
"VIRUSTOTAL_APIKEY" no lugar de "VIRUSTOTAL_API_KEY" aparece aqui e nao no
meio de uma analise, e fica um lugar unico para auditar o que e lido do
ambiente.

Regra que atravessa o modulo inteiro: chave de API nunca aparece em log,
em repr, em mensagem de erro nem em saida serializada. O __repr__ das
configuracoes mascara os segredos de proposito, porque despejar o objeto de
config num log de depuracao e a forma mais comum de vazar credencial.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field, fields
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)


# Raiz do projeto: dois niveis acima deste arquivo (config/settings.py).
RAIZ = Path(__file__).resolve().parent.parent

CAMINHO_ENV = RAIZ / "config" / ".env"
CAMINHO_ENV_EXEMPLO = RAIZ / "config" / ".env.example"

# Valores de exemplo que indicam que o usuario nao preencheu a chave.
PLACEHOLDERS = frozenset(
    {
        "",
        "coloque_sua_chave_aqui",
        "your_api_key_here",
        "changeme",
        "xxx",
        "none",
        "null",
    }
)


def _texto(nome: str, padrao: str = "") -> str:
    return os.getenv(nome, padrao).strip()


def _inteiro(nome: str, padrao: int) -> int:
    """Le um inteiro do ambiente, caindo no padrao quando invalido."""
    bruto = os.getenv(nome, "").strip()
    if not bruto:
        return padrao
    try:
        return int(bruto)
    except ValueError:
        logger.warning("%s='%s' nao e inteiro; usando %d", nome, bruto, padrao)
        return padrao


def _booleano(nome: str, padrao: bool) -> bool:
    bruto = os.getenv(nome, "").strip().lower()
    if not bruto:
        return padrao
    return bruto in ("1", "true", "sim", "yes", "on")


def _chave(nome: str) -> str:
    """
    Le uma chave de API, tratando o valor de exemplo como ausente.

    Sem isso, quem copia o .env.example e esquece de preencher recebe um
    401 confuso da API em vez de "a chave nao foi configurada".
    """
    valor = _texto(nome)
    return "" if valor.lower() in PLACEHOLDERS else valor


def _mascarar(chave: str) -> str:
    """Representacao segura de uma chave, para diagnostico."""
    if not chave:
        return "<nao configurada>"
    if len(chave) <= 8:
        return "<configurada>"
    return f"{chave[:4]}...{chave[-2:]} ({len(chave)} caracteres)"


@dataclass
class Configuracoes:
    """Todas as configuracoes do framework."""

    # --- Credenciais (nunca serializadas nem logadas) ---
    virustotal_api_key: str = field(default="", repr=False)
    shodan_api_key: str = field(default="", repr=False)
    malwarebazaar_api_key: str = field(default="", repr=False)

    # --- Limites de uso ---
    # O plano gratuito do VirusTotal permite 4 requisicoes por minuto.
    virustotal_rate_limit: int = 4
    http_timeout: int = 30

    # --- Caminhos ---
    samples_dir: Path = field(default_factory=lambda: RAIZ / "data" / "samples")
    output_dir: Path = field(default_factory=lambda: RAIZ / "output")
    mitre_cache_dir: Path = field(default_factory=lambda: RAIZ / "data" / "mitre_cache")

    # --- Comportamento ---
    enable_enrichment: bool = True
    log_level: str = "INFO"

    # --- Diagnostico ---
    env_encontrado: bool = False
    avisos: list[str] = field(default_factory=list)

    # ----- Consultas -----

    @property
    def virustotal_habilitado(self) -> bool:
        return self.enable_enrichment and bool(self.virustotal_api_key)

    @property
    def shodan_habilitado(self) -> bool:
        return self.enable_enrichment and bool(self.shodan_api_key)

    @property
    def algum_enriquecimento_habilitado(self) -> bool:
        return self.virustotal_habilitado or self.shodan_habilitado

    def diagnostico(self) -> dict[str, str]:
        """Estado das credenciais, com as chaves mascaradas."""
        return {
            "arquivo .env": str(CAMINHO_ENV) if self.env_encontrado else "<nao encontrado>",
            "VirusTotal": _mascarar(self.virustotal_api_key),
            "Shodan": _mascarar(self.shodan_api_key),
            "MalwareBazaar": _mascarar(self.malwarebazaar_api_key),
            "enriquecimento": "habilitado" if self.enable_enrichment else "desabilitado",
        }

    def criar_diretorios(self) -> None:
        """Cria os diretorios de trabalho, se ainda nao existirem."""
        for caminho in (self.samples_dir, self.output_dir, self.mitre_cache_dir):
            caminho.mkdir(parents=True, exist_ok=True)

    def __repr__(self) -> str:
        """
        Representacao sem segredo nenhum.

        Reimplementado a mao porque repr=False nos campos protege o repr
        gerado pelo dataclass, mas nao impede que alguem imprima o objeto
        esperando ver a config inteira.
        """
        visiveis = ", ".join(
            f"{f.name}={getattr(self, f.name)!r}"
            for f in fields(self)
            if f.repr and f.name != "avisos"
        )
        return (
            f"Configuracoes({visiveis}, "
            f"virustotal_api_key={_mascarar(self.virustotal_api_key)!r}, "
            f"shodan_api_key={_mascarar(self.shodan_api_key)!r})"
        )


def carregar(
    caminho_env: str | Path | None = None,
    sobrescrever_ambiente: bool = False,
) -> Configuracoes:
    """
    Carrega as configuracoes do .env e do ambiente.

    Args:
        caminho_env: caminho alternativo do .env. Padrao: config/.env.
        sobrescrever_ambiente: se True, o .env tem precedencia sobre as
            variaveis ja definidas no ambiente. O padrao e False, para que
            uma variavel exportada no shell ou injetada por CI vença o
            arquivo - que e o comportamento esperado em execucao automatizada.

    Returns:
        Configuracoes, sempre; problemas viram avisos, nunca excecao. O
        framework precisa rodar offline, sem nenhuma chave configurada.
    """
    caminho = Path(caminho_env) if caminho_env else CAMINHO_ENV
    encontrado = caminho.is_file()

    if encontrado:
        load_dotenv(caminho, override=sobrescrever_ambiente)
        logger.debug("configuracoes carregadas de %s", caminho)

    cfg = Configuracoes(
        virustotal_api_key=_chave("VIRUSTOTAL_API_KEY"),
        shodan_api_key=_chave("SHODAN_API_KEY"),
        malwarebazaar_api_key=_chave("MALWAREBAZAAR_API_KEY"),
        virustotal_rate_limit=_inteiro("VIRUSTOTAL_RATE_LIMIT", 4),
        http_timeout=_inteiro("HTTP_TIMEOUT", 30),
        enable_enrichment=_booleano("ENABLE_ENRICHMENT", True),
        log_level=_texto("LOG_LEVEL", "INFO").upper(),
        env_encontrado=encontrado,
    )

    for variavel, atributo in (
        ("SAMPLES_DIR", "samples_dir"),
        ("OUTPUT_DIR", "output_dir"),
        ("MITRE_CACHE_DIR", "mitre_cache_dir"),
    ):
        valor = _texto(variavel)
        if valor:
            bruto = Path(valor)
            # Caminho relativo no .env e relativo a raiz do projeto, e nao
            # ao diretorio de onde o comando foi executado.
            setattr(cfg, atributo, bruto if bruto.is_absolute() else RAIZ / bruto)

    # --- Avisos de diagnostico ---

    if not encontrado:
        cfg.avisos.append(
            f"{caminho} nao encontrado. Copie {CAMINHO_ENV_EXEMPLO.name} para "
            ".env e preencha as chaves. A analise estatica funciona sem elas; "
            "apenas o enriquecimento externo fica indisponivel"
        )

    if cfg.enable_enrichment:
        faltando = [
            nome
            for nome, chave in (
                ("VirusTotal", cfg.virustotal_api_key),
                ("Shodan", cfg.shodan_api_key),
            )
            if not chave
        ]
        if faltando:
            cfg.avisos.append(
                "chave ausente para: " + ", ".join(faltando)
                + " (essas consultas serao puladas)"
            )
    else:
        cfg.avisos.append(
            "ENABLE_ENRICHMENT=false: nenhuma consulta externa sera feita"
        )

    if cfg.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        cfg.avisos.append(f"LOG_LEVEL='{cfg.log_level}' invalido; usando INFO")
        cfg.log_level = "INFO"

    return cfg


# Instancia compartilhada, carregada na importacao.
CONFIG = carregar()


def configurar_logging(nivel: str | None = None) -> None:
    """Configura o logging do framework com o nivel do .env."""
    logging.basicConfig(
        level=getattr(logging, (nivel or CONFIG.log_level), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
