"""
Formato comum das consultas de reputacao.

Cada fonte (URLhaus, ThreatFox, AbuseIPDB, OTX, URLScan, Censys...) fala a
propria lingua. Aqui todas viram a mesma coisa, para a interface e o
relatorio mostrarem lado a lado sem saber de onde veio cada campo.

O veredito separa cinco situacoes que costumam ser confundidas:

  - "malicioso"   : a fonte registra o indicador como malicioso
  - "suspeito"    : ha registro, mas fraco (poucos relatos, confianca baixa)
  - "contexto"    : a fonte conhece o indicador e traz informacao, sem
                    julga-lo (ex.: varreduras do URLScan, hospedagem)
  - "sem_registro": a fonte respondeu e nao conhece o indicador
  - "erro"        : nao foi possivel perguntar (rede, chave, cota)

"Sem registro" nao e "limpo": infraestrutura de phishing vive dias, e a
maioria nunca chega a nenhuma base. E "erro" nao diz nada sobre o
indicador.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

VEREDITOS = ("malicioso", "suspeito", "contexto", "sem_registro", "erro")


@dataclass
class Reputacao:
    fonte: str
    indicador: str
    tipo: str                     # ip, dominio, url, hash, email
    veredito: str = "sem_registro"
    resumo: str = ""
    tags: list[str] = field(default_factory=list)
    detalhes: dict = field(default_factory=dict)
    # Pagina do indicador na fonte, para o analista abrir.
    referencia: str = ""
    erro: str = ""

    @property
    def encontrado(self) -> bool:
        return self.veredito in ("malicioso", "suspeito")

    def to_dict(self) -> dict:
        dados = asdict(self)
        dados["encontrado"] = self.encontrado
        return dados


def falha(fonte: str, indicador: str, tipo: str, erro: str) -> Reputacao:
    return Reputacao(fonte, indicador, tipo, "erro", erro=erro)
