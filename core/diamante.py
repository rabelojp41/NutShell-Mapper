"""
Diamond Model e TTPs a partir dos achados.

O Diamond Model (Caltagirone, Pendergast e Betz, 2013) descreve um evento de
intrusao por quatro vertices ligados entre si:

    Adversario  --  Capacidade
        |               |
    Infraestrutura --  Vitima

  - Adversario: quem opera. Num e-mail, o que se ve sao as PERSONAS que ele
    controla (remetente, Reply-To); o operador real fica desconhecido, e o
    modelo diz isso em vez de preencher com palpite.
  - Capacidade: o que ele usa - tecnicas, isca, anexo, truques de evasao.
  - Infraestrutura: por onde a capacidade chega a vitima. O modelo separa
    Tipo 1 (do adversario: dominio registrado para o golpe, servidor que
    disparou) de Tipo 2 (intermediaria: Gmail, Outlook, CDN - servico
    legitimo abusado, que nao se derruba bloqueando o dominio inteiro).
  - Vitima: quem recebeu. So o dominio e o endereco mascarado: o relatorio
    e feito para ser compartilhado.

Mais os meta-atributos (quando, fase da Kill Chain, resultado, direcao,
metodologia, recursos) e os dois eixos: o social-politico (a relacao entre
adversario e vitima - alvo escolhido ou disparo em massa) e o tecnico (como
capacidade e infraestrutura dependem uma da outra).

O que torna o modelo util para CTI sao os PIVOS: cada vertice conhecido
leva aos outros. Um Reply-To leva a outras mensagens da campanha; um
dominio no mesmo certificado leva a infraestrutura irma.

TTPs sao Tatica -> Tecnica -> Procedimento. Tatica e o objetivo, tecnica e
o como em geral (ATT&CK), procedimento e o como ESTE adversario fez, com a
evidencia. E o procedimento que diferencia um relatorio de uma lista de IDs.

Nada aqui e inventado: todo item aponta para o achado de onde saiu.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

from core import dominios

NOMES_DE_TATICA = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "stealth": "Stealth (Defense Evasion)",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}
ORDEM_DE_TATICA = list(NOMES_DE_TATICA)

# Tecnicas que a analise de e-mail pode apontar: nome e tatica.
TECNICAS_DE_EMAIL = {
    "T1589.002": ("Gather Victim Identity Information: Email Addresses", "reconnaissance"),
    "T1598": ("Phishing for Information", "reconnaissance"),
    "T1585.002": ("Establish Accounts: Email Accounts", "resource-development"),
    "T1583.001": ("Acquire Infrastructure: Domains", "resource-development"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "initial-access"),
    "T1566.002": ("Phishing: Spearphishing Link", "initial-access"),
    "T1204": ("User Execution", "execution"),
    "T1656": ("Impersonation", "stealth"),
    "T1036": ("Masquerading", "stealth"),
    "T1027.006": ("Obfuscated Files or Information: HTML Smuggling", "stealth"),
}


@dataclass
class ItemDiamante:
    valor: str
    descricao: str
    # Infraestrutura: "tipo 1" (do adversario) ou "tipo 2" (intermediaria).
    tipo: str = ""


@dataclass
class Vertice:
    nome: str
    resumo: str
    itens: list[ItemDiamante] = field(default_factory=list)


@dataclass
class TTP:
    tatica: str
    tatica_nome: str
    tecnica: str
    tecnica_nome: str
    procedimento: str
    evidencias: list[str] = field(default_factory=list)


@dataclass
class Pivo:
    de: str        # vertice de partida
    para: str      # vertice de chegada
    acao: str


@dataclass
class ModeloDiamante:
    adversario: Vertice
    capacidade: Vertice
    infraestrutura: Vertice
    vitima: Vertice
    meta: dict[str, str] = field(default_factory=dict)
    eixo_social: str = ""
    eixo_tecnico: str = ""
    ttps: list[TTP] = field(default_factory=list)
    pivos: list[Pivo] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _mascarar(endereco: str) -> str:
    """fulano@empresa.com -> f*****@empresa.com: o relatorio circula."""
    if "@" not in endereco:
        return endereco
    local, dominio = endereco.rsplit("@", 1)
    return f"{local[:1]}{'*' * max(3, len(local) - 1)}@{dominio}"


def _ordenar_ttps(ttps: list[TTP]) -> list[TTP]:
    def chave(t: TTP):
        return (ORDEM_DE_TATICA.index(t.tatica) if t.tatica in ORDEM_DE_TATICA else 99, t.tecnica)
    return sorted(ttps, key=chave)


# ============================================================
# E-mail
# ============================================================


def _consultas_por_dominio(consultas: list[Any] | None) -> dict[str, dict]:
    saida = {}
    for c in consultas or []:
        d = c if isinstance(c, dict) else c.to_dict()
        saida[d.get("registravel") or d.get("dominio", "")] = d
    return saida


def ttps_do_email(r: Any, consultas: list[Any] | None = None) -> list[TTP]:
    """TTPs do e-mail: as tecnicas dos sinais, mais as de preparacao que eles implicam."""
    por_tecnica: dict[str, list[str]] = {}
    for s in r.sinais:
        if s.tecnica:
            por_tecnica.setdefault(s.tecnica, []).append(s.detalhe)
    for t in r.tecnicas:
        por_tecnica.setdefault(t["id"], list(t.get("motivos", [])))

    ident = {i.campo: i for i in r.identidades if "@" in i.endereco}
    webmail = [i for i in ident.values() if dominios.e_webmail(i.dominio) and i.campo in ("Reply-To", "From", "Sender")]
    webmail += [
        type("L", (), {"endereco": l.destino[7:].split("?")[0], "campo": "mailto"})()
        for l in r.links if l.tipo == "mailto" and dominios.e_webmail(l.dominio)
    ]
    if webmail:
        por_tecnica.setdefault("T1585.002", []).append(
            f"conta de webmail para receber as vítimas: {webmail[0].endereco} ({webmail[0].campo})"
        )

    consultas_ = _consultas_por_dominio(consultas)
    for base, c in consultas_.items():
        idade = c.get("idade_dias")
        if c.get("imitacao") or (idade is not None and idade < 180):
            motivo = c.get("imitacao") or f"registrado há {idade} dias"
            por_tecnica.setdefault("T1583.001", []).append(f"{base}: {motivo}")
    remetente = ident.get("From")
    if remetente and dominios.imitacao_de_marca(remetente.dominio):
        por_tecnica.setdefault("T1583.001", []).append(
            f"{remetente.dominio}: {dominios.imitacao_de_marca(remetente.dominio).explicacao}"
        )
    rastreio = [u for u in r.imagens_remotas if any(p in u.lower() for p in ("track", "pixel", "open"))]
    if rastreio:
        host = urlsplit(rastreio[0]).hostname or ""
        por_tecnica.setdefault("T1589.002", []).append(
            f"pixel de rastreamento em {dominios.defang(host)} confirma que a caixa existe e foi aberta"
        )

    procedimentos = {
        "T1598": "Pede à vítima que responda ou entre em contato, para colher dados na conversa, fora do alcance do filtro de links.",
        "T1585.002": "Usa uma conta de e-mail gratuita criada para o golpe como canal de retorno.",
        "T1583.001": "Registra domínio próprio para a campanha, com nome que imita marca ou recém-criado.",
        "T1566.001": "Entrega o conteúdo malicioso como anexo da mensagem.",
        "T1566.002": "Entrega um link que leva a vítima para fora do e-mail, ao site do atacante.",
        "T1204": "Depende de a vítima abrir o anexo ou clicar.",
        "T1656": "Se passa por marca ou serviço conhecido no nome exibido e no conteúdo.",
        "T1036": "Disfarça o tipo real do anexo com nome ou extensão enganosa.",
        "T1027.006": "Monta o arquivo malicioso dentro do navegador a partir de um anexo HTML.",
        "T1589.002": "Rastreia a abertura da mensagem para validar quais endereços estão ativos.",
    }
    ttps = []
    for tecnica, evidencias in por_tecnica.items():
        nome, tatica = TECNICAS_DE_EMAIL.get(tecnica, (tecnica, ""))
        ttps.append(TTP(tatica, NOMES_DE_TATICA.get(tatica, tatica), tecnica, nome,
                        procedimentos.get(tecnica, ""), sorted(set(evidencias))[:4]))
    return _ordenar_ttps(ttps)


def _metodologia(r: Any) -> str:
    codigos = {s.codigo for s in r.sinais}
    if "golpe_por_resposta" in codigos:
        return "phishing por resposta (a vítima é levada a escrever para o atacante)"
    if any(s.codigo == "anexo" for s in r.sinais):
        return "phishing com anexo malicioso"
    if codigos & {"link_disfarcado", "link_imitacao", "link_ip", "link_encurtado", "formulario"}:
        return "phishing de credenciais por link"
    return "e-mail suspeito sem método de entrega definido"


def diamante_do_email(r: Any, consultas: list[Any] | None = None) -> ModeloDiamante:
    ident = {}
    for i in r.identidades:
        if "@" in i.endereco and i.campo not in ident:
            ident[i.campo] = i
    marca = next((s.titulo.replace("Finge ser ", "") for s in r.sinais if s.codigo == "personificacao"), "")
    consultas_ = _consultas_por_dominio(consultas)

    # --- Adversario ---
    adv = Vertice("Adversário", "O operador é desconhecido; o que se vê são as personas que ele controla.")
    if marca:
        adv.itens.append(ItemDiamante(f"se passa por {marca}", "persona usada na isca"))
    for campo, descricao in (("From", "remetente exibido"), ("Reply-To", "recebe as respostas das vítimas"),
                             ("Return-Path", "remetente do envelope (SMTP)"), ("Sender", "Sender")):
        if campo in ident:
            nome = f" ({ident[campo].nome})" if ident[campo].nome else ""
            adv.itens.append(ItemDiamante(ident[campo].endereco, f"{descricao}{nome}"))
    for l in r.links:
        if l.tipo == "mailto" and "@" in l.destino:
            endereco = l.destino[7:].split("?")[0].lower()
            if all(endereco != x.valor for x in adv.itens):
                adv.itens.append(ItemDiamante(endereco, "destino dos botões (mailto)"))

    # --- Capacidade ---
    cap = Vertice("Capacidade", _metodologia(r).capitalize() + ".")
    if r.assunto:
        cap.itens.append(ItemDiamante(r.assunto, "isca (assunto)"))
    for t in r.tecnicas:
        cap.itens.append(ItemDiamante(t["id"], t["nome"]))
    for a in r.anexos:
        cap.itens.append(ItemDiamante(a.nome, f"anexo {a.tipo_real}, sha256 {a.sha256[:16]}…"))
    truques = {"texto_oculto": ("texto escondido para enganar o antispam", "evasão"),
               "cabecalho_duplicado": ("cabeçalho duplicado para confundir filtros", "evasão"),
               "link_disfarcado": ("link com texto enganoso", "evasão"),
               "rastreamento": ("pixel de rastreamento", "reconhecimento")}
    for codigo in dict.fromkeys(s.codigo for s in r.sinais):
        if codigo in truques:
            cap.itens.append(ItemDiamante(*truques[codigo]))

    # --- Infraestrutura ---
    inf = Vertice("Infraestrutura", "Tipo 1: controlada pelo adversário. Tipo 2: serviço legítimo usado por ele.")
    if r.origem is not None:
        helo = f" (HELO {r.origem.de})" if r.origem.de and r.origem.de != r.origem.ip else ""
        inf.itens.append(ItemDiamante(r.origem.ip, f"servidor que disparou a mensagem{helo}", "tipo 1"))
    vistos: set[str] = set()

    def dominio(nome: str, descricao: str) -> None:
        base = dominios.registravel(nome)
        if not base or base in vistos:
            return
        vistos.add(base)
        tipo = "tipo 2" if dominios.e_webmail(base) or dominios.e_encurtador(base) else "tipo 1"
        extra = []
        c = consultas_.get(base)
        if c:
            if c.get("idade_dias") is not None:
                extra.append(f"{c['idade_dias']} dias")
            if c.get("registrador"):
                extra.append(c["registrador"])
            if c.get("dominios_irmaos"):
                extra.append(f"certificado com {len(c['dominios_irmaos'])} domínio(s) irmão(s)")
            if any("não existe mais" in o for o in c.get("observacoes", [])):
                extra.append("derrubado")
        inf.itens.append(ItemDiamante(base, descricao + (f" · {', '.join(extra)}" if extra else ""), tipo))

    for campo, descricao in (("From", "domínio do remetente"), ("Return-Path", "domínio do envelope"),
                             ("Reply-To", "domínio do Reply-To")):
        if campo in ident:
            dominio(ident[campo].dominio, descricao)
    for l in r.links:
        if l.dominio and l.tipo in ("http", "encurtador", "mailto"):
            dominio(l.dominio, "domínio de link" if l.tipo != "mailto" else "domínio do mailto")
    for u in r.imagens_remotas:
        dominio(urlsplit(u).hostname or "", "pixel de rastreamento")
    for base, c in consultas_.items():
        for irmao in c.get("dominios_irmaos", [])[:5]:
            if irmao not in vistos:
                vistos.add(irmao)
                inf.itens.append(ItemDiamante(irmao, f"no mesmo certificado que {base}", "tipo 1"))

    # --- Vitima ---
    vit = Vertice("Vítima", "Quem recebeu. Endereço mascarado: o relatório circula.")
    for nome, valor in r.cabecalhos:
        if nome.lower() in ("to", "cc", "delivered-to"):
            for pedaco in valor.replace(",", " ").split():
                pedaco = pedaco.strip("<>;\"'")
                if "@" in pedaco:
                    vit.itens.append(ItemDiamante(_mascarar(pedaco), f"destinatário ({nome})"))
    if marca:
        vit.itens.append(ItemDiamante(f"usuários de {marca}", "perfil visado pela isca"))

    # --- Meta-atributos e eixos ---
    metodologia = _metodologia(r)
    recursos = []
    if any(dominios.e_webmail(i.dominio) for i in ident.values()) or any(
        l.tipo == "mailto" and dominios.e_webmail(l.dominio) for l in r.links
    ):
        recursos.append("conta de webmail")
    if any(i.tipo == "tipo 1" and not dominios.e_ip(i.valor) for i in inf.itens):
        recursos.append("domínio próprio")
    if r.origem is not None:
        recursos.append("servidor de envio")
    meta = {
        "Data": r.data or (r.saltos[0].quando if r.saltos else ""),
        "Fase (Kill Chain)": "Entrega (Delivery)",
        "Resultado": "desconhecido: a análise não observa se a vítima respondeu ou clicou",
        "Direção": "adversário → vítima",
        "Metodologia": metodologia,
        "Recursos": ", ".join(recursos) or "indeterminados",
    }
    if marca:
        eixo_social = (f"Isca genérica de {marca}, marca com base enorme de usuários: sem sinal de alvo escolhido, "
                       "o padrão é de disparo em massa.")
    else:
        eixo_social = "Sem elementos para dizer se a vítima foi escolhida ou se é disparo em massa."
    reply = ident.get("Reply-To")
    if "golpe_por_resposta" in {s.codigo for s in r.sinais} or (reply and dominios.e_webmail(reply.dominio)):
        conta = reply.endereco if reply else next((x.valor for x in adv.itens if "mailto" in x.descricao), "")
        eixo_tecnico = (f"A capacidade depende de uma conta de webmail ({conta}) para receber as vítimas, e de um "
                        f"servidor próprio{' em ' + r.origem.ip if r.origem else ''} para disparar. Derrubar a conta "
                        "quebra o golpe; bloquear só o domínio do remetente, não.")
    elif r.links:
        eixo_tecnico = "A capacidade depende dos domínios dos links: bloqueá-los interrompe a cadeia."
    else:
        eixo_tecnico = "Capacidade e infraestrutura não mostram dependência clara."

    # --- Pivos ---
    pivos: list[Pivo] = []
    if reply:
        pivos.append(Pivo("Adversário", "Vítima", f"Procurar outras mensagens com Reply-To {reply.endereco} (use a regra YARA da campanha)."))
    if r.origem is not None:
        pivos.append(Pivo("Infraestrutura", "Adversário", f"Consultar {r.origem.ip} em reputação de IP (VirusTotal, Shodan) e buscar outros e-mails vindos dele."))
    for base, c in consultas_.items():
        if c.get("dominios_irmaos"):
            pivos.append(Pivo("Infraestrutura", "Infraestrutura", f"Investigar os domínios no mesmo certificado de {base}: {', '.join(c['dominios_irmaos'][:5])}."))
    remetente = ident.get("From")
    if remetente and not dominios.e_webmail(remetente.dominio):
        pivos.append(Pivo("Infraestrutura", "Infraestrutura", f"Buscar nos logs de certificados domínios com o mesmo padrão de nome de {remetente.dominio}."))
    if any(dominios.e_webmail(i.dominio) for i in ident.values()) or any(l.tipo == "mailto" for l in r.links):
        pivos.append(Pivo("Adversário", "Adversário", "Denunciar a conta de webmail ao provedor (formulário de abuso): derrubá-la corta o canal de retorno."))

    return ModeloDiamante(adv, cap, inf, vit, meta, eixo_social, eixo_tecnico, ttps_do_email(r, consultas), pivos)


# ============================================================
# Artefato
# ============================================================


def ttps_do_artefato(r: Any) -> list[TTP]:
    ttps = []
    if not r.mapeamento:
        return ttps
    for t in r.mapeamento.tecnicas:
        evidencias = [f"{e.tipo.value}: {e.trecho}"[:160] for e in t.evidencias[:4]]
        for tatica in t.taticas or [""]:
            ttps.append(TTP(tatica, NOMES_DE_TATICA.get(tatica, tatica), t.tecnica_id, t.nome,
                            t.descricao or "Capacidade observada no binário (não execução).", evidencias))
    return _ordenar_ttps(ttps)


def diamante_do_artefato(r: Any) -> ModeloDiamante:
    adv = Vertice("Adversário", "Desconhecido. Grupos com repertório parecido são hipótese, não atribuição.")
    if r.atribuicao:
        for c in r.atribuicao.candidatos[:3]:
            adv.itens.append(ItemDiamante(f"{c.nome} ({c.grupo_id})", f"repertório parecido · confiança {c.confianca.value}"))

    cap = Vertice("Capacidade", "O que o artefato é capaz de fazer, pela análise estática.")
    nome = r.caminho.replace("\\", "/").rsplit("/", 1)[-1]
    sha = getattr(r.extracao, "sha256", "") if r.extracao else ""
    cap.itens.append(ItemDiamante(nome, f"artefato · sha256 {sha[:16]}…" if sha else "artefato"))
    if r.mapeamento:
        for t in r.mapeamento.tecnicas:
            cap.itens.append(ItemDiamante(t.tecnica_id, t.nome))
    if r.regra_yara is not None and r.regra_yara.valida:
        cap.itens.append(ItemDiamante(r.regra_yara.nome, "regra YARA validada contra a amostra"))

    inf = Vertice("Infraestrutura", "Endereços de rede encontrados no artefato (possível C2 ou download).")
    for ioc in r.iocs if hasattr(r, "iocs") else []:
        if ioc.tipo.value in ("ipv4", "ipv6", "dominio", "url"):
            tipo = "tipo 2" if dominios.e_webmail(ioc.valor) or dominios.e_encurtador(ioc.valor) else "tipo 1"
            inf.itens.append(ItemDiamante(ioc.valor, f"{ioc.tipo.value} · confiança {ioc.confianca.value}", tipo))

    vit = Vertice("Vítima", "Desconhecida: a análise estática não observa em quem o artefato foi usado.")

    meta = {
        "Data": r.iniciado_em or "",
        "Fase (Kill Chain)": ", ".join(
            e.estagio.value for e in (r.kill_chain.estagios if r.kill_chain else []) if e.tecnicas
        ) or "indeterminada",
        "Resultado": "desconhecido: nada foi executado",
        "Direção": "infraestrutura → vítima (presumida)",
        "Metodologia": "artefato malicioso",
        "Recursos": f"{len(inf.itens)} endereço(s) de rede",
    }
    pivos = [Pivo("Infraestrutura", "Adversário", f"Consultar {i.valor} em reputação (VirusTotal, Shodan).") for i in inf.itens[:3]]
    if sha:
        pivos.append(Pivo("Capacidade", "Adversário", "Buscar o hash no MalwareBazaar e a regra YARA em acervos de amostras."))
    return ModeloDiamante(
        adv, cap, inf, vit, meta,
        "Sem dados sobre a vítima: o eixo social-político não pode ser avaliado por análise estática.",
        "A capacidade depende dos endereços de rede embutidos: bloqueá-los interrompe a comunicação." if inf.itens else
        "Nenhum endereço de rede embutido: a capacidade não depende de infraestrutura visível.",
        ttps_do_artefato(r), pivos,
    )
