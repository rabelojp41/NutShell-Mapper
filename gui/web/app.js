/*
 * Nut-Shell Mapper - interface
 *
 * REGRA DE SEGURANCA QUE ATRAVESSA O ARQUIVO
 *
 * Quase todo texto exibido aqui veio de dentro de um malware: strings,
 * URLs, caminhos, nomes de chave de registro. O dado e do adversario. Uma
 * string como <img src=x onerror=...> embutida no binario viraria codigo
 * rodando dentro da ferramenta do analista - e esta pagina fala com uma
 * ponte que grava arquivo e baixa amostra.
 *
 * Por isso nenhum dado passa por innerHTML. Todo elemento e criado por
 * h(), que so conhece texto como no de texto. A politica de seguranca do
 * index.html e a segunda barreira, nao a primeira.
 */
"use strict";

// ============================================================
// DOM seguro
// ============================================================

function h(tag, props, ...filhos) {
  const el = document.createElement(tag);
  for (const [chave, valor] of Object.entries(props || {})) {
    if (valor === null || valor === undefined || valor === false) continue;
    if (chave === "class") el.className = valor;
    else if (chave.startsWith("on") && typeof valor === "function") el.addEventListener(chave.slice(2), valor);
    else if (chave === "dataset") Object.assign(el.dataset, valor);
    else if (chave === "style") aplicarEstilo(el, valor);
    else el.setAttribute(chave, valor === true ? "" : String(valor));
  }
  anexar(el, filhos);
  return el;
}

// A politica de seguranca proibe o atributo style (style-src 'self'), o que
// fecha a porta para CSS injetado por dado. Estilo definido pelo proprio
// codigo passa pelo CSSOM, que a politica permite.
function aplicarEstilo(el, declaracoes) {
  for (const parte of String(declaracoes).split(";")) {
    const i = parte.indexOf(":");
    if (i < 0) continue;
    el.style.setProperty(parte.slice(0, i).trim(), parte.slice(i + 1).trim());
  }
}

function anexar(el, filhos) {
  for (const filho of filhos.flat(Infinity)) {
    if (filho === null || filho === undefined || filho === false) continue;
    el.appendChild(filho instanceof Node ? filho : document.createTextNode(String(filho)));
  }
  return el;
}

function limpar(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

// Icones: tracos desenhados aqui, constantes do codigo, nunca dado de fora.
const ICONES = {
  simbolo: ["M4 12h4l3-8 4 16 3-8h2"],
  mais: ["M12 5v14", "M5 12h14"],
  arquivo: ["M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z", "M14 3v5h5"],
  subir: ["M12 16V4", "M7 9l5-5 5 5", "M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"],
  visao: ["M4 5h7v7H4z", "M13 5h7v4h-7z", "M13 11h7v8h-7z", "M4 14h7v5H4z"],
  alvo: ["M12 3v3", "M12 18v3", "M3 12h3", "M18 12h3", "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"],
  grade: ["M4 4h16v16H4z", "M4 10h16", "M10 4v16"],
  cadeia: ["M5 6h14", "M5 12h14", "M5 18h14", "M9 6v12"],
  pessoas: ["M16 19v-1a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v1", "M9.5 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6z", "M21 19v-1a4 4 0 0 0-3-3.9", "M15.5 4.1a3 3 0 0 1 0 5.8"],
  chave: ["M15 7a4 4 0 1 1-3.9 5H3v3h3v-3h2", "M15 7h.01"],
  texto: ["M4 6h16", "M4 11h16", "M4 16h10"],
  chip: ["M7 7h10v10H7z", "M10 3v4", "M14 3v4", "M10 17v4", "M14 17v4", "M3 10h4", "M3 14h4", "M17 10h4", "M17 14h4"],
  escudo: ["M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z", "M9 12l2 2 4-4"],
  globo: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M3 12h18", "M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z"],
  faisca: ["M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z", "M19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8z"],
  alerta: ["M12 4l9 16H3z", "M12 10v4", "M12 17h.01"],
  info: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 11v5", "M12 8h.01"],
  caixa: ["M3 7l9-4 9 4v10l-9 4-9-4z", "M3 7l9 4 9-4", "M12 11v10"],
  engrenagem: ["M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z", "M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"],
  copiar: ["M9 9h11v11H9z", "M5 15H4V4h11v1"],
  externo: ["M14 4h6v6", "M20 4l-9 9", "M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"],
  baixar: ["M12 4v12", "M7 11l5 5 5-5", "M4 20h16"],
  seta: ["M9 6l6 6-6 6"],
  abaixo: ["M6 9l6 6 6-6"],
  busca: ["M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z", "M20 20l-4-4"],
  ok: ["M5 12l5 5 9-10"],
  x: ["M6 6l12 12", "M18 6L6 18"],
  play: ["M7 5l12 7-12 7z"],
  parar: ["M7 7h10v10H7z"],
  pasta: ["M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"],
  recarregar: ["M20 11a8 8 0 1 0-2.3 5.7", "M20 5v6h-6"],
  disco: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 14.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z", "M12 12h.01"],
  pausar: ["M9 5v14", "M15 5v14"],
  anterior: ["M17 6v12l-9-6z", "M7 6v12"],
  proxima: ["M7 6v12l9-6z", "M17 6v12"],
  lista: ["M9 6h11", "M9 12h11", "M9 18h11", "M4.5 6h.01", "M4.5 12h.01", "M4.5 18h.01"],
  volume: ["M4 10v4h3l5 4V6L7 10z", "M16 9.5a3.5 3.5 0 0 1 0 5"],
  carta: ["M4 6h16v12H4z", "M4 7l8 6 8-6"],
};

function icone(nome) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.7");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONES[nome] || []) {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    svg.appendChild(p);
  }
  return svg;
}

// ============================================================
// Formatacao
// ============================================================

const fmtNum = (n, casas = 0) =>
  Number(n || 0).toLocaleString("pt-BR", { minimumFractionDigits: casas, maximumFractionDigits: casas });

function fmtBytes(n) {
  if (n < 1024) return `${fmtNum(n)} bytes`;
  if (n < 1024 ** 2) return `${fmtNum(n / 1024, 1)} KB`;
  return `${fmtNum(n / 1024 ** 2, 1)} MB`;
}

function fmtDuracao(s) {
  if (s < 1) return `${fmtNum(s, 2)} s`;
  if (s < 60) return `${fmtNum(s, 1)} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${Math.round(s % 60)} s`;
}

function fmtRelogio(s) {
  const m = Math.floor(s / 60);
  return `${String(m).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
}

function fmtData(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return "";
  return d.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

const CONFIANCA = { alta: "Alta", media: "Média", baixa: "Baixa" };
const ORDEM_CONFIANCA = { alta: 0, media: 1, baixa: 2 };

const TIPO_IOC = {
  ipv4: "IPv4", ipv6: "IPv6", dominio: "Domínio", url: "URL", email: "E-mail",
  caminho_windows: "Caminho", caminho_unc: "Caminho UNC", chave_registro: "Registro",
  hash: "Hash", bitcoin: "Bitcoin", cve: "CVE",
};

const TIPO_STRING = { static: "Estática", stack: "Pilha", tight: "Tight", decoded: "Decodificada" };

const KILL_CHAIN = {
  Reconhecimento: "Reconhecimento", Armamento: "Armamento", Entrega: "Entrega",
  Exploracao: "Exploração", Instalacao: "Instalação",
  "Comando e Controle": "Comando e controle", "Acoes no Objetivo": "Ações no objetivo",
};

const TIPO_EVIDENCIA = {
  string: "string", import: "import", conteudo_desofuscado: "desofuscado", secao: "seção", recurso: "recurso",
};

function nomeTatica(t) {
  return String(t).split("-").map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join(" ");
}

const selo = (conf) => h("span", { class: `selo ${conf}` }, CONFIANCA[conf] || conf);

function porConfianca(a, b) {
  return (ORDEM_CONFIANCA[a.confianca] ?? 9) - (ORDEM_CONFIANCA[b.confianca] ?? 9);
}

function contarConfianca(lista) {
  const c = { alta: 0, media: 0, baixa: 0 };
  for (const i of lista) if (i.confianca in c) c[i.confianca]++;
  return c;
}

// ============================================================
// Ponte com o Python
// ============================================================

let ponte = null;

function chamar(metodo, ...args) {
  return new Promise((resolver) => {
    ponte[metodo](...args, (resposta) => {
      try {
        resolver(resposta ? JSON.parse(resposta) : null);
      } catch (erro) {
        resolver({ ok: false, erro: String(erro) });
      }
    });
  });
}

const tarefas = {};

// ============================================================
// Estado
// ============================================================

const estado = {
  vista: "nova",
  ambiente: null,
  arquivo: null,
  opcoes: {
    usar_floss: true,
    gerar_yara: true,
    usar_stix: true,
    resumo_ia: false,
    enriquecer: false,
    formato: "auto",
    tamanho_minimo_de_string: 4,
    cve: "",
    vetor_cvss: "",
    // Vem do Python (estado().modelo_padrao) assim que a ponte conecta.
    modelo_ia: "",
  },
  ollama: null,          // diagnostico
  verificandoOllama: false,
  andamento: null,
  resultado: null,
  filtro: { iocs: "todos", buscaIocs: "", tecnicas: "todos", strings: "todos", buscaStrings: "", limiteStrings: 300 },
  bazaar: { hash: "", carregando: false, consulta: null, erro: "", baixando: false, baixada: null },
  email: { arquivo: null, online: false, carregando: false, dados: null, erro: "", mensagem: "", ia: null, yara: null },
  dominio: { valor: "", subdominios: true, carregando: false, dados: null, erro: "", filtro: "" },
  attackAtualizando: false,
  menuAberto: null,
};

function ir(vista) {
  const mudou = estado.vista !== vista;
  estado.vista = vista;
  estado.menuAberto = null;
  renderizar(mudou);
}

// ============================================================
// Avisos flutuantes e modal
// ============================================================

function avisar(tipo, titulo, detalhe = "", acao = null) {
  const caixa = document.getElementById("avisos");
  const el = h(
    "div",
    { class: `aviso-flutuante ${tipo}`, role: "status" },
    icone(tipo === "erro" ? "alerta" : "ok"),
    h("div", { class: "aviso-flutuante-texto" }, h("div", {}, titulo), detalhe && h("div", { class: "t3", title: detalhe }, detalhe)),
    acao && h("button", { class: "btn btn-pequeno", onclick: () => { acao.fazer(); el.remove(); } }, acao.rotulo),
    h("button", { class: "btn-icone", title: "Fechar", onclick: () => el.remove() }, icone("x")),
  );
  caixa.appendChild(el);
  setTimeout(() => el.remove(), tipo === "erro" ? 9000 : 6000);
}

function confirmar({ titulo, tipo = "aviso", paragrafos = [], botao = "Continuar", perigo = false }) {
  return new Promise((resolver) => {
    const fechar = (resposta) => {
      fundo.remove();
      document.removeEventListener("keydown", teclas);
      resolver(resposta);
    };
    const teclas = (e) => { if (e.key === "Escape") fechar(false); };
    const confirmarBtn = h("button", { class: `btn ${perigo ? "btn-perigo" : "btn-primario"}`, onclick: () => fechar(true) }, botao);
    const fundo = h(
      "div",
      { class: "modal-fundo", onclick: (e) => { if (e.target === fundo) fechar(false); } },
      h(
        "div",
        { class: "modal", role: "dialog", "aria-modal": "true" },
        h(
          "div",
          { class: "modal-corpo" },
          h("h2", { class: `modal-titulo ${tipo}` }, icone(tipo === "perigo" ? "alerta" : "info"), titulo),
          paragrafos.map((p) => h("p", {}, p)),
        ),
        h(
          "div",
          { class: "modal-acoes" },
          h("button", { class: "btn btn-fantasma", onclick: () => fechar(false) }, "Cancelar"),
          confirmarBtn,
        ),
      ),
    );
    document.body.appendChild(fundo);
    document.addEventListener("keydown", teclas);
    // O foco vai para Cancelar em acao perigosa: Enter por reflexo nao pode
    // trazer malware para o disco.
    (perigo ? fundo.querySelector(".btn-fantasma") : confirmarBtn).focus();
  });
}

async function copiar(texto, rotulo = "Copiado") {
  await chamar("copiar", texto);
  avisar("ok", rotulo, texto.length > 70 ? texto.slice(0, 70) + "…" : texto);
}

function valorCopiavel(texto, classe = "mono") {
  return h(
    "div",
    { class: "valor-copiavel" },
    h("span", { class: classe }, texto),
    h("button", { class: "btn-icone", title: "Copiar", onclick: (e) => { e.stopPropagation(); copiar(texto); } }, icone("copiar")),
  );
}

function linkExterno(url, rotulo) {
  return h(
    "button",
    { class: "btn btn-fantasma btn-pequeno", onclick: async () => {
      const r = await chamar("abrirLink", url);
      if (!r?.ok) avisar("erro", "Link não aberto", r?.erro || "");
    } },
    rotulo,
    icone("externo"),
  );
}

// ============================================================
// Estrutura: navegacao, topo, rodape
// ============================================================

function itemNav(vista, rotulo, nomeIcone, contagem = null, classeContagem = "") {
  const ativo = estado.vista === vista || (vista === "nova" && estado.vista === "andamento");
  return h(
    "button",
    { class: "nav-item", "aria-current": ativo ? "page" : null, onclick: () => ir(vista === "nova" && estado.andamento?.rodando ? "andamento" : vista) },
    icone(nomeIcone),
    h("span", {}, rotulo),
    contagem !== null && h("span", { class: `nav-contagem ${classeContagem}` }, contagem),
  );
}

function renderizarNav() {
  const nav = limpar(document.getElementById("nav"));
  const r = estado.resultado;
  const rodando = estado.andamento?.rodando;

  const grupoAnalise = [itemNav("nova", rodando ? "Analisando…" : "Nova análise", rodando ? "recarregar" : "mais")];
  if (r) {
    const kc = (r.kill_chain?.estagios || []).filter((e) => e.tecnicas.length).length;
    grupoAnalise.push(
      itemNav("visao", "Visão geral", "visao"),
      itemNav("indicadores", "Indicadores", "alvo", r.iocs.length),
      itemNav("tecnicas", "Técnicas ATT&CK", "grade", r.mapeamento?.tecnicas.length ?? 0),
      itemNav("killchain", "Kill Chain", "cadeia", `${kc}/7`),
      itemNav("atribuicao", "Atribuição", "pessoas", r.atribuicao?.candidatos.length ?? 0),
    );
  }
  nav.appendChild(h("div", { class: "nav-grupo" }, grupoAnalise));

  if (r) {
    const yara = r.regra_yara;
    nav.appendChild(
      h(
        "div",
        { class: "nav-grupo" },
        h("div", { class: "nav-titulo" }, "Detalhes técnicos"),
        itemNav("desofuscacao", "Desofuscação", "chave", r.desofuscacao?.achados.length ?? 0),
        itemNav("strings", "Strings", "texto", fmtNum(r.extracao?.strings.length ?? 0)),
        itemNav("pe", "Executável (PE)", "chip", r.info_pe?.e_pe ? null : "—"),
        itemNav("yara", "Regra YARA", "escudo", yara ? (yara.valida ? "válida" : "inválida") : "—", yara ? (yara.valida ? "bom" : "alerta") : ""),
      ),
    );
    const avisos = (r.avisos?.length || 0) + (r.erros?.length || 0);
    nav.appendChild(
      h(
        "div",
        { class: "nav-grupo" },
        h("div", { class: "nav-titulo" }, "Contexto"),
        itemNav("enriquecimento", "Enriquecimento", "globo"),
        itemNav("ia", "Resumo por IA", "faisca"),
        itemNav("avisos", "Avisos e limites", "info", avisos, r.erros?.length ? "alerta" : ""),
      ),
    );
  }

  nav.appendChild(
    h(
      "div",
      { class: "nav-grupo" },
      h("div", { class: "nav-titulo" }, "Ferramentas"),
      itemNav("email", "Análise de e-mail", "carta", estado.email.dados ? estado.email.dados.pontuacao : null, estado.email.dados?.pontuacao >= 60 ? "alerta" : ""),
      itemNav("dominio", "Domínio", "busca"),
      itemNav("bazaar", "MalwareBazaar", "caixa"),
      itemNav("config", "Configuração", "engrenagem"),
    ),
  );
}

function renderizarRodape() {
  const rodape = limpar(document.getElementById("rodape"));
  rodape.appendChild(icone("escudo"));
  aplicarEstilo(rodape.lastChild, "width:14px;height:14px");
  rodape.appendChild(h("span", {}, "Nada é executado"));
}

const VISTAS_DE_RESULTADO = new Set([
  "visao", "indicadores", "tecnicas", "killchain", "atribuicao",
  "desofuscacao", "strings", "pe", "yara", "enriquecimento", "ia", "avisos",
]);

const TITULO_VISTA = {
  visao: "Visão geral", indicadores: "Indicadores", tecnicas: "Técnicas ATT&CK", killchain: "Kill Chain",
  atribuicao: "Atribuição", desofuscacao: "Desofuscação", strings: "Strings", pe: "Executável (PE)",
  yara: "Regra YARA", enriquecimento: "Enriquecimento", ia: "Resumo por IA", avisos: "Avisos e limites",
};

function renderizarTopo() {
  const topo = limpar(document.getElementById("topo"));
  const v = estado.vista;

  if (v === "nova") {
    topo.append(
      h("div", { class: "topo-titulo" }, "Nova análise"),
      h(
        "div",
        { class: "topo-acoes" },
        !estado.arquivo && h("span", { class: "topo-sub" }, "Selecione um arquivo para começar"),
        h("button", { class: "btn btn-primario", disabled: !estado.arquivo, onclick: analisar, title: "Ctrl+Enter" }, icone("play"), "Analisar"),
      ),
    );
    return;
  }

  if (v === "andamento") {
    topo.append(
      h("div", { class: "topo-titulo" }, estado.andamento?.rodando ? "Analisando" : "Análise"),
      h("span", { class: "topo-sub" }, estado.arquivo?.nome || ""),
    );
    return;
  }

  if (VISTAS_DE_RESULTADO.has(v) && estado.resultado) {
    const r = estado.resultado;
    topo.append(
      h("div", { class: "topo-titulo", title: r.caminho }, r.nome),
      h("span", { class: "topo-sub" }, "/  " + TITULO_VISTA[v]),
      h("div", { class: "topo-acoes" }, botaoExportarRelatorio(), botaoExportarIndicadores()),
    );
    return;
  }

  const ferramentas = { bazaar: "MalwareBazaar", email: "Análise de e-mail", dominio: "Domínio" };
  topo.append(h("div", { class: "topo-titulo" }, ferramentas[v] || "Configuração"));
  if (v === "email" && estado.email.arquivo) topo.append(h("span", { class: "topo-sub" }, "/  " + estado.email.arquivo.nome));
}

function botaoMenu(id, rotulo, nomeIcone, itens, primario = false) {
  const aberto = estado.menuAberto === id;
  return h(
    "div",
    { class: "menu-ancora" },
    h(
      "button",
      { class: `btn ${primario ? "btn-primario" : ""}`, onclick: (e) => { e.stopPropagation(); estado.menuAberto = aberto ? null : id; renderizarTopo(); } },
      icone(nomeIcone), rotulo, icone("abaixo"),
    ),
    aberto && h(
      "div",
      { class: "menu", role: "menu" },
      itens.map(([texto, detalhe, fazer]) =>
        h("button", { class: "menu-item", role: "menuitem", onclick: () => { estado.menuAberto = null; renderizarTopo(); fazer(); } },
          h("span", {}, texto), h("span", {}, detalhe))),
    ),
  );
}

function botaoExportarRelatorio() {
  return botaoMenu("relatorio", "Relatório", "arquivo", [
    ["PDF", ".pdf", () => exportarRelatorio("pdf")],
    ["Word", ".docx", () => exportarRelatorio("docx")],
    ["Markdown", ".md", () => exportarRelatorio("md")],
    ["JSON", ".json", () => exportarRelatorio("json")],
  ]);
}

function botaoExportarIndicadores() {
  return botaoMenu("iocs", "Indicadores", "baixar", [
    ["Alta e média", "recomendado", () => exportarIndicadores("media")],
    ["Somente alta", "para bloqueio", () => exportarIndicadores("alta")],
    ["Todos, inclusive baixa", "para revisão", () => exportarIndicadores("baixa")],
  ], true);
}

// ============================================================
// Renderizacao
// ============================================================

const VISTAS = {};

function renderizar(rolarParaTopo = false) {
  renderizarNav();
  renderizarTopo();
  const conteudo = document.getElementById("conteudo");
  const rolagem = conteudo.scrollTop;
  limpar(conteudo);
  const construir = VISTAS[estado.vista] || VISTAS.nova;
  try {
    conteudo.appendChild(construir());
  } catch (erro) {
    // Uma vista quebrada nao pode derrubar a janela inteira.
    console.error(erro);
    conteudo.appendChild(pagina(null, h("div", { class: "nota perigo" }, icone("alerta"),
      h("div", {}, h("strong", {}, "Falha ao montar esta tela. "), String(erro)))));
  }
  conteudo.scrollTop = rolarParaTopo ? 0 : rolagem;
}

function pagina(cabecalho, ...corpo) {
  return h("div", { class: "pagina" }, cabecalho, corpo);
}

function cabecalho(titulo, descricao) {
  return h("div", { class: "pagina-cabecalho" }, h("h1", { class: "pagina-titulo" }, titulo), descricao && h("p", { class: "pagina-desc" }, descricao));
}

function vazio(nomeIcone, titulo, texto, acao = null) {
  return h("div", { class: "vazio" }, icone(nomeIcone), h("div", { class: "vazio-titulo" }, titulo), texto && h("p", {}, texto), acao);
}

function nota(tipo, ...conteudo) {
  const ic = { aviso: "alerta", perigo: "alerta", info: "info" }[tipo] || "info";
  return h("div", { class: `nota ${tipo}` }, icone(ic), h("div", {}, conteudo));
}

function segmentos(opcoes, atual, aoEscolher) {
  return h(
    "div",
    { class: "segmentos", role: "group" },
    opcoes.map(([valor, rotulo, contagem]) =>
      h("button", { class: "segmento", "aria-pressed": String(valor === atual), onclick: () => aoEscolher(valor) },
        rotulo, contagem !== undefined && h("span", { class: "num" }, contagem))),
  );
}

function interruptor(marcado, aoMudar, desabilitado = false, rotulo = "") {
  const entrada = h("input", { type: "checkbox", "aria-label": rotulo, disabled: desabilitado });
  entrada.checked = marcado;
  entrada.addEventListener("change", () => aoMudar(entrada.checked, entrada));
  return h("label", { class: "interruptor" }, entrada, h("span"));
}

function medida(valor, classe = "", texto = null) {
  const pct = Math.max(0, Math.min(1, valor)) * 100;
  return h(
    "div",
    { class: "medida" },
    h("div", { class: "medida-trilho" }, h("div", { class: `medida-preenchimento ${classe}`, style: `width:${pct.toFixed(1)}%` })),
    h("span", { class: "num" }, texto ?? fmtNum(valor, 2)),
  );
}

function busca(valor, placeholder, aoDigitar) {
  const entrada = h("input", { class: "campo", type: "search", placeholder, value: valor, spellcheck: "false" });
  entrada.addEventListener("input", () => aoDigitar(entrada.value));
  return h("div", { class: "busca" }, icone("busca"), entrada);
}

// ============================================================
// Vista: nova analise
// ============================================================

VISTAS.nova = () => {
  const o = estado.opcoes;
  const amb = estado.ambiente;
  const chaves = amb?.chaves || {};

  const alvo = estado.arquivo
    ? h(
        "div",
        { class: "arquivo" },
        h("div", { class: "arquivo-icone" }, icone("arquivo")),
        h(
          "div",
          { class: "arquivo-info" },
          h("div", { class: "arquivo-nome", title: estado.arquivo.nome }, estado.arquivo.nome),
          h("div", { class: "arquivo-meta" }, `${estado.arquivo.formato} · ${fmtBytes(estado.arquivo.tamanho)}`),
          h("div", { class: "arquivo-caminho", title: estado.arquivo.caminho }, estado.arquivo.caminho),
        ),
        h("button", { class: "btn", onclick: () => ponte.escolherArquivo() }, "Trocar"),
      )
    : h(
        "div",
        { class: "alvo" },
        icone("subir"),
        h("div", { class: "alvo-titulo" }, "Arraste um arquivo para cá"),
        h("p", { class: "alvo-desc" }, "Executável, DLL, shellcode, documento. Ele é lido, nunca executado."),
        h("button", { class: "btn", onclick: () => ponte.escolherArquivo() }, icone("pasta"), "Escolher arquivo"),
      );

  // --- IA: status do Ollama ---
  let extraIA = null;
  if (o.resumo_ia) {
    const d = estado.ollama;
    if (estado.verificandoOllama || !d) {
      extraIA = h("div", { class: "opcao-extra" }, h("span", { class: "status-servico verificando" }, "Verificando o Ollama…"));
    } else if (d.estado === "pronto") {
      const seletor = h("select", { class: "campo", "aria-label": "Modelo" }, d.modelos.map((m) => h("option", { value: m }, m)));
      seletor.value = d.modelos.includes(o.modelo_ia) ? o.modelo_ia : d.modelos[0];
      o.modelo_ia = seletor.value;
      seletor.addEventListener("change", () => { o.modelo_ia = seletor.value; });
      extraIA = h("div", { class: "opcao-extra" },
        h("span", { class: "status-servico ok" }, `Ollama ${d.versao} · pronto`), seletor);
    } else {
      extraIA = h("div", { class: "opcao-extra", style: "flex-direction:column;align-items:flex-start;gap:8px" },
        h("span", { class: "status-servico falha" }, { nao_instalado: "Ollama não instalado", parado: `Ollama instalado${d.versao ? " (" + d.versao + ")" : ""}, mas fechado`, sem_modelo: `Ollama ${d.versao} · modelo ausente` }[d.estado]),
        h("div", { class: "t3", style: "font-size:12px" }, orientacaoOllama(d), " A análise roda normalmente; só o resumo é pulado."),
        h("div", { class: "linha" },
          d.estado === "nao_instalado" && linkExterno("https://ollama.com/download", "Baixar o Ollama"),
          h("button", { class: "btn btn-pequeno", onclick: () => verificarOllama() }, icone("recarregar"), "Verificar de novo")),
      );
    }
  }

  const attackDesc = amb?.attack?.em_cache
    ? "Nomes, táticas e grupos do bundle STIX oficial. Necessário para a atribuição."
    : "Necessário para a atribuição. O bundle (cerca de 50 MB) ainda não foi baixado: será baixado na primeira análise.";

  const chavesConfiguradas = ["virustotal", "shodan", "malwarebazaar"].filter((k) => chaves[k]);
  const nomesChave = { virustotal: "VirusTotal", shodan: "Shodan", malwarebazaar: "MalwareBazaar" };

  const opcoes = h(
    "div",
    { class: "opcoes" },
    opcao("Extração com FLOSS", "Recupera strings montadas em tempo de execução (pilha, tight, decodificadas). Mais lento.", "usar_floss"),
    opcao("Regra YARA", "Gera a regra e a valida contra a própria amostra antes de aceitá-la.", "gerar_yara"),
    opcao("Metadados oficiais do ATT&CK", attackDesc, "usar_stix"),
    opcao("Resumo por IA local", "Texto de apoio escrito pelo Ollama, na sua máquina. Cada afirmação é conferida contra os achados.", "resumo_ia", extraIA, (ligado) => { if (ligado) verificarOllama(); }),
    opcao(
      "Consultar fontes externas",
      "VirusTotal, Shodan, NVD e MalwareBazaar recebem hashes e indicadores. O arquivo nunca é enviado.",
      "enriquecer",
      h("div", { class: "opcao-extra" }, h("span", { class: "t3", style: "font-size:12px" },
        chavesConfiguradas.length
          ? `Chaves configuradas: ${chavesConfiguradas.map((k) => nomesChave[k]).join(", ")}. A NVD não precisa de chave.`
          : "Nenhuma chave configurada: só a NVD, que não precisa de chave, será consultada.")),
      null,
      async (ligado, entrada) => {
        if (!ligado) return true;
        const ok = await confirmar({
          titulo: "Enviar indicadores a terceiros?",
          paragrafos: [
            "Os hashes e indicadores deste artefato serão enviados ao VirusTotal, ao Shodan, à NVD e ao MalwareBazaar.",
            "Quem opera esses serviços verá o que você está investigando e quando. Em investigação sensível, isso pode avisar o adversário de que ele foi detectado.",
            "O arquivo em si não é enviado, apenas o hash.",
          ],
          botao: "Ativar consulta",
        });
        if (!ok) entrada.checked = false;
        return ok;
      },
    ),
  );

  const avancado = h(
    "details",
    { class: "avancado" },
    h("summary", {}, icone("seta"), "Opções avançadas"),
    h(
      "div",
      { class: "grade-campos" },
      h("div", { class: "largo" },
        h("span", { class: "rotulo" }, "Formato do artefato"),
        segmentos([["auto", "Automático"], ["pe", "PE"], ["sc32", "Shellcode 32"], ["sc64", "Shellcode 64"]], o.formato, (v) => { o.formato = v; renderizar(); }),
        h("div", { class: "ajuda" }, "No automático, arquivo sem cabeçalho PE é tentado como shellcode nas duas arquiteturas."),
      ),
      campoTexto("Tamanho mínimo de string", "tamanho_minimo_de_string", "number", "4", "Strings mais curtas são ignoradas. 4 é o padrão do FLOSS."),
      h("div"),
      campoTexto("CVE explorada", "cve", "text", "ex.: CVE-2021-44228",
        "Normalmente fica vazio: CVE citada nas strings é detectada sozinha. Preencha só se você sabe, por fonte externa, que a amostra explora uma CVE que não aparece nela."),
      campoTexto("Vetor CVSS", "vetor_cvss", "text", "ex.: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Opcional. Com a CVE preenchida e a consulta externa ligada, o vetor oficial vem da NVD."),
    ),
  );

  return h(
    "div",
    { class: "pagina estreita" },
    cabecalho("Nova análise", "Extrai strings e indicadores, reverte ofuscação, mapeia técnicas ATT&CK e gera regra YARA, sem executar o arquivo."),
    alvo,
    h("div", { class: "secao-titulo mt-24" }, "O que executar"),
    opcoes,
    avancado,
  );

  function opcao(nome, descricao, chave, extra = null, depois = null, antes = null) {
    return h(
      "div",
      { class: "opcao" },
      h("div", { class: "opcao-texto" }, h("div", { class: "opcao-nome" }, nome), h("div", { class: "opcao-desc" }, descricao), extra),
      interruptor(o[chave], async (ligado, entrada) => {
        if (antes && !(await antes(ligado, entrada))) return;
        o[chave] = ligado;
        if (depois) depois(ligado);
        renderizar();
      }, false, nome),
    );
  }

  function campoTexto(rotulo, chave, tipo, placeholder, ajuda) {
    const entrada = h("input", { class: `campo ${tipo === "text" ? "mono" : ""}`, type: tipo, placeholder, value: o[chave], spellcheck: "false" });
    if (tipo === "number") { entrada.min = "3"; entrada.max = "64"; }
    entrada.addEventListener("input", () => { o[chave] = tipo === "number" ? Number(entrada.value) : entrada.value; });
    return h("label", {}, h("span", { class: "rotulo" }, rotulo), entrada, h("div", { class: "ajuda" }, ajuda));
  }
};

function orientacaoOllama(d) {
  if (d.estado === "nao_instalado") return "Instale o Ollama e depois rode no terminal: " + (d.comando_instalacao || "ollama pull " + d.modelo_pedido) + ".";
  if (d.estado === "parado") return "Abra o aplicativo Ollama e clique em Verificar de novo.";
  if (d.estado === "sem_modelo") return "Rode no terminal: " + (d.comando_instalacao || "ollama pull " + d.modelo_pedido) + ".";
  return "";
}

function verificarOllama() {
  estado.verificandoOllama = true;
  renderizar();
  ponte.verificarOllama(estado.opcoes.modelo_ia);
}

tarefas.ollama = (t) => {
  estado.verificandoOllama = false;
  estado.ollama = t.ok ? t.dados : { estado: "parado", versao: "", modelos: [], modelo_pedido: estado.opcoes.modelo_ia };
  if (["nova", "config"].includes(estado.vista)) renderizar();
};

async function analisar() {
  if (!estado.arquivo || estado.andamento?.rodando) return;
  const o = estado.opcoes;
  if (o.tamanho_minimo_de_string < 3 || o.tamanho_minimo_de_string > 64 || !Number.isFinite(o.tamanho_minimo_de_string)) {
    avisar("erro", "Tamanho mínimo de string inválido", "Use um valor entre 3 e 64.");
    return;
  }
  const resposta = await chamar("analisar", JSON.stringify(o));
  if (!resposta?.ok) {
    avisar("erro", "A análise não começou", resposta?.erro || "");
    return;
  }
  iniciarAndamento();
}

// ============================================================
// Vista: andamento
// ============================================================

const ETAPAS = [
  ["Extracao de strings", "Extração de strings"],
  ["Analise do PE", "Análise do executável"],
  ["Desofuscacao", "Desofuscação"],
  ["Geracao da regra YARA", "Geração da regra YARA", (o) => o.gerar_yara],
  ["Mapeamento ATT&CK", "Mapeamento ATT&CK"],
  ["Cyber Kill Chain", "Cyber Kill Chain"],
  ["Atribuicao de grupo", "Atribuição de grupo"],
  ["Score CVSS", "Score CVSS", (o) => o.enriquecer || o.vetor_cvss],
  ["Consulta ao VirusTotal", "Consulta ao VirusTotal", (o, a) => o.enriquecer && a?.chaves?.virustotal],
  ["Consulta ao Shodan", "Consulta ao Shodan", (o, a) => o.enriquecer && a?.chaves?.shodan],
  ["Consulta ao MalwareBazaar", "Consulta ao MalwareBazaar", (o, a) => o.enriquecer && a?.chaves?.malwarebazaar],
  ["Resumo por IA local", "Resumo por IA local", (o) => o.resumo_ia],
];

let relogio = null;

function iniciarAndamento() {
  const o = { ...estado.opcoes };
  estado.andamento = {
    rodando: true,
    cancelando: false,
    inicio: performance.now(),
    fracao: 0,
    atual: null,
    etapas: Object.fromEntries(
      ETAPAS.filter(([, , cond]) => !cond || cond(o, estado.ambiente)).map(([chave]) => [chave, { estado: "pendente" }]),
    ),
  };
  estado.resultado = null;
  ir("andamento");
  clearInterval(relogio);
  relogio = setInterval(atualizarRelogio, 250);
}

function atualizarRelogio() {
  const a = estado.andamento;
  if (!a?.rodando) return;
  const el = document.getElementById("andamento-tempo");
  if (el) el.textContent = fmtRelogio((performance.now() - a.inicio) / 1000) + " decorridos";
  if (a.atual) {
    const t = document.getElementById("tempo-etapa-atual");
    if (t) t.textContent = fmtDuracao((performance.now() - a.etapas[a.atual].inicio) / 1000);
  }
}

function aoProgredir(p) {
  const a = estado.andamento;
  if (!a) return;
  a.fracao = p.fracao;
  if (p.estagio === "Concluido") { encerrarEtapaAtual("feita"); return atualizarAndamento(); }
  if (a.atual !== p.estagio) {
    encerrarEtapaAtual("feita");
    a.etapas[p.estagio] = a.etapas[p.estagio] || { estado: "pendente" };
    Object.assign(a.etapas[p.estagio], { estado: "rodando", inicio: performance.now(), mensagem: "" });
    a.atual = p.estagio;
  }
  a.etapas[p.estagio].mensagem = p.mensagem || "";
  atualizarAndamento();
}

function encerrarEtapaAtual(como) {
  const a = estado.andamento;
  if (!a?.atual) return;
  const e = a.etapas[a.atual];
  e.estado = como;
  e.duracao = (performance.now() - e.inicio) / 1000;
  a.atual = null;
}

function atualizarAndamento() {
  if (estado.vista === "andamento") renderizar();
}

VISTAS.andamento = () => {
  const a = estado.andamento;
  if (!a) return pagina(null, vazio("info", "Nenhuma análise em andamento", ""));
  const decorrido = (performance.now() - a.inicio) / 1000;

  const linhas = Object.entries(a.etapas).map(([chave, e]) => {
    const rotulo = (ETAPAS.find(([k]) => k === chave) || [, chave])[1];
    const marca = e.estado === "feita" ? icone("ok") : e.estado === "falhou" ? icone("x") : null;
    const tempo = e.estado === "rodando"
      ? h("span", { class: "etapa-tempo", id: "tempo-etapa-atual" }, fmtDuracao((performance.now() - e.inicio) / 1000))
      : e.duracao !== undefined ? h("span", { class: "etapa-tempo" }, fmtDuracao(e.duracao))
      : e.estado === "pulada" ? h("span", { class: "etapa-tempo" }, "pulada") : h("span");
    return h(
      "div",
      { class: `etapa ${e.estado}` },
      h("div", { class: "etapa-marca" }, marca),
      h("div", {}, h("div", { class: "etapa-nome" }, rotulo), (e.estado === "rodando" || e.estado === "falhou") && e.mensagem && h("div", { class: "etapa-msg" }, e.mensagem)),
      tempo,
    );
  });

  return h(
    "div",
    { class: "pagina estreita" },
    h(
      "div",
      { class: "andamento-cab" },
      h("div", {}, h("h1", { class: "pagina-titulo" }, a.rodando ? (a.cancelando ? "Cancelando…" : "Analisando") : "Análise encerrada"),
        h("div", { class: "andamento-tempo", id: "andamento-tempo" }, fmtRelogio(decorrido) + " decorridos")),
      a.rodando && h("button", { class: "btn", disabled: a.cancelando, onclick: cancelar }, icone("parar"), "Cancelar"),
    ),
    h("div", { class: "barra-geral" }, h("div", { style: `width:${Math.round(a.fracao * 100)}%` })),
    h("div", { class: "etapas" }, linhas),
    a.cancelando && h("p", { class: "t3 mt-16" }, "A etapa em andamento termina antes de parar. Emulação do FLOSS pode levar alguns segundos."),
  );
};

function cancelar() {
  if (!estado.andamento) return;
  estado.andamento.cancelando = true;
  ponte.cancelar();
  renderizar();
}

function aoConcluir(resultado) {
  const a = estado.andamento;
  clearInterval(relogio);
  if (a) {
    encerrarEtapaAtual("feita");
    const falhas = new Set((resultado.erros || []).map((e) => e.estagio));
    for (const [chave, e] of Object.entries(a.etapas)) {
      if (falhas.has(chave)) e.estado = "falhou";
      else if (e.estado === "pendente") e.estado = "pulada";
    }
    a.rodando = false;
  }
  estado.resultado = resultado;
  estado.filtro = { iocs: "todos", buscaIocs: "", tecnicas: "todos", strings: "todos", buscaStrings: "", limiteStrings: 300 };
  if (resultado.cancelado) avisar("erro", "Análise cancelada", "O que foi concluído antes do cancelamento está disponível.");
  ir("visao");
}

function aoFalhar(mensagem) {
  clearInterval(relogio);
  if (estado.andamento) {
    encerrarEtapaAtual("falhou");
    estado.andamento.rodando = false;
  }
  avisar("erro", "A análise falhou", mensagem);
  renderizar();
}

// ============================================================
// Vista: visao geral
// ============================================================

VISTAS.visao = () => {
  const r = estado.resultado;
  if (!r) return pagina(null, vazio("visao", "Nenhuma análise ainda", "Comece por uma nova análise.", h("button", { class: "btn btn-primario", onclick: () => ir("nova") }, "Nova análise")));

  const tecnicas = [...(r.mapeamento?.tecnicas || [])].sort(porConfianca);
  const iocs = [...r.iocs].sort(porConfianca);
  const cTec = contarConfianca(tecnicas);
  const cIoc = contarConfianca(iocs);
  const estagios = r.kill_chain?.estagios || [];
  const acesos = estagios.filter((e) => e.tecnicas.length).length;
  const yara = r.regra_yara;
  const formato = r.info_pe?.e_pe
    ? `PE ${r.info_pe.tipo} ${r.info_pe.arquitetura}`.trim()
    : r.extracao?.formato_floss && r.extracao.formato_floss !== "pe" ? `Shellcode ${r.extracao.formato_floss}` : "Não é PE";

  const detConfianca = (c) => {
    const partes = ["alta", "media", "baixa"].filter((k) => c[k]).map((k) => h("span", { class: `selo ${k}` }, `${c[k]} ${CONFIANCA[k].toLowerCase()}`));
    return partes.length ? partes : [h("span", { class: "t3" }, "nenhum")];
  };

  const numeros = h(
    "div",
    { class: "numeros" },
    h("button", { class: "numero", onclick: () => ir("indicadores") },
      h("div", { class: "numero-rotulo" }, "Indicadores"), h("div", { class: "numero-valor" }, r.iocs.length), h("div", { class: "numero-det" }, detConfianca(cIoc))),
    h("button", { class: "numero", onclick: () => ir("tecnicas") },
      h("div", { class: "numero-rotulo" }, "Técnicas ATT&CK"), h("div", { class: "numero-valor" }, tecnicas.length), h("div", { class: "numero-det" }, detConfianca(cTec))),
    h("button", { class: "numero", onclick: () => ir("killchain") },
      h("div", { class: "numero-rotulo" }, "Kill Chain"), h("div", { class: "numero-valor" }, acesos, h("small", {}, " de 7")), h("div", { class: "numero-det" }, "estágios com evidência")),
    h("button", { class: "numero", onclick: () => ir("yara") },
      h("div", { class: "numero-rotulo" }, "Regra YARA"),
      h("div", { class: "numero-valor", style: "font-size:20px;line-height:1.6" }, yara ? (yara.valida ? "Válida" : "Inválida") : "—"),
      h("div", { class: "numero-det" }, yara ? (yara.valida ? h("span", { class: "selo ok" }, "casa com a amostra") : h("span", { class: "selo alta" }, "ver motivo")) : h("span", { class: "t3" }, "não gerada"))),
  );

  const faixa = h(
    "div",
    { class: "faixa" },
    estagios.map((e, i) => h(
      "button",
      { class: `faixa-etapa ${e.tecnicas.length ? "acesa" : ""}`, onclick: () => ir("killchain"), title: KILL_CHAIN[e.estagio] || e.estagio },
      h("div", { class: "faixa-num" }, String(i + 1).padStart(2, "0")),
      h("div", { class: "faixa-nome" }, KILL_CHAIN[e.estagio] || e.estagio),
      h("div", { class: "faixa-qtd" }, e.tecnicas.length ? `${e.tecnicas.length} técnica${e.tecnicas.length > 1 ? "s" : ""}` : "—"),
    )),
  );

  const topTecnicas = h(
    "div",
    { class: "painel" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Técnicas de maior confiança")),
    tecnicas.length
      ? h("ul", { class: "lista-compacta" }, tecnicas.slice(0, 5).map((t) => h(
          "li", {},
          h("div", { class: "linha-1" }, h("span", { class: "id-tecnica" }, t.tecnica_id), h("span", { class: "nome-cortado", title: t.nome }, t.nome)),
          selo(t.confianca),
          t.evidencias?.[0] && h("div", { class: "linha-2", title: t.evidencias[0].trecho }, t.evidencias[0].trecho),
        )))
      : h("div", { class: "painel-vazio" }, "Nenhuma técnica com evidência suficiente."),
    tecnicas.length > 5 && h("div", { class: "painel-rodape" }, h("button", { class: "btn btn-fantasma btn-pequeno", onclick: () => ir("tecnicas") }, `Ver as ${tecnicas.length}`, icone("seta"))),
  );

  const topIocs = h(
    "div",
    { class: "painel" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Indicadores de maior confiança")),
    iocs.length
      ? h("ul", { class: "lista-compacta" }, iocs.slice(0, 6).map((i) => h(
          "li", {},
          h("div", { class: "linha-1" }, h("span", { class: "etiqueta" }, TIPO_IOC[i.tipo] || i.tipo), h("span", { class: "mono nome-cortado", title: i.valor }, i.valor)),
          selo(i.confianca),
        )))
      : h("div", { class: "painel-vazio" }, "Nenhum indicador identificado."),
    iocs.length > 6 && h("div", { class: "painel-rodape" }, h("button", { class: "btn btn-fantasma btn-pequeno", onclick: () => ir("indicadores") }, `Ver os ${iocs.length}`, icone("seta"))),
  );

  return h(
    "div",
    { class: "pagina" },
    r.erros?.length > 0 && h("div", { style: "margin-bottom:20px" }, nota("aviso",
      h("strong", {}, `${r.erros.length} etapa${r.erros.length > 1 ? "s falharam" : " falhou"}. `),
      "O resultado abaixo é parcial. ",
      h("button", { class: "btn btn-fantasma btn-pequeno", onclick: () => ir("avisos") }, "Ver quais"))),
    h(
      "div",
      { class: "identidade" },
      h("div", {},
        h("h1", {}, r.nome),
        h("div", { class: "meta" },
          h("span", {}, formato),
          h("span", {}, fmtBytes(r.extracao?.tamanho_bytes || 0)),
          h("span", {}, `analisado em ${fmtDuracao(r.duracao_segundos)}`),
          h("span", {}, fmtData(r.iniciado_em)))),
    ),
    h(
      "dl",
      { class: "hashes" },
      h("dt", {}, "SHA256"), h("dd", {}, valorCopiavel(r.sha256 || "—")),
      h("dt", {}, "MD5"), h("dd", {}, valorCopiavel(r.extracao?.md5 || "—")),
      r.info_pe?.imphash && [h("dt", {}, "Imphash"), h("dd", {}, valorCopiavel(r.info_pe.imphash))],
    ),
    numeros,
    h("div", { class: "secao-titulo" }, "Cyber Kill Chain"),
    faixa,
    h("div", { class: "colunas" }, topTecnicas, topIocs),
    blocoCvss(r, true),
    blocoIA(r, true),
  );
};

function blocoCvss(r, compacto = false) {
  const c = r.cvss;
  if (!c) return null;
  const sev = { Critica: "alta", Alta: "alta", Media: "media", Baixa: "baixa", Nenhuma: "baixa" }[c.severidade_base] || "baixa";
  const nomeSev = { Critica: "Crítica", Alta: "Alta", Media: "Média", Baixa: "Baixa", Nenhuma: "Nenhuma" }[c.severidade_base] || c.severidade_base;
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" },
      h("span", { class: "painel-titulo" }, "CVSS da vulnerabilidade citada"),
      c.cve && h("span", { class: "etiqueta mono" }, c.cve),
      h("span", { class: `etiqueta ${sev}`, style: "margin-left:auto" }, `${fmtNum(c.score_base, 1)} · ${nomeSev}`)),
    h("div", { class: "painel-corpo pilha" },
      h("div", { class: "mono t2" }, c.vetor),
      nota("info", h("strong", {}, "O score descreve a falha, não este arquivo. "),
        "O artefato apenas referencia esta vulnerabilidade. Se ele a explora, e com que sucesso, a análise estática não determina."),
      !compacto && c.metricas?.length > 0 && h("dl", { class: "defs" }, c.metricas.map((m) => [h("dt", {}, m.nome), h("dd", {}, m.valor_legivel)])),
    ),
  );
}

function blocoIA(r, compacto = false) {
  const ia = r.resumo_ia;
  if (!ia) return null;
  if (!ia.gerado) {
    return compacto ? null : nota("aviso", h("strong", {}, "O resumo não foi gerado. "), ia.erro || "");
  }
  const inv = ia.invencoes || [];
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" },
      icone("faisca"),
      h("span", { class: "painel-titulo" }, "Leitura por IA"),
      h("span", { class: "t3", style: "font-size:12px" }, `${ia.modelo} · ${fmtDuracao(ia.duracao_segundos)}`),
      h("span", { class: `etiqueta ${inv.length ? "alta" : "ok"}`, style: "margin-left:auto" },
        inv.length ? `${inv.length} afirmação${inv.length > 1 ? "ões" : ""} sem respaldo` : "Conferido com os achados")),
    h("div", { class: "painel-corpo" },
      h("p", { class: "texto-ia" }, ia.texto),
      inv.length > 0 && h("div", { class: "mt-16" }, nota("perigo",
        h("strong", {}, "O modelo citou o que a análise não observou:"),
        h("ul", { style: "margin:6px 0 0;padding-left:18px" }, inv.map((i) => h("li", {}, h("span", { class: "mono" }, i.valor), ` (${i.tipo}): ${i.explicacao}`))))),
      !compacto && h("p", { class: "t3 mt-16", style: "font-size:12px" }, ia.ressalva)),
  );
}

// ============================================================
// Vista: indicadores
// ============================================================

VISTAS.indicadores = () => {
  const r = estado.resultado;
  const f = estado.filtro;
  const c = contarConfianca(r.iocs);
  const corpo = h("tbody");

  const preencher = () => {
    limpar(corpo);
    const termo = f.buscaIocs.trim().toLowerCase();
    const lista = [...r.iocs].sort(porConfianca).filter((i) =>
      (f.iocs === "todos" || i.confianca === f.iocs) &&
      (!termo || i.valor.toLowerCase().includes(termo) || (TIPO_IOC[i.tipo] || i.tipo).toLowerCase().includes(termo)));
    if (!lista.length) {
      corpo.appendChild(h("tr", {}, h("td", { colspan: "4", class: "t3", style: "text-align:center;padding:28px" }, r.iocs.length ? "Nenhum indicador com esse filtro." : "Nenhum indicador identificado.")));
      return;
    }
    for (const i of lista) {
      corpo.appendChild(h(
        "tr", {},
        h("td", { class: "estreita" }, selo(i.confianca)),
        h("td", { class: "estreita" }, h("span", { class: "etiqueta" }, TIPO_IOC[i.tipo] || i.tipo)),
        h("td", {}, valorCopiavel(i.valor)),
        h("td", { class: "t2", title: i.origem ? "Encontrado em: " + i.origem : "" }, i.observacao || h("span", { class: "t3" }, TIPO_STRING[i.tipo_string] || "")),
      ));
    }
  };
  preencher();

  return pagina(
    cabecalho("Indicadores", "IPs, domínios, URLs e demais indicadores encontrados no arquivo, inclusive os revelados pela desofuscação. A confiança diz o quanto o valor parece ser o que aparenta."),
    h("div", { class: "barra-ferramentas" },
      segmentos([["todos", "Todos", r.iocs.length], ["alta", "Alta", c.alta], ["media", "Média", c.media], ["baixa", "Baixa", c.baixa]], f.iocs, (v) => { f.iocs = v; renderizar(); }),
      busca(f.buscaIocs, "Buscar valor ou tipo", (v) => { f.buscaIocs = v; preencher(); })),
    h("div", { class: "painel" }, h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "Confiança"), h("th", {}, "Tipo"), h("th", {}, "Valor"), h("th", {}, "Observação"))),
      corpo))),
    c.baixa > 0 && h("p", { class: "t3 mt-16", style: "font-size:12px" },
      "Indicadores de confiança baixa ficam fora da exportação padrão: existem para você julgar, e alimentariam um bloqueio automático com ruído."),
  );
};

// ============================================================
// Vista: tecnicas
// ============================================================

VISTAS.tecnicas = () => {
  const r = estado.resultado;
  const m = r.mapeamento;
  if (!m) return pagina(cabecalho("Técnicas ATT&CK"), vazio("grade", "Mapeamento não executado", "A etapa de mapeamento falhou ou foi pulada. Veja Avisos e limites."));
  const f = estado.filtro;
  const todas = [...m.tecnicas].sort(porConfianca);
  const c = contarConfianca(todas);
  const lista = todas.filter((t) => f.tecnicas === "todos" || t.confianca === f.tecnicas);

  const blocos = lista.map((t) => {
    // Varios padroes costumam casar com a mesma string: agrupa pelo trecho.
    const porTrecho = new Map();
    for (const e of t.evidencias || []) {
      const chave = e.tipo + "\u0000" + e.trecho;
      if (!porTrecho.has(chave)) porTrecho.set(chave, { ...e, padroes: 0 });
      porTrecho.get(chave).padroes++;
    }
    return h(
      "div",
      { class: "tecnica" },
      h("div", { class: "tecnica-cab" },
        h("span", { class: "id-tecnica" }, t.tecnica_id),
        h("span", { class: "tecnica-nome" }, t.nome),
        selo(t.confianca)),
      t.descricao && h("p", { class: "tecnica-desc" }, t.descricao),
      porTrecho.size > 0 && h("div", { class: "evidencias" }, [...porTrecho.values()].slice(0, 6).map((e) => h(
        "div", { class: "evidencia" },
        h("span", { class: "t3" }, TIPO_EVIDENCIA[e.tipo] || e.tipo),
        h("span", { class: "mono" }, e.trecho),
        e.padroes > 1 && h("span", { class: "t3" }, `${e.padroes} padrões`),
      ))),
      h("div", { class: "tecnica-rodape" },
        h("div", { class: "etiquetas" }, (t.taticas || []).map((x) => h("span", { class: "etiqueta" }, nomeTatica(x)))),
        t.url && h("div", { style: "margin-left:auto" }, linkExterno(t.url, "MITRE ATT&CK"))),
    );
  });

  return pagina(
    cabecalho("Técnicas ATT&CK", "Capacidades observadas no arquivo. Uma técnica listada significa que o recurso está presente, não que foi executado."),
    h("div", { class: "barra-ferramentas" },
      segmentos([["todos", "Todas", todas.length], ["alta", "Alta", c.alta], ["media", "Média", c.media], ["baixa", "Baixa", c.baixa]], f.tecnicas, (v) => { f.tecnicas = v; renderizar(); }),
      h("span", { class: "direita t3", style: "font-size:12px" }, `Fonte: ${{ stix: "bundle STIX oficial", catalogo_local: "catálogo local" }[m.fonte] || m.fonte}${m.versao_attack ? " · ATT&CK " + m.versao_attack : ""}`)),
    h("div", { class: "painel" }, blocos.length ? blocos : h("div", { class: "painel-vazio" }, "Nenhuma técnica com esse filtro.")),
    (m.avisos || []).map((a) => h("div", { class: "mt-16" }, nota("info", a))),
  );
};

// ============================================================
// Vista: kill chain
// ============================================================

VISTAS.killchain = () => {
  const r = estado.resultado;
  const kc = r.kill_chain;
  if (!kc) return pagina(cabecalho("Kill Chain"), vazio("cadeia", "Kill Chain não montada", "Depende do mapeamento ATT&CK, que falhou ou foi pulado."));

  return pagina(
    cabecalho("Cyber Kill Chain", "As técnicas observadas, organizadas nos sete estágios da intrusão. Um arquivo sozinho costuma cobrir só parte da cadeia."),
    h("div", { class: "cadeia" }, kc.estagios.map((e, i) => h(
      "div",
      { class: `cadeia-etapa ${e.tecnicas.length ? "acesa" : ""}` },
      h("div", { class: "cadeia-num" }, i + 1),
      h("div", {},
        h("div", { class: "cadeia-titulo" }, KILL_CHAIN[e.estagio] || e.estagio),
        h("div", { class: "cadeia-sub" }, e.tecnicas.length ? `${e.tecnicas.length} técnica${e.tecnicas.length > 1 ? "s" : ""}` : "Sem evidência neste artefato"),
        e.tecnicas.length > 0 && h("div", { class: "cadeia-lista" }, [...e.tecnicas].sort(porConfianca).map((t) => h(
          "div", { class: "cadeia-item" },
          h("span", { class: "id-tecnica" }, t.tecnica_id),
          h("span", {}, t.nome),
          selo(t.confianca))))),
    ))),
    (kc.avisos || []).map((a) => h("div", { class: "mt-16" }, nota("info", a))),
  );
};

// ============================================================
// Vista: atribuicao
// ============================================================

VISTAS.atribuicao = () => {
  const r = estado.resultado;
  const at = r.atribuicao;
  const semStix = !r.opcoes?.usar_stix;
  if (!at || !at.candidatos.length) {
    return pagina(
      cabecalho("Atribuição"),
      vazio("pessoas", "Nenhum grupo comparado",
        semStix
          ? "A comparação com grupos conhecidos usa o bundle oficial do ATT&CK. Ligue “Metadados oficiais do ATT&CK” na próxima análise."
          : "Nenhum grupo documentado tem repertório compatível com as técnicas observadas."),
    );
  }

  const candidatos = at.candidatos.map((c, i) => {
    const aliases = (c.aliases || []).filter((a) => a !== c.nome);
    return h(
      "div",
      { class: "candidato" },
      h("div", { class: "candidato-pos" }, i + 1),
      h("div", { style: "min-width:0" },
        h("div", { class: "candidato-nome" }, c.nome, h("span", { class: "mono" }, c.grupo_id)),
        h("div", { class: "candidato-aliases" }, aliases.length ? aliases.join(" · ") : "sem outros nomes"),
        h("div", { class: "etiquetas" }, (c.tecnicas_em_comum || []).map((t) =>
          h("span", { class: "etiqueta mono", title: `${t.nome}${t.exato ? "" : " (técnica-mãe em comum)"} · usada por ${t.grupos_que_usam} grupos` },
            (t.exato ? "" : "~") + t.tecnica_id))),
        c.url && h("div", { style: "margin-top:8px" }, linkExterno(c.url, "Perfil no MITRE"))),
      h("div", { class: "candidato-metricas" },
        h("div", { class: "linha" }, h("span", { class: "rot" }, "Pontuação"), medida(c.pontuacao, "")),
        h("div", { class: "linha" }, h("span", { class: "rot" }, "Cobertura"), medida(c.cobertura, "baixa")),
        h("div", { class: "linha" }, h("span", { class: "rot" }, "Especificidade"), medida(c.especificidade, "baixa")),
        h("div", { class: "linha", style: "margin-top:2px" }, h("span", { class: "rot" }, "Confiança"), selo(c.confianca))),
    );
  });

  return pagina(
    cabecalho("Atribuição", `Grupos com repertório documentado compatível com as técnicas observadas. ${at.total_de_grupos_avaliados} grupos comparados.`),
    nota("info", h("strong", {}, "Sobreposição de técnicas não é atribuição. "), at.ressalva.replace(/^Sobreposicao de tecnicas ATT&CK nao e atribuicao\.\s*/i, "")),
    h("div", { class: "painel mt-16" }, candidatos),
    h("p", { class: "t3 mt-16", style: "font-size:12px" },
      "Cobertura: quanto do repertório do grupo aparece no arquivo. Especificidade: o quanto as técnicas em comum são raras entre grupos. ~ indica técnica-mãe em comum, não a sub-técnica exata."),
  );
};

// ============================================================
// Vista: desofuscacao
// ============================================================

VISTAS.desofuscacao = () => {
  const r = estado.resultado;
  const d = r.desofuscacao;
  if (!d) return pagina(cabecalho("Desofuscação"), vazio("chave", "Desofuscação não executada", "A etapa falhou ou foi pulada."));

  const cadeia = (a) => h("div", { class: "etiquetas" }, (a.tecnicas || []).flatMap((t, i, arr) => {
    const nome = i === arr.length - 1 && a.chave ? `${t}(${a.chave})` : t;
    return [h("span", { class: "etiqueta mono acento" }, nome), i < arr.length - 1 && h("span", { class: "t3" }, "→")];
  }));

  return pagina(
    cabecalho("Desofuscação", `Base64, Base32, hex, ROT13, XOR de 1 byte e compressão, encadeados até três camadas. ${fmtNum(d.candidatos_avaliados)} strings candidatas avaliadas.`),
    d.achados.length
      ? h("div", { class: "painel" }, h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
          h("thead", {}, h("tr", {}, h("th", {}, "Nota"), h("th", {}, "Cadeia"), h("th", {}, "Original"), h("th", {}, "Revelado"))),
          h("tbody", {}, d.achados.map((a) => h(
            "tr", {},
            h("td", { class: "estreita", style: "width:120px" }, medida(a.pontuacao, a.pontuacao >= 0.8 ? "" : "media")),
            h("td", { class: "estreita" }, cadeia(a)),
            h("td", { class: "quebra mono t3", style: "max-width:280px" }, a.original.length > 120 ? a.original.slice(0, 120) + "…" : a.original),
            h("td", { class: "quebra" }, valorCopiavel(a.decodificado), a.ancoras?.length > 0 && h("div", { class: "t3", style: "font-size:11.5px;margin-top:3px" }, "âncoras: " + a.ancoras.join(", "))),
          ))))))
      : h("div", { class: "painel" }, vazio("chave", "Nenhuma ofuscação revertida", "Nenhuma string candidata decodificou para algo legível.")),
    h("p", { class: "t3 mt-16", style: "font-size:12px" },
      "A nota mede quão plausível é o resultado. Âncoras são trechos reconhecíveis no texto revelado, como http:// ou cmd.exe: a evidência mais concreta de que a decodificação acertou."),
  );
};

// ============================================================
// Vista: strings
// ============================================================

VISTAS.strings = () => {
  const r = estado.resultado;
  const ex = r.extracao;
  if (!ex) return pagina(cabecalho("Strings"), vazio("texto", "Nenhuma string extraída", ""));
  const f = estado.filtro;
  const contagem = { static: 0, stack: 0, tight: 0, decoded: 0 };
  for (const s of ex.strings) if (s.tipo in contagem) contagem[s.tipo]++;

  const corpo = h("tbody");
  const rodape = h("div");

  const preencher = () => {
    limpar(corpo);
    limpar(rodape);
    const termo = f.buscaStrings.trim().toLowerCase();
    const lista = ex.strings.filter((s) => (f.strings === "todos" || s.tipo === f.strings) && (!termo || s.valor.toLowerCase().includes(termo)));
    for (const s of lista.slice(0, f.limiteStrings)) {
      corpo.appendChild(h("tr", {},
        h("td", { class: "estreita" }, h("span", { class: "etiqueta" }, TIPO_STRING[s.tipo] || s.tipo)),
        h("td", { class: "estreita t3" }, s.encoding),
        h("td", { class: "valor" }, s.valor)));
    }
    if (!lista.length) corpo.appendChild(h("tr", {}, h("td", { colspan: "3", class: "t3", style: "text-align:center;padding:28px;font-family:var(--font-ui)" }, "Nenhuma string com esse filtro.")));
    if (lista.length > f.limiteStrings) {
      rodape.appendChild(h("div", { class: "painel-rodape linha" },
        h("span", { class: "t3" }, `Mostrando ${fmtNum(f.limiteStrings)} de ${fmtNum(lista.length)}`),
        h("button", { class: "btn btn-pequeno", style: "margin-left:auto", onclick: () => { f.limiteStrings += 1000; preencher(); } }, "Mostrar mais")));
    }
  };
  preencher();

  return pagina(
    cabecalho("Strings", `${fmtNum(ex.strings.length)} strings extraídas${ex.usou_floss ? " com o FLOSS" : " pelo extrator nativo"}.`),
    !ex.usou_floss && h("div", { style: "margin-bottom:14px" }, nota("aviso", h("strong", {}, "O FLOSS não foi usado. "), "Só strings estáticas aparecem; as montadas em tempo de execução (pilha, tight, decodificadas) ficaram de fora.")),
    h("div", { class: "barra-ferramentas" },
      segmentos([["todos", "Todas", ex.strings.length], ["static", "Estáticas", contagem.static], ["stack", "Pilha", contagem.stack], ["tight", "Tight", contagem.tight], ["decoded", "Decodificadas", contagem.decoded]],
        f.strings, (v) => { f.strings = v; f.limiteStrings = 300; renderizar(); }),
      busca(f.buscaStrings, "Buscar nas strings", (v) => { f.buscaStrings = v; f.limiteStrings = 300; preencher(); })),
    h("div", { class: "painel lista-strings" }, h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "Tipo"), h("th", {}, "Codificação"), h("th", {}, "Valor"))), corpo)), rodape),
  );
};

// ============================================================
// Vista: PE
// ============================================================

VISTAS.pe = () => {
  const r = estado.resultado;
  const pe = r.info_pe;
  if (!pe || !pe.e_pe) {
    return pagina(cabecalho("Executável (PE)"), vazio("chip", "Não é um executável PE",
      pe?.erro ? `O cabeçalho não foi reconhecido (${pe.erro}). Imports, seções e recursos não se aplicam a este arquivo.` : "Imports, seções e recursos não se aplicam a este arquivo."));
  }
  const imports = Object.entries(pe.imports || {});
  const totalFuncoes = imports.reduce((s, [, f]) => s + f.length, 0);

  return pagina(
    cabecalho("Executável (PE)", "Estrutura do binário: de onde vêm as funções que ele usa e como as seções estão organizadas."),
    h("div", { class: "painel" }, h("div", { class: "painel-corpo" }, h("dl", { class: "defs" },
      h("dt", {}, "Tipo"), h("dd", {}, `${pe.tipo} · ${pe.arquitetura}`),
      h("dt", {}, "Compilado em"), h("dd", {}, pe.timestamp_compilacao ? fmtData(pe.timestamp_compilacao) + (new Date(pe.timestamp_compilacao) > new Date() ? " (data no futuro: campo forjado ou reprodutível)" : "") : "—"),
      h("dt", {}, "Imphash"), h("dd", {}, pe.imphash ? valorCopiavel(pe.imphash) : "—"),
      h("dt", {}, "Recursos"), h("dd", {}, pe.tipos_de_recurso?.length ? pe.tipos_de_recurso.join(", ") : "—"),
    ))),
    pe.indicios?.length > 0 && h("div", { class: "mt-16" }, nota("aviso", h("strong", {}, "Indícios estruturais"),
      h("ul", { style: "margin:6px 0 0;padding-left:18px" }, pe.indicios.map((i) => h("li", {}, i))))),
    h("div", { class: "secao-titulo mt-24" }, "Seções", h("span", { class: "t3" }, String(pe.secoes.length))),
    h("div", { class: "painel" }, h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "Nome"), h("th", {}, "Tamanho virtual"), h("th", {}, "Tamanho em disco"), h("th", {}, "Permissões"), h("th", { style: "width:220px" }, "Entropia"))),
      h("tbody", {}, pe.secoes.map((s) => h("tr", {},
        h("td", { class: "mono" }, s.nome),
        h("td", { class: "num" }, fmtBytes(s.tamanho_virtual)),
        h("td", { class: "num" }, fmtBytes(s.tamanho_bruto)),
        h("td", { class: "mono t2" }, "R" + (s.gravavel ? "W" : "-") + (s.executavel ? "X" : "-")),
        h("td", { title: s.entropia >= 7.2 ? "Entropia alta: conteúdo compactado ou cifrado" : "" }, medida(s.entropia / 8, s.entropia >= 7.2 ? "alta" : s.entropia >= 6.5 ? "media" : "", fmtNum(s.entropia, 2))),
      )))))),
    h("div", { class: "secao-titulo mt-24" }, "Imports", h("span", { class: "t3" }, `${imports.length} DLLs · ${fmtNum(totalFuncoes)} funções`)),
    h("div", { class: "painel" }, imports.length
      ? imports.map(([dll, funcoes]) => h("details", { class: "tecnica", style: "padding:10px 18px" },
          h("summary", { style: "cursor:pointer;display:flex;gap:10px;align-items:center" }, h("span", { class: "mono" }, dll), h("span", { class: "t3", style: "margin-left:auto" }, `${funcoes.length}`)),
          h("div", { class: "mono t2", style: "margin-top:8px;line-height:1.8;column-width:220px" }, funcoes.map((fn) => h("div", {}, fn)))))
      : h("div", { class: "painel-vazio" }, "Nenhum import. Binário sem tabela de imports costuma resolver as APIs em tempo de execução, o que por si só é indício de evasão.")),
    pe.exports?.length > 0 && [
      h("div", { class: "secao-titulo mt-24" }, "Exports", h("span", { class: "t3" }, String(pe.exports.length))),
      h("div", { class: "painel" }, h("div", { class: "painel-corpo mono t2", style: "column-width:240px" }, pe.exports.map((e) => h("div", {}, e)))),
    ],
  );
};

// ============================================================
// Vista: YARA
// ============================================================

function realcarYara(texto) {
  // Realce por tokens, sempre como no de texto: a regra carrega strings do
  // malware, e elas nao podem virar HTML.
  const bloco = h("pre", { class: "codigo" });
  const padrao = /(\/\/[^\n]*)|("(?:[^"\\]|\\.)*")|(\$[A-Za-z0-9_]*)|\b(rule|meta|strings|condition|and|or|not|of|them|any|all|at|in|filesize|ascii|wide|nocase|fullword|private|global|import)\b/g;
  let ultimo = 0;
  let m;
  while ((m = padrao.exec(texto))) {
    if (m.index > ultimo) bloco.appendChild(document.createTextNode(texto.slice(ultimo, m.index)));
    const classe = m[1] ? "com" : m[2] ? "str" : m[3] ? "var" : "kw";
    bloco.appendChild(h("span", { class: classe }, m[0]));
    ultimo = padrao.lastIndex;
  }
  bloco.appendChild(document.createTextNode(texto.slice(ultimo)));
  return bloco;
}

VISTAS.yara = () => {
  const r = estado.resultado;
  const y = r.regra_yara;
  if (!y) return pagina(cabecalho("Regra YARA"), vazio("escudo", "Nenhuma regra gerada", r.opcoes?.gerar_yara ? "A geração falhou. Veja Avisos e limites." : "A geração de regra estava desligada nesta análise."));

  const verificacao = (ok, rotulo) => h("div", { class: "linha" }, h("span", { class: `selo ${ok ? "ok" : "alta"}` }, rotulo));

  return pagina(
    cabecalho("Regra YARA", "Gerada a partir das strings mais distintivas e testada contra a própria amostra antes de ser considerada utilizável."),
    h("div", { class: "numeros", style: "grid-template-columns:repeat(3,1fr)" },
      h("div", { class: "numero", style: "cursor:default" }, h("div", { class: "numero-rotulo" }, "Veredito"), h("div", { class: "numero-valor", style: "font-size:20px;line-height:1.6" }, y.valida ? "Válida" : "Inválida"),
        h("div", { class: "numero-det" }, verificacao(y.compila, y.compila ? "compila" : "não compila"), verificacao(y.casa_com_a_amostra, y.casa_com_a_amostra ? "casa com a amostra" : "não casa com a amostra"))),
      h("div", { class: "numero", style: "cursor:default" }, h("div", { class: "numero-rotulo" }, "Strings usadas"), h("div", { class: "numero-valor" }, y.strings_usadas?.length ?? 0), h("div", { class: "numero-det" }, `casa com ${y.minimo_para_casar} delas`)),
      h("div", { class: "numero", style: "cursor:default" }, h("div", { class: "numero-rotulo" }, "Falsos positivos"), h("div", { class: "numero-valor" }, y.falsos_positivos?.length ?? 0), h("div", { class: "numero-det" }, "em binários benignos testados")),
    ),
    (y.avisos || []).map((a) => h("div", { style: "margin-bottom:12px" }, nota("aviso", a))),
    blocoRevisaoYara(r),
    h("div", { class: "painel mt-16" },
      h("div", { class: "painel-cab" }, h("span", { class: "mono" }, y.nome + ".yar"),
        h("div", { class: "painel-acoes" },
          h("button", { class: "btn btn-pequeno", onclick: () => copiar(y.texto, "Regra copiada") }, icone("copiar"), "Copiar"),
          h("button", { class: "btn btn-pequeno", onclick: salvarYara }, icone("baixar"), "Salvar .yar"))),
      realcarYara(y.texto)),
  );
};

// ------------------------------------------------------------
// Revisao da regra por IA
// ------------------------------------------------------------

const NOME_RISCO = { alto: "Alto", medio: "Médio", baixo: "Baixo" };
const CLASSE_RISCO = { alto: "alta", medio: "media", baixo: "baixa" };

function seloRisco(risco) {
  return h("span", { class: `selo ${CLASSE_RISCO[risco] || "baixa"}` }, NOME_RISCO[risco] || risco);
}

function origemEtiqueta(calculado) {
  return h("span", { class: `etiqueta ${calculado ? "" : "acento"}`, title: calculado ? "Calculado pela ferramenta, sem modelo" : "Escrito pelo modelo local" },
    calculado ? "calculado" : "IA");
}

function revisarYara() {
  const r = estado.resultado;
  estado.revisaoYara = { sha: r.sha256, carregando: true, mensagem: "", dados: null, erro: "" };
  renderizar();
  ponte.revisarYara(estado.opcoes.modelo_ia || estado.ambiente?.modelo_padrao || "");
}

tarefas.revisao_yara = (t) => {
  const rv = estado.revisaoYara;
  if (!rv) return;
  rv.carregando = false;
  if (t.ok) rv.dados = t.dados;
  else rv.erro = t.erro || "a revisão falhou";
  if (estado.vista === "yara") renderizar();
};

function blocoRevisaoYara(r) {
  const rv = estado.revisaoYara?.sha === r.sha256 ? estado.revisaoYara : null;
  const d = estado.ollama;
  const iaPronta = d?.estado === "pronto";

  if (!rv || (!rv.dados && !rv.carregando)) {
    return h("div", { class: "painel" },
      h("div", { class: "painel-cab" }, icone("faisca"), h("span", { class: "painel-titulo" }, "Revisão da regra")),
      h("div", { class: "painel-corpo pilha" },
        h("p", { class: "t2", style: "margin:0" },
          "Explica o que cada string é, o que a condição exige e onde a regra é fraca. A condição e as fraquezas são calculadas pela ferramenta; a explicação das strings vem do modelo local e é conferida."),
        rv?.erro && nota("perigo", rv.erro),
        h("div", { class: "linha" },
          h("button", { class: "btn btn-primario btn-pequeno", onclick: revisarYara }, icone("faisca"), "Revisar regra"),
          h("span", { class: `status-servico ${iaPronta ? "ok" : "falha"}` },
            iaPronta ? `com ${estado.opcoes.modelo_ia} (Ollama ${d.versao})` : "sem IA: o Ollama não está pronto. A parte calculada funciona mesmo assim."))));
  }

  if (rv.carregando) {
    return h("div", { class: "painel" },
      h("div", { class: "painel-cab" }, icone("faisca"), h("span", { class: "painel-titulo" }, "Revisão da regra")),
      h("div", { class: "painel-corpo" },
        h("div", { class: "etapa rodando", style: "border:0;padding:0" },
          h("div", { class: "etapa-marca" }),
          h("div", {}, h("div", { class: "etapa-nome" }, "Revisando a regra…"),
            h("div", { class: "etapa-msg", id: "revisao-andamento" }, rv.mensagem || "carregando o modelo")),
          h("span"))));
  }

  const v = rv.dados;
  const selo = !v.gerado
    ? h("span", { class: "etiqueta" }, "sem IA")
    : v.confiavel
      ? h("span", { class: "etiqueta ok" }, "Conferida: nada inventado")
      : h("span", { class: "etiqueta alta" }, `${v.problemas.length} problema${v.problemas.length > 1 ? "s" : ""} na saída da IA`);

  const linhas = v.comentarios.map((c) => h("tr", {},
    h("td", { class: "mono estreita" }, c.id),
    h("td", { class: "quebra", style: "max-width:260px" },
      h("span", { class: "mono" }, c.valor.length > 90 ? c.valor.slice(0, 90) + "…" : c.valor),
      c.suspeita_de_injecao && h("div", { style: "margin-top:4px" }, h("span", { class: "etiqueta alta" }, "possível prompt injection"))),
    h("td", {}, c.o_que_e || h("span", { class: "t3" }, v.gerado ? "sem comentário da IA" : "—"),
      c.fatos?.length > 0 && h("div", { class: "t3", style: "font-size:11.5px;margin-top:4px;line-height:1.5" }, c.fatos.map((f) => h("div", {}, "· " + f)))),
    h("td", { class: "estreita" }, seloRisco(c.risco_calculado),
      c.divergencia && h("div", { class: "t3", style: "font-size:11.5px;margin-top:3px", title: c.motivo_ia || "" },
        `IA disse ${(NOME_RISCO[c.risco_ia] || c.risco_ia).toLowerCase()} (${c.divergencia})`)),
  ));

  const fraquezas = [
    ...v.fraquezas_calculadas.map((f) => [f, true]),
    ...v.pontos_fracos.map((f) => [f, false]),
  ];

  return h("div", { class: "painel" },
    h("div", { class: "painel-cab" },
      icone("faisca"), h("span", { class: "painel-titulo" }, "Revisão da regra"), selo,
      h("div", { class: "painel-acoes" },
        v.gerado && h("span", { class: "t3", style: "font-size:12px;align-self:center" }, `${v.modelo} · ${fmtDuracao(v.duracao_segundos)}`),
        h("button", { class: "btn btn-pequeno", onclick: revisarYara }, icone("recarregar"), "Revisar de novo"))),
    h("div", { class: "painel-corpo pilha" },
      !v.gerado && v.erro && nota("aviso", h("strong", {}, "A parte da IA não rodou. "), v.erro, " O que aparece abaixo foi calculado pela ferramenta."),
      v.problemas.length > 0 && nota("perigo", h("strong", {}, "A conferência encontrou problemas na saída da IA:"),
        h("ul", { style: "margin:6px 0 0;padding-left:18px" }, v.problemas.map((p) => h("li", {}, p)))),
      h("div", {},
        h("div", { class: "linha", style: "margin-bottom:4px" }, h("strong", {}, "O que a regra exige"), origemEtiqueta(true)),
        h("div", { class: "t2" }, v.condicao_explicada)),
      v.resumo && h("div", {},
        h("div", { class: "linha", style: "margin-bottom:4px" }, h("strong", {}, "Leitura"), origemEtiqueta(false)),
        h("p", { class: "texto-ia", style: "margin:0" }, v.resumo)),
      fraquezas.length > 0 && h("div", {},
        h("div", { style: "margin-bottom:6px" }, h("strong", {}, "Pontos fracos")),
        h("div", { class: "pilha", style: "gap:6px" }, fraquezas.map(([texto, calc]) =>
          h("div", { class: "linha", style: "align-items:flex-start;gap:10px" }, origemEtiqueta(calc), h("span", { class: "t2" }, texto))))),
      v.sugestoes.length > 0 && h("div", {},
        h("div", { class: "linha", style: "margin-bottom:6px" }, h("strong", {}, "Sugestões"), origemEtiqueta(false)),
        h("ul", { style: "margin:0;padding-left:18px", class: "t2" }, v.sugestoes.map((s) => h("li", {}, s))))),
    h("div", { class: "tabela-wrap", style: "border-top:1px solid var(--border)" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "String"), h("th", {}, "Valor"), h("th", {}, "O que é"), h("th", {}, "Falso positivo"))),
      h("tbody", {}, linhas))),
    h("div", { class: "painel-rodape t3", style: "font-size:12px" },
      "A condição, os fatos de cada string e o risco de falso positivo são calculados pela ferramenta, não pelo modelo. O texto da IA é apoio: foi conferido quanto a identificadores, contagens e cobertura, mas o julgamento é seu."));
}

// ============================================================
// Vista: enriquecimento
// ============================================================

VISTAS.enriquecimento = () => {
  const r = estado.resultado;
  if (!r.opcoes?.enriquecer) {
    return pagina(cabecalho("Enriquecimento"), vazio("globo", "Consulta externa não executada",
      "Nenhum dado deste artefato saiu da máquina. Para cruzar com VirusTotal, Shodan, NVD e MalwareBazaar, ligue “Consultar fontes externas” na próxima análise."));
  }
  const partes = [];

  if (r.virustotal?.length) {
    partes.push(h("div", { class: "secao-titulo" }, "VirusTotal"), h("div", { class: "painel" }, h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "Indicador"), h("th", {}, "Tipo"), h("th", {}, "Detecção"), h("th", {}, "Família sugerida"))),
      h("tbody", {}, r.virustotal.map((v) => h("tr", {},
        h("td", { class: "quebra" }, valorCopiavel(v.indicador)),
        h("td", { class: "estreita" }, h("span", { class: "etiqueta" }, v.tipo)),
        h("td", { class: "estreita" }, v.erro ? h("span", { class: "t3" }, v.erro) : !v.encontrado ? h("span", { class: "t3" }, "não encontrado") :
          h("span", { class: `selo ${v.maliciosos >= 5 ? "alta" : v.maliciosos > 0 ? "media" : "baixa"}` }, `${v.maliciosos}/${v.total_de_motores}`)),
        h("td", {}, v.familia_sugerida || h("span", { class: "t3" }, "—")),
      )))))));
  }

  if (r.shodan?.length) {
    partes.push(h("div", { class: "secao-titulo mt-24" }, "Shodan"), h("div", { class: "painel" }, h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "IP"), h("th", {}, "Portas"), h("th", {}, "Organização"), h("th", {}, "País"), h("th", {}, "CVEs"))),
      h("tbody", {}, r.shodan.map((s) => h("tr", {},
        h("td", { class: "mono" }, s.ip),
        h("td", { class: "mono t2" }, s.erro ? s.erro : !s.encontrado ? "não encontrado" : (s.portas || []).join(", ") || "—"),
        h("td", {}, s.organizacao || "—"),
        h("td", {}, s.pais || "—"),
        h("td", {}, (s.vulnerabilidades || []).length ? h("div", { class: "etiquetas" }, s.vulnerabilidades.slice(0, 6).map((c) => h("span", { class: "etiqueta mono" }, c))) : "—"),
      )))))));
  }

  if (r.nvd?.length) {
    partes.push(h("div", { class: "secao-titulo mt-24" }, "NVD", h("span", { class: "t3" }, "vulnerabilidades citadas pelo artefato")),
      h("div", { class: "painel" }, h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
        h("thead", {}, h("tr", {}, h("th", {}, "CVE"), h("th", {}, "Score"), h("th", {}, "Publicada"), h("th", {}, "Descrição"))),
        h("tbody", {}, r.nvd.map((n) => h("tr", {},
          h("td", { class: "mono estreita" }, n.cve),
          h("td", { class: "estreita" }, n.encontrado ? h("span", { class: `etiqueta ${n.score_base >= 7 ? "alta" : n.score_base >= 4 ? "media" : ""}` }, fmtNum(n.score_base, 1)) : h("span", { class: "t3" }, n.erro || "não encontrada")),
          h("td", { class: "estreita t2" }, n.publicada_em ? fmtData(n.publicada_em).slice(0, 10) : "—"),
          h("td", { class: "t2" }, n.descricao ? (n.descricao.length > 180 ? n.descricao.slice(0, 180) + "…" : n.descricao) : "—"),
        )))))),
      h("div", { class: "mt-16" }, nota("info", h("strong", {}, "O artefato apenas referencia estas vulnerabilidades. "),
        "Se ele as explora, e com que sucesso, a análise estática não determina: o score descreve a falha, não este arquivo.")));
  }

  const mb = r.malwarebazaar;
  if (mb) {
    partes.push(h("div", { class: "secao-titulo mt-24" }, "MalwareBazaar"), h("div", { class: "painel" }, h("div", { class: "painel-corpo" },
      mb.encontrado ? h("dl", { class: "defs" },
        h("dt", {}, "Família"), h("dd", {}, mb.familia || "—"),
        h("dt", {}, "Tags"), h("dd", {}, mb.tags?.length ? h("div", { class: "etiquetas" }, mb.tags.map((t) => h("span", { class: "etiqueta" }, t))) : "—"),
        h("dt", {}, "Entrega"), h("dd", {}, mb.metodo_de_entrega || "—"),
        h("dt", {}, "Visto pela 1ª vez"), h("dd", {}, mb.primeira_vez_visto || "—"),
        h("dt", {}, "YARA da comunidade"), h("dd", {}, mb.regras_yara?.length ? mb.regras_yara.join(", ") : "—"))
        : h("span", { class: "t3" }, mb.erro || "Hash não encontrado no MalwareBazaar."))));
  }

  const cvss = blocoCvss(r);
  if (cvss) partes.push(h("div", { class: "secao-titulo mt-24" }, "CVSS"), cvss);

  return pagina(
    cabecalho("Enriquecimento", "O que as fontes externas sabem sobre os indicadores deste arquivo."),
    partes.length ? partes : vazio("globo", "Nenhuma fonte respondeu", "Verifique as chaves em Configuração. A NVD só é consultada quando o arquivo cita uma CVE."),
  );
};

// ============================================================
// Vista: resumo por IA
// ============================================================

VISTAS.ia = () => {
  const r = estado.resultado;
  if (!r.opcoes?.resumo_ia) {
    return pagina(cabecalho("Resumo por IA"), vazio("faisca", "Resumo não solicitado", "Ligue “Resumo por IA local” na próxima análise. Roda no Ollama, na sua máquina: nada sai dela."));
  }
  return pagina(
    cabecalho("Resumo por IA", "Texto de apoio escrito por modelo local. As seções de evidência são a fonte; este texto é conferido contra elas."),
    blocoIA(r, false) || nota("aviso", "O resumo não foi gerado."),
  );
};

// ============================================================
// Vista: avisos
// ============================================================

VISTAS.avisos = () => {
  const r = estado.resultado;
  return pagina(
    cabecalho("Avisos e limites", "O que falhou, o que foi pulado e o que esta análise não cobre. Ausência de evidência não é evidência de ausência."),
    r.erros?.length > 0 && [
      h("div", { class: "secao-titulo" }, "Etapas que falharam"),
      h("div", { class: "painel" }, h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
        h("tbody", {}, r.erros.map((e) => h("tr", {},
          h("td", { class: "estreita" }, h("span", { class: "selo alta" }, e.estagio)),
          h("td", { class: "mono t2 quebra" }, e.mensagem))))))),
    ],
    h("div", { class: "secao-titulo mt-24" }, "Avisos da análise", h("span", { class: "t3" }, String(r.avisos?.length || 0))),
    r.avisos?.length
      ? h("div", { class: "painel" }, h("ul", { class: "lista-compacta" }, r.avisos.map((a) => h("li", { style: "display:block;color:var(--text-2)" }, a))))
      : h("div", { class: "painel" }, h("div", { class: "painel-vazio" }, "Nenhum aviso.")),
  );
};

// ============================================================
// Vista: MalwareBazaar
// ============================================================

VISTAS.bazaar = () => {
  const b = estado.bazaar;
  const temChave = estado.ambiente?.chaves?.malwarebazaar;
  const entrada = h("input", { class: "campo mono", placeholder: "SHA256, SHA1 ou MD5", value: b.hash, spellcheck: "false" });
  entrada.addEventListener("input", () => { b.hash = entrada.value; });
  entrada.addEventListener("keydown", (e) => { if (e.key === "Enter") consultarBazaar(); });

  const c = b.consulta;
  let resultado = null;
  if (b.erro) resultado = h("div", { class: "mt-16" }, nota("perigo", b.erro));
  else if (c && !c.encontrado) resultado = h("div", { class: "mt-16" }, nota("info", h("strong", {}, "Não encontrado. "), c.observacoes?.join(" ") || "O MalwareBazaar não tem este hash."));
  else if (c) {
    resultado = h("div", { class: "painel mt-16" },
      h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, c.familia || "Família não identificada"), c.tipo && h("span", { class: "etiqueta" }, c.tipo)),
      h("div", { class: "painel-corpo" }, h("dl", { class: "defs" },
        h("dt", {}, "SHA256"), h("dd", {}, valorCopiavel(c.sha256)),
        h("dt", {}, "Arquivo"), h("dd", {}, `${c.nome_do_arquivo || "—"} · ${fmtBytes(c.tamanho_bytes || 0)}`),
        h("dt", {}, "Tags"), h("dd", {}, c.tags?.length ? h("div", { class: "etiquetas" }, c.tags.map((t) => h("span", { class: "etiqueta" }, t))) : "—"),
        h("dt", {}, "Entrega"), h("dd", {}, c.metodo_de_entrega || "—"),
        h("dt", {}, "Visto pela 1ª vez"), h("dd", {}, `${c.primeira_vez_visto || "—"}${c.reportado_por ? " · por " + c.reportado_por : ""}`),
        h("dt", {}, "YARA da comunidade"), h("dd", {}, c.regras_yara?.length ? h("div", { class: "etiquetas" }, c.regras_yara.slice(0, 12).map((y) => h("span", { class: "etiqueta mono" }, y))) : "—"),
      )),
      h("div", { class: "painel-rodape linha" },
        h("span", { class: "t3", style: "font-size:12px" }, "Traz malware para esta máquina. Só em ambiente isolado."),
        h("button", { class: "btn btn-perigo", style: "margin-left:auto", disabled: b.baixando, onclick: baixarAmostra }, icone("baixar"), b.baixando ? "Baixando…" : "Baixar amostra (ZIP cifrado)")),
    );
  }

  const baixada = b.baixada && h("div", { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, icone("caixa"), h("span", { class: "painel-titulo" }, "Amostra baixada, ainda cifrada")),
    h("div", { class: "painel-corpo pilha" },
      h("dl", { class: "defs" },
        h("dt", {}, "Arquivo"), h("dd", {}, h("span", { class: "mono" }, b.baixada.caminho)),
        h("dt", {}, "Senha do ZIP"), h("dd", {}, valorCopiavel(b.baixada.senha))),
      h("p", { class: "t2", style: "margin:0" }, "Zipado, o arquivo é inerte. Extrair grava o malware vivo em disco, sem extensão, e o seleciona para análise.")),
    h("div", { class: "painel-rodape linha" },
      h("button", { class: "btn", onclick: () => chamar("abrirArquivo", b.baixada.caminho.replace(/[\\/][^\\/]*$/, "")) }, icone("pasta"), "Abrir pasta"),
      h("button", { class: "btn btn-perigo", style: "margin-left:auto", onclick: extrairAmostra }, "Extrair e analisar…")));

  return h(
    "div",
    { class: "pagina estreita" },
    cabecalho("MalwareBazaar", "Consulta por hash no MalwareBazaar (abuse.ch): família, tags, método de entrega e regras YARA da comunidade. A consulta envia só o hash."),
    !temChave && h("div", { style: "margin-bottom:16px" }, nota("aviso", h("strong", {}, "Auth-Key não configurada. "),
      "Adicione MALWAREBAZAAR_API_KEY em config/.env. A chave é gratuita, em auth.abuse.ch, e vale para todos os serviços do abuse.ch.")),
    h("div", { class: "linha" }, entrada,
      h("button", { class: "btn btn-primario", disabled: b.carregando || !temChave, onclick: consultarBazaar }, b.carregando ? "Consultando…" : "Consultar")),
    resultado,
    baixada,
  );
};

function consultarBazaar() {
  const b = estado.bazaar;
  if (!b.hash.trim()) return;
  Object.assign(b, { carregando: true, erro: "", consulta: null, baixada: null });
  renderizar();
  ponte.bazaarConsultar(b.hash.trim());
}

tarefas.bazaar = (t) => {
  const b = estado.bazaar;
  b.carregando = false;
  if (t.ok) { b.consulta = t.dados; if (t.dados.sha256) b.hash = t.dados.sha256; }
  else b.erro = t.erro;
  if (estado.vista === "bazaar") renderizar();
};

async function baixarAmostra() {
  const b = estado.bazaar;
  const sha = b.consulta?.sha256;
  if (!sha) return;
  const ok = await confirmar({
    titulo: "Baixar amostra de malware?",
    tipo: "perigo",
    perigo: true,
    paragrafos: [
      `Você vai baixar ${b.consulta.familia || "esta amostra"} do MalwareBazaar.`,
      "Ela será gravada como ZIP cifrado, sem descompactar. Em repouso, é inerte.",
      "Ainda assim, isto traz malware para esta máquina. Faça apenas em ambiente isolado, com snapshot.",
    ],
    botao: "Baixar",
  });
  if (!ok) return;
  b.baixando = true;
  renderizar();
  ponte.bazaarBaixar(sha);
}

tarefas.baixar = (t) => {
  const b = estado.bazaar;
  b.baixando = false;
  if (t.ok) { b.baixada = t.dados; avisar("ok", "Amostra baixada (cifrada)", t.dados.caminho); }
  else if (!t.cancelado) avisar("erro", "Download falhou", t.erro || "");
  if (estado.vista === "bazaar") renderizar();
};

async function extrairAmostra() {
  const b = estado.bazaar;
  const ok = await confirmar({
    titulo: "Extrair o malware?",
    tipo: "perigo",
    perigo: true,
    paragrafos: [
      "Extrair grava o malware vivo em disco. É a única ação da ferramenta com esse efeito.",
      "O arquivo sai sem extensão, para não abrir com duplo clique, mas continua sendo malware. O Windows ainda vai pedir uma última confirmação.",
    ],
    botao: "Continuar",
  });
  if (!ok) return;
  const r = await chamar("bazaarExtrair", b.baixada.sha256);
  if (r?.ok) {
    b.baixada = null;
    avisar("ok", r.hash_confere ? "Extraída, SHA256 conferido" : "Extraída, mas o SHA256 NÃO confere", r.caminho);
    ir("nova");
  } else if (!r?.cancelado) avisar("erro", "Falha ao extrair", r?.erro || "");
}

// ============================================================
// Vista: configuracao
// ============================================================

VISTAS.config = () => {
  const amb = estado.ambiente;
  if (!amb) return pagina(null, vazio("engrenagem", "Carregando…", ""));
  const d = estado.ollama;
  const linhaStatus = (rotulo, ok, textoOk, textoFalha) => h("div", { class: "opcao" },
    h("div", { class: "opcao-texto" }, h("div", { class: "opcao-nome" }, rotulo)),
    h("span", { class: `status-servico ${ok ? "ok" : "falha"}` }, ok ? textoOk : textoFalha));

  let ollamaStatus;
  if (estado.verificandoOllama || !d) ollamaStatus = h("span", { class: "status-servico verificando" }, "Verificando…");
  else if (d.estado === "pronto") ollamaStatus = h("span", { class: "status-servico ok" }, `Versão ${d.versao} · pronto`);
  else ollamaStatus = h("span", { class: "status-servico falha" }, { nao_instalado: "Não instalado", parado: "Instalado, mas fechado", sem_modelo: "Sem o modelo" }[d.estado]);

  return h(
    "div",
    { class: "pagina estreita" },
    cabecalho("Configuração", "Estado do ambiente. As chaves ficam em config/.env, que o Git ignora: elas nunca aparecem aqui nem vão para o repositório."),
    h("div", { class: "secao-titulo" }, "Chaves de API"),
    h("div", { class: "opcoes" },
      linhaStatus("VirusTotal", amb.chaves.virustotal, "Configurada", "Não configurada"),
      linhaStatus("Shodan", amb.chaves.shodan, "Configurada", "Não configurada"),
      linhaStatus("MalwareBazaar", amb.chaves.malwarebazaar, "Configurada", "Não configurada"),
      linhaStatus("Consultas externas no .env", amb.enriquecimento_habilitado, "Habilitadas", "Desabilitadas (ENABLE_ENRICHMENT)")),
    // Sem .env mas com chave: ela veio de variavel de ambiente (CI, shell).
    // Mandar "copie o .env.example" nesse caso seria orientacao errada.
    !amb.env_encontrado && h("div", { class: "mt-16" },
      Object.values(amb.chaves).some(Boolean)
        ? nota("info", h("strong", {}, "config/.env não encontrado. "), "As chaves configuradas vieram de variáveis de ambiente.")
        : nota("aviso", h("strong", {}, "config/.env não encontrado. "), "Copie config/.env.example para config/.env e preencha as chaves que tiver.")),

    h("div", { class: "secao-titulo mt-24" }, "IA local"),
    h("div", { class: "opcoes" },
      h("div", { class: "opcao" },
        h("div", { class: "opcao-texto" },
          h("div", { class: "opcao-nome" }, "Ollama"),
          h("div", { class: "opcao-desc" }, d?.estado === "pronto" ? `Modelos: ${d.modelos.join(", ")}` : d ? orientacaoOllama(d) : "Roda os modelos localmente. Nada sai da máquina."),
          h("div", { class: "opcao-extra" },
            h("button", { class: "btn btn-pequeno", disabled: estado.verificandoOllama, onclick: () => verificarOllama() }, icone("recarregar"), "Verificar"),
            d?.estado === "nao_instalado" && linkExterno("https://ollama.com/download", "Baixar o Ollama"))),
        ollamaStatus)),

    h("div", { class: "secao-titulo mt-24" }, "MITRE ATT&CK"),
    h("div", { class: "opcoes" },
      h("div", { class: "opcao" },
        h("div", { class: "opcao-texto" },
          h("div", { class: "opcao-nome" }, "Bundle STIX oficial"),
          h("div", { class: "opcao-desc" }, amb.attack.em_cache ? `Em cache local (${fmtNum(amb.attack.tamanho_mb, 1)} MB).` : "Não baixado. Necessário para a atribuição de grupos. O download tem cerca de 50 MB."),
          h("div", { class: "opcao-extra" },
            h("button", { class: "btn btn-pequeno", disabled: estado.attackAtualizando, onclick: atualizarAttack }, icone("baixar"),
              estado.attackAtualizando ? "Baixando…" : amb.attack.em_cache ? "Atualizar" : "Baixar"))),
        h("span", { class: `status-servico ${amb.attack.em_cache ? "ok" : "falha"}` }, amb.attack.em_cache ? "Disponível" : "Ausente"))),

    h("p", { class: "t3 mt-24", style: "font-size:12px" }, "Nut-Shell Mapper · análise estática de artefatos e threat intelligence. O arquivo analisado é lido, nunca executado."),
  );
};

function atualizarAttack() {
  estado.attackAtualizando = true;
  renderizar();
  ponte.atualizarAttack();
}

tarefas.attack = async (t) => {
  estado.attackAtualizando = false;
  if (t.ok) avisar("ok", "ATT&CK atualizado", `Versão ${t.dados.versao} · ${fmtNum(t.dados.objetos)} objetos`);
  else avisar("erro", "Falha ao baixar o ATT&CK", t.erro || "");
  estado.ambiente = await chamar("estado");
  renderizar();
};

// ============================================================
// Exportacao
// ============================================================

async function exportarRelatorio(formato) {
  const r = await chamar("exportarRelatorio", formato);
  if (r?.cancelado) return;
  if (!r?.ok) return avisar("erro", "Relatório não exportado", r?.erro || "");
  avisar("ok", "Relatório salvo", r.caminho, { rotulo: "Abrir", fazer: () => chamar("abrirArquivo", r.caminho) });
}

async function exportarIndicadores(corte) {
  const r = await chamar("exportarIndicadores", corte);
  if (r?.cancelado) return;
  if (!r?.ok) return avisar("erro", "Indicadores não exportados", r?.erro || "");
  const f = r.formatos;
  const resumo = Object.entries(f).map(([k, v]) => `${k.toUpperCase()} ${v.exportados}`).join(" · ");
  avisar("ok", `Indicadores exportados: ${resumo}`, r.pasta, { rotulo: "Abrir pasta", fazer: () => chamar("abrirArquivo", r.pasta) });
}

async function salvarYara() {
  const y = estado.resultado?.regra_yara;
  if (!y) return;
  if (!y.valida) {
    const ok = await confirmar({
      titulo: "Salvar uma regra inválida?",
      paragrafos: ["Esta regra não compila ou não casa com a própria amostra.", ...(y.avisos || []), "Salvar mesmo assim, para inspeção?"],
      botao: "Salvar mesmo assim",
    });
    if (!ok) return;
  }
  const r = await chamar("salvarYara");
  if (r?.cancelado) return;
  if (!r?.ok) return avisar("erro", "Regra não salva", r?.erro || "");
  avisar("ok", "Regra salva", r.caminho, { rotulo: "Abrir", fazer: () => chamar("abrirArquivo", r.caminho) });
}

// ============================================================
// E-mail
// ============================================================
//
// Tudo que aparece aqui veio do e-mail do atacante: assunto, nomes,
// enderecos, links. Nenhum link vira <a>: o destino e mostrado ja
// "defangado" (hxxps://golpe[.]com) e so pode ser copiado.

const GRAVIDADE = { alta: "Alta", media: "Média", baixa: "Baixa" };
const ORDEM_GRAVIDADE = { alta: 0, media: 1, baixa: 2 };

function defang(valor) {
  return String(valor || "").replace(/^http/i, "hxxp").replaceAll(".", "[.]").replaceAll("@", "[@]");
}

function classeDoResultado(valor) {
  if (!valor) return "";
  if (valor === "pass") return "ok";
  if (["fail", "softfail"].includes(valor)) return "alta";
  return "media";
}

function classeDoVeredito(pontos) {
  if (pontos >= 60) return "alta";
  if (pontos >= 30) return "media";
  return "baixa";
}

function linkTecnica(id) {
  return linkExterno(`https://attack.mitre.org/techniques/${id.replace(".", "/")}/`, id);
}

VISTAS.email = () => {
  const e = estado.email;
  const d = e.dados;

  const escolher = h(
    "div",
    { class: "painel" },
    h(
      "div",
      { class: "painel-corpo linha" },
      icone("carta"),
      h("div", { style: "min-width:0;flex:1" },
        h("div", { class: "email-arquivo" }, e.arquivo ? e.arquivo.nome : "Nenhum e-mail selecionado"),
        h("div", { class: "t3", style: "font-size:12px" }, e.arquivo ? "Pronto para analisar" : "Arraste um arquivo .eml para a janela ou escolha abaixo.")),
      h("button", { class: "btn", onclick: () => ponte.escolherEmail() }, icone("pasta"), "Escolher .eml"),
      h("button", { class: "btn btn-primario", disabled: !e.arquivo || e.carregando, onclick: analisarEmail },
        icone(e.carregando ? "recarregar" : "play"), e.carregando ? "Analisando…" : "Analisar"),
    ),
    h(
      "div",
      { class: "painel-rodape linha" },
      interruptor(e.online, (v) => { e.online = v; }, e.carregando, "Consultar domínios na internet"),
      h("div", {},
        h("div", { style: "font-weight:600" }, "Consultar domínios na internet"),
        h("div", { class: "t3", style: "font-size:12px" }, "DNS, idade e registrador dos domínios do e-mail. Só o nome do domínio sai daqui; nenhum link é acessado.")),
    ),
  );

  let corpo = null;
  if (e.carregando) corpo = h("div", { class: "mt-16" }, nota("info", e.mensagem || "Lendo cabeçalhos, corpo e anexos…"));
  else if (e.erro) corpo = h("div", { class: "mt-16" }, nota("perigo", h("strong", {}, "Não foi possível analisar. "), e.erro));
  else if (d) corpo = resultadoDoEmail(d);

  return h(
    "div",
    { class: "pagina" },
    cabecalho("Análise de e-mail", "Cabeçalhos, caminho entre servidores, SPF/DKIM/DMARC, remetente falso, links e anexos. Nada é aberto: nenhum link é visitado, nenhuma imagem remota é carregada e nenhum anexo é executado."),
    escolher,
    corpo,
  );
};

function resultadoDoEmail(d) {
  const de = d.identidades.find((i) => i.campo === "From" && i.endereco.includes("@")) || d.identidades.find((i) => i.campo === "From");
  const outros = d.identidades.filter((i) => i !== de && i.campo !== "Message-ID");
  const sinais = [...d.sinais].sort((a, b) => ORDEM_GRAVIDADE[a.gravidade] - ORDEM_GRAVIDADE[b.gravidade]);
  const classe = classeDoVeredito(d.pontuacao);
  const aut = d.autenticacao;

  const veredito = h(
    "div",
    { class: `painel email-veredito ${classe}` },
    h("div", { class: "painel-corpo" },
      h("div", { class: "email-veredito-linha" },
        h("div", { style: "min-width:0;flex:1" },
          h("div", { class: "email-veredito-titulo" }, d.veredito),
          h("div", { class: "email-assunto" }, d.assunto || "(sem assunto)"),
          de && h("div", { class: "email-de" }, de.nome ? `${de.nome} ` : "", h("span", { class: "mono" }, `<${de.endereco}>`)),
        ),
        h("div", { class: "email-pontos" }, h("span", { class: "num" }, d.pontuacao), h("span", { class: "t3" }, "/100")),
      ),
      medida(d.pontuacao / 100, classe, " "),
      h("div", { class: "email-autenticacao" },
        ["spf", "dkim", "dmarc"].map((m) => h("span", { class: `etiqueta ${classeDoResultado(aut[m])}` }, `${m.toUpperCase()} ${aut[m] || "?"}`)),
        d.tecnicas.map((t) => h("span", { class: "etiqueta acento mono", title: t.nome }, t.id)),
      ),
    ),
  );

  const painelSinais = h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, `Por que (${sinais.length})`)),
    sinais.length
      ? h("div", { class: "email-sinais" }, sinais.map((s) =>
          h("div", { class: "email-sinal" },
            selo(s.gravidade),
            h("div", { style: "min-width:0;flex:1" },
              h("div", { class: "email-sinal-titulo" }, s.titulo),
              h("div", { class: "t2", style: "font-size:12.5px" }, s.detalhe)),
            s.tecnica && linkTecnica(s.tecnica))))
      : h("div", { class: "painel-corpo t2" }, "Nenhum sinal de phishing nos cabeçalhos, no corpo ou nos anexos."),
  );

  const identidades = h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Quem enviou, de verdade")),
    h("div", { class: "painel-corpo" }, h("dl", { class: "defs" },
      [de, ...outros].filter(Boolean).map((i) => [
        h("dt", {}, i.campo),
        h("dd", {}, i.nome && h("span", {}, `${i.nome} `), valorCopiavel(i.endereco)),
      ]),
      d.origem && [h("dt", {}, "Servidor de origem"), h("dd", {}, valorCopiavel(d.origem.ip), " ", h("span", { class: "t3" }, d.origem.de_reverso || d.origem.de || ""))],
      aut.dominio_envelope && [h("dt", {}, "Envelope (SMTP)"), h("dd", {}, h("span", { class: "mono" }, aut.dominio_envelope))],
    )),
  );

  const caminho = !d.saltos.length ? null : h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Caminho da mensagem"), h("span", { class: "t3", style: "font-size:12px" }, "do remetente até a sua caixa")),
    h("ol", { class: "email-saltos" }, d.saltos.map((s) => {
      const origem = d.origem && s.ordem === d.origem.ordem;
      return h("li", { class: `email-salto${origem ? " origem" : ""}` },
        h("div", { class: "email-salto-ponto" }),
        h("div", { style: "min-width:0;flex:1" },
          h("div", { class: "email-salto-host" }, h("span", { class: "mono" }, s.de || "?"), s.ip && h("span", { class: "etiqueta mono" }, s.ip), origem && h("span", { class: "etiqueta alta" }, "origem")),
          h("div", { class: "t3", style: "font-size:12px" }, `→ ${s.por || "?"}`, s.protocolo ? ` · ${s.protocolo}` : "", s.quando ? ` · ${fmtData(s.quando)}` : "", s.atraso_segundos ? ` · +${Math.round(s.atraso_segundos)} s` : "")));
    })),
  );

  const links = !d.links.length ? null : h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, `Links (${d.links.length})`), h("span", { class: "t3", style: "font-size:12px" }, "nenhum foi acessado")),
    h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "Tipo"), h("th", {}, "Destino"), h("th", {}, "Texto exibido"))),
      h("tbody", {}, d.links.map((l) => h("tr", {},
        h("td", { class: "estreita" }, h("span", { class: `etiqueta ${l.observacoes.length ? "media" : ""}` }, l.tipo)),
        h("td", { class: "quebra" }, valorCopiavel(defang(l.destino)), l.observacoes.map((o) => h("div", { class: "t3", style: "font-size:12px" }, o))),
        h("td", { class: "t2" }, l.texto || "—")))))),
  );

  const anexos = !d.anexos.length ? null : h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, `Anexos (${d.anexos.length})`), h("span", { class: "t3", style: "font-size:12px" }, "nenhum foi aberto")),
    h("div", { class: "email-sinais" }, d.anexos.map((a) =>
      h("div", { class: "email-sinal" },
        icone("arquivo"),
        h("div", { style: "min-width:0;flex:1" },
          h("div", { class: "email-sinal-titulo" }, a.nome, " ", h("span", { class: "t3" }, `${fmtBytes(a.tamanho)} · ${a.tipo_real}`)),
          valorCopiavel(a.sha256),
          a.observacoes.map((o) => h("div", { class: "t2", style: "font-size:12.5px" }, o)))))),
  );

  const iocs = h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, `Indicadores (${d.iocs.length})`),
      h("button", { class: "btn btn-pequeno", style: "margin-left:auto", disabled: !d.iocs.length, onclick: exportarIndicadoresEmail }, icone("baixar"), "Exportar CSV, STIX e MISP")),
    h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "Confiança"), h("th", {}, "Tipo"), h("th", {}, "Valor (sem risco de clique)"), h("th", {}, "Onde"))),
      h("tbody", {}, d.iocs.map((i) => h("tr", {},
        h("td", { class: "estreita" }, selo(i.confianca)),
        h("td", { class: "estreita t2" }, TIPO_IOC[i.tipo] || i.tipo),
        h("td", { class: "quebra" }, valorCopiavel(i.defang)),
        h("td", { class: "t3" }, i.origem)))))),
  );

  const doms = !d.dominios?.length ? null : h("div", { class: "mt-16" }, d.dominios.map((c) => painelDominio(c, true)));

  const oculto = !d.texto_oculto ? null : h(
    "details",
    { class: "painel mt-16 dobra" },
    h("summary", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Texto escondido"), h("span", { class: "t3", style: "font-size:12px" }, `${fmtNum(d.texto_oculto.length)} caracteres que o leitor não vê`)),
    h("div", { class: "painel-corpo mono email-texto" }, d.texto_oculto.slice(0, 4000)),
  );

  const cabecalhos = h(
    "details",
    { class: "painel mt-16 dobra" },
    h("summary", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, `Todos os cabeçalhos (${d.cabecalhos.length})`)),
    h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("tbody", {}, d.cabecalhos.map(([k, v]) => h("tr", {}, h("td", { class: "estreita mono t2" }, k), h("td", { class: "quebra mono" }, v)))))),
  );

  return h("div", { class: "mt-16" },
    d.avisos?.length ? nota("aviso", d.avisos.join(" ")) : null,
    veredito, acoesDoEmail(), blocoIAEmail(), painelSinais, blocoDiamante(d.diamante), blocoTTPs(d.diamante),
    blocoPiramide(d.piramide), blocoGrafo(d.grafo), blocoYaraEmail(), identidades, caminho, links, anexos, iocs,
    doms, oculto, cabecalhos);
}

function analisarEmail() {
  const e = estado.email;
  if (!e.arquivo) return;
  Object.assign(e, { carregando: true, erro: "", dados: null, mensagem: "", ia: null, yara: null });
  renderizar();
  ponte.analisarEmail(e.online);
}

tarefas.email = (t) => {
  const e = estado.email;
  e.carregando = false;
  if (t.ok) e.dados = t.dados;
  else e.erro = t.erro;
  renderizarNav();
  if (estado.vista === "email") renderizar();
};

async function exportarIndicadoresEmail() {
  const r = await chamar("exportarIndicadoresEmail", "media");
  if (r?.cancelado) return;
  if (!r?.ok) return avisar("erro", "Indicadores não exportados", r?.erro || "");
  avisar("ok", "Indicadores exportados", r.pasta, { rotulo: "Abrir pasta", fazer: () => chamar("abrirArquivo", r.pasta) });
}

// ============================================================
// Dominio
// ============================================================

function painelDominio(c, compacto = false) {
  const dns = ["A", "AAAA", "MX", "NS"].filter((t) => c.dns?.[t]?.length);
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" },
      icone("globo"),
      h("span", { class: "painel-titulo mono" }, c.dominio),
      c.idade_dias !== null && c.idade_dias !== undefined && h("span", { class: `etiqueta ${c.idade_dias < 180 ? "alta" : ""}` }, `${fmtNum(c.idade_dias)} dias`),
      c.imitacao && h("span", { class: "etiqueta alta" }, "imita marca")),
    h("div", { class: "painel-corpo pilha" },
      c.imitacao && nota("perigo", c.imitacao),
      c.observacoes?.length ? h("ul", { class: "dominio-obs" }, c.observacoes.map((o) => h("li", {}, o))) : null,
      h("dl", { class: "defs" },
        c.criado_em && [h("dt", {}, "Registrado em"), h("dd", {}, fmtData(c.criado_em) || c.criado_em, c.registrador ? ` · ${c.registrador}` : "")],
        dns.map((t) => [h("dt", {}, t), h("dd", {}, h("div", { class: "etiquetas" }, c.dns[t].slice(0, 8).map((v) => h("span", { class: "etiqueta mono" }, v))))]),
        h("dt", {}, "SPF"), h("dd", { class: "mono quebra" }, c.spf || "—"),
        h("dt", {}, "DMARC"), h("dd", { class: "mono quebra" }, c.dmarc || "—"),
      ),
      !compacto && c.subdominios?.length ? listaDeSubdominios(c) : null,
      c.erros?.length ? h("div", { class: "t3", style: "font-size:12px" }, c.erros.join(" · ")) : null,
    ),
  );
}

function listaDeSubdominios(c) {
  const f = estado.dominio;
  const lista = h("div", { class: "dominio-subs" });
  // Filtrar redesenha so a lista: redesenhar a tela tiraria o foco do campo.
  const preencher = () => {
    const termo = (f.filtro || "").toLowerCase();
    limpar(lista);
    anexar(lista, c.subdominios.filter((n) => !termo || n.includes(termo)).slice(0, 400).map((n) => h("span", { class: "etiqueta mono" }, n)));
  };
  preencher();
  return h("div", {},
    h("div", { class: "linha", style: "margin-bottom:8px" },
      h("strong", {}, `Subdomínios (${fmtNum(c.subdominios.length)}${c.subdominios_truncados ? "+" : ""})`),
      h("span", { class: "t3", style: "font-size:12px" }, "dos logs públicos de certificados"),
      c.subdominios.length > 12 && h("div", { style: "margin-left:auto" }, busca(f.filtro || "", "Filtrar", (v) => { f.filtro = v; preencher(); }))),
    lista,
    h("div", { class: "linha mt-16" }, h("button", { class: "btn btn-pequeno", onclick: () => copiar(c.subdominios.join("\n"), "Subdomínios copiados") }, icone("copiar"), "Copiar todos")));
}

VISTAS.dominio = () => {
  const f = estado.dominio;
  const entrada = h("input", { class: "campo mono", placeholder: "exemplo.com", value: f.valor, spellcheck: "false" });
  entrada.addEventListener("input", () => { f.valor = entrada.value; });
  entrada.addEventListener("keydown", (ev) => { if (ev.key === "Enter") consultarDominio(); });

  let corpo = null;
  if (f.carregando) corpo = h("div", { class: "mt-16" }, nota("info", "Consultando DNS, registro e certificados…"));
  else if (f.erro) corpo = h("div", { class: "mt-16" }, nota("perigo", f.erro));
  else if (f.dados) corpo = painelDominio(f.dados);

  return h(
    "div",
    { class: "pagina estreita" },
    cabecalho("Domínio", "DNS (IPs, servidor de e-mail, SPF, DMARC), idade e registrador, e subdomínios encontrados em certificados públicos. Tudo passivo: nenhuma requisição chega ao servidor do domínio."),
    h("div", { class: "linha" }, entrada,
      h("button", { class: "btn btn-primario", disabled: f.carregando, onclick: consultarDominio }, f.carregando ? "Consultando…" : "Consultar")),
    h("div", { class: "linha mt-16" },
      interruptor(f.subdominios, (v) => { f.subdominios = v; }, f.carregando, "Buscar subdomínios"),
      h("span", { class: "t2" }, "Buscar subdomínios nos logs de certificados (crt.sh, Cert Spotter)")),
    corpo,
  );
};

function consultarDominio() {
  const f = estado.dominio;
  const valor = f.valor.trim().replace(/^https?:\/\//i, "").split("/")[0];
  if (!valor) return;
  Object.assign(f, { valor, carregando: true, erro: "", dados: null, filtro: "" });
  renderizar();
  ponte.consultarDominio(valor, f.subdominios);
}

tarefas.dominio = (t) => {
  const f = estado.dominio;
  f.carregando = false;
  if (t.ok) f.dados = t.dados;
  else f.erro = t.erro;
  if (estado.vista === "dominio") renderizar();
};

// ============================================================
// CTI do e-mail: acoes, IA, Diamond Model, TTPs, piramide e grafo
// ============================================================
//
// Os desenhos sao SVG montado elemento por elemento. Nenhum rotulo vira
// markup: todo texto entra por textContent, como no resto da pagina.

const SVG_NS = "http://www.w3.org/2000/svg";

function svg(tag, atributos = {}, texto = null) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(atributos)) {
    if (v !== null && v !== undefined && v !== false) el.setAttribute(k, String(v));
  }
  if (texto !== null) el.textContent = String(texto);
  return el;
}

function curto(texto, limite) {
  texto = String(texto || "");
  return texto.length > limite ? texto.slice(0, limite - 1) + "…" : texto;
}

function acoesDoEmail() {
  const e = estado.email;
  const ia = e.ia || {};
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Produzir inteligência")),
    h(
      "div",
      { class: "painel-corpo cti-acoes" },
      h("button", { class: "btn btn-primario", disabled: ia.carregando, onclick: resumirEmailComIA },
        icone(ia.carregando ? "recarregar" : "faisca"), ia.carregando ? "Gerando resumo…" : ia.dados ? "Gerar resumo de novo" : "Resumo por IA"),
      h("button", { class: "btn", onclick: gerarYaraEmail }, icone("escudo"), "Regra YARA da campanha"),
      h("button", { class: "btn", onclick: salvarPdfEmail }, icone("arquivo"), "Relatório executivo (PDF)"),
      h("button", { class: "btn", onclick: exportarNavigatorEmail }, icone("grade"), "Layer do ATT&CK Navigator"),
    ),
  );
}

function blocoIAEmail() {
  const ia = estado.email.ia;
  if (!ia) return null;
  if (ia.carregando) {
    return h("div", { class: "mt-16" }, nota("info", h("span", { id: "ia-email-andamento" }, ia.mensagem || "Carregando o modelo na GPU…")));
  }
  if (ia.erro) return h("div", { class: "mt-16" }, nota("perigo", h("strong", {}, "Resumo não gerado. "), ia.erro));
  const d = ia.dados;
  if (!d) return null;
  if (!d.gerado) return h("div", { class: "mt-16" }, nota("aviso", h("strong", {}, "Resumo não gerado. "), d.erro || ""));
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, icone("faisca"), h("span", { class: "painel-titulo" }, "Resumo executivo"),
      h("span", { class: `etiqueta ${d.confiavel ? "ok" : "alta"}` }, d.confiavel ? "conferido: nada inventado" : `${d.invencoes.length} afirmação(ões) sem respaldo`),
      h("span", { class: "t3", style: "margin-left:auto;font-size:12px" }, `${d.modelo} · ${fmtNum(d.duracao_segundos, 0)} s`)),
    h("div", { class: "painel-corpo pilha" },
      d.texto.split("\n").filter((p) => p.trim()).map((p) => h("p", { class: "ia-paragrafo" }, p)),
      d.invencoes.map((i) => nota("perigo", h("strong", {}, `${i.tipo}: ${i.valor}. `), i.explicacao)),
      d.avisos.filter((a) => !a.includes("afirmação")).map((a) => nota("aviso", a)),
      h("div", { class: "t3", style: "font-size:12px" }, d.ressalva)),
  );
}

function blocoYaraEmail() {
  const y = estado.email.yara;
  if (!y) return null;
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, icone("escudo"), h("span", { class: "painel-titulo" }, "Regra YARA da campanha"),
      h("span", { class: `etiqueta ${y.valida ? "ok" : "alta"}` }, y.valida ? "válida" : "não validada"),
      y.texto && h("button", { class: "btn btn-pequeno", style: "margin-left:auto", onclick: () => copiar(y.texto, "Regra copiada") }, icone("copiar"), "Copiar"),
      y.texto && h("button", { class: "btn btn-pequeno", onclick: salvarYaraEmail }, icone("baixar"), "Salvar .yar")),
    h("div", { class: "painel-corpo pilha" },
      h("p", { class: "t2", style: "margin:0" }, "Pega outras mensagens da mesma campanha: só entram indicadores do atacante que aparecem literalmente no arquivo, nada da vítima. Validada contra o próprio e-mail e contra um e-mail comum."),
      y.avisos.map((a) => nota("aviso", a)),
      y.texto && realcarYara(y.texto)),
  );
}

// ---------- Diamond Model ----------

function blocoDiamante(dm) {
  if (!dm) return null;
  const L = 640, A = 372, cx = L / 2, cy = A / 2 + 14, r = 92;
  const desenho = svg("svg", { viewBox: `0 0 ${L} ${A}`, class: "diamante-svg", role: "img", "aria-label": "Diamond Model" });
  const pontos = [[cx, cy - r], [cx + r * 1.25, cy], [cx, cy + r], [cx - r * 1.25, cy]];
  desenho.appendChild(svg("polygon", { points: pontos.map((p) => p.join(",")).join(" "), class: "diamante-forma" }));
  desenho.appendChild(svg("line", { x1: cx, y1: cy - r, x2: cx, y2: cy + r, class: "diamante-eixo" }));
  desenho.appendChild(svg("line", { x1: cx - r * 1.25, y1: cy, x2: cx + r * 1.25, y2: cy, class: "diamante-eixo" }));
  desenho.appendChild(svg("text", { x: cx + 6, y: cy - 30, class: "diamante-rotulo-eixo" }, "social-político"));
  desenho.appendChild(svg("text", { x: cx - 108, y: cy - 6, class: "diamante-rotulo-eixo" }, "técnico"));

  const vertice = (v, x, y, ancora) => {
    const g = svg("g", { class: "diamante-vertice" });
    g.appendChild(svg("text", { x, y, "text-anchor": ancora, class: "diamante-nome" }, v.nome));
    v.itens.slice(0, 4).forEach((item, k) =>
      g.appendChild(svg("text", { x, y: y + 16 + k * 14, "text-anchor": ancora, class: `diamante-item${item.tipo === "tipo 1" ? " t1" : ""}` }, curto(item.valor, 36))));
    if (v.itens.length > 4) g.appendChild(svg("text", { x, y: y + 16 + 4 * 14, "text-anchor": ancora, class: "diamante-mais" }, `+ ${v.itens.length - 4}`));
    desenho.appendChild(g);
  };
  vertice(dm.adversario, cx, 18, "middle");
  vertice(dm.capacidade, cx + r * 1.25 + 14, cy - 28, "start");
  vertice(dm.infraestrutura, cx - r * 1.25 - 14, cy - 28, "end");
  vertice(dm.vitima, cx, cy + r + 22, "middle");
  for (const [x, y] of pontos) desenho.appendChild(svg("circle", { cx: x, cy: y, r: 5, class: "diamante-ponto" }));

  const lista = (v) => h("div", { class: "diamante-lista" },
    h("div", { class: "diamante-lista-cab" }, h("strong", {}, v.nome), h("span", { class: "t3" }, v.resumo)),
    v.itens.length ? h("ul", {}, v.itens.map((i) => h("li", {},
      i.tipo && h("span", { class: `etiqueta ${i.tipo === "tipo 1" ? "alta" : ""}` }, i.tipo),
      h("span", { class: "mono" }, i.valor), h("span", { class: "t3" }, ` — ${i.descricao}`)))) : h("div", { class: "t3" }, "nada observado"));

  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Diamond Model"),
      h("span", { class: "t3", style: "font-size:12px" }, "adversário · capacidade · infraestrutura · vítima")),
    h("div", { class: "painel-corpo pilha" },
      h("div", { class: "diamante-desenho" }, desenho),
      h("dl", { class: "defs" },
        Object.entries(dm.meta).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v || "—")]),
        h("dt", {}, "Eixo social-político"), h("dd", {}, dm.eixo_social),
        h("dt", {}, "Eixo técnico"), h("dd", {}, dm.eixo_tecnico)),
      h("div", { class: "diamante-listas" }, [dm.adversario, dm.capacidade, dm.infraestrutura, dm.vitima].map(lista)),
      dm.pivos.length ? h("div", {},
        h("strong", {}, "Próximos pivôs"),
        h("ul", { class: "pivos" }, dm.pivos.map((p) => h("li", {}, h("span", { class: "etiqueta acento" }, `${p.de} → ${p.para}`), " ", p.acao)))) : null),
  );
}

function blocoTTPs(dm) {
  if (!dm?.ttps?.length) return null;
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, `TTPs (${dm.ttps.length})`),
      h("span", { class: "t3", style: "font-size:12px" }, "tática → técnica → procedimento")),
    h("div", { class: "tabela-wrap" }, h("table", { class: "tabela" },
      h("thead", {}, h("tr", {}, h("th", {}, "Tática"), h("th", {}, "Técnica"), h("th", {}, "Procedimento (como este adversário fez)"))),
      h("tbody", {}, dm.ttps.map((t) => h("tr", {},
        h("td", { class: "estreita t2" }, t.tatica_nome),
        h("td", {}, linkTecnica(t.tecnica), h("div", { class: "t3", style: "font-size:12px" }, t.tecnica_nome)),
        h("td", {}, t.procedimento, t.evidencias.map((ev) => h("div", { class: "t3", style: "font-size:12px" }, ev)))))))),
  );
}

// ---------- Pyramid of Pain ----------

function blocoPiramide(p) {
  if (!p) return null;
  const degraus = [...p.degraus].reverse();
  const maior = Math.max(1, ...Object.values(p.contagem));
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Pyramid of Pain"),
      h("span", { class: "t3", style: "font-size:12px" }, "quanto custa ao atacante trocar cada indicador")),
    h("div", { class: "painel-corpo pilha" },
      h("div", { class: "piramide" }, degraus.map((d, k) => {
        const n = p.contagem[d.id] || 0;
        const itens = p.itens.filter((i) => i.degrau === d.id);
        const faixa = h("div", { class: `piramide-faixa nivel-${k}${n ? "" : " vazia"}`, title: itens.map((i) => i.valor).join("\n") },
          h("span", { class: "piramide-nome" }, d.nome), h("span", { class: "piramide-n" }, n));
        aplicarEstilo(faixa, `width:${34 + k * 13}%`);
        return h("div", { class: "piramide-linha" }, faixa,
          h("div", { class: "piramide-info" }, h("span", { class: "etiqueta" }, d.dor), h("span", { class: "t3" }, d.explicacao)));
      })),
      h("p", { class: "t2", style: "margin:0" }, p.leitura),
      h("div", { class: "ioc-ioa" },
        ["IoA", "IoC"].map((classe) => {
          const itens = p.itens.filter((i) => i.classe === classe);
          return h("div", {},
            h("strong", {}, classe === "IoA" ? `Indicadores de ataque (${itens.length})` : `Indicadores de comprometimento (${itens.length})`),
            h("div", { class: "t3", style: "font-size:12px;margin-bottom:6px" }, classe === "IoA" ? "comportamento: vale para a próxima campanha" : "valores: o atacante troca em minutos"),
            h("div", { class: "etiquetas" }, itens.slice(0, 16).map((i) => h("span", { class: `etiqueta ${classe === "IoA" ? "acento" : "mono"}`, title: i.origem }, curto(classe === "IoC" ? defang(i.valor) : i.valor, 48)))));
        })),
    ),
  );
}

// ---------- Grafo de pivo ----------
//
// Layout por forcas, calculado aqui, sem biblioteca: molas nas arestas,
// repulsao entre nos, a mensagem presa no centro. Arrastar move o no;
// clicar mostra o detalhe.

const COR_DO_NO = {
  mensagem: "var(--text)", artefato: "var(--text)", endereco: "var(--alta)", dominio: "var(--accent)",
  ip: "var(--media)", url: "var(--accent)", tecnica: "var(--ok)", anexo: "var(--alta)", marca: "var(--baixa)", grupo: "var(--baixa)",
};

function layoutDoGrafo(g, L, A) {
  const pos = {};
  const centro = g.nos.find((n) => n.vertice === "centro")?.id;
  g.nos.forEach((n, k) => {
    const ang = (2 * Math.PI * k) / g.nos.length;
    pos[n.id] = n.id === centro ? { x: L / 2, y: A / 2 } : { x: L / 2 + Math.cos(ang) * L * 0.3, y: A / 2 + Math.sin(ang) * A * 0.32 };
  });
  for (let passo = 0; passo < 320; passo++) {
    const forca = {};
    for (const n of g.nos) forca[n.id] = { x: 0, y: 0 };
    for (let i = 0; i < g.nos.length; i++) {
      for (let j = i + 1; j < g.nos.length; j++) {
        const a = pos[g.nos[i].id], b = pos[g.nos[j].id];
        let dx = a.x - b.x, dy = a.y - b.y;
        const d2 = Math.max(dx * dx + dy * dy, 40);
        const f = 5200 / d2;
        const d = Math.sqrt(d2);
        dx /= d; dy /= d;
        forca[g.nos[i].id].x += dx * f; forca[g.nos[i].id].y += dy * f;
        forca[g.nos[j].id].x -= dx * f; forca[g.nos[j].id].y -= dy * f;
      }
    }
    for (const a of g.arestas) {
      const p = pos[a.de], q = pos[a.para];
      if (!p || !q) continue;
      const dx = q.x - p.x, dy = q.y - p.y;
      const d = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const f = (d - 120) * 0.02;
      forca[a.de].x += (dx / d) * f; forca[a.de].y += (dy / d) * f;
      forca[a.para].x -= (dx / d) * f; forca[a.para].y -= (dy / d) * f;
    }
    const calor = 1 - passo / 320;
    for (const n of g.nos) {
      if (n.id === centro) continue;
      const p = pos[n.id];
      p.x = Math.min(L - 60, Math.max(60, p.x + Math.max(-12, Math.min(12, forca[n.id].x)) * calor));
      p.y = Math.min(A - 24, Math.max(20, p.y + Math.max(-12, Math.min(12, forca[n.id].y)) * calor));
    }
  }
  return pos;
}

function blocoGrafo(g) {
  if (!g?.nos?.length) return null;
  const L = 900, A = 520;
  const pos = layoutDoGrafo(g, L, A);
  const desenho = svg("svg", { viewBox: `0 0 ${L} ${A}`, class: "grafo-svg", role: "img", "aria-label": "Grafo de pivô" });
  const detalhe = h("div", { class: "grafo-detalhe t2" }, "Clique num nó para ver o que ele é. Arraste para reorganizar.");
  const linhas = [];
  for (const a of g.arestas) {
    if (!pos[a.de] || !pos[a.para]) continue;
    const linha = svg("line", { class: `grafo-aresta${a.tracejada ? " tracejada" : ""}` });
    // Ligacao de comportamento (tracejada) fica sem rotulo: a tatica aparece
    // ao clicar no no, e os rotulos se amontoariam em volta do centro.
    const rotulo = svg("text", { class: "grafo-rotulo-aresta", "text-anchor": "middle" }, a.tracejada ? "" : a.rotulo);
    desenho.append(linha, rotulo);
    linhas.push({ a, linha, rotulo });
  }
  const grupos = {};
  for (const n of g.nos) {
    const grupo = svg("g", { class: `grafo-no${n.destaque ? " destaque" : ""}`, tabindex: "0" });
    const raio = n.vertice === "centro" ? 11 : 7;
    const circulo = svg("circle", { r: raio });
    circulo.style.setProperty("fill", COR_DO_NO[n.tipo] || "var(--text-2)");
    grupo.append(circulo, svg("text", { y: raio + 13, "text-anchor": "middle" }, curto(n.rotulo, 30)));
    desenho.appendChild(grupo);
    grupos[n.id] = grupo;
    const mostrar = () => {
      limpar(detalhe);
      anexar(detalhe, [h("strong", {}, n.rotulo), " ", h("span", { class: "etiqueta" }, n.tipo), n.detalhe ? h("span", { class: "t3" }, ` — ${n.detalhe}`) : null]);
      for (const outro of Object.values(grupos)) outro.classList.remove("selecionado");
      grupo.classList.add("selecionado");
    };
    grupo.addEventListener("click", mostrar);
    grupo.addEventListener("keydown", (ev) => { if (ev.key === "Enter") mostrar(); });
    grupo.addEventListener("pointerdown", (ev) => {
      ev.preventDefault();
      grupo.setPointerCapture(ev.pointerId);
      const mover = (m) => {
        const caixa = desenho.getBoundingClientRect();
        pos[n.id] = { x: ((m.clientX - caixa.left) / caixa.width) * L, y: ((m.clientY - caixa.top) / caixa.height) * A };
        posicionar();
      };
      const soltar = () => { grupo.removeEventListener("pointermove", mover); grupo.removeEventListener("pointerup", soltar); };
      grupo.addEventListener("pointermove", mover);
      grupo.addEventListener("pointerup", soltar);
    });
  }
  function posicionar() {
    for (const { a, linha, rotulo } of linhas) {
      const p = pos[a.de], q = pos[a.para];
      linha.setAttribute("x1", p.x); linha.setAttribute("y1", p.y);
      linha.setAttribute("x2", q.x); linha.setAttribute("y2", q.y);
      rotulo.setAttribute("x", (p.x + q.x) / 2); rotulo.setAttribute("y", (p.y + q.y) / 2 - 3);
    }
    for (const [id, grupo] of Object.entries(grupos)) grupo.setAttribute("transform", `translate(${pos[id].x},${pos[id].y})`);
  }
  posicionar();

  const legenda = h("div", { class: "grafo-legenda" },
    [["endereco", "endereço"], ["dominio", "domínio"], ["ip", "IP"], ["tecnica", "técnica"], ["anexo", "anexo"], ["marca", "marca"]].map(([tipo, nome]) => {
      const bolinha = h("span", { class: "grafo-bolinha" });
      aplicarEstilo(bolinha, `background:${COR_DO_NO[tipo]}`);
      return h("span", {}, bolinha, nome);
    }));
  return h(
    "div",
    { class: "painel mt-16" },
    h("div", { class: "painel-cab" }, h("span", { class: "painel-titulo" }, "Grafo de pivô"),
      h("span", { class: "t3", style: "font-size:12px" }, `${g.nos.length} nós · ${g.arestas.length} ligações`), legenda),
    h("div", { class: "grafo-area" }, desenho),
    h("div", { class: "painel-rodape" }, detalhe),
  );
}

// ---------- Acoes ----------

function resumirEmailComIA() {
  estado.email.ia = { carregando: true, mensagem: "" };
  renderizar();
  ponte.resumirEmailComIA(estado.opcoes.modelo_ia || estado.ambiente?.modelo_padrao || "");
}

tarefas.ia_email = (t) => {
  estado.email.ia = t.ok ? { carregando: false, dados: t.dados } : { carregando: false, erro: t.erro };
  if (estado.vista === "email") renderizar();
};

async function gerarYaraEmail() {
  const r = await chamar("gerarYaraEmail");
  if (!r?.ok) return avisar("erro", "Regra não gerada", r?.erro || "");
  estado.email.yara = r.regra;
  renderizar();
}

async function salvarYaraEmail() {
  const r = await chamar("salvarYaraEmail");
  if (r?.cancelado) return;
  if (!r?.ok) return avisar("erro", "Regra não salva", r?.erro || "");
  avisar("ok", "Regra salva", r.caminho);
}

async function salvarPdfEmail() {
  const r = await chamar("salvarPdfEmail");
  if (r?.cancelado) return;
  if (!r?.ok) return avisar("erro", "PDF não gerado", r?.erro || "");
  avisar("ok", r.com_ia ? "Relatório executivo salvo" : "Relatório salvo (sem resumo por IA)", r.caminho,
    { rotulo: "Abrir", fazer: () => chamar("abrirArquivo", r.caminho) });
}

async function exportarNavigatorEmail() {
  const r = await chamar("exportarNavigatorEmail");
  if (r?.cancelado) return;
  if (!r?.ok) return avisar("erro", "Layer não exportada", r?.erro || "");
  avisar("ok", "Layer do Navigator salva", "Abra em mitre-attack.github.io/attack-navigator → Open Existing Layer.");
}

// ============================================================
// Toca-discos
// ============================================================
//
// O audio toca no Python; aqui e so o prato, o braco e os controles. O
// deck e montado uma vez e depois so atualizado: recriar o vinil a cada
// aviso de posicao zeraria o angulo do giro, e o disco daria um pulo.
// Nomes de faixa e album vem de nome de arquivo e passam por h() como
// todo o resto.

const disco = {
  catalogo: null,
  estado: null,
  el: null,
  capaNoSelo: null,
  listaAberta: false,
  albumVisto: 0,
  chaveDaLista: "",
};

function albumDoDisco(i = disco.estado?.album ?? 0) {
  return disco.catalogo?.albuns?.[i] || null;
}

function receberCatalogo(c) {
  if (!c?.ok) return;
  disco.catalogo = c;
  disco.estado = c.estado;
  if (!disco.el) montarTocaDiscos();
  disco.chaveDaLista = "";
  atualizarTocaDiscos();
}

function montarTocaDiscos() {
  const raiz = limpar(document.getElementById("toca-discos"));
  const el = {};
  el.selo = h("div", { class: "td-selo" });
  el.braco = h("div", { class: "td-braco" }, h("div", { class: "td-cabeca" }));
  el.prato = h(
    "button",
    { class: "td-prato", title: "Tocar ou pausar", onclick: () => ponte.discoAlternar() },
    h("div", { class: "td-vinil" }, h("div", { class: "td-sulcos" }), el.selo, h("div", { class: "td-furo" })),
    h("div", { class: "td-reflexo" }),
    h("div", { class: "td-pivo" }),
    el.braco,
    h("div", { class: "td-luz" }),
  );
  el.titulo = h("div", { class: "td-titulo" });
  el.artista = h("div", { class: "td-artista" });
  el.tocar = h("button", { class: "td-botao td-principal", onclick: () => ponte.discoAlternar() });
  el.anterior = h("button", { class: "td-botao", title: "Anterior", onclick: () => ponte.discoAnterior() }, icone("anterior"));
  el.proxima = h("button", { class: "td-botao", title: "Próxima", onclick: () => ponte.discoProxima() }, icone("proxima"));
  el.preenchido = h("div", { class: "td-preenchido" });
  el.barra = h("div", { class: "td-barra", title: "Ir para este ponto", onclick: buscarNoDisco }, el.preenchido);
  el.decorrido = h("span");
  el.duracao = h("span");
  el.lista = h("div", { class: "td-lista", role: "dialog", "aria-label": "Faixas", onclick: (e) => e.stopPropagation() });

  raiz.append(
    h(
      "div",
      { class: "td-deck" },
      el.prato,
      h(
        "div",
        { class: "td-info" },
        el.titulo,
        el.artista,
        h(
          "div",
          { class: "td-controles" },
          el.anterior,
          el.tocar,
          el.proxima,
          h("button", { class: "td-botao td-abrir-lista", title: "Faixas e álbuns", onclick: (e) => { e.stopPropagation(); alternarListaDoDisco(); } }, icone("lista")),
        ),
      ),
    ),
    el.barra,
    h("div", { class: "td-tempo" }, el.decorrido, el.duracao),
    el.lista,
  );
  disco.el = el;
}

function atualizarTocaDiscos() {
  const el = disco.el;
  if (!el) return;
  const e = disco.estado || {};
  const album = albumDoDisco();
  const temFaixa = !!album?.faixas?.length;
  const raiz = document.getElementById("toca-discos");
  raiz.classList.toggle("tocando", !!e.tocando);
  raiz.classList.toggle("sem-faixa", !temFaixa);

  // A capa e uma data URL grande: so troca a imagem quando o album muda.
  const capa = album?.capa || "";
  if (disco.capaNoSelo !== capa) {
    limpar(el.selo);
    if (capa) el.selo.appendChild(h("img", { src: capa, alt: "", draggable: "false" }));
    disco.capaNoSelo = capa;
  }

  let titulo, subtitulo;
  if (!album) {
    titulo = "Nenhum disco";
    subtitulo = "Coloque músicas em midia/";
  } else if (!temFaixa) {
    titulo = album.nome;
    subtitulo = "Sem faixas ainda";
  } else {
    titulo = album.faixas[e.faixa] ?? album.faixas[0];
    subtitulo = [album.artista, album.nome].filter(Boolean).join(" · ");
  }
  el.titulo.textContent = titulo;
  el.titulo.title = titulo;
  el.artista.textContent = e.erro || subtitulo;
  el.artista.title = e.erro || subtitulo;
  el.artista.classList.toggle("erro", !!e.erro);

  limpar(el.tocar).appendChild(icone(e.tocando ? "pausar" : "play"));
  el.tocar.title = e.tocando ? "Pausar" : "Tocar";
  for (const b of [el.tocar, el.anterior, el.proxima, el.prato]) b.disabled = !temFaixa;

  const duracao = e.duracao_ms || 0;
  const posicao = Math.min(e.posicao_ms || 0, duracao);
  el.preenchido.style.width = duracao ? `${(posicao / duracao) * 100}%` : "0%";
  el.decorrido.textContent = duracao ? fmtFaixa(posicao) : "-:--";
  el.duracao.textContent = duracao ? fmtFaixa(duracao) : "-:--";

  // A lista so e refeita quando muda o que ela mostra, e nao a cada meio
  // segundo de posicao: refazer levaria a rolagem de volta ao topo.
  const chave = `${e.album}:${e.faixa}:${e.tocando}`;
  if (disco.listaAberta && chave !== disco.chaveDaLista) renderizarListaDoDisco();
}

// 3:07, e nao 03:07: e assim que todo player mostra tempo de musica.
function fmtFaixa(ms) {
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function buscarNoDisco(ev) {
  const duracao = disco.estado?.duracao_ms || 0;
  if (!duracao) return;
  const caixa = disco.el.barra.getBoundingClientRect();
  const fracao = Math.min(1, Math.max(0, (ev.clientX - caixa.left) / caixa.width));
  ponte.discoBuscar(Math.round(fracao * duracao));
}

async function alternarListaDoDisco() {
  disco.listaAberta = !disco.listaAberta;
  if (disco.listaAberta) {
    disco.albumVisto = disco.estado?.album ?? 0;
    // Abrir a lista rele a pasta: musica recem-copiada ja aparece.
    receberCatalogo(await chamar("discoRecarregar"));
  }
  renderizarListaDoDisco();
}

function renderizarListaDoDisco() {
  const el = disco.el;
  if (!el) return;
  const lista = limpar(el.lista);
  lista.classList.toggle("aberta", disco.listaAberta);
  if (!disco.listaAberta) return;

  const e = disco.estado || {};
  disco.chaveDaLista = `${e.album}:${e.faixa}:${e.tocando}`;
  const albuns = disco.catalogo?.albuns || [];
  const visto = Math.min(disco.albumVisto, Math.max(0, albuns.length - 1));
  const album = albuns[visto];

  if (!album) {
    lista.append(
      h("div", { class: "td-lista-nome" }, "Nenhum disco na pasta"),
      h("p", { class: "td-lista-dica" }, "Crie uma pasta por álbum dentro de midia/, no formato “Artista - Álbum”, com os arquivos de áudio e uma imagem capa.jpg."),
    );
  } else {
    lista.append(
      album.capa
        ? h("img", { class: "td-lista-capa", src: album.capa, alt: "", draggable: "false" })
        : h("div", { class: "td-lista-capa td-sem-capa" }, icone("disco")),
      h("div", { class: "td-lista-nome" }, album.nome),
      album.artista && h("div", { class: "td-lista-artista" }, album.artista),
    );
    if (!album.faixas.length) {
      lista.append(h("p", { class: "td-lista-dica" }, "Copie os arquivos de áudio para a pasta deste álbum e abra esta lista de novo."));
    }
    lista.append(
      h(
        "ol",
        { class: "td-faixas" },
        album.faixas.map((titulo, j) => {
          const atual = visto === e.album && j === e.faixa;
          return h(
            "li",
            {},
            h(
              "button",
              { class: "td-faixa", "aria-current": atual ? "true" : null, onclick: () => chamar("discoEscolher", visto, j) },
              atual && e.tocando
                ? h("span", { class: "td-eq", "aria-hidden": "true" }, h("i"), h("i"), h("i"))
                : h("span", { class: "td-num" }, j + 1),
              h("span", { class: "td-faixa-titulo" }, titulo),
            ),
          );
        }),
      ),
    );
  }

  if (albuns.length > 1) {
    lista.append(
      h("div", { class: "td-lista-secao" }, "Álbuns"),
      h(
        "div",
        { class: "td-albuns" },
        albuns.map((a, i) =>
          h(
            "button",
            {
              class: "td-album",
              "aria-current": i === visto ? "true" : null,
              title: [a.artista, a.nome].filter(Boolean).join(" - "),
              onclick: () => { disco.albumVisto = i; renderizarListaDoDisco(); },
            },
            a.capa ? h("img", { src: a.capa, alt: "", draggable: "false" }) : icone("disco"),
          ),
        ),
      ),
    );
  }

  const volume = h("input", {
    type: "range", min: "0", max: "100", step: "1", class: "td-volume", "aria-label": "Volume",
    oninput: (ev) => ponte.discoVolume(Number(ev.target.value)),
  });
  volume.value = String(e.volume ?? 70);
  lista.append(
    h(
      "div",
      { class: "td-lista-rodape" },
      icone("volume"),
      volume,
      h("button", { class: "td-botao", title: "Abrir a pasta de músicas", onclick: () => chamar("discoAbrirPasta") }, icone("pasta")),
    ),
  );
}

// ============================================================
// Moscas
// ============================================================
//
// Voo de mosca e zigue-zague com paradas: muda de direcao o tempo todo,
// pousa um pouco, sai de novo. Por isso e JavaScript, e nao um caminho
// fixo em CSS, que se repetiria igual e denunciaria o truque.

const MOSCAS = 5;

function soltarMoscas() {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const campo = document.getElementById("moscas");
  const sorteio = (min, max) => min + Math.random() * (max - min);
  const moscas = Array.from({ length: MOSCAS }, () => {
    const el = h("div", { class: "mosca" }, h("i"), h("i"));
    campo.appendChild(el);
    return {
      el,
      x: sorteio(0, campo.clientWidth || 800),
      y: sorteio(0, campo.clientHeight || 600),
      angulo: sorteio(0, 2 * Math.PI),
      velocidade: sorteio(0.05, 0.12),
      pousada: sorteio(0, 4000),
      voo: 0,
    };
  });

  let antes = performance.now();
  function passo(agora) {
    const dt = Math.min(50, agora - antes);
    antes = agora;
    const largura = campo.clientWidth;
    const altura = campo.clientHeight;
    for (const m of moscas) {
      if (m.pousada > 0) {
        m.pousada -= dt;
        if (m.pousada <= 0) {
          m.voo = sorteio(1200, 4500);
          m.velocidade = sorteio(0.05, 0.12);
          m.angulo += sorteio(-2, 2);
        }
      } else {
        m.angulo += sorteio(-0.35, 0.35);
        // De vez em quando, uma arrancada.
        if (Math.random() < 0.01) m.velocidade = sorteio(0.15, 0.25);
        m.velocidade += (0.08 - m.velocidade) * 0.02;
        m.x += Math.cos(m.angulo) * m.velocidade * dt;
        m.y += Math.sin(m.angulo) * m.velocidade * dt;
        if (m.x < 8 || m.x > largura - 8) m.angulo = Math.PI - m.angulo;
        if (m.y < 8 || m.y > altura - 8) m.angulo = -m.angulo;
        m.voo -= dt;
        if (m.voo <= 0) m.pousada = sorteio(1500, 6000);
      }
      m.x = Math.min(Math.max(m.x, 8), Math.max(8, largura - 8));
      m.y = Math.min(Math.max(m.y, 8), Math.max(8, altura - 8));
      m.el.classList.toggle("voando", m.pousada <= 0);
      m.el.style.transform = `translate(${m.x.toFixed(1)}px, ${m.y.toFixed(1)}px) rotate(${(m.angulo + Math.PI / 2).toFixed(3)}rad)`;
    }
    requestAnimationFrame(passo);
  }
  requestAnimationFrame(passo);
}

// ============================================================
// Inicio
// ============================================================

function conectar() {
  const simbolo = document.getElementById("marca-simbolo");
  simbolo.appendChild(icone("disco"));
  renderizarRodape();
  soltarMoscas();

  new QWebChannel(qt.webChannelTransport, async (canal) => {
    ponte = canal.objects.ponte;

    ponte.arquivoSelecionado.connect((json) => {
      const a = JSON.parse(json);
      if (!a.ok) return avisar("erro", "Arquivo não aberto", a.erro || "");
      estado.arquivo = a;
      if (!estado.andamento?.rodando) ir("nova");
    });
    ponte.progresso.connect((json) => aoProgredir(JSON.parse(json)));
    ponte.concluido.connect((json) => aoConcluir(JSON.parse(json)));
    ponte.falhou.connect((mensagem) => aoFalhar(mensagem));
    ponte.tarefaConcluida.connect((json) => {
      const t = JSON.parse(json);
      (tarefas[t.id] || (() => {}))(t);
    });
    ponte.arrastando.connect((json) => document.body.classList.toggle("arrastando", JSON.parse(json).ativo));
    ponte.andamentoTarefa.connect((json) => {
      const t = JSON.parse(json);
      if (t.id === "ia_email" && estado.email.ia?.carregando) {
        estado.email.ia.mensagem = t.mensagem;
        const el = document.getElementById("ia-email-andamento");
        if (el) el.textContent = t.mensagem;
      }
      if (t.id === "email" && estado.email.carregando) {
        estado.email.mensagem = t.mensagem;
        if (estado.vista === "email") renderizar();
      }
      if (t.id === "revisao_yara" && estado.revisaoYara?.carregando) {
        estado.revisaoYara.mensagem = t.mensagem;
        // So o texto muda: re-renderizar a tela inteira a cada meio segundo
        // faria a rolagem pular enquanto o analista le a regra.
        const el = document.getElementById("revisao-andamento");
        if (el) el.textContent = t.mensagem;
      }
    });

    ponte.emailSelecionado.connect((json) => {
      const a = JSON.parse(json);
      Object.assign(estado.email, { arquivo: a, dados: null, erro: "", ia: null, yara: null });
      ir("email");
    });
    ponte.discoMudou.connect((json) => {
      disco.estado = JSON.parse(json);
      atualizarTocaDiscos();
    });

    estado.ambiente = await chamar("estado");
    estado.opcoes.modelo_ia = estado.ambiente.modelo_padrao;
    renderizar();
    verificarOllamaSilencioso();
    receberCatalogo(await chamar("discoCatalogo"));
  });
}

function verificarOllamaSilencioso() {
  // Ja deixa o diagnostico pronto para a tela de configuracao, sem mostrar
  // "verificando" em lugar nenhum.
  ponte.verificarOllama(estado.opcoes.modelo_ia);
}

document.addEventListener("click", () => {
  if (estado.menuAberto) { estado.menuAberto = null; renderizarTopo(); }
  if (disco.listaAberta) { disco.listaAberta = false; renderizarListaDoDisco(); }
});

document.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key.toLowerCase() === "o") { e.preventDefault(); ponte?.escolherArquivo(); }
  if (e.ctrlKey && e.key === "Enter" && estado.vista === "nova") { e.preventDefault(); analisar(); }
});

// Arrastar sobre a pagina: o Qt intercepta o soltar para obter o caminho
// real, que o navegador nao revela. Aqui so impede a pagina de tentar abrir
// o arquivo como documento.
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => e.preventDefault());

conectar();
