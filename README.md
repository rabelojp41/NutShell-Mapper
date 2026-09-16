# RabMapper

Framework de **Cyber Threat Intelligence** em Python para analise estatica de
artefatos suspeitos: extracao de strings, desofuscacao, geracao de regras YARA,
mapeamento MITRE ATT&CK, atribuicao de grupos, Cyber Kill Chain, scoring CVSS,
enriquecimento via VirusTotal/Shodan e relatorio automatizado.

> Projeto de portfolio. Testado com amostras publicas (MalwareBazaar, tria.ge)
> e arquivos benignos (EICAR) em ambiente de desenvolvimento.

## Pipeline

```
binario -> strings (floss) -> desofuscacao -> IOCs
                |                    |
                v                    v
          regra YARA          MITRE ATT&CK -> Kill Chain -> Atribuicao
                |                    |
                +--------> enriquecimento (VT / Shodan)
                                     |
                                     v
                          relatorio PDF / DOCX
```

## Estrutura

| Modulo | Responsabilidade |
|---|---|
| `core/string_extractor.py` | roda FLOSS (static/stack/tight/decoded), com extrator nativo de fallback; identifica IOCs por regex com nivel de confianca |
| `core/deobfuscator.py` | Base64, Base32, hex, ROT13, XOR de 1 byte, zlib e gzip, encadeados ate profundidade 3; triagem por entropia e pontuacao de plausibilidade |
| `core/pe_analyzer.py` | imports, exports, secoes com entropia, imphash, recursos e indicios estruturais |
| `core/yara_generator.py` | seleciona as strings mais distintivas, gera a regra e a **valida contra o proprio artefato** antes de considera-la utilizavel |
| `core/mitre_mapper.py` | catalogo local de 40 tecnicas ATT&CK mais enriquecimento opcional pelo STIX oficial |
| `core/killchain.py` | agrupa as tecnicas nos 7 estagios da Cyber Kill Chain |
| `core/group_attribution.py` | cruza as tecnicas com os intrusion-sets, ponderando pela raridade de cada tecnica |
| `core/cvss_calculator.py` | score CVSS 3.1 (base, temporal e ambiental) |
| `core/pipeline.py` | orquestra as etapas, isola falhas e consolida o resultado |
| `enrichment/virustotal_client.py` | lookup de hash, IP, dominio e URL. **Nao envia o arquivo** |
| `enrichment/shodan_client.py` | portas e servicos dos IPs publicos extraidos |
| `reports/report_generator.py` | relatorio em Markdown, JSON, PDF e DOCX |
| `gui/` | interface desktop em PySide6 |
| `main.py` | linha de comando |

## Instalacao

> **Requer Python 3.10.x no Windows.** O `flare-floss` depende de
> `binary2strings`, extensao C++ que so publica wheel pre-compilada para
> `cp310`. Em 3.11/3.12/3.13/3.14 o pip tenta compilar do zero e falha com
> `Unable to find a compatible Visual Studio installation`.

```bash
winget install -e --id Python.Python.3.10
```

```bash
git clone https://github.com/rabelojp41/RabMapper.git
cd RabMapper
py -3.10 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy config\.env.example config\.env
```

Preencha `config/.env` com suas chaves de API.

### Verificar a instalacao

```bash
python -m tests.check_env
```

Valida que FLOSS, yara-python, pefile, mitreattack-python, cvss, reportlab,
python-docx e PySide6 importam corretamente.

## Uso

### Linha de comando

```bash
python main.py analisar amostra.bin
```

```bash
python main.py analisar amostra.bin --relatorio pdf md --cvss "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
```

Outros comandos:

| Comando | O que faz |
|---|---|
| `python main.py config` | mostra a configuracao e verifica o ambiente |
| `python main.py cvss "<vetor>"` | calcula um score CVSS 3.1 avulso |
| `python main.py atualizar-attack` | baixa o bundle STIX do MITRE ATT&CK |
| `python main.py gui` | abre a interface grafica |

Opcoes uteis do `analisar`: `--sem-floss` (bem mais rapido, so strings
estaticas), `--sem-stix` (offline), `--benigno arquivo.exe` (testa a regra
YARA contra um binario legitimo), `--enriquecer` (consulta VirusTotal e
Shodan).

### Interface grafica

```bash
python main.py gui
```

Arraste o artefato para a janela, escolha as opcoes e clique em Analisar. O
resultado aparece em abas: Resumo, Indicadores, Strings, Desofuscacao, PE,
ATT&CK, Kill Chain, Atribuicao, YARA, Enriquecimento e Limitacoes.

### Testes

```bash
python -m pytest tests/ -q
```

328 testes, todos offline: nenhum faz requisicao de rede nem depende do
bundle de 45 MB do ATT&CK.

## Seguranca

- **O artefato nunca e executado.** A analise e inteiramente estatica. Ainda
  assim, manipule amostras reais somente em maquina virtual isolada.
- **Chaves de API somente via `.env`**, nunca hardcoded e nunca commitadas.
  Os clients sanitizam qualquer mensagem de erro antes de ela virar log: o
  Shodan autentica por query string, e sem isso um timeout comum vazaria a
  credencial.
- **Enriquecimento externo e desligado por padrao.** Consultar o VirusTotal
  revela a quem opera o servico quais indicadores voce esta investigando. A
  GUI pede confirmacao explicita antes de habilitar.
- **O arquivo nunca e enviado ao VirusTotal** — apenas o hash. Enviar a
  amostra a publicaria para os assinantes do servico, de forma irreversivel.
  Nao ha funcao de upload no codigo, e ha teste que falha se alguem
  adicionar uma.
- **Binarios de malware nunca vao para o repositorio**, apenas hashes de
  referencia. O `.gitignore` bloqueia `data/samples/`, `.env` e extensoes de
  executavel em qualquer diretorio.
- **Nada aqui e veredito.** Tecnica ATT&CK significa capacidade observada,
  nao comportamento comprovado; sobreposicao de tecnicas nao e atribuicao; e
  o relatorio sempre traz a secao "Limitacoes desta analise" dizendo o que
  ficou de fora.

## Licenca

MIT
