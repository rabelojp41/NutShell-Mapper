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
| `core/string_extractor.py` | roda FLOSS, separa strings estaticas/stack/decodificadas, sinaliza IOCs por regex |
| `core/deobfuscator.py` | Base64, XOR (brute-force 1 byte), hex, ROT13, zlib/gzip; heuristica de entropia |
| `core/yara_generator.py` | gera e valida regra YARA a partir de strings unicas, imports PE e secoes de alta entropia |
| `core/mitre_mapper.py` | cacheia STIX oficial do ATT&CK e mapeia comportamentos em tecnicas |
| `core/group_attribution.py` | cruza tecnicas com intrusion-sets (APT29, FIN7, ...) |
| `core/killchain.py` | agrupa tecnicas nos 7 estagios da Cyber Kill Chain |
| `core/cvss_calculator.py` | score CVSS 3.1 a partir do vetor |
| `enrichment/virustotal_client.py` | lookup de hash, IP e dominio |
| `enrichment/shodan_client.py` | portas/servicos expostos dos IPs extraidos |
| `reports/report_generator.py` | consolida tudo em PDF/DOCX |
| `gui/` | interface grafica desktop (PySide6) |
| `main.py` | orquestra o pipeline via CLI |

## Instalacao

```bash
git clone https://github.com/rabelojp41/RabMapper.git
cd RabMapper
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -r requirements.txt
copy config\.env.example config\.env
```

Preencha `config/.env` com suas chaves de API.

## Uso

```bash
python main.py --sample data/samples/arquivo.bin --report pdf
```

## Seguranca

- Chaves de API somente via `.env` (nunca hardcoded, nunca commitadas).
- Binarios de malware nunca vao para o repositorio — apenas hashes de referencia.
- Analise **estatica**. O framework nao executa o artefato. Manipule amostras
  reais somente em VM isolada.

## Licenca

MIT
