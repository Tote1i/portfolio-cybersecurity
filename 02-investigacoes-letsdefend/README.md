# 02. Investigações Práticas (SOC)

Este diretório reúne write-ups de investigações de alertas feitas em plataformas de simulação de SOC (LetsDefend e, quando indicado, CyberDefenders). O foco não é o "gabarito" dos desafios, e sim o **método**: como triar um alerta, que evidências coletar, como chegar a um veredito e que resposta recomendar.

> **Aviso:** os cenários pertencem às plataformas e são ambientes simulados. Os write-ups descrevem metodologia e raciocínio, sem reproduzir respostas literais dos desafios.

---

## Metodologia

Todo caso segue o mesmo fluxo:

1. **Triagem:** o alerta faz sentido? Qual a severidade e o ativo afetado?
2. **Coleta:** logs, cabeçalho de e-mail, processos, conexões de rede.
3. **Análise de reputação:** VirusTotal, URLScan.io, AbuseIPDB e sandbox (ANY.RUN / Hybrid Analysis) quando há anexo.
4. **Correlação:** o IP/hash/domínio aparece em outros eventos? Houve atividade posterior?
5. **Veredito e resposta:** True Positive ou False Positive, com justificativa, mapeamento MITRE ATT&CK e ação recomendada (contenção, erradicação, recuperação).

Os write-ups usam o [template padrão](./templates/template-writeup.md). Todos os IOCs aparecem em formato *defanged* (ex.: `hxxp://exemplo[.]com`).

---

## Casos

| # | Caso | Tipo | Severidade | Veredito | Técnicas MITRE | Status |
|---|---|---|---|---|---|---|
| 01 | _a definir_ | Phishing (link) | | | | Planejado |
| 02 | _a definir_ | Phishing (anexo) | | | | Planejado |
| 03 | _a definir_ | Malware / execução suspeita | | | | Planejado |
| 04 | _a definir_ | Autenticação / força bruta | | | | Planejado |

*A tabela é atualizada conforme cada write-up é publicado. Substitua "a definir" por link para a pasta do caso.*

---

## Ferramentas utilizadas

| Categoria | Ferramentas |
|---|---|
| Plataforma de simulação | LetsDefend |
| Reputação / OSINT | VirusTotal, URLScan.io, AbuseIPDB |
| Análise de arquivos | ANY.RUN, Hybrid Analysis |
| Decodificação | CyberChef |
| Tráfego | Wireshark (quando há PCAP) |
| Referência de táticas | MITRE ATT&CK, Cyber Kill Chain |

---

## Estrutura do diretório

```
02-investigacoes-letsdefend/
├── README.md
├── templates/
│   └── template-writeup.md
├── 01-phishing-.../
│   ├── README.md
│   └── evidencias/
├── 02-.../
└── ...
```

---

## Conexão com os outros projetos

- **[01. Home Lab (Wazuh)](../01-homelab-wazuh/):** a lógica de triagem e o mapeamento MITRE usados aqui são os mesmos aplicados nos alertas do laboratório.
- **[03. Analisador de Logs (Python)](../03-script-log-analyzer/):** o caso de força bruta serve de referência para o padrão que o script deve detectar.

---

[Voltar ao portfólio](../README.md)
