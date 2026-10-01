# [Tipo do alerta] — [Nome curto do caso]

> **Plataforma:** LetsDefend | **Alerta:** SOCxxx | **Data da investigação:** AAAA-MM-DD
> **Severidade:** Critical / High / Medium / Low | **Tipo:** Phishing / Malware / Web Attack / Autenticação
> **Veredito:** True Positive / False Positive | **Tempo gasto:** ~XX min

---

## 1. Resumo

<!-- 2 a 3 linhas: o que disparou, o que você encontrou e qual foi a conclusão. Escreva como se o gestor só fosse ler isto. -->

## 2. Contexto do alerta

| Campo | Valor |
|---|---|
| Regra que disparou | |
| Data/hora do evento | |
| Host / usuário envolvido | |
| IP de origem / destino | |
| Ação do dispositivo de segurança | Permitido / Bloqueado |

## 3. Investigação

<!-- Passo a passo cronológico. Para cada passo: O QUE você verificou, ONDE (qual aba/ferramenta) e POR QUÊ. O raciocínio é o que o recrutador quer ler. -->

### 3.1 Triagem
- O alerta faz sentido para o ativo e o horário? 
- Houve tráfego/ação real ou apenas tentativa?

### 3.2 Coleta
- **E-mail:** remetente, Reply-To, cabeçalho (SPF/DKIM/DMARC), anexos, links
- **Endpoint:** processos, árvore pai/filho, conexões de rede, arquivos criados
- **Logs:** eventos relacionados ao IP/usuário/host na janela de tempo

### 3.3 Análise de reputação
| Artefato | Ferramenta | Resultado |
|---|---|---|
| | VirusTotal / URLScan / AbuseIPDB / Sandbox | |

### 3.4 Correlação
- O IP/domínio/hash aparece em outros eventos?
- Houve atividade posterior (movimentação lateral, novas conexões, persistência)?

## 4. IOCs

> Sempre em formato *defanged*. Exemplos: `hxxp://exemplo[.]com`, `192[.]0[.]2[.]10`, `usuario[@]exemplo[.]com`

| Tipo | Valor | Contexto |
|---|---|---|
| IP | | |
| Domínio / URL | | |
| Hash (SHA256) | | |
| Arquivo | | |
| E-mail | | |

## 5. Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Evidência no caso |
|---|---|---|---|
| | | T1xxx | |

*(Opcional: Cyber Kill Chain — em qual fase o ataque foi interrompido?)*

## 6. Veredito e justificativa

**Veredito:** True Positive / False Positive

<!-- Por que? Liste as evidências que sustentam a conclusão e, se houver, o que poderia ter te feito concluir o contrário. -->

## 7. Resposta recomendada

| Fase | Ação |
|---|---|
| **Contenção** | (isolar host, bloquear IP/domínio, desabilitar conta...) |
| **Erradicação** | (remover arquivo, resetar credenciais, remover persistência...) |
| **Recuperação** | (restaurar serviço, monitoramento reforçado...) |
| **Prevenção** | (regra de detecção, treinamento, hardening...) |

## 8. Lições aprendidas

- O que eu fiz bem:
- O que eu faria diferente:
- Conceito/ferramenta nova que aprendi:

## 9. Conexão com outros projetos *(quando fizer sentido)*

<!-- Ex.: regra equivalente no Wazuh (projeto 01), script que detectaria o mesmo padrão (projeto 03). -->

---

### Checklist antes de publicar

- [ ] IOCs em formato defanged
- [ ] Sem dados da minha conta, tokens, chaves ou informações pessoais nos prints
- [ ] Li os termos da plataforma e **não** publiquei respostas literais do desafio
- [ ] Escrevi sobre método e raciocínio, não sobre gabarito
- [ ] Prints salvos em `evidencias/` e referenciados no texto
- [ ] Revisei ortografia e a coerência do veredito com as evidências
- [ ] Atualizei a tabela de casos no README da pasta 02
