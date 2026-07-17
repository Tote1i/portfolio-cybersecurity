# Homelab de Detecção — Implementação e Análise com Wazuh SIEM

## Descrição

Homelab de segurança para prática de engenharia de detecção, coleta de telemetria de endpoints e triagem de alertas em ambiente controlado, usando Wazuh como SIEM.

O laboratório está dividido em duas fases:

- **Fase 1 (concluída):** centralização de logs, auditoria de autenticação e baseline de telemetria em endpoint Windows.
- **Fase 2 (em andamento):** simulação de ataques de rede com Kali Linux e validação de regras de correlação.

## Arquitetura

| Componente | Função | SO / Ferramenta | IP |
|---|---|---|---|
| SIEM Manager | Servidor central (Indexer, Server, Dashboard) | Ubuntu Server + Wazuh 4.9.2 | 192.168.1.23 |
| Endpoint monitorado | Alvo de auditoria e coleta de eventos | Windows 11 Home | 192.168.1.15 |
| Host de ataque (Fase 2) | Simulação de agente de ameaça | Kali Linux | a definir |

Ambiente virtualizado em Oracle VirtualBox, rede em modo Bridge para permitir comunicação direta entre VM e host físico.

---

## Fase 1 — Centralização de logs e auditoria local

### 1. Setup do servidor

Deploy do Wazuh (Indexer, Server e Dashboard) em instalação single-node, para fins de laboratório.

### 2. Deploy do agente no endpoint Windows

Instalação e registro do agente via PowerShell:

```powershell
# Download e instalação silenciosa do agente, apontando para o manager
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.1.23' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='endpoint-01'

NET START WazuhSvc
```

Validação: agente aparece como "ativo" no dashboard e eventos de segurança do Windows passam a ser indexados.

### 3. Cenário de teste: falhas de autenticação local

**Ação executada:** bloqueio de sessão local (Windows+L), seguido de 4 tentativas de login com senha incorreta e 1 tentativa bem-sucedida.

**Objetivo do teste:** validar que o pipeline de coleta (Agent → Manager → Indexer → Dashboard) captura e classifica corretamente eventos de autenticação nativos do Windows.

**Resultado:** as 4 falhas foram capturadas como Event ID 4625 (Logon Failure) e classificadas pela regra Wazuh 60122 (nível 5). O logon bem-sucedido subsequente gerou Event ID 4624, classificado pela regra 60110 (nível 8, por seguir uma sequência de falhas).

### 4. Alerta bruto (exemplo)

```json
{
  "_index": "wazuh-alerts-4.x-2026.07.17",
  "agent": {
    "ip": "192.168.1.15",
    "name": "endpoint-01",
    "id": "001"
  },
  "data": {
    "win": {
      "eventdata": {
        "logonType": "2",
        "ipAddress": "127.0.0.1",
        "status": "0xc000006d"
      },
      "system": {
        "eventID": "4625",
        "channel": "Security",
        "severityValue": "AUDIT_FAILURE"
      }
    }
  },
  "rule": {
    "level": 5,
    "description": "Logon Failure - Unknown user or bad password",
    "id": "60122"
  }
}
```

**Indicadores extraídos:**
- `logonType: 2` — logon interativo, executado localmente na máquina (não é acesso remoto).
- `eventID: 4625` — código nativo do Windows para falha de autenticação.
- `status: 0xc000006d` — senha ou usuário incorretos.

### 5. Análise do analista

Este é um evento de baixa severidade e alta previsibilidade: falha de autenticação local seguida de sucesso, mesmo usuário, mesmo host, curto intervalo de tempo. Classificado como **falso-positivo / atividade esperada** — consistente com erro de digitação do próprio usuário.

Se o volume de falhas fosse maior, viesse de IP externo, ou envolvesse `logonType: 3` (logon de rede) ou `logonType: 10` (RDP), a classificação mudaria para investigação ativa de possível brute-force (ver Fase 2). Não há ação de resposta necessária neste caso — o cenário serve para validar que o canal de telemetria funciona corretamente antes de introduzir cenários mais complexos.

### 6. Mapeamento MITRE ATT&CK — Fase 1

| Tática | Técnica | Comportamento simulado | Telemetria de detecção |
|---|---|---|---|
| Credential Access | T1110.001 — Brute Force: Password Guessing | Múltiplas tentativas de senha incorreta na tela de bloqueio local | Event ID 4625, Logon Type 2, regra Wazuh 60122 |

*Nota: o evento não representa uma técnica ofensiva real (foi gerado pelo próprio operador do lab para validar o pipeline de coleta), mas o mapeamento demonstra como o mesmo padrão seria classificado caso ocorresse em um cenário real de força bruta local.*

---

## Fase 2 — Simulação de ataques de rede (em andamento)

> Esta fase ainda não foi executada. Descrição abaixo é o planejamento dos testes.

### Objetivo

Validar a capacidade de detecção do Wazuh contra vetores de ataque de rede, usando Kali Linux como host de origem.

### Testes planejados

| Tática MITRE | Técnica | Ferramenta | Detecção esperada |
|---|---|---|---|
| Reconnaissance | T1595.001 — Active Scanning: IP Addresses | `nmap` | Correlação de múltiplas conexões/porta em curto intervalo |
| Credential Access | T1110.002 — Brute Force: Password Cracking | `hydra` (RDP/SMB) | Event ID 4625, Logon Type 3, múltiplas falhas do mesmo IP |
| Execution | T1204.002 — User Execution: Malicious File | `msfvenom` (payload de teste, ambiente isolado) | Sysmon Event ID 1 (criação de processo), árvore de processo suspeita |

Integração planejada: Sysmon no endpoint Windows para auditoria de criação de processos, complementando os logs nativos de segurança.

---

## Como reproduzir este ambiente

1. Provisionar VM Ubuntu Server (mín. 4GB RAM) e instalar Wazuh (instalação single-node via script oficial).
2. Provisionar endpoint Windows (VM ou físico) e instalar o Wazuh Agent, apontando para o IP do manager.
3. Confirmar no dashboard que o agente está ativo e eventos de segurança estão sendo indexados.
4. Gerar os cenários de teste descritos na Fase 1 e validar a classificação dos alertas.

---

## Evidências

*(adicionar aqui: prints do dashboard do Wazuh mostrando os alertas classificados, print da lista de agentes ativos)*

---

## Tecnologias utilizadas

- Wazuh SIEM 4.9.2 (Manager, Indexer, Dashboard)
- Windows 11 Home — endpoint monitorado
- Kali Linux — host de simulação de ataque (Fase 2)
- Oracle VirtualBox — virtualização
- PowerShell — automação de deploy do agente
