# 🛡️ Laboratório de Engenharia de Detecção: Implementação, Auditoria e Análise de Ataques com Wazuh SIEM

## 📝 Descrição do Projeto
Este projeto documenta a criação de um homelab avançado de segurança cibernética utilizando o **Wazuh SIEM**. O objetivo é construir um ambiente controlado para engenharia de detecção, análise de telemetria de endpoints e validação de regras de segurança baseadas em cenários reais de ameaças.

O laboratório foi estruturado estrategicamente em fases evolutivas, simulando o amadurecimento de um Centro de Operações de Segurança (SOC) corporativo:
*   **Fase 1:** Centralização de Logs, Auditoria de Identidade e Baseline de Telemetria Local.
*   **Fase 2 (Em Desenvolvimento):** Simulação de Ataques Ativos (Red Team) com Kali Linux e Engenharia de Detecção Avançada (Blue Team).

---

## 🎯 Objetivos de Aprendizado e Prática
A implementação deste laboratório visa consolidar conceitos práticos fundamentais para o mercado de Cybersecurity, alinhados com matrizes globais de conhecimento (como os objetivos de gerenciamento de vetores de ataque, ferramentas de segurança e mitigação da certificação CompTIA Security+):
*   Compreensão de vetores de ataque, atores de ameaça e suas motivações.
*   Análise técnica de logs e telemetria de sistemas operacionais.
*   Configuração e deploy de agentes SIEM/XDR em ambientes híbridos.
*   Mapeamento de comportamentos maliciosos utilizando a matriz **MITRE ATT&CK**.
*   Auditoria de conformidade regulatória (PCI DSS, GDPR/LGPD).

---

## 🏗️ Arquitetura do Laboratório
O ambiente utiliza uma estrutura híbrida para simular a segmentação de redes corporativas:

*   **SIEM Manager (Blue Team Server):** Instalação central do Wazuh hospedada em uma Máquina Virtual Linux (Ubuntu Server) via Oracle VirtualBox (IP: `192.168.1.23`), configurada em modo *Bridge*.
*   **Endpoint Monitorado (Agente Local):** Máquina física operando **Windows 11 Home** (IP: `192.168.1.15`), atuando como o alvo principal de monitoramento e auditoria.
*   **Atacante (Red Team Server - Fase 2):** Máquina Virtual dedicada rodando **Kali Linux**, simulando um agente de ameaça externo ou persistido na rede local.

---

## 🚀 Fase 1: Centralização de Logs, Auditoria Local e Baseline

### 1. Preparação do Servidor e Infraestrutura
*   Configuração da interface de rede da máquina virtual em modo *Bridge* para garantir visibilidade e roteamento direto na sub-rede física.
*   Deploy e validação do ecossistema central do Wazuh (Indexer, Server e Dashboard).

### 2. Implantação do Agente no Endpoint Windows
A distribuição e provisionamento do agente no endpoint físico foram automatizados via terminal administrativo usando **PowerShell**:

```powershell
# Download e instalação silenciosa do agente apontando para o servidor manager
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.1.23' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Meu-Windows-Fisico'

# Inicialização do serviço do agente
NET START WazuhSvc
```
### 3. Simulação de Ameaça Local: Abuso de Autenticação (PoC)
Para homologar a integridade do canal de logs e validar a resposta do SIEM, simulou-se um comportamento suspeito de Erros de Autenticação Interativa.
*   O teste Prático: Bloqueio de sessão local (Windows + L) seguido pela geração intencional de 4 falhas consecutivas de login, seguidas por uma autenticação bem-sucedida.
*   Resultados no Dashboard: O motor do Wazuh capturou em tempo real as falhas (Evento de Auditoria Nativo do Windows 4625) mapeando-as sob a Regra ID 60122 (Nível 5), seguido pela elevação de privilégios interativos após o acesso legítimo (Regra ID 60110 (Nível 8)).

### 4. Análise Técnica do Evento (JSON do Alerta)
Abaixo está o trecho do log bruto processado e indexado pelo Wazuh, demonstrando como o SIEM normaliza os dados do Windows para os analistas de SOC:

```json
{
  "_index": "wazuh-alerts-4.x-2026.07.17",
  "agent": {
    "ip": "192.168.1.15",
    "name": "Meu-Windows-Fisico",
    "id": "001"
  },
  "data": {
    "win": {
      "eventdata": {
        "logonType": "2",
        "ipAddress": "127.0.0.1",
        "subjectUserName": "TOTE$",
        "status": "0xc000006d"
      },
      "system": {
        "eventID": "4625",
        "channel": "Security",
        "severityValue": "AUDIT_FAILURE",
        "computer": "Tote"
      }
    }
  },
  "rule": {
    "level": 5,
    "description": "Logon Failure - Unknown user or bad password",
    "id": "60122",
    "mitre": {
      "technique": ["Account Access Removal"],
      "id": ["T1531"],
      "tactic": ["Impact"]
    }
  }
}
```
### Indicadores Técnicos Extraídos:
*   logonType: 2: Confirma que a tentativa foi um Logon Interativo (feito localmente na máquina).
*   eventID: 4625: Código nativo do Windows para falhas de autenticação.
*   severityValue: AUDIT_FAILURE: O sistema identificou e registrou a quebra de conformidade na tentativa de acesso.

---

## 🎯 Fase 2: Simulação de Ataques Ativos (Red Team) e Detecção Avançada

> ⚠️ **Nota de Escopo:** Esta fase está em desenvolvimento ativo no homelab. Os cenários abaixo mapeiam o planejamento de testes de intrusão internos para validação das regras de correlação de rede do Wazuh.

### 1. Planejamento de Vetores de Ataque (Kali Linux)
As simulações serão executadas a partir do host atacante baseado em **Kali Linux**, focando nos seguintes objetivos táticos:
*   **Reconhecimento Ativo (Port Scanning):** Execução de varreduras de portas e serviços via `nmap` para identificar portas abertas (ex: RDP 3389, SMB 445) no endpoint alvo.
*   **Ataque de Força Bruta de Rede (Credential Stuffing):** Tentativas automatizadas de login remoto via protocolo RDP ou SMB utilizando a ferramenta `hydra`.
*   **Entrega de Payload e Persistência:** Geração de um agente de acesso reverso (backdoor) via `msfvenom` (Metasploit) para validar a capacidade do XDR do Wazuh em detectar binários não assinados em execução.

### 2. Engenharia de Detecção Esperada (Blue Team)
Para cada ataque simulado, o monitoramento será refinado através do mapeamento de logs específicos:
*   Detecção de tráfego anômalo e picos de conexão na mesma porta em curto intervalo de tempo.
*   Monitoramento do Event ID `4625` do Windows com `logonType: 3` (Logon de Rede), diferenciando a força bruta remota do erro interativo local mapeado na Fase 1.
*   Integração do **Sysmon** (System Monitor) no endpoint para auditoria de criação de processos (`Event ID 1`) causados por payloads gerados no Kali.

---

## 📊 Mapeamento Global e Compliance Regulatório
Toda a atividade registrada no laboratório (tanto local quanto as simulações de rede) é correlacionada pelo motor do SIEM com padrões de mercado:
*   **MITRE ATT&CK:** Mapeamento direto com as táticas de **Initial Access** (Acesso Inicial - T1110 / Brute Force), *Privilege Escalation* (Elevação de Privilégio) e *Impact* (T1531).
*   **Conformidade de Dados:** Validação automática de conformidade com os requisitos **PCI DSS (10.2.4 e 10.2.5)** e diretrizes de auditoria da **GDPR / LGPD** para controle restrito de acessos.

---

## 🛠️ Tecnologias Utilizadas
*   **Wazuh SIEM v4.9.2** (Manager, Indexer & Dashboard)
*   **Windows 11 Home** (Endpoint Monitorado / Auditoria de Eventos)
*   **Kali Linux** (Plataforma de Simulação de Adversários / Red Team)
*   **Oracle VirtualBox** (Hipervisor / Virtualização do Ambiente)
*   **PowerShell** (Automação de deploys e gerência de serviços locais)
