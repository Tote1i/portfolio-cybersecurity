# 🛡️ Laboratório de Defesa Cibernética: Implementação e Monitoramento com Wazuh SIEM

## 📝 Descrição do Projeto
Este projeto documenta a criação de um laboratório prático de monitoramento de segurança utilizando o **Wazuh SIEM**. O objetivo foi implementar uma estrutura centralizada para coleta, análise e correlação de eventos de segurança de endpoints em tempo real, mapeando ameaças diretamente com frameworks internacionais de segurança.

---

## 🏗️ Arquitetura do Laboratório
O ambiente foi estruturado de forma híbrida utilizando virtualização e sistemas físicos para simular um cenário real de monitoramento corporativo:

*   **SIEM Manager (Servidor):** Wazuh Manager hospedado em uma Máquina Virtual (Linux) através do Oracle VirtualBox (IP: `192.168.1.23`).
*   **Endpoint Monitorado (Agente):** Máquina física rodando **Windows 11 Home** (IP: `192.168.1.15`), configurada com o agente leve do Wazuh para envio de logs.

---

## 🚀 Passo a Passo da Implementação

### 1. Preparação do Servidor
*   Configuração da máquina virtual no VirtualBox utilizando placas de rede em modo *Bridge* para permitir a comunicação direta entre a rede física e o servidor SIEM.
*   Instalação e validação do ecossistema central do Wazuh (Indexer, Server e Dashboard).

### 2. Implantação do Agente no Windows
A instalação no endpoint físico foi realizada de forma silenciosa via terminal administrativo utilizando o **PowerShell**:

```powershell
# Download e instalação silenciosa do agente apontando para o servidor manager
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.1.23' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Meu-Windows-Fisico'

# Inicialização do serviço do agente
NET START WazuhSvc
```
---

## 🔍 Simulação de Ataque e Análise de Logs (PoC)

Para validar a eficácia das regras de detecção do SIEM, foi realizada uma simulação de **Ataque de Força Bruta / Erros de Autenticação Interativa**.

### O Teste Prático
1. A tela do endpoint Windows foi bloqueada (`Windows + L`).
2. Foram geradas sequencialmente **4 falhas de logon intencionais** com credenciais incorretas, seguidas por um logon com sucesso.

### Resultados no Dashboard do SIEM
O comportamento disparou imediatamente alarmes no painel de **Threat Hunting** do Wazuh, gerando a correlação automática dos seguintes eventos estruturados:

*   **Logon Failure (Regra ID: 60122 | Nível 5):** Captura exata do evento de auditoria `4625` do Windows.
*   **User Account Changed / Special Privileges (Regra ID: 60110 | Nível 8):** Alerta gerado assim que o usuário legítimo reconectou e recebeu privilégios interativos pós-falhas.

---

## 🔬 Análise Técnica do Evento (JSON do Alerta)
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
*   **`logonType: 2`**: Confirma que a tentativa foi um **Logon Interativo** (feito localmente na máquina).
*   **`eventID: 4625`**: Código nativo do Windows para falhas de autenticação.
*   **`severityValue: AUDIT_FAILURE`**: O sistema identificou e registrou a quebra de conformidade na tentativa de acesso.

---

## 📊 Mapeamento e Compliance Regulatório
O motor do Wazuh correlacionou o evento automaticamente com matrizes globais de segurança da informação:
*   **MITRE ATT&CK:** Identificado nas táticas de **Initial Access** (Acesso Inicial), *Privilege Escalation* (Elevação de Privilégio) e *Impact*.
*   **Conformidade de Dados:** Mapeado sob as normas internacionais **PCI DSS (10.2.4 e 10.2.5)** e **GDPR (IV_32.2)** para controle e auditoria de acessos inválidos.

---

## 🛠️ Tecnologias Utilizadas
*   **Wazuh SIEM v4.9.2** (Manager, Indexer & Dashboard)
*   **Windows 11 Home** (Endpoint / Auditoria de Eventos)
*   **Oracle VirtualBox** (Ambiente de Virtualização)
*   **PowerShell** (Automação de deploy e gerenciamento de serviços)
