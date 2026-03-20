<p align="center">
  <img src="https://img.shields.io/badge/Azure-Brute--Force%20Defense-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Azure Brute-Force Defense" />
  <img src="https://img.shields.io/badge/AI-GPT--4o--mini-FF6F00?style=for-the-badge&logo=openai&logoColor=white" alt="GPT-4o-mini" />
  <img src="https://img.shields.io/badge/Threat_Hunting-NullClaw-DC143C?style=for-the-badge&logo=target&logoColor=white" alt="NullClaw" />
  <img src="https://img.shields.io/badge/Sentinel-SIEM-5C2D91?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Sentinel" />
</p>

<h1 align="center">Azure Brute-Force SSH Defense</h1>

<p align="center">
  <strong>AI-powered threat hunting and log analysis — no KQL required.</strong><br/>
  Talk to your security logs in plain English. Azure OpenAI does the rest.
</p>

<p align="center">
  <a href="#quick-deploy">Quick Deploy</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#features">Features</a> •
  <a href="#demo-walkthrough">Demo</a> •
  <a href="#project-structure">Structure</a> •
  <a href="#license">License</a>
</p>

---

## What is this?

A **proof-of-concept** that demonstrates how Azure AI can transform security operations. Instead of writing complex KQL queries to hunt threats in your logs, you simply **chat** with an AI assistant that:

- **Queries your Azure Log Analytics** workspace automatically
- **Analyzes SSH brute-force attacks** using GPT-4o-mini
- **Hunts for NullClaw** (a Zig-built attack tool) across Syslog and auditd data
- **Provides actionable recommendations** — severity ratings, remediation steps, posture assessments

> **No KQL knowledge needed.** Just ask: *"Show me who's attacking my server"* — the AI handles the rest.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Azure Resource Group                        │
│                                                                     │
│  ┌──────────────┐    SSH Brute-Force     ┌──────────────────────┐  │
│  │  Defender VM  │◄──────────────────────│   Function App (B1)  │  │
│  │  Ubuntu 22.04 │    SimulateAttack()    │                      │  │
│  │  ── Fail2ban  │                        │  ├─ SimulateAttack   │  │
│  │  ── AMA       │                        │  ├─ AnalyzeLogs      │  │
│  │  ── auditd    │                        │  └─ ChatProxy ──────►├──┤
│  └──────┬───────┘                        └──────────┬───────────┘  │
│         │ Syslog                                     │              │
│         ▼                                            │              │
│  ┌──────────────┐    KQL Queries          ┌─────────┴────────┐    │
│  │ Log Analytics │◄──────────────────────│  Azure OpenAI    │    │
│  │  Workspace    │                        │  GPT-4o-mini     │    │
│  │  ── Sentinel  │                        │  (Managed ID)    │    │
│  └──────────────┘                        └──────────────────┘    │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Frontend — Static Website (Azure Blob Storage)              │  │
│  │  Chat UI → AnalyzeLogs → ChatProxy → GPT-4o-mini response   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

| Component | Purpose |
|---|---|
| **Defender VM** | Ubuntu 22.04 B2s with Fail2ban, Azure Monitor Agent, auditd |
| **Function App** | 3 functions — attack simulation, log analysis, AI chat proxy |
| **Log Analytics** | Centralized log storage with Syslog ingestion via DCRs |
| **Microsoft Sentinel** | SIEM layer for security analytics and hunting |
| **Azure OpenAI** | GPT-4o-mini for natural language log analysis |
| **Static Website** | Chat-based frontend for conversational threat hunting |

---

## Features

### Conversational Threat Hunting
Ask questions in plain English — the AI queries your logs and responds with structured analysis:

```
You:  "Are there any brute-force attacks in the last hour?"
AI:   "I detected 47 failed SSH login attempts from 3 unique IPs.
       Top attacker: 185.220.101.x with 32 attempts targeting 'root'.
       Severity: MEDIUM. Fail2ban has banned 2 of 3 IPs..."
```

### NullClaw Threat Hunting
Automated detection of [NullClaw](https://github.com/nullclaw) — a Zig-compiled attack tool — across 4 vectors:
- **Installation** — git clone / download attempts
- **Compilation** — Zig build commands in Syslog
- **Execution** — Zig-compiled binary signatures in auditd
- **Behavior** — Sub-second SSH brute-force bursts (Zig speed fingerprint)

### Azure OpenAI Integration
- Uses **managed identity** (no API keys in code)
- `DefaultAzureCredential` for zero-secret authentication
- ChatProxy exposes an OpenAI-compatible `/v1/chat/completions` endpoint

### Automated Defense
- **Fail2ban** auto-bans IPs after 3 failed SSH attempts
- **NSG rules** for network-level blocking
- **Severity assessment** — NONE / LOW / MEDIUM / HIGH / CRITICAL
- **Actionable recommendations** generated per analysis

---

## Quick Deploy

### Prerequisites
- Azure subscription with **Contributor** access
- Azure CLI installed (`az login`)
- PowerShell 7+
- Python 3.11+

### Option 1: Bicep Template (Recommended)

Deploy the entire infrastructure with one command:

```powershell
# Clone the repo
git clone https://github.com/el-bakkali/azure-bruteforce-defense.git
cd azure-bruteforce-defense

# Create resource group
az group create --name rg-bruteforce-defense --location uksouth

# Deploy infrastructure
az deployment group create `
  --resource-group rg-bruteforce-defense `
  --template-file infra/main.bicep `
  --parameters adminPassword='YourSecurePassword123!'

# Deploy Function App code
.\post-deploy-config.ps1

# Enable static website & deploy frontend
$storageAccount = (az deployment group show -g rg-bruteforce-defense -n main --query properties.outputs.storageAccountName.value -o tsv)

az storage blob service-properties update `
  --account-name $storageAccount `
  --static-website --index-document index.html --auth-mode login

az storage blob upload `
  --account-name $storageAccount `
  --container-name '$web' `
  --file frontend/index.html `
  --name index.html `
  --content-type "text/html" --auth-mode login --overwrite
```

### Option 2: PowerShell Scripts (Step-by-step)

```powershell
# 1. Deploy infrastructure (VM, Function App, LAW, Sentinel, NSG, DCRs)
.\deploy-infrastructure.ps1

# 2. Deploy Function App code
.\post-deploy-config.ps1

# 3. (Optional) Deploy Sentinel analytics rules
.\deploy-sentinel-rules.ps1
```

### Function App: Remote Build (Recommended)

The Function App uses **remote build** — Azure installs Python dependencies on its Linux servers during deployment. This avoids cross-platform issues (e.g. developing on Windows, deploying to Linux) and removes the need for any local build step.

**Enable remote build** (one-time setup):
```powershell
az functionapp config appsettings set `
  --name <funcApp> --resource-group rg-bruteforce-defense `
  --settings `
    SCM_DO_BUILD_DURING_DEPLOYMENT=true `
    ENABLE_ORYX_BUILD=true `
    WEBSITE_RUN_FROM_PACKAGE=0
```

**Deploy from VS Code:**
1. Install the [Azure Functions extension](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurefunctions)
2. Open the `function-app/` folder
3. Right-click in the Azure sidebar > **Deploy to Function App** > select your app
4. Azure runs `pip install -r requirements.txt` on the server — no local `.venv` or `.python_packages` needed

> The `.funcignore` file excludes `.venv`, `.python_packages`, `.github`, and other local-only files from the deployment package.

### Post-Deployment: Azure OpenAI Setup (if using Option 2)

1. **Create Azure OpenAI resource** in the Azure portal
2. **Deploy gpt-4o-mini** model (GlobalStandard SKU)
3. **Assign role** to Function App managed identity:
   ```powershell
   az role assignment create `
     --assignee (az functionapp identity show -g rg-bruteforce-defense -n <funcApp> --query principalId -o tsv) `
     --role "Cognitive Services OpenAI User" `
     --scope (az cognitiveservices account show -g rg-bruteforce-defense -n <openAiName> --query id -o tsv)
   ```
4. **Set app settings**:
   ```powershell
   az functionapp config appsettings set `
     -g rg-bruteforce-defense -n <funcApp> `
     --settings `
       AZURE_OPENAI_ENDPOINT="https://<name>.openai.azure.com/" `
       AZURE_OPENAI_DEPLOYMENT="gpt-4o-mini"
   ```

---

## Demo Walkthrough

### 1. Open SSH for Attack Simulation
```
Azure Portal → NSG → Inbound rules → AllowSSH → Source: Any → Save
```

### 2. Simulate Brute-Force Attack
```http
POST https://<funcApp>.azurewebsites.net/api/SimulateAttack?code=<key>
Content-Type: application/json

{ "target": "<vmIp>", "username": "root", "attempts": 20 }
```

### 3. Analyze with AI
Open the frontend at `https://<storageAccount>.z33.web.core.windows.net/`

- Enter your Function App URL and function key
- Click **"Attack Summary (1h)"** → AI analyzes the brute-force data
- Click **"NullClaw Hunt"** → scans for advanced threat indicators
- Or just ask: *"What should I do to improve security?"*

### 4. Explore in Sentinel
```
Azure Portal → Sentinel → Hunting → Run hunting queries
Log Analytics → Syslog | where SyslogMessage has "Failed password"
```

### 5. Lock Down
```
Azure Portal → NSG → AllowSSH rule → Delete (or restrict source IP)
```

---

## Project Structure

```
azure-bruteforce-defense/
│
├── infra/
│   ├── main.bicep                    # Bicep IaC — full stack deployment
│   └── main.parameters.json          # Parameter file (customize per env)
│
├── function-app/
│   ├── host.json                     # Azure Functions host config
│   ├── requirements.txt              # Python: azure-functions, azure-identity,
│   │                                 #         azure-monitor-query, paramiko
│   ├── AnalyzeLogs/
│   │   └── __init__.py               # Log analysis + NullClaw threat hunting
│   ├── ChatProxy/
│   │   └── __init__.py               # Azure OpenAI proxy (managed identity)
│   └── SimulateAttack/
│       └── __init__.py               # SSH brute-force simulation (paramiko)
│
├── frontend/
│   └── index.html                    # Chat UI — conversational threat hunting
│
├── nullclaw-func/                    # NullClaw custom handler (experimental)
│   ├── host.json
│   ├── syslog-hunter-prompt.md
│   └── ...
│
├── deploy-infrastructure.ps1         # Full infrastructure deployment
├── post-deploy-config.ps1            # Function App code deployment
├── setup-fail2ban.sh                 # Fail2ban + auditd on Defender VM
├── deploy-sentinel-rules.ps1         # Sentinel analytics rules
├── alerts-guide.md                   # Alert configuration guide
└── README.md
```

---

## API Reference

### `POST /api/AnalyzeLogs`

Query Log Analytics for SSH attack data or run NullClaw threat hunts.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `hours` | int | `1` | Lookback window (1–168 hours) |
| `hunt` | string | — | Set to `"nullclaw"` for threat hunting |
| `query` | string | — | Custom KQL query (advanced users) |

**Response** — structured report with severity, attacker IPs, Fail2ban actions, recommendations.

### `POST /api/v1/chat/completions`

OpenAI-compatible chat completions (proxied to Azure OpenAI via managed identity).

| Parameter | Type | Description |
|---|---|---|
| `messages` | array | Chat messages `[{role, content}]` |
| `max_tokens` | int | Max response tokens |
| `temperature` | float | Creativity (0.0–2.0) |

### `POST /api/SimulateAttack`

Simulate SSH brute-force against the Defender VM.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `target` | string | env var | VM IP address |
| `username` | string | `root` | SSH username |
| `attempts` | int | `15` | Number of attempts (max: 50) |

---

## Security Design

| Aspect | Implementation |
|---|---|
| **No hardcoded secrets** | All auth via managed identity + `DefaultAzureCredential` |
| **No secrets in frontend** | Function key entered at runtime, stored in browser localStorage only |
| **Azure AD authentication** | Function App → Azure OpenAI uses AAD tokens, never API keys |
| **Network isolation** | NSG controls SSH access; locked down after demo |
| **RBAC least privilege** | Functions get only required roles (Log Analytics Reader, OpenAI User) |
| **HTTPS enforced** | All endpoints require TLS |

---

## Cost Estimate

| Resource | SKU | ~Monthly Cost |
|---|---|---|
| Defender VM | Standard_B2s | ~$30 |
| Function App | B1 (Linux) | ~$13 |
| Log Analytics | Pay-per-GB | ~$2–5 |
| Azure OpenAI | GPT-4o-mini (10K TPM) | ~$1–3 |
| Storage | Standard LRS | < $1 |
| **Total** | | **~$47–52/month** |

> **Tip:** Deallocate the VM when not demoing to cut costs by ~$30/month.

---

## Cleanup

```powershell
az group delete --name rg-bruteforce-defense --yes --no-wait
```

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

<p align="center">
  Built by <a href="https://github.com/el-bakkali">El Bakkali</a> — Azure Security & AI
</p>
