# 研究紀錄 (Research): OrbStack 優先的 npm 供應鏈防禦 PoC

**Feature**: `001-orbstack-sandbox-gates`  
**日期**: 2026-05-27  
**輸入來源**: `spec.md`、`todo.md`、官方文件與本機可用工具檢查。

## Decision: 使用 Python 3.11+ 作為 Supervisor 與 demo orchestration 主體

**Rationale**: 本功能核心是讀取 JSON/YAML/file artifacts、驗證 schema、整理 scanner/sandbox evidence，並套用 deterministic 決策矩陣；Python 可用最少程式碼完成 CLI、parser、schema validation 與 pytest TDD。使用者也明確偏好 Python script 版本。Node.js/npm 僅作為 fixture 與 package lifecycle 展示，不承擔 Supervisor 判斷。

**Alternatives considered**:

- Bash-only orchestration：較快但不利於 schema 驗證、錯誤分類、fixture tests 與跨平台維護。
- Node.js Supervisor：與 npm 生態一致，但本 PoC 不需要 JS runtime 以外的更多 app logic，且 Python 對檔案/JSON 測試更直接。
- 長駐 service/API：超出展示型 PoC 範圍，增加部署與安全面。

## Decision: 採 OrbStack-first Docker 相容 runtime；不可用時停止 live sandbox demo

**Rationale**: `todo.md` 指出 NemoClaw/OpenShell 需要 Docker/容器能力，feature spec 已確認 OrbStack 是 macOS 本機展示優先路徑。安全上不可在 host 直接執行惡意 `postinstall`；因此 readiness gate 必須在 live sandbox install 前確認 OrbStack/Docker 與 OpenShell 可用。若 OrbStack 不可用，流程改用 sanitized fixture reports 與手動驗證說明，不執行 live install。

**Alternatives considered**:

- Docker Desktop/Colima fallback：可增加相容性，但會讓 demo 環境矩陣變大；本 feature 只承諾 OrbStack 優先與 fixture fallback。
- Host execution fallback：違反 safety boundary，已拒絕。
- 遠端 sandbox：需要憑證與網路服務，超出 PoC 範圍。

## Decision: Snyk gate 以 `snyk test --json --severity-threshold=high` 或 sanitized fixture evidence 評估

**Rationale**: PoC 的第一層防線是 high/critical CVE gate。live mode 會在 npm fixture 目錄中執行 Snyk CLI 並保存 JSON 報告；fixture mode 使用已清理報告，在無 token、無登入或無網路時仍可重現 Supervisor 判讀。Snyk CLI 旗標需在實作任務以官方文件與本機 `snyk test --help` 再確認，避免 CLI 版本差異破壞 demo。

**Alternatives considered**:

- 僅使用 live Snyk：展示環境依賴 token/網路，無法保證可重現。
- 僅使用 fixture：無法示範真實 scanner integration；保留作為 fallback 而非唯一模式。
- 以 npm audit 取代 Snyk：不符合本 PoC 三 gate 範圍。

**參考**: Snyk CLI `test` 官方文件：<https://docs.snyk.io/developer-tools/snyk-cli/commands/test>

## Decision: Socket gate 優先保存 `socket scan create --report --json` 報告，`socket ci` 可作 CI-like policy exit code 檢查

**Rationale**: Socket 官方文件描述 `socket scan create --report` 會等待 scan 完成並產生 report，`--json` 可輸出 JSON；`socket ci` 是適合自動化 policy check 的命令，若 scan 不符合 security/license policy exit code 會非 0。Supervisor 應同時支援 fixture JSON 與 live command result，並將 `healthy: false`、policy violation 或非 0 exit code 正規化為 Socket deny evidence。

**Alternatives considered**:

- 只用 `socket ci`：適合 pass/fail，但不一定提供足夠機器可讀 report artifact。
- 只用 `socket scan create` 不等待 report：無法保證 Supervisor 有完整 evidence。
- 將 Socket 視為本地惡意 JS static analyzer：不符合 Socket gate 的展示定位，已拒絕。

**參考**: Socket scan 官方文件：<https://docs.socket.dev/docs/socket-scan>；Socket CI 官方文件：<https://docs.socket.dev/docs/socket-ci>

## Decision: OpenShell policy 使用 allowlist 與 default-deny egress；NemoClaw/OpenShell CLI 以 adapter 隔離

**Rationale**: OpenShell 官方 policy schema 包含 `filesystem_policy`、`process` 與 `network_policies` 等區段，網路教學描述可建立 sandbox、觀察 default-deny，再套用細粒度 network policy。本 PoC 只需證明 sandbox 內合成 canary secret 讀取失敗與合成外連目的地被拒絕；policy 應保存在 `policies/openshell-npm-install.yaml`，但實作前必須依本機 OpenShell/NemoClaw 版本驗證 binary path、policy schema 與 sandbox command flags。

**Alternatives considered**:

- 在 plan 中硬編 NemoClaw command：目前本機未安裝 `openshell`/`nemoclaw`，且 CLI 介面可能變動；為避免文件誤導，改由 adapter 與實作任務驗證。
- 使用 OS-level host firewall/demo script：不等同 OpenShell containment，且可能污染宿主機設定。
- 將真實 host secret mount 進 sandbox：違反安全邊界，已拒絕；僅允許合成 canary fixture。

**參考**: OpenShell policy schema：<https://docs.nvidia.com/openshell/reference/policy-schema>；OpenShell network policy tutorial：<https://docs.nvidia.com/openshell/latest/get-started/tutorials/first-network-policy>

## Decision: Supervisor 決策以 JSON Schema contract 固定輸入/輸出

**Rationale**: `allow`、`deny`、`manual_review` 是 PoC 的主要 user-facing result，需要讓審查者不重跑 demo 也能理解原因。JSON Schema 可作為 contract tests，確保 decision artifact 包含 result、reasons、evidence refs、missing gates、timestamps 與 next actions；Markdown summary 僅作人類可讀輔助。

**Alternatives considered**:

- Free-form Markdown only：易讀但不可自動驗證。
- Database record：超出 PoC 需求且增加清理/敏感資料風險。
- LLM-only narrative decision：不可重現，違反 evidence-driven gate。

## Decision: Demo config invalid 時先產生 `manual_review`，且禁止 scanner/sandbox 執行

**Rationale**: Spec 已明確要求 demo config 驗證失敗不可執行 scanner 或 sandbox。此設計能避免路徑錯誤、未清理 fixture、錯誤 sandbox mode 或輸出目錄污染導致安全風險。`manual_review` decision 應指出 config validation errors 與 required next actions。

**Alternatives considered**:

- 使用隱含預設補齊 config：可能意外執行 live scanner 或 sandbox install，已拒絕。
- 只回傳 process error 不產生 decision artifact：會破壞 evidence traceability，已拒絕。
