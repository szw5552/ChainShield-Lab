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

## Phase 2 本機工具與 hosted API 驗證紀錄（2026-05-27）

### Snyk / Socket CLI flags 與 fallback 行為

**本機確認日期**: 2026-05-27T04:19:06+08:00。

**本機命令與觀察結果**:

| Tool | Command | Observed behavior | Phase 2 decision impact |
|------|---------|-------------------|-------------------------|
| Snyk | `snyk --version` | `command not found: snyk` | live Snyk 為 optional runtime dependency；本機未安裝時不得阻擋 fixture-first demo，但 live mode 應產生 `manual_review` 或 fallback 到 sanitized fixture evidence。 |
| Snyk | `snyk test --help` | `command not found: snyk` | 無法本機確認目前 CLI flags；實作 adapter 必須隔離 CLI invocation，並以 fixture mode 作為可重現路徑。 |
| Socket | `socket --version` | `command not found: socket` | live Socket 為 optional runtime dependency；本機未安裝時不得阻擋 fixture-first demo。 |
| Socket | `socket scan create --help` | `command not found: socket` | 無法本機確認目前 CLI flags；保留官方文件命令作為 live adapter 預期，並要求 runtime evidence 記錄 unavailable。 |
| Socket | `socket ci --help` | `command not found: socket` | 無法本機確認 exit code；Supervisor 僅可依 sanitized fixture 或 adapter classification table 判斷。 |

**官方文件依據**:

- Snyk CLI `test`: <https://docs.snyk.io/developer-tools/snyk-cli/commands/test>
- Socket scan: <https://docs.socket.dev/docs/socket-scan>
- Socket CI: <https://docs.socket.dev/docs/socket-ci>

**Socket exit-code classification table**:

| Classification | Example source | Supervisor status | Required evidence |
|----------------|----------------|-------------------|-------------------|
| `policy_failure` | `socket ci` policy/security/license failure 或 fixture 中明確 policy violation | `deny` | sanitized command summary、exit code、policy reason 或 fixture path |
| `auth_or_network_unavailable` | CLI 未登入、token 缺失、DNS/TLS/service unavailable | `manual_review`，若 config 提供對應 sanitized fixture report 則 fallback 並標示 `live_unavailable` | start/end time、exit code/stderr classification、fixture fallback path（若有） |
| `parse_or_schema_error` | JSON 無法解析或缺少必要欄位 | `manual_review` | parser error、source path、sanitized raw summary（不可保存 raw log） |
| `timeout` | live command 超過 120 秒 | `manual_review` | start/end time、timeout reason、sanitized command summary |
| `unknown_exit_code` | 無法映射的非 0 exit code | `manual_review` | exit code、sanitized command summary、next action |

**Fallback 規則**: live Snyk/Socket unavailable 時，若 demo config 提供 sanitized fixture report，Supervisor 可使用 fixture evidence 完成決策並在 evidence reasons 標示 `live_unavailable`；若缺少 fixture 或 scanner mode 為 `skip` 且無其他明確 deny，輸出 `manual_review` 並將對應 gate 放入 `missing_gates`。

### OpenShell / NemoClaw CLI、policy schema 與 OrbStack readiness（Phase 2 初始紀錄）

**本機確認日期**: 2026-05-27T04:19:06+08:00。

**本機命令與觀察結果**:

| Tool | Command | Observed behavior | Phase 2 decision impact |
|------|---------|-------------------|-------------------------|
| OpenShell | `openshell --version` / `openshell --help` | `command not found: openshell` | live sandbox mode 不可執行；不得 host fallback；需使用 sanitized fixture 或 manual verification path 產生 `manual_review`。 |
| NemoClaw | `nemoclaw --version` / `nemoclaw --help` | `command not found: nemoclaw` | 無法本機確認 NemoClaw wrapper flags；實作不得硬編未驗證 flags。 |
| OrbStack | `orb version` | `Version: 2.1.3 (2010300)`，commit `7a3258b...` | OrbStack CLI 存在，但 OpenShell/NemoClaw 缺失時 readiness 仍失敗。 |
| Docker | `docker --version` | `Docker version 29.4.0, build 9d7ad9f` | 僅作 OrbStack Docker-compatible runtime readiness 訊號；不得回退為未經 spec 授權的一般 Docker flow。 |

**官方文件依據**:

- OpenShell policy schema reference: <https://docs.nvidia.com/openshell/reference/policy-schema>
- OpenShell network policy tutorial: <https://docs.nvidia.com/openshell/latest/get-started/tutorials/first-network-policy>

**Policy schema 觀察**: OpenShell policy YAML top-level 包含 `version`、`filesystem_policy`、`landlock`、`process`、`network_policies`。filesystem policy path 必須為 absolute path、不得包含 `..` traversal，且未列入 read-only/read-write 的 path 應視為不可存取；network policies 用於定義 binary 可連線目標，因此本 PoC policy 應 default-deny egress，並只允許合成測試目的地的阻擋證據被記錄。Phase 2 初始環境尚未安裝 OpenShell/NemoClaw，因此當時不硬編 sandbox command flags，僅保留 adapter/readiness 安全失敗行為；後續 OpenShell 0.0.44 live 行為以本節下方補充紀錄為準。

**Host fallback 禁止**: live sandbox readiness 需要 OrbStack/Docker-compatible runtime 與 OpenShell/NemoClaw 皆可用；缺任一項時輸出 `manual_review`，不得執行 host `npm install`，不得改用未經 spec 明確授權的一般 Docker runtime。

### OpenShell 0.0.44 live sandbox 驗證補充

**本機確認日期**: 2026-05-27T17:19:07Z。

**背景**: Phase 2 初始紀錄顯示本機當時未安裝 OpenShell/NemoClaw，因此只保留 readiness failure 與 fixture fallback 設計。後續安裝 NemoClaw/OpenShell 後，本輪以 OpenShell `0.0.44`、OrbStack Docker runtime 與 `policies/openshell-npm-install.yaml` 驗證 live sandbox 行為；以下紀錄 supersede Phase 2 對 OpenShell CLI 不可用的實作限制，但不改變 host fallback 禁止原則。

**本機命令與觀察結果**:

| Tool / 行為 | Command summary | Observed behavior | Decision impact |
|-------------|-----------------|-------------------|-----------------|
| OpenShell version | `openshell --version` | `openshell 0.0.44` | live sandbox mode 可執行；仍需 OrbStack readiness 與 host fallback 禁止。 |
| Create/upload flags | `openshell sandbox create --help` | `--upload <LOCAL_PATH>[:<SANDBOX_PATH>]` 存在，但本版本不接受多個 `--upload`。 | Demo wrapper 必須先建立單一 bundle，再用單一 `--upload` 上傳。 |
| Exec flags | `openshell sandbox exec --help` | 支援 `--name`、`--no-tty`、`--workdir` 與 command args；`sandbox connect -- sh ...` 不適用。 | live log collection 與 canary probe 使用 `sandbox exec --name ... --no-tty -- sh -lc ...`。 |
| `/workspace` upload | `--upload <fixtures>:/workspace` | `mkdir: cannot create directory '/workspace': Permission denied`。 | 不使用 `/workspace` 作為 live demo path。 |
| 多個 upload | 多次 `--upload` | `the argument '--upload <UPLOAD>' cannot be used multiple times`。 | 必須使用單一 bundle。 |
| `/tmp` upload | `--upload <bundle>:/tmp` | 成功，且 OpenShell proxy mode baseline 會放行 `/tmp`。 | 可作 demo bundle 目的地，但放在 `/tmp` 的 canary 不會自然觸發 OpenShell filesystem deny。 |
| `/sandbox` upload | `--upload <canary>:/sandbox/...` | 成功，但 `/sandbox` 為 baseline 可讀區，canary 可被讀出。 | 不可宣稱 `/sandbox` 內 canary 形成 OpenShell policy file-read deny。 |
| `/home/sandbox` / `/var/tmp` upload | `--upload <canary>:/home/sandbox/...` / `/var/tmp/...` | upload 失敗，permission denied。 | 不採用作為免 custom image 的 canary 放置點。 |
| Default-deny egress | live `npm install --ignore-scripts=false --install-links` | OCSF `NET:OPEN [MED] DENIED` 觀察到 `registry.npmjs.org:443` 與 `chainshield-egress-test.invalid:443`。 | `network_egress` evidence 可由 OpenShell OPA deny log 滿足。 |
| Filesystem read fallback | sandbox 內 `chmod 000 <synthetic canary>` 後以 postinstall / exec probe 讀取 | 讀取失敗可轉為 `filesystem_read` evidence，`policy_rule_id="manual_probe.permission_denied"`。 | 本 PoC 不採用 custom OpenShell image；live filesystem evidence 以 chmod-hardened synthetic canary probe 誠實標記，不宣稱為原生 OCSF FILE deny。 |

**成功 run 紀錄**: `run-20260527T171906573747Z-2f26c3f6ae03` 的 OpenShell gate 為 `pass`，包含三筆 `network_egress` deny event 與一筆 `filesystem_read` event；filesystem event 的 `policy_rule_id` 為 `manual_probe.permission_denied`，artifact path 為 runtime output `reports/sandbox/openshell-live-run-20260527T171906573747Z-2f26c3f6ae03.log`，不得提交到 git。

**安全結論**:

- Live sandbox demo 不使用 custom OpenShell image。
- Host `npm install` 與 host `postinstall` 仍禁止。
- Synthetic canary stdout 不得保存；若 canary probe 意外成功，只能保存 redacted 訊號並輸出 `manual_review`。
- `sandbox_demo_override` 只允許 containment demonstration；即使 OpenShell gate `pass`，Snyk/Socket static `deny` 仍維持最終 `deny`。

### NVIDIA Nemotron hosted API 驗證

**本機確認日期**: 2026-05-27T04:19:06+08:00。

**官方文件依據**:

- NVIDIA NIM LLM API Reference: <https://docs.nvidia.com/nim/large-language-models/2.0.5/reference/api-reference.html>
- NVIDIA Build model card: <https://build.nvidia.com/nvidia/nemotron-3-nano-30b-a3b/modelcard>

**官方文件觀察**: NVIDIA NIM LLM API Reference 說明 NIM exposes OpenAI-compatible inference endpoints，包含 `POST /v1/chat/completions`、`POST /v1/completions` 與 `GET /v1/models`。Build model card 顯示模型 ID `nvidia/nemotron-3-nano-30b-a3b`，且模型定位為可下載/部署的 NVIDIA Nemotron 3 Nano 30B A3B model。

**本機 smoke/manual check**:

| Check | Command summary | Observed behavior | Decision |
|-------|-----------------|-------------------|----------|
| Models endpoint | `GET https://integrate.api.nvidia.com/v1/models`（未帶 token） | HTTP `200`，response model list 包含 `nvidia/nemotron-3-nano-30b-a3b` | 保留 plan 暫定預設 `NEMOTRON_BASE_URL=https://integrate.api.nvidia.com/v1` 與 `NEMOTRON_MODEL=nvidia/nemotron-3-nano-30b-a3b`。 |
| Authenticated chat completion | `POST /v1/chat/completions` with `Authorization: Bearer $NVIDIA_API_KEY` | 本機未提供 `NVIDIA_API_KEY`，未執行 authenticated request | Worker provider 應輸出 sanitized provider failure evidence，然後依序 fallback：`codex_subagent` -> `claude_subagent` -> `manual_review`。 |

**必要 headers 與 redaction**: live request 必須使用 `Content-Type: application/json` 與 `Authorization: Bearer $NVIDIA_API_KEY`；任何 artifact、error、command summary、agent invocation evidence 不得保存 token 值，需將 bearer/API key value 替換為 `[REDACTED]`。

**Timeout/error response 規則**: 每個 provider attempt 預設 `timeout_seconds=60`。401/403、429、5xx、timeout、JSON parse failure 或 missing `NVIDIA_API_KEY` 均產生 provider failure evidence；Worker provider failure 只能支援 `manual_review` 或 fallback evidence，不能直接改判 Supervisor `allow`/`deny`。
