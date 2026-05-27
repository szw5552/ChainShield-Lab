# 快速開始 (Quickstart): OrbStack 優先的 npm 供應鏈防禦 PoC

**Feature**: `001-orbstack-sandbox-gates`  
**安全提醒**: 不得在宿主機直接執行惡意 fixture 的 `postinstall`。PoC-only `postinstall` 只能嘗試合成 canary secret 讀取與合成測試目的地 egress；live install-time demo 只能在通過 OrbStack/OpenShell readiness 的 sandbox/container flow 中執行。

## 1. 安全展示路徑總覽

本 PoC 有四種展示路徑：

1. **Fixture-first 決策展示**：使用已清理 Snyk/Socket/OpenShell reports，不需要 scanner token，也不執行 live sandbox install。
2. **Live scanner gate 展示**：在 npm fixture 上執行 Snyk/Socket，將 live reports 交給 Supervisor 判讀。
3. **OrbStack live sandbox 展示**：只在 OrbStack、Docker 相容 runtime 與 OpenShell/NemoClaw 均通過 readiness 時執行，並只讀取合成 canary secret fixture。
4. **Nemotron Worker live 展示**：使用 Nemotron 3 Nano via NVIDIA hosted API 產生 worker evidence summary；若 unavailable，fallback 到本地 Codex/Claude subagent 與 ChainShield Worker skill。

## 2. 前置需求

- Python 3.11+。
- Node.js 20+ 與 npm 10+，僅用於建立 npm fixture 與 lockfile。
- OrbStack 作為優先 Docker 相容 runtime；不可用時停止 live sandbox install demo。
- Live scanner mode 才需要 `snyk` 與 `socket` CLI 登入；fixture mode 不需要 token。
- Live sandbox mode 才需要可執行的 `openshell`/NemoClaw stack。
- Nemotron Worker live path 才需要 `NVIDIA_API_KEY`；不得寫入 config、fixture、report 或 git。

## 3. 預期專案檔案

```text
fixtures/
├── malicious-poc-pkg/
├── poc-app/
└── reports/
policies/
└── openshell-npm-install.yaml
specs/001-orbstack-sandbox-gates/contracts/
├── demo-config.schema.json
├── gate-evidence.schema.json
├── agent-invocation-evidence.schema.json
└── supervisor-decision.schema.json
.agents/skills/chainshield-worker/
└── SKILL.md
```

## 4. TDD 起始驗證

在實作前先建立 failing tests，至少涵蓋：

```bash
pytest tests/contract tests/unit
```

預期 red state：

- demo config schema 尚未接上 CLI 時，contract test 失敗。
- `snyk high/critical -> deny` 決策測試失敗。
- `socket unhealthy -> deny` 決策測試失敗。
- `config invalid -> manual_review 並阻止 scanner/sandbox` 測試失敗。
- `allow` 缺少 Snyk 或 Socket pass evidence 時測試失敗。
- `sandbox_demo_override.enabled=true` 缺少 reason 或嘗試覆寫 `deny` 時測試失敗。

## 5. Fixture-first 決策展示（優先且安全）

建立或使用版本控管的 demo config，例如：

```json
{
  "version": 1,
  "request_id": "demo-fixture-deny-001",
  "package_manager": "npm",
  "scanner_mode": {
    "snyk": "fixture",
    "socket": "fixture"
  },
  "sandbox_mode": "fixture",
  "worker_provider": {
    "enabled": false,
    "primary": "nemotron_api",
    "fallbacks": [
      "codex_subagent",
      "claude_subagent"
    ],
    "timeout_seconds": 60,
    "output_path": "reports/worker/demo-fixture-deny-001-worker.json"
  },
  "fixtures": {
    "poc_app": "fixtures/poc-app",
    "malicious_package": "fixtures/malicious-poc-pkg",
    "snyk_report": "fixtures/reports/snyk-high-critical.json",
    "socket_report": "fixtures/reports/socket-unhealthy.json",
    "openshell_log": "fixtures/reports/openshell-deny.log",
    "canary_secret": "fixtures/canary/canary-secret.txt"
  },
  "outputs": {
    "decision_json": "reports/decisions/demo-fixture-deny-001.json",
    "markdown_summary": "reports/decisions/demo-fixture-deny-001.md"
  },
  "safety": {
    "sandbox_demo_override": {
      "enabled": false,
      "reason": null
    },
    "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect"
  }
}
```

實作完成後執行：

```bash
python -m chainshield.cli evaluate --config demo-config.fixture.json
```

預期 evidence：

- 產生符合 `contracts/supervisor-decision.schema.json` 的 JSON decision。
- 若 Snyk high/critical 或 Socket unhealthy，decision 為 `deny`。
- 若 evidence 缺失且無明確 deny，decision 為 `manual_review`，並阻止 sandbox install demo。

## 6. Live scanner gate 展示

先確認 CLI 旗標與登入狀態；不要把 token 寫進 config 或 report：

```bash
snyk test --help
socket scan create --help
socket ci --help
```

建議 live commands（實作任務需以本機版本再驗證）：

```bash
cd fixtures/poc-app
snyk test --json --severity-threshold=high
socket scan create --report --json .
# 或用於 CI-like pass/fail：socket ci
```

預期 evidence：

- Snyk report 若包含 high/critical vulnerability，Supervisor 產生 `deny`。
- Socket report 若 `unhealthy`、organization policy violation、malware/supply-chain risk，或可判定的 policy failure exit code，Supervisor 產生 `deny`；不可解析或未知 exit code 產生 `manual_review`。
- Live scanner 不可用時，改用 sanitized fixture reports，不阻塞 fixture-first demo。
- Snyk live scanner 必須在 120 秒內完成或輸出 timeout failure evidence。
- Socket live scanner 必須在 120 秒內完成或輸出 timeout failure evidence。
- Timeout evidence 必須包含 start/end time、exit code 或 timeout reason、sanitized command summary，且不得保存 token 或 auth file。

## 7. OrbStack/OpenShell live sandbox 展示

先做 readiness check；任一項失敗都停止 live install demo，且不得改用未經本 spec 明確授權的一般 Docker runtime：

```bash
orb status
docker version
openshell --help
```

實作完成後，sandbox flow 應只在容器中執行 npm install，並使用 OpenShell policy；若靜態 gate 已 `deny`，demo config 必須明確設定 `sandbox_demo_override.enabled=true` 並提供 reason，且最終 decision 不得因此改判為 `allow`。`--sandbox-only` 僅代表只執行受控 sandbox 展示路徑；仍必須執行 demo config 驗證、OrbStack/OpenShell readiness、安全路徑檢查與必要的 override reason 檢查：

```bash
python scripts/run-demo.py --config demo-config.live-sandbox.json --sandbox-only
```

預期 evidence：

- postinstall 嘗試讀取 chmod-hardened synthetic canary secret 時失敗。
- postinstall 嘗試連到合成測試目的地時，因 OpenShell default-deny egress 失敗。
- OpenShell deny log 或等價失敗證據同時包含 file read block 與 network egress block；live filesystem block 允許以 `manual_probe.permission_denied` 標記 chmod-hardened synthetic canary probe，不得誤稱為 OpenShell 原生 OCSF FILE deny。
- 每筆 OpenShell containment evidence 至少包含 event type、blocked path 或 blocked target、policy/rule identifier、result、timestamp、artifact path、`source_kind` (`live` 或 `fixture`) 與 sanitized marker。
- 若只取得其中一種 evidence，不得宣稱 containment 成功；decision 必須標示 evidence 不足或 `manual_review`。
- OrbStack/OpenShell live sandbox install demo 必須在 5 分鐘內完成，或輸出 readiness、timeout 或 containment insufficiency failure evidence。
- 任一 timeout 或 readiness failure 不得觸發 host `npm install` 或 host `postinstall`。

### OpenShell 0.0.44 live 行為註記

本機 OpenShell 0.0.44 驗證顯示：

- `openshell sandbox create --upload` 不接受多個 `--upload`；demo 需先建立單一 bundle 再上傳。
- `--upload` 可寫入的 `/tmp` 與 `/sandbox` 會被 OpenShell proxy mode baseline 放行，因此將 canary 放在這些路徑時，不會自然產生 filesystem deny。
- `/home/sandbox` 與 `/var/tmp` 之類非 baseline 路徑無法透過 `--upload` 寫入，不能作為免 custom image 的 canary 放置點。
- 本 PoC 不採用 custom OpenShell image；live filesystem block 改以 sandbox 內 `chmod 000` synthetic canary，再用 sandbox exec probe 驗證 permission denied。
- 若 canary probe 意外可讀，artifact 只記錄 redacted 訊號，並輸出 `manual_review`；不得把 canary 內容寫入 reports。

### Live timeout 與 failure evidence

- Snyk live scanner 與 Socket live scanner 各自必須在 120 秒內完成或明確失敗；OrbStack/OpenShell live sandbox install demo 必須在 5 分鐘內完成或明確失敗。
- Failure evidence 必須標示 failed gate、start/end time、timeout reason 或 readiness reason、artifact path、sanitized marker 與建議下一步。
- 若本機缺少 live tool，保留 sanitized fixture evidence 與 manual observation artifact 作為替代展示，不得回退到宿主機直接執行惡意 PoC。
- Manual observation 只能作為 `manual_review` 的說明性證據或人工驗證紀錄；不得用來滿足最終 `allow` 所需的 gate evidence。

## 8. Nemotron Worker 與 subagent fallback 展示

Nemotron live Worker 使用 NVIDIA hosted API；實作前需以官方文件與本機環境確認 endpoint/model。預設設定：

```bash
export NVIDIA_API_KEY="<set-in-shell-only>"
export NEMOTRON_BASE_URL="${NEMOTRON_BASE_URL:-https://integrate.api.nvidia.com/v1}"
export NEMOTRON_MODEL="${NEMOTRON_MODEL:-nvidia/nemotron-3-nano-30b-a3b}"
```

官方驗證來源：

- NVIDIA NIM API Reference: `https://docs.api.nvidia.com/nim/reference/nvidia-nemotron-3-nano-30b-a3b-infer`
- NVIDIA LLM NIM API Reference: `https://docs.nvidia.com/nim/large-language-models/latest/api-reference.html`

Demo config 啟用 Worker provider 時：

```json
{
  "worker_provider": {
    "enabled": true,
    "primary": "nemotron_api",
    "fallbacks": ["codex_subagent", "claude_subagent"],
    "timeout_seconds": 60,
    "output_path": "reports/worker/demo-worker-evidence.json"
  }
}
```

預期 evidence：

- CLI 產生 sanitized run-specific task packet（格式為 `reports/worker-task-packet-<run_id>.json`），只包含 artifact references、evidence checklist 與 request metadata；若寫入被安全檢查拒絕，invocation 必須標示 `task_packet_path="in-memory"`，不得指向舊檔。
- Nemotron 3 Nano Worker 只產生 worker evidence summary，不直接執行 shell command，也不裁決 `allow`/`deny`。
- 成功的 worker evidence summary 必須包含 `finding_status`，且值只能是 `clear`、`concern` 或 `inconclusive`；只有 `clear` 可在 deterministic gate 皆通過時支援 `allow`，`concern` 或 `inconclusive` 只能阻止 `allow` 並導向 `manual_review`，不得直接形成 `deny`。
- Nemotron API timeout、401/403、429、5xx 或 response 無法解析時，系統產生 provider failure evidence，並建立 Codex/Claude subagent fallback packet。
- 本地 subagent fallback 必須使用 `.agents/skills/chainshield-worker/SKILL.md`，只讀取 sanitized task packet 與 artifact references。
- 所有 provider 都 unavailable 且 demo config 要求 live worker evidence 時，Supervisor 輸出 `manual_review`，列出 missing worker provider evidence 與下一步。
- Worker invocation artifact 不得包含 `NVIDIA_API_KEY`、token、真實秘密、未清理 prompt、原始敏感 log 或 host-sensitive path。
- 若 Worker output 要求執行 shell command、scanner/sandbox command、host lifecycle script 或未授權 tool invocation，必須記錄為 worker boundary violation evidence；該 output 不得被採用為可執行任務，且除非 deterministic gate 另有明確 `deny`，Supervisor 應輸出 `manual_review`。

## 9. Markdown 摘要 30 秒可讀性檢查

- 檢查者不重跑 demo，只閱讀產生的 Markdown 摘要。
- 30 秒內必須能指出：
  1. 決策結果是 `allow`、`deny` 或 `manual_review`
  2. 主要理由
  3. 缺失 gate 清單
  4. 下一步建議
  5. demo-only scope disclaimer
- 若任一項無法在 30 秒內辨識，視為 SC-006 未通過。

## 10. 清理與保存規則

- 不提交 live tarball、暫存 scanner output、未清理 OpenShell logs 或任何 token/auth file。
- 不提交 Nemotron prompt dump、API response 原文、`NVIDIA_API_KEY`、provider auth 檔或未清理 worker task packet。
- 保存 fixture/report 前先確認沒有真實秘密、SSH key、cloud profile、個人 `.env`、未遮罩本機路徑。
- 保存的 decision JSON 必須包含 `generated_at`、`gate_results`、`agent_invocations`、`missing_gates`、`next_actions` 與 artifact paths。

## 11. 手動驗證記錄格式

若 live OpenShell 行為無法自動化，請在 Markdown summary 或 manual observation artifact 記錄：

```text
Given OrbStack 與 OpenShell readiness 通過
When sandbox 內 npm install 執行 PoC package
Then 合成 canary secret 讀取失敗，且合成 egress target 連線失敗
Evidence: <sanitized log path>
Runtime: <start/end timestamp，應小於 5 分鐘或明確失敗>
Reviewer: <initials 或角色，不放個人秘密>
```


## Phase 2 Nemotron 驗證摘要

經 Phase 2（2026-05-27）驗證後的預設設定：

```sh
export NEMOTRON_BASE_URL="https://integrate.api.nvidia.com/v1"
export NEMOTRON_MODEL="nvidia/nemotron-3-nano-30b-a3b"
export NVIDIA_API_KEY="<do-not-commit>"
```

官方驗證來源與本機 smoke 摘要：

- NVIDIA Build model card: `https://build.nvidia.com/nvidia/nemotron-3-nano-30b-a3b/modelcard`
- NVIDIA LLM NIM API Reference: `https://docs.nvidia.com/nim/large-language-models/2.0.5/reference/api-reference.html`
- 本機 `GET https://integrate.api.nvidia.com/v1/models`（未帶 token）於 2026-05-27 回傳 HTTP `200`，model list 包含 `nvidia/nemotron-3-nano-30b-a3b`。
- 本機未設定 `NVIDIA_API_KEY`，因此未執行 authenticated `POST /v1/chat/completions`；live Worker 應將此狀態記為 sanitized provider failure evidence，並 fallback 到 `codex_subagent` -> `claude_subagent` -> `manual_review`。


## Phase 2 工具驗證摘要（2026-05-27）

- 本機未安裝 `snyk`、`socket`、`openshell` 或 `nemoclaw`；fixture-first demo 仍可執行，live mode 必須輸出 unavailable/`manual_review` evidence 或使用 sanitized fixture fallback。
- 本機 `orb version` 顯示 OrbStack `2.1.3 (2010300)`，`docker --version` 顯示 Docker `29.4.0`；但 OpenShell/NemoClaw 缺失時 live sandbox readiness 仍必須失敗，且不得 host fallback。
- Socket exit-code classification 以 `policy_failure -> deny`、`auth_or_network_unavailable -> manual_review`、`parse_or_schema_error -> manual_review`、`timeout -> manual_review`、`unknown_exit_code -> manual_review` 為 Phase 2 adapter 基準。
- OpenShell policy schema 以 `version`、`filesystem_policy`、`landlock`、`process`、`network_policies` 為已查證 top-level 結構；未驗證本機 CLI flags 前不得硬編 sandbox command。

## manual-sandbox-verification

Phase 4 手動 sandbox 驗證路徑（當本機缺少 OpenShell/NemoClaw 或 live tool 無法自動化時）：

- 使用 `fixtures/configs/demo-fixture-sandbox.json` 與 `fixtures/reports/openshell-deny.log` 作為 sanitized fixture 替代 evidence。
- `sandbox_mode=live` 時，OrbStack/OpenShell readiness 失敗必須輸出 `manual_review`，並列出 readiness status、start/end timestamp 或 timeout reason、containment evidence status 與「禁止 host fallback」。
- live sandbox install demo runtime 目標為 5 分鐘內完成；超時需保存 sanitized timeout/failure evidence，不得改用 host `npm install` 或未授權的一般 Docker runtime。
- manual observation 只能作為說明性註記或 `manual_review` 依據；不得單獨滿足 `allow`。

## Phase 7 live OpenShell 驗證紀錄（2026-05-27）

本輪使用 `.venv/bin/python scripts/run-demo.py --config tmp/demo-live-sandbox-rerun5.json --sandbox-only` 驗證 OpenShell 0.0.44 live sandbox。靜態 gate 維持 `deny`，sandbox override 只展示 containment，不得把最終 decision 改為 `allow`。

| Gate | Status | 主要 evidence |
|------|--------|---------------|
| Snyk | `deny` | fixture report 含 high/critical malicious-poc-pkg vulnerability。 |
| Socket | `deny` | fixture report 含 unhealthy dependency health。 |
| OpenShell | `pass` | live `network_egress` deny 來自 OPA log；live `filesystem_read` block 來自 chmod-hardened synthetic canary probe，`policy_rule_id="manual_probe.permission_denied"`。 |

最新已知成功 run 範例：`run-20260527T171906573747Z-2f26c3f6ae03`，artifact 位於 `reports/sandbox/openshell-live-run-20260527T171906573747Z-2f26c3f6ae03.log`。此 artifact 為 runtime output，仍不得提交到 git。

## Phase 6 fixture-first 驗證紀錄（2026-05-27）

本輪收尾驗證使用 `.venv/bin/python -m chainshield.cli evaluate --config <config>`，不需要 Snyk/Socket token，不啟動 host `npm install`，也不執行 live OpenShell sandbox。CLI/tool 可用性與旗標限制引用 `specs/001-orbstack-sandbox-gates/research.md` 的 Phase 2 初始紀錄：當時本機未安裝 `snyk`、`socket`、`openshell`、`nemoclaw`，因此該輪 live mode 必須走 unavailable/`manual_review` evidence 或 sanitized fixture fallback；後續 OpenShell 0.0.44 live 行為以 Phase 7 live OpenShell 驗證紀錄為準。

| Config | Exit code | Decision | Runtime | 主要 evidence |
|--------|-----------|----------|---------|---------------|
| `fixtures/configs/demo-fixture-deny.json` | `1` | `deny` | 約 `0.0705s` | Snyk high/critical 與 Socket unhealthy，未進入 sandbox install。 |
| `fixtures/configs/demo-fixture-allow.json` | `0` | `allow` | 約 `0.0679s` | Snyk pass 與 Socket pass；無 missing gate。 |
| `fixtures/configs/demo-fixture-manual-review.json` | `2` | `manual_review` | 約 `0.0667s` | `socket` 設為 `skip`，`missing_gates=["socket"]`。 |
| `fixtures/configs/demo-fixture-sandbox.json` | `1` | `deny` | 約 `0.0677s` | static deny 保持 `deny`；fixture OpenShell log 只作 containment demo evidence，override 不得改判 `allow`。 |

產生的 runtime artifacts 位於 `reports/`（已由 `.gitignore` 排除），包含對應 `*-decision.json` 與 `*-summary.md`。重新驗證前請刪除舊的輸出檔，因為 artifact writer 會拒絕覆寫既有 decision/summary。

### Markdown 30 秒可讀性 manual check

人工檢查 `reports/demo-fixture-allow-summary.md`、`reports/demo-fixture-deny-summary.md`、`reports/demo-fixture-manual-review-summary.md` 與 `reports/demo-fixture-sandbox-summary.md` 的前 6 行，30 秒內皆可辨識：

- `Result`：`allow`、`deny` 或 `manual_review`。
- `Primary reasons`：主要 deny/manual_review/allow 理由。
- `Missing gates`：缺失 gate 或 `none`。
- `Next actions`：下一步；`manual_review` 不提供人工直接改判 `allow` 的路徑。
- 文件底部仍包含 demo-only npm supply-chain defense PoC scope disclaimer。

### Runtime 與安全注意事項

- Fixture scanner、Supervisor report processing 與 fixture-first 總流程皆低於 Phase 6 performance gate：fixture scanner < 30 秒、Supervisor processing < 30 秒、fixture-first CLI 總流程 < 10 秒。
- `reports/`、`scanner-output/`、`sandbox-logs/`、tarball、token/auth 檔與未清理 log 不得提交；只有 `fixtures/reports/` 中明確標示 sanitized 的 fixture reports 可版本控管。
- Artifact redaction integration test 已覆蓋 token/API key、SSH private key、cloud profile 與個人 `.env` pattern；若 sanitizer 命中，CLI 只保存 sanitized `manual_review` reason，不保存原始秘密內容。

## Phase 6 Nemotron Worker fallback 驗證紀錄（2026-05-27）

本輪未設定 `NVIDIA_API_KEY`，因此未執行 authenticated Nemotron `POST /v1/chat/completions`。依 `research.md` 的 NVIDIA Nemotron hosted API 驗證結論，live Worker 仍使用 canonical chain：`nemotron_api` -> `codex_subagent` -> `claude_subagent` -> `manual_review`；primary 失敗後 fallback order 固定為 `codex_subagent` -> `claude_subagent` -> `manual_review`。

執行：

```bash
.venv/bin/python -m chainshield.cli evaluate --config fixtures/configs/demo-worker-fallback.json
```

觀察結果：

- Exit code `2`，Supervisor decision 為 `manual_review`，`missing_gates=["worker_provider"]`。
- Runtime 約 `0.0760s`；未設定 API key 時不進行外部 authenticated request。
- `agent_invocations` 依序包含：
  1. `nemotron_api`：`failed`，`missing_evidence=["nvidia_api_key"]`，error 為 sanitized `NVIDIA_API_KEY unavailable`。
  2. `codex_subagent`：`failed`，提示需使用 `.agents/skills/chainshield-worker/SKILL.md` 進行本地 manual handoff。
  3. `claude_subagent`：`failed`，提示需使用 `.agents/skills/chainshield-worker/SKILL.md` 進行本地 manual handoff。
- CLI 產生 sanitized run-specific task packet（格式為 `reports/worker-task-packet-<run_id>.json`），只包含 artifact refs、evidence checklist、request metadata 與「不得執行 scanner/sandbox/shell/npm lifecycle」安全界線；不得重用既有 `reports/worker-task-packet.json` 舊檔作為本次 evidence。
- Provider unavailable evidence 只可支援 `manual_review`；不得覆寫 Snyk/Socket/OpenShell deterministic gate，也不得直接形成 `allow` 或 `deny`。
