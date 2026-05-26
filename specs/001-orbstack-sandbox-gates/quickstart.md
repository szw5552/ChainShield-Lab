# 快速開始 (Quickstart): OrbStack 優先的 npm 供應鏈防禦 PoC

**Feature**: `001-orbstack-sandbox-gates`  
**安全提醒**: 不得在宿主機直接執行惡意 fixture 的 `postinstall`。PoC-only `postinstall` 只能嘗試合成 canary secret 讀取與合成測試目的地 egress；live install-time demo 只能在通過 OrbStack/OpenShell readiness 的 sandbox/container flow 中執行。

## 1. 安全展示路徑總覽

本 PoC 有三種展示路徑：

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
    "synthetic_egress_target": "https://blocked-egress.invalid/payload"
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
- Snyk live scanner 必須在 5 分鐘內完成或輸出 timeout failure evidence。
- Socket live scanner 必須在 5 分鐘內完成或輸出 timeout failure evidence。
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

- postinstall 嘗試讀取 sandbox allowlist 外的合成 canary secret 時失敗。
- postinstall 嘗試連到合成測試目的地時，因 default-deny egress 失敗。
- OpenShell deny log 或等價失敗證據同時包含 file read block 與 network egress block。
- 每筆 OpenShell containment evidence 至少包含 event type、blocked path 或 blocked target、policy/rule identifier、result、timestamp、artifact path、live/fixture source marker 與 sanitized marker。
- 若只取得其中一種 evidence，不得宣稱 containment 成功；decision 必須標示 evidence 不足或 `manual_review`。
- OrbStack/OpenShell live sandbox install demo 必須在 5 分鐘內完成，或輸出 readiness、timeout 或 containment insufficiency failure evidence。
- 任一 timeout 或 readiness failure 不得觸發 host `npm install` 或 host `postinstall`。

### Live timeout 與 failure evidence

- Snyk live scanner、Socket live scanner 與 OrbStack/OpenShell live sandbox install demo 都必須在 5 分鐘內完成或明確失敗。
- Failure evidence 必須標示 failed gate、start/end time、timeout reason 或 readiness reason、artifact path、sanitized marker 與建議下一步。
- 若本機缺少 live tool，保留 sanitized fixture evidence 與 manual observation artifact 作為替代展示，不得回退到宿主機直接執行惡意 PoC。

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

- CLI 產生 sanitized `reports/worker-task-packet.json`，只包含 artifact references、evidence checklist 與 request metadata。
- Nemotron 3 Nano Worker 只產生 worker evidence summary，不直接執行 shell command，也不裁決 `allow`/`deny`。
- Nemotron API timeout、401/403、429、5xx 或 response 無法解析時，系統產生 provider failure evidence，並建立 Codex/Claude subagent fallback packet。
- 本地 subagent fallback 必須使用 `.agents/skills/chainshield-worker/SKILL.md`，只讀取 sanitized task packet 與 artifact references。
- 所有 provider 都 unavailable 且 demo config 要求 live worker evidence 時，Supervisor 輸出 `manual_review`，列出 missing worker provider evidence 與下一步。
- Worker invocation artifact 不得包含 `NVIDIA_API_KEY`、token、真實秘密、未清理 prompt、原始敏感 log 或 host-sensitive path。

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
