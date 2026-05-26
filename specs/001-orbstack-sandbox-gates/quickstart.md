# 快速開始 (Quickstart): OrbStack 優先的 npm 供應鏈防禦 PoC

**Feature**: `001-orbstack-sandbox-gates`  
**安全提醒**: 不得在宿主機直接執行惡意 fixture 的 `postinstall`。live install-time demo 只能在通過 OrbStack/OpenShell readiness 的 sandbox/container flow 中執行。

## 1. 安全展示路徑總覽

本 PoC 有三種展示路徑：

1. **Fixture-first 決策展示**：使用已清理 Snyk/Socket/OpenShell reports，不需要 scanner token，也不執行 live sandbox install。
2. **Live scanner gate 展示**：在 npm fixture 上執行 Snyk/Socket，將 live reports 交給 Supervisor 判讀。
3. **OrbStack live sandbox 展示**：只在 OrbStack、Docker 相容 runtime 與 OpenShell/NemoClaw 均通過 readiness 時執行，並只讀取合成 canary secret fixture。

## 2. 前置需求

- Python 3.11+。
- Node.js 20+ 與 npm 10+，僅用於建立 npm fixture 與 lockfile。
- OrbStack 作為優先 Docker 相容 runtime；不可用時停止 live sandbox install demo。
- Live scanner mode 才需要 `snyk` 與 `socket` CLI 登入；fixture mode 不需要 token。
- Live sandbox mode 才需要可執行的 `openshell`/NemoClaw stack。

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
└── supervisor-decision.schema.json
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
    "allow_static_gate_bypass": false,
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
- Socket report 若 unhealthy、policy violation 或 CLI exit code 非 0，Supervisor 產生 `deny`。
- Live scanner 不可用時，改用 sanitized fixture reports，不阻塞 fixture-first demo。

## 7. OrbStack/OpenShell live sandbox 展示

先做 readiness check；任一項失敗都停止 live install demo：

```bash
orb status
docker version
openshell --help
```

實作完成後，sandbox flow 應只在容器中執行 npm install，並使用 OpenShell policy：

```bash
python scripts/run-demo.py --config demo-config.live-sandbox.json --sandbox-only
```

預期 evidence：

- postinstall 嘗試讀取 sandbox allowlist 外的合成 canary secret 時失敗。
- postinstall 嘗試連到合成測試目的地時，因 default-deny egress 失敗。
- OpenShell deny log 或等價失敗證據同時包含 file read block 與 network egress block。
- 若只取得其中一種 evidence，不得宣稱 containment 成功；decision 必須標示 evidence 不足或 `manual_review`。

## 8. 清理與保存規則

- 不提交 live tarball、暫存 scanner output、未清理 OpenShell logs 或任何 token/auth file。
- 保存 fixture/report 前先確認沒有真實秘密、SSH key、cloud profile、個人 `.env`、未遮罩本機路徑。
- 保存的 decision JSON 必須包含 `generated_at`、`gate_results`、`missing_gates`、`next_actions` 與 artifact paths。

## 9. 手動驗證記錄格式

若 live OpenShell 行為無法自動化，請在 Markdown summary 或 manual observation artifact 記錄：

```text
Given OrbStack 與 OpenShell readiness 通過
When sandbox 內 npm install 執行 PoC package
Then 合成 canary secret 讀取失敗，且合成 egress target 連線失敗
Evidence: <sanitized log path>
Runtime: <start/end timestamp，應小於 5 分鐘或明確失敗>
Reviewer: <initials 或角色，不放個人秘密>
```
