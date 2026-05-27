# ChainShield Lab

ChainShield Lab 是一個展示型 PoC，用來示範 AI-assisted npm supply-chain defense：在安裝 npm 套件前先用 Snyk 與 Socket 做 deterministic static gates，必要時再用 OrbStack/OpenShell sandbox 展示安裝期 containment，最後由 Supervisor 產生可追蹤的 `allow`、`deny` 或 `manual_review` 決策證據。

本專案的範圍刻意很小：三個 demo gates、檔案型 JSON/YAML artifacts、fixture-first 可重現展示，以及可選的 Nemotron/Codex/Claude Worker evidence summary。它不是 production CI/CD 平台、SOC/SIEM 整合，也不是通用惡意程式分析框架。

## Demo Gates

1. **Snyk Gate**：讀取 Snyk report；若 dependency tree 出現 `high` 或 `critical` vulnerability，Supervisor 產生 `deny`。
2. **Socket Gate**：讀取 Socket report；若 dependency health、organization policy、malware 或 supply-chain risk 命中，Supervisor 產生 `deny`。
3. **OpenShell Gate**：只在受控 sandbox 展示路徑中檢查安裝期 containment；file read block 與 network egress block 皆完整時，才可作為 containment evidence。

## 架構概念

```text
Demo Config
   |
   v
+-----------------------------+
| ChainShield Supervisor CLI  |
| - validate config/safe paths|
| - collect gate evidence     |
| - decide allow/deny/review  |
+-------------+---------------+
              |
              +--> Snyk report fixture/live
              +--> Socket report fixture/live
              +--> OpenShell log fixture/live sandbox
              +--> optional Worker evidence summary
              |
              v
+-----------------------------+
| Decision Artifacts          |
| - JSON decision             |
| - Markdown summary          |
| - sanitized artifact refs   |
+-----------------------------+
```

## 核心元件

- `src/chainshield/cli.py`：`python -m chainshield.cli evaluate --config ...` entrypoint，串接 config validation、scanner、sandbox、Worker 與 artifact 輸出。
- `src/chainshield/config.py`：驗證 demo config、repository-local path、禁止 parent traversal、home expansion、敏感檔名、symlink escape 與 artifact overwrite。
- `src/chainshield/evidence.py`：normalize Snyk、Socket 與 OpenShell evidence。
- `src/chainshield/supervisor.py`：唯一 deterministic decision matrix，輸出 `allow`、`deny`、`manual_review`。
- `src/chainshield/scanners.py`：Snyk/Socket fixture mode 與 optional live mode adapter。
- `src/chainshield/sandbox.py`：OrbStack-first readiness 與 OpenShell sandbox install orchestration；禁止 host fallback。
- `src/chainshield/worker_provider.py`：Nemotron API、Codex subagent、Claude subagent fallback 的 sanitized Worker evidence flow。
- `fixtures/`、`policies/`、`specs/001-orbstack-sandbox-gates/contracts/`：可版本控管的 demo fixtures、OpenShell policy 與 JSON Schemas。

## 安全邊界

- 不得在宿主機直接執行 `fixtures/malicious-poc-pkg` 的 `postinstall`。
- Live install-time demo 只能在 OrbStack/OpenShell readiness 通過後的 sandbox flow 執行。
- OrbStack 不可用時，live sandbox demo 會停止並回報 `manual_review`；不得 fallback 到宿主機或未授權的一般 Docker runtime。
- PoC fixture 只使用 synthetic canary secret 與 synthetic egress target，不使用真實秘密、SSH key、cloud profile 或個人 `.env`。
- Snyk、Socket、NVIDIA API token 只能放在 shell environment 或工具自己的安全登入狀態中，不得寫入 config、report 或 git。
- Runtime outputs 寫入 `reports/`，且 artifact path 已存在時 CLI 會拒絕覆寫，請改用新的 output path。

## 環境需求

- Python 3.11+
- Node.js 20+ / npm 10+（用於 npm fixture 與 live scanner/sandbox 展示）
- Fixture-first demo 不需要 Snyk、Socket、NVIDIA API 或 OrbStack 登入
- Live scanner mode 才需要已登入的 `snyk` 與 `socket` CLI
- Live sandbox mode 才需要 OrbStack、Docker 相容 runtime 與 `openshell`/NemoClaw CLI
- Nemotron Worker live path 才需要 `NVIDIA_API_KEY`

建立本機 Python 環境：

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
```

## Fixture-First Demo

Fixture-first 是最安全、最可重現的展示路徑；它只讀取 repository-local sanitized reports，不執行 live scanner，也不執行 live sandbox install。

```bash
python -m chainshield.cli evaluate --config fixtures/configs/demo-fixture-deny.json
python -m chainshield.cli evaluate --config fixtures/configs/demo-fixture-allow.json
python -m chainshield.cli evaluate --config fixtures/configs/demo-fixture-manual-review.json
```

預期結果：

- `demo-fixture-deny.json`：Snyk high/critical 或 Socket unhealthy evidence 命中，輸出 `deny`，且不進入 sandbox install。
- `demo-fixture-allow.json`：Snyk 與 Socket fixture 都通過、未要求 sandbox evidence，輸出 deterministic `allow`。
- `demo-fixture-manual-review.json`：Socket gate 被 `skip`，輸出 `manual_review` 與 `missing_gates=["socket"]`。

每次成功執行會產生 decision JSON 與 Markdown summary；若 `reports/...` 檔案已存在，請改 config 的 `outputs` 路徑後重跑。

## Sandbox Containment Demo

Fixture sandbox demo 使用已清理的 OpenShell deny log，適合在沒有 live OrbStack/OpenShell 的環境中展示 containment evidence：

```bash
python -m chainshield.cli evaluate --config fixtures/configs/demo-fixture-sandbox.json
python scripts/run-demo.py --config fixtures/configs/demo-fixture-sandbox.json --sandbox-only
```

重點行為：

- `sandbox_demo_override.enabled=true` 只允許在 static gate `deny` 後進入第三層 sandbox 展示。
- Sandbox evidence 不得把 static gate `deny` 改判成 `allow`。
- 完整 OpenShell containment evidence 需要同時包含 synthetic canary file-read block 與 synthetic egress block。
- `--sandbox-only` 仍會執行 demo config 驗證、static gate 判讀、安全路徑檢查與必要 override reason 檢查。

Live sandbox demo：

```bash
orb status
docker info --format '{{.OperatingSystem}}'
openshell --version
python scripts/run-demo.py --config fixtures/configs/demo-live-sandbox.json --sandbox-only
```

任一 readiness check 不足時，CLI 必須輸出 `manual_review` 或 containment insufficiency evidence，且不得執行 host `npm install`。

## Worker Provider Demo

Worker provider 只產生 sanitized evidence summary，不執行 shell、scanner、sandbox 或 host lifecycle command，也不能覆寫 Supervisor 的 deterministic gate rules。

```bash
export NVIDIA_API_KEY='<set-in-shell-only>'
export NEMOTRON_BASE_URL='https://integrate.api.nvidia.com/v1'
export NEMOTRON_MODEL='nvidia/nemotron-3-nano-30b-a3b'

python -m chainshield.cli evaluate --config fixtures/configs/demo-worker-nemotron.json
python -m chainshield.cli evaluate --config fixtures/configs/demo-worker-fallback.json
```

Worker 規則：

- Canonical provider chain：`nemotron_api` -> `codex_subagent` -> `claude_subagent` -> `manual_review`。
- Primary failure 後 fallback order：`codex_subagent` -> `claude_subagent` -> `manual_review`。
- 每個 provider attempt 預設 timeout 為 60 秒。
- `finding_status=clear` 只能在 Snyk、Socket 與必要 OpenShell gate 都通過時支援 `allow`。
- `finding_status=concern`、`inconclusive`、缺失 worker evidence、provider unavailable 或 boundary violation 都會阻止 `allow` 並導向 `manual_review`，除非 static gates 已有 deterministic `deny`。

## Decision Artifacts

Supervisor decision JSON 符合 `specs/001-orbstack-sandbox-gates/contracts/supervisor-decision.schema.json`，包含：

- `request_id`、`run_id`、`generated_at`
- `decision`：`allow`、`deny` 或 `manual_review`
- `primary_reasons`
- `gate_results`
- `agent_invocations`
- `missing_gates`
- `next_actions`
- `artifacts`：decision、summary、report、log、worker artifact refs

Markdown summary 的頂部固定呈現 result、主要理由、缺失 gate 與下一步，讓 reviewer 不重跑 demo 也能在 30 秒內掌握結論。

## 測試

執行完整測試：

```bash
pytest tests/
```

常用範圍：

```bash
pytest tests/contract
pytest tests/unit
pytest tests/integration/test_static_gate_decision.py
pytest tests/integration/test_sandbox_gate.py
pytest tests/integration/test_decision_outputs.py
```

本專案遵循 test-first：可自動化的行為需先有 failing test，再做最小實作；live OpenShell/OrbStack 或 Nemotron unavailable 的情境，需以 quickstart/manual verification path 與 sanitized evidence 補足。

## 專案結構

```text
src/chainshield/                 # Supervisor CLI、evidence normalization、sandbox/worker adapters
fixtures/configs/                # Demo configs for deny/allow/manual_review/sandbox/worker
fixturesreports/                # Sanitized Snyk/Socket/OpenShell fixture reports
fixtures/malicious-poc-pkg/      # PoC-only npm package; private and local-only
fixtures/poc-app/                # npm app fixture and lockfile
fixtures/canary/                 # Synthetic canary secrets for sandbox demo only
policies/openshell-npm-install.yaml
specs/001-orbstack-sandbox-gates/ # Spec Kit artifacts, contracts, quickstart, tasks
scripts/run-demo.py              # Safe wrapper around CLI evaluation
```

## 不在範圍內

- 不建立 production CI/CD rollout。
- 不建立 SOC/SIEM integration。
- 不發布 PoC package 到 public registry。
- 不把 Socket 當成本地任意 JavaScript 惡意程式完整靜態分析器。
- 不以 LLM 取代 deterministic Supervisor gate rules 或人工資安審查。
- 不擴大到 pnpm、Yarn、PyPI、Cargo 或一般 malware-analysis framework。

## 參考文件

- Current implementation plan: `specs/001-orbstack-sandbox-gates/plan.md`
- Quickstart and manual verification: `specs/001-orbstack-sandbox-gates/quickstart.md`
- Demo config schema: `specs/001-orbstack-sandbox-gates/contracts/demo-config.schema.json`
- Supervisor decision schema: `specs/001-orbstack-sandbox-gates/contracts/supervisor-decision.schema.json`
- OpenShell policy template: `policies/openshell-npm-install.yaml`
