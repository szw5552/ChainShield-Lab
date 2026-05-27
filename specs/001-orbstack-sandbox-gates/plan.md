# 實作計畫 (Implementation Plan): OrbStack 優先的 npm 供應鏈防禦 PoC

**Branch**: `001-orbstack-sandbox-gates` | **Date**: 2026-05-27 | **Spec**: `specs/001-orbstack-sandbox-gates/spec.md`

**Input**: Feature specification from `specs/001-orbstack-sandbox-gates/spec.md`; 技術堆疊來源為 `todo.md`。

**Note**: 本計畫由 `/speckit-plan` 產生；`tasks.md` 已由 `/speckit-tasks` 產生，並作為目前實作任務來源。

**語言政策**: 產生的 plan.md、research.md、data-model.md、quickstart.md 與相關使用者可見內容 MUST 使用繁體中文 (zh-TW)；程式碼、檔案路徑、指令、API 名稱與憲章引用可保留英文。

## 摘要 (Summary)

本功能建立一個展示型 npm 供應鏈防禦 PoC：Supervisor 先以 Snyk 與 Socket 證據決定 `allow`、`deny` 或 `manual_review`；一般流程只有在證據充分且 demo config 合法時才允許進入受控 sandbox install 展示，若靜態 gate 已 `deny`，只能在 demo config 明確設定 `sandbox_demo_override.enabled=true` 並提供理由時進入第三層 sandbox containment 展示，且不得因此改判為 `allow`。安裝期展示優先使用 OrbStack 提供 Docker 相容容器環境；OpenShell OPA policy 證明 default-deny network egress 被阻擋，filesystem read 則在不採用 custom OpenShell image 的限制下，使用 chmod-hardened synthetic canary probe 產生 `manual_probe.permission_denied` evidence。AI Worker flow 採 Nemotron 3 Nano via NVIDIA hosted API 作為 primary Worker provider，失敗時 fallback 到本地 Codex/Claude subagent 與 ChainShield Worker agent skill；Worker 只產生 sanitized evidence summary，最終裁決仍由 deterministic Supervisor gate rules 執行。實作採 Python CLI 與檔案型 JSON/YAML artifact 作為最小可重現核心，Node.js/npm 僅用於 fixture 與套件安裝展示。

## 技術背景 (Technical Context)

**Language/Version**: Python 3.11+ 作為 Supervisor、CLI 與自動化腳本主體；Node.js 20+ / npm 10+ 用於 npm fixture 與 `postinstall` PoC；YAML/JSON 用於 OpenShell policy、demo config 與 evidence artifacts。

**Primary Dependencies**: Python 標準函式庫優先；測試使用 `pytest`；JSON Schema 驗證可使用 `jsonschema` 或等價輕量驗證器；Nemotron live Worker 使用 NVIDIA OpenAI-compatible hosted API；暫定預設為 `NEMOTRON_BASE_URL=https://integrate.api.nvidia.com/v1`、`NEMOTRON_MODEL=nvidia/nemotron-3-nano-30b-a3b`，但這些值必須由 T063 在實作前以官方文件與本機 smoke/manual check 驗證，並以版本控管的 `research.md` 紀錄作為最終依據；憑證由環境變數 `NVIDIA_API_KEY` 提供且不得寫入 config/report；外部 CLI 為 `snyk`、`socket`、`docker`/OrbStack、`openshell`/NemoClaw，且 Snyk/Socket/Nemotron login、API key 與網路能力皆視為 optional runtime dependencies。

**Storage**: 檔案系統 artifact；版本控管保存 sanitized fixtures、demo config、JSON Schema 與 policy 範本，執行時輸出寫入 `reports/` 或 config 指定目錄並避免提交未清理 log、tarball、token 或機器專屬路徑。

**Testing**: TDD 使用 `pytest`；contract tests 驗證 `contracts/*.schema.json`、demo config 驗證失敗時產生 `manual_review` 並阻止 scanner/sandbox；unit tests 驗證 Snyk/Socket/OpenShell evidence parser、Nemotron request sanitization、Worker provider fallback 與 Supervisor 決策矩陣；integration tests 使用 sanitized report fixtures；live OpenShell/OrbStack install demo 與 live Nemotron API smoke test 以手動驗證或標記測試執行。

**Target Platform**: macOS Apple Silicon 開發與展示環境，OrbStack 優先且唯一授權的 live sandbox Docker 相容 runtime；sandbox 內為 Linux/container 環境；若 OrbStack 不可用，不得回退為宿主機直接執行惡意 PoC，也不得改用未經本 spec 明確授權的一般 Docker runtime。

**Project Type**: 單一 repository 的 Python CLI + npm fixture + sandbox policy PoC；不是 web service、production CI/CD 平台、SOC/SIEM 整合或一般 malware-analysis framework。

**Performance Goals**: 使用 fixture 證據的 Supervisor 決策應在 10 秒內完成；live Snyk/Socket scanner 各自應記錄開始/結束時間並在 120 秒內完成或明確失敗；fixture scanner 與 Supervisor report processing 各應在 30 秒內完成或明確失敗；OrbStack live sandbox install demo 應在 5 分鐘內完成或明確回報環境未就緒/containment 證據不足；Markdown 摘要應讓審查者在 30 秒內辨識結果、理由、缺失 gate 與下一步。

**Constraints**: 不直接在宿主機執行惡意 `postinstall`；PoC-only `postinstall` 只能嘗試合成 canary secret 讀取與合成測試目的地 egress；OpenShell 讀檔展示只使用 sandbox 內合成 canary secret，且 live mode 的 filesystem evidence 必須誠實標記 chmod-hardened synthetic canary probe，不得誤稱為 OpenShell 原生 OCSF FILE deny；網路展示預設拒絕所有 sandbox egress 且只允許合成測試目的地；demo config 驗證失敗時必須產生 `manual_review` 並阻止 scanner/sandbox；`sandbox_demo_override.enabled=true` 只能允許第三層 sandbox 展示，不能覆寫靜態 gate 的 `deny`；Nemotron/Codex/Claude Worker provider 不得保存 API key、token、未清理 prompt 或原始敏感 log，也不得直接決定 `allow`/`deny`；CLI flags、OpenShell/NemoClaw policy schema 與 NVIDIA API model/endpoint 在實作任務開始前必須以本機版本與官方文件再驗證。

**Scale/Scope**: 單一 npm fixture family、三個 demo gates、單一 Supervisor 決策檔與可選 Markdown 摘要；不擴大到 pnpm/Yarn/PyPI/Cargo、多租戶、長期報表儲存或 production rollout。

## 憲章檢查 (Constitution Check)

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **TDD**: PASS。先撰寫 contract/unit tests：schema 驗證、config invalid -> `manual_review` 並阻止執行、Snyk high/critical -> `deny`、Socket unhealthy/policy violation -> `deny`、缺失/衝突證據 -> `manual_review`、明確 deny + 缺失 gate -> `deny`。red state 以尚未存在的 parser/decision CLI 失敗確認；live sandbox 行為若不可自動化，需以 quickstart 的手動驗證與 expected evidence 補足。
- **BDD**: PASS。`spec.md` 已包含 P1/P2/P3 Given/When/Then；本計畫在 data model、contracts 與 quickstart 中維持三個故事可獨立展示與驗證。
- **KISS**: PASS。採單一 Python CLI、檔案型 artifact 與最小 adapter，不建立服務端、資料庫、queue、plugin 平台或 SIEM connector；複雜度只限於隔離外部 CLI 呼叫與解析證據。
- **UX / Language**: PASS。Spec Kit artifacts 使用繁體中文；決策術語固定為 `allow`、`deny`、`manual_review`、Gate 證據、Supervisor 決策、Demo Config、Sandbox 展示環境。
- **Performance / Evidence**: PASS。明定 fixture 決策、live scanner、sandbox install 與報告可讀性時間目標；每次決策都保存 JSON evidence reference，不要求審查者重跑 demo。

## 專案結構 (Project Structure)

### 文件 (this feature)

```text
specs/001-orbstack-sandbox-gates/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── demo-config.schema.json
│   ├── gate-evidence.schema.json
│   ├── agent-invocation-evidence.schema.json
│   └── supervisor-decision.schema.json
└── tasks.md              # Phase 2 output，由 /speckit-tasks 產生
```

### 原始碼 (repository root)

```text
src/
└── chainshield/
    ├── __init__.py
    ├── cli.py                 # Python CLI entrypoint，讀取 demo config 並輸出決策 artifact
    ├── config.py              # demo config schema 驗證與安全前置檢查
    ├── schemas.py             # JSON Schema 載入與 contract validation helper
    ├── evidence.py            # Snyk/Socket/OpenShell evidence normalization
    ├── supervisor.py          # allow/deny/manual_review 決策矩陣
    ├── artifacts.py           # sanitized artifact writer、decision output 與 Markdown summary renderer
    ├── scanners.py            # Snyk/Socket CLI adapter；fixture/live mode 共用 interface
    ├── worker_provider.py     # Nemotron API Worker、Codex/Claude subagent fallback 與 invocation evidence
    └── sandbox.py             # OrbStack/OpenShell readiness 與 sandbox install orchestration

fixtures/
├── configs/                   # 版本控管 demo config；描述 fixture、scanner mode、sandbox mode、輸出路徑與可選 Worker 設定
├── canary/                    # 合成 canary secret fixture；僅供 sandbox 讀檔阻擋展示使用
├── malicious-poc-pkg/         # PoC-only npm package；不得發布；postinstall 僅在 sandbox flow 執行
├── poc-app/                   # npm application fixture 與 lockfile
└── reports/                   # sanitized Snyk/Socket/OpenShell/Worker fixture reports

policies/
└── openshell-npm-install.yaml # OpenShell policy 範本；實作前需以本機 CLI/schema 驗證

scripts/
└── run-demo.py                # 優先使用 Python script 串接 fixture/live demo，不新增 bash-only 主流程

.agents/
└── skills/
    └── chainshield-worker/    # Codex/Claude subagent fallback skill；只產生 sanitized Worker evidence

tests/
├── contract/
├── integration/
└── unit/
```

**Structure Decision**: 選擇單一 Python CLI 專案結構，因為 PoC 的核心是讀取檔案型 evidence、套用 deterministic 決策矩陣、執行少量外部 CLI adapter，無需 web backend、frontend、資料庫或長駐服務。npm 與 OpenShell 相關內容以 `fixtures/`、`policies/` 與 sanitized `reports/` 分離，降低誤執行惡意 fixture 的風險。

## Phase 0 研究摘要 (Research Summary)

完整決策紀錄見 `specs/001-orbstack-sandbox-gates/research.md`。主要結論：

- 使用 Python 3.11+ 實作 Supervisor/Worker orchestration script，符合使用者偏好 Python script 與 TDD parser/decision tests。
- 使用 Nemotron 3 Nano via NVIDIA hosted API 作為 primary Worker provider，Codex/Claude subagent + ChainShield Worker skill 作為 fallback；Worker evidence 只輔助展示 agent flow，不取代 deterministic Supervisor。
- 使用 OrbStack-first Docker readiness；OrbStack 不可用時停止 live sandbox demo，僅允許 fixture/manual evidence。
- Snyk 與 Socket live mode 只作 optional evidence source；fixture reports 是可重現 demo 的一級路徑。
- OpenShell/NemoClaw 以 policy/schema adapter 包裝；實作前需以官方文件與本機版本再次驗證 CLI flags，不在 plan 中承諾未驗證的 NemoClaw command。

## Phase 1 設計摘要 (Design Summary)

- **Data model**: `data-model.md` 定義安裝評估請求、Demo Config、sandbox demo override、Gate 證據、Sandbox 展示環境、Supervisor 決策與展示輸出。
- **Contracts**: `contracts/` 定義 demo config、gate evidence 與 Supervisor decision JSON Schema，作為 CLI 輸入/輸出的 contract tests 基礎。
- **Quickstart**: `quickstart.md` 提供 fixture-first 安全展示、live scanner prerequisites、OrbStack/OpenShell manual verification 與預期 evidence。
- **Agent context**: `AGENTS.md` 的 Spec Kit 區塊已更新為本 plan 路徑。

## Post-Design 憲章檢查 (Constitution Re-Check)

- **TDD**: PASS。contracts 與 data model 已足以產生 failing tests；quickstart 明確標示 manual-only live sandbox 驗證條件。
- **BDD**: PASS。P1/P2/P3 story 均能透過 fixture/live paths 個別展示；`deny`、`allow`、`manual_review` 決策與 spec scenarios 一致。
- **KISS**: PASS。設計仍維持單一 CLI + 檔案 artifact；沒有新增 database、daemon 或泛用 malware analysis pipeline。
- **UX / Language**: PASS。所有新增 Spec Kit artifacts 均為 zh-TW，英文僅保留命令、schema key 與產品名稱。
- **Performance / Evidence**: PASS。contracts 要求 timestamps、evidence paths、missing gates 與 next actions；quickstart 含 runtime expectations 與 failure behavior。

## 複雜度追蹤 (Complexity Tracking)

無憲章違規；不需複雜度例外。

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| N/A | N/A | N/A |
