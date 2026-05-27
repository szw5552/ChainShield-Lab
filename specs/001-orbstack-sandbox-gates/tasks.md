# 任務 (Tasks): OrbStack 優先的 npm 供應鏈防禦 PoC

**語言政策**: 本 tasks.md 使用繁體中文 (zh-TW)；程式碼、檔案路徑、指令、任務 ID 與必要英文專有名詞保留英文。

**Input**: `specs/001-orbstack-sandbox-gates/plan.md`、`specs/001-orbstack-sandbox-gates/spec.md`、`specs/001-orbstack-sandbox-gates/research.md`、`specs/001-orbstack-sandbox-gates/data-model.md`、`specs/001-orbstack-sandbox-gates/contracts/`、`specs/001-orbstack-sandbox-gates/quickstart.md`

**Prerequisites**: Python 3.11+、Node.js 20+ / npm 10+；live scanner mode 才需要 `snyk` / `socket` CLI；live sandbox mode 才需要 OrbStack、Docker 相容 runtime 與 OpenShell/NemoClaw。

**Tests**: TDD 為強制要求。每個可自動化的 user story 先新增 failing test 並確認 red，再實作最小 passing change；live OpenShell/OrbStack 行為若無法自動化，需保留 quickstart 的手動驗證路徑與 sanitized evidence。

**Organization**: 任務依使用者故事分組，使每個故事可獨立實作、測試與展示；所有任務均對應 `spec.md` 的 Given/When/Then 驗收情境。

## Phase 1: 設定 (Setup / Shared Infrastructure)

**Purpose**: 建立最小 Python CLI 專案骨架、測試目錄與安全輸出邊界。

- [X] T001 建立 Python package 與測試目錄骨架，新增 `src/chainshield/__init__.py`、`tests/contract/.gitkeep`、`tests/integration/.gitkeep`、`tests/unit/.gitkeep`
- [X] T002 在 `pyproject.toml` 定義 Python 3.11+ 專案 metadata、`pytest` 與 `jsonschema` 測試相依套件
- [X] T003 [P] 在 `.gitignore` 排除 repository root runtime output `/reports/`、live scanner output、tarball、暫存 sandbox log 與本機 auth/token 檔案；不得排除 `fixtures/reports/`，因為 sanitized fixture reports 必須可版本控管
- [X] T004 [P] 建立 fixture 與 policy 目錄保留檔，新增 `fixtures/reports/.gitkeep`、`fixtures/configs/.gitkeep`、`fixtures/canary/.gitkeep`、`policies/.gitkeep`

---

## Phase 2: 基礎建設 (Foundational / Blocking Prerequisites)

**Purpose**: 完成所有故事共用的 config 驗證、schema helper、CLI entrypoint、工具旗標驗證與安全失敗行為；本階段完成前不得開始任何 user story 實作。

**Critical**: `demo config invalid -> manual_review 並阻止 scanner/sandbox` 是跨故事安全邊界，必須先用 failing tests 固定；Snyk/Socket/OpenShell/NemoClaw CLI flags 與 policy schema 也必須在依賴它們的實作任務前完成驗證。

**FR-004 子條款對應**: T005/T009/T012 覆蓋 FR-004a/FR-004c/FR-004f；T024/T077 覆蓋 FR-004b；T080/T079/T025/T039/T040/T058 覆蓋 FR-004d/FR-004e；T007/T010 覆蓋 FR-004g。

- [X] T005 [P] 新增 demo config schema contract test 並確認 red，覆蓋 valid/invalid config、`sandbox_demo_override`、禁止額外欄位，以及 fixture/policy/output path 的 repository-local、parent traversal、home expansion (`~` / `$HOME`)、absolute sensitive path、auth/token/SSH/cloud profile filename/path pattern、symlink escape 驗證與 output path / decision artifact collision case 於 `tests/contract/test_demo_config_schema.py`
- [X] T006 [P] 新增 gate evidence 與 supervisor decision schema contract test 並確認 red，覆蓋 required fields 與 sanitized evidence 於 `tests/contract/test_evidence_decision_schema.py`
- [X] T080 [P] 新增 shared Supervisor static gate decision core unit test 並確認 red，僅覆蓋 foundational static gate matrix：Snyk deny、Socket deny、缺失 evidence -> `manual_review`、`scanner_mode.snyk=skip` / `scanner_mode.socket=skip` 且無其他明確 deny 時 -> `manual_review` 並標示 `missing_gates`、static gate `deny` 不可被 sandbox demo override 改判為 `allow`，於 `tests/unit/test_supervisor_decisions.py`
- [X] T059 [P] 新增 Worker provider config 與 agent invocation evidence schema contract test 並確認 red，覆蓋 `worker_provider.enabled`、Nemotron provider defaults、每個 provider 嘗試的預設 `timeout_seconds=60`、canonical `provider_chain` `nemotron_api` -> `codex_subagent` -> `claude_subagent` -> `manual_review`、`fallback_order_after_primary_failure` `codex_subagent` -> `claude_subagent` -> `manual_review`、`agent_invocations` 與 API key redaction 於 `tests/contract/test_worker_provider_contract.py`
- [X] T071 [P] 新增 artifact sanitizer unit test 並確認 red，覆蓋 token/API key、SSH key、cloud profile、個人 `.env` pattern、未遮罩 host-sensitive path 與 raw scanner/sandbox log 片段；sanitizer 命中時必須拒絕保存原始 artifact、產生 sanitized failure reason，並要求後續 scanner/sandbox 不得執行，於 `tests/unit/test_artifact_sanitizer.py`
- [X] T073 [P] 新增 `run_id` generation unit test 並確認 red，覆蓋 `run_id` 必須由 repository-local demo config path、fixture identity、timestamp 與 evidence hash 組成，且相同輸入在固定 timestamp/hash 下可重現、不同 fixture 或 evidence hash 必須產生不同 `run_id`，於 `tests/unit/test_run_id.py`
- [X] T007 新增 invalid config integration test 並確認 red，驗證 `manual_review` 決策且不呼叫 scanner/sandbox；同時覆蓋底層 CLI / artifact writer 在 output path 或 decision artifact 已存在時拒絕新的 run、不得覆寫既有 evidence/decision artifact，並要求使用新的 output path，於 `tests/integration/test_invalid_config_blocks_execution.py`
- [X] T008 實作 JSON Schema 載入與 validation helper，讀取 `specs/001-orbstack-sandbox-gates/contracts/*.schema.json` 於 `src/chainshield/schemas.py`
- [X] T009 實作 Demo Config model、`sandbox_demo_override` 驗證、repository-local 路徑檢查、parent traversal/home expansion/absolute sensitive path/auth-token-SSH-cloud-profile path pattern/symlink escape 阻擋與安全前置驗證於 `src/chainshield/config.py`
- [X] T072 實作 artifact sanitizer 與 sanitized failure artifact builder，提供保存前檢查、敏感內容偵測、raw artifact 拒存、`manual_review` failure reason 建立，以及供 CLI/Supervisor 判斷停止後續 scanner/sandbox 的結果型別，於 `src/chainshield/artifacts.py`
- [X] T010 實作 decision artifact 寫入器與 atomic JSON output helper；若 output path 或 decision artifact 已存在或被目前 run 鎖定，底層 writer 必須拒絕覆寫、回傳 `manual_review` failure reason，並要求使用新的 output path；所有 artifact 寫入前必須呼叫 T072 sanitizer 於 `src/chainshield/artifacts.py`
- [X] T074 實作 `run_id` builder，從 demo config path、fixture identity、timestamp 與 evidence hash 建立 repository-local 可追溯 ID，並串接 Demo Config model 與 Supervisor decision model，於 `src/chainshield/config.py`、`src/chainshield/supervisor.py`
- [X] T079 實作 shared Supervisor static gate decision core，支援 Snyk deny、Socket deny、缺失 evidence -> `manual_review`、`scanner_mode.snyk=skip` / `scanner_mode.socket=skip` 且無其他明確 deny 時 -> `manual_review` 並填入 `missing_gates`、static gate `deny` 不可被 sandbox demo override 改判為 `allow`，供 US1、US2 與 US3 共用，於 `src/chainshield/supervisor.py`
- [X] T062 擴充並驗證既有 agent invocation evidence schema 與 supervisor decision schema，使 decision 可保存 `agent_invocations`、worker artifact paths、`worker_provider` missing gate、canonical `provider_chain`、`fallback_order_after_primary_failure`、`finding_status` 與 boundary violation evidence；必須在 T059 已執行並確認 red state 後開始，且 T059 的 red state 應來自缺少必要 Worker 欄位或 schema 約束，而非 schema 檔案不存在，於 `specs/001-orbstack-sandbox-gates/contracts/agent-invocation-evidence.schema.json`、`specs/001-orbstack-sandbox-gates/contracts/supervisor-decision.schema.json`
- [X] T011 實作 `python -m chainshield.cli evaluate --config ...` CLI 骨架與 invalid config 失敗路徑於 `src/chainshield/cli.py`
- [X] T012 建立 invalid config 測試 fixture，包含格式錯誤、不安全 sandbox 設定、不合法 `sandbox_demo_override`、parent traversal path、home expansion path、repository 外部 path、敏感檔名樣式、auth/token/SSH/cloud profile path pattern 與 symlink escape path 於 `fixtures/configs/demo-invalid.json`
- [X] T013 [P] 驗證 Snyk 與 Socket CLI 可用命令、exit code、必要 flags 與 fixture/live mode fallback 行為，將 `snyk test --help`、`socket scan create --help`、`socket ci --help` 的本機確認結果、command、version、observed behavior、日期與 Socket exit-code classification table 記錄於 `specs/001-orbstack-sandbox-gates/research.md`；`quickstart.md` 僅引用該紀錄並保留操作摘要。classification table 至少區分 `policy_failure -> deny`、`auth_or_network_unavailable -> manual_review`、`parse_or_schema_error -> manual_review`、`timeout -> manual_review`、`unknown_exit_code -> manual_review`
- [X] T014 [P] 驗證 OpenShell/NemoClaw CLI、policy schema、filesystem 行為、default-deny egress 與 host fallback 禁止行為，將本機版本、command、支援 flags、observed behavior、日期、限制與替代 fixture path 記錄於 `specs/001-orbstack-sandbox-gates/research.md`；後續 OpenShell 0.0.44 live 驗證補充必須記錄單一 `--upload` 限制、`/tmp`/`/sandbox` baseline 可讀行為、`sandbox exec` 旗標、chmod-hardened synthetic canary probe 與成功 run evidence；`quickstart.md` 僅保留手動驗證步驟與預期 evidence 摘要
- [X] T063 [P] 驗證 NVIDIA Nemotron 3 Nano hosted API model id、OpenAI-compatible endpoint、必要 headers、timeout/error response 與 token redaction 規則，將官方文件依據、本機 smoke/manual check、command 或 request summary、observed behavior 與日期記錄於 `specs/001-orbstack-sandbox-gates/research.md`；若觀察到的 endpoint/model 與 `plan.md` 暫定預設不同，必須更新 `research.md` 與 `quickstart.md`，且 implementation 必須以 `research.md` 驗證紀錄為準；`quickstart.md` 僅保留 NVIDIA API setup 與 fallback 操作摘要
- [X] T015 執行 implementation 前憲章符合性檢查，確認 TDD red-first 任務、BDD 情境追蹤、KISS 範圍、zh-TW 文件語言、performance/evidence gates 與 evidence-driven security decision 均已對應；若發現不符合，必須先修正 spec/plan/tasks，否則不得開始 user story implementation。檢查準則以本 task 固定於 `specs/001-orbstack-sandbox-gates/tasks.md`，執行結果以 task 完成狀態與必要的 follow-up issue/notes 表示，不在 implementation 期間回寫 tasks.md 內容

**憲章符合性檢查**: Phase 2 完成後、任何 user story implementation 開始前，必須確認本 tasks.md 仍符合 constitution 的 TDD、BDD、KISS、UX language、performance/evidence 與 evidence-driven security decision 要求；若不符合，必須先修正 spec/plan/tasks，不得進入 user story implementation。

**Checkpoint**: Foundation ready；`pytest tests/contract tests/unit/test_artifact_sanitizer.py tests/unit/test_run_id.py tests/integration/test_invalid_config_blocks_execution.py` 應可通過，invalid config 不會啟動 scanner 或 sandbox，且工具 flags/policy schema 已有 `research.md` 驗證紀錄。

---

## Phase 3: 使用者故事 1 - 以相依套件風險先行阻擋安裝 (Priority: P1) MVP

**Goal**: 使用 Snyk 與 Socket fixture/live evidence 在安裝展示前產生可追蹤的 `allow`、`deny` 或 `manual_review`，並避免執行惡意 `postinstall`。

**Independent Test**: 使用 sanitized Snyk high/critical 與 Socket unhealthy fixture 執行 `python -m chainshield.cli evaluate --config fixtures/configs/demo-fixture-deny.json`，應在不執行 npm install 的情況下輸出 `deny`，且理由可追溯到 Snyk 或 Socket evidence。

### 使用者故事 1 的測試 (TDD mandatory)

- [X] T016 [P] [US1] 新增 Snyk parser unit test 並確認 red，覆蓋 high/critical -> `deny`、low/medium 且無 high/critical -> `pass` 並保留 residual risk、pass -> `pass`、不可解析 -> `manual_review` 於 `tests/unit/test_snyk_evidence.py`
- [X] T017 [P] [US1] 新增 Socket parser unit test 並確認 red，覆蓋 unhealthy、organization policy violation、malware/supply-chain risk、依 `research.md` classification table 判定的 policy failure exit code -> `deny`，以及不可解析、auth/network unavailable、timeout、未知 exit code -> `manual_review` 於 `tests/unit/test_socket_evidence.py`
- [X] T018 [P] [US1] 新增 static gate integration test 並確認 red，驗證 fixture-first deny 且不觸發 host `npm install` 於 `tests/integration/test_static_gate_decision.py`
- [X] T055 [P] [US1] 新增 live scanner timeout/failure unit test 並確認 red，覆蓋 Snyk/Socket live command 必須在 120 秒內完成或輸出 timeout failure evidence，且 evidence 包含 start/end time、exit code 或 timeout reason 與 sanitized command summary；同時覆蓋 live scanner 因 auth/network/service unavailable 失敗時，若 config 提供對應 sanitized fixture report 必須 fallback 到 fixture evidence 並標示 `live_unavailable`，於 `tests/unit/test_scanner_timeouts.py`
- [X] T076 [P] [US1] 新增 Snyk low/medium residual risk integration test 並確認 red，驗證 low/medium 且無 high/critical 的 Snyk fixture 不會造成 `deny`，但 Supervisor JSON/Markdown 摘要必須列出 residual risk，於 `tests/integration/test_static_gate_decision.py`
- [X] T077 [P] [US1] 新增 live scanner unavailable fallback integration test 並確認 red，覆蓋 live Snyk/Socket 因未登入、網路或服務錯誤不可用且 config 提供 fixture report 時，Supervisor 使用 fixture evidence 完成決策並標示 `live_unavailable`；缺少對應 fixture report、`scanner_mode.snyk=skip` 或 `scanner_mode.socket=skip` 且無其他明確 deny 時必須輸出 `manual_review` 且 `missing_gates` 指出缺失或 skip 的必要 static gate，於 `tests/integration/test_static_gate_decision.py`

### 使用者故事 1 的實作 (Implementation)

- [X] T019 [P] [US1] 建立 sanitized Snyk fixture reports，包含 deny、low/medium residual risk 與 pass 範例於 `fixtures/reports/snyk-high-critical.json`、`fixtures/reports/snyk-low-medium.json`、`fixtures/reports/snyk-pass.json`
- [X] T020 [P] [US1] 建立 sanitized Socket fixture reports，包含 unhealthy、organization policy violation、malware/supply-chain risk 與 pass 範例；若以單一 deny fixture 表示多種命中，fixture 內必須明確包含可測試的 policy violation 與 malware/supply-chain risk 欄位，於 `fixtures/reports/socket-unhealthy.json`、`fixtures/reports/socket-policy-violation.json`、`fixtures/reports/socket-malware-risk.json`、`fixtures/reports/socket-pass.json`
- [X] T021 [P] [US1] 建立 npm app fixture 與 PoC-only package manifest，避免任何 host install 執行；`fixtures/poc-app/package.json` 與 sanitized deterministic `fixtures/poc-app/package-lock.json` 必須只引用本機 PoC fixture，不得觸發 host lifecycle script；`fixtures/malicious-poc-pkg/package.json` 必須設定 `private: true`、不得包含 `publish` / `prepublishOnly` / registry 發布設定，且不得指向 public registry，於 `fixtures/poc-app/package.json`、`fixtures/poc-app/package-lock.json`、`fixtures/malicious-poc-pkg/package.json`
- [X] T022 [US1] 實作 Snyk report normalization，將 high/critical vulnerability 轉為 Gate Evidence `deny`，將只有 low/medium 且無 high/critical 的結果轉為 `pass` 並保留 residual risk 於 `src/chainshield/evidence.py`
- [X] T023 [US1] 實作 Socket report normalization，將 unhealthy、organization policy violation、malware/supply-chain risk 與依 `research.md` classification table 判定的 policy failure exit code 轉為 Gate Evidence，並將不可解析、auth/network unavailable、timeout 或未知 exit code 轉為 `manual_review` evidence 於 `src/chainshield/evidence.py`
- [X] T024 [US1] 實作 Snyk/Socket fixture mode 與 live mode adapter 介面，live command 只記錄無 token 摘要，且每個 live scanner 必須在 120 秒內完成或明確失敗並輸出 start/end time、exit code、timeout reason 與 sanitized command summary；當 live scanner 因 auth/network/service unavailable 失敗且 config 提供對應 sanitized fixture report 時，必須 fallback 到 fixture evidence 並在 Gate Evidence 標示 `live_unavailable`，否則輸出 `manual_review` evidence，於 `src/chainshield/scanners.py`
- [X] T025 [US1] 串接 US1 static gate 決策案例，僅呼叫 T079 建立的 shared Supervisor static gate decision core，不得新增第二套 Snyk/Socket 決策矩陣；驗證 Snyk/Socket fixture/live evidence 可產生 `deny` 或 `manual_review` 於 `src/chainshield/supervisor.py`
- [X] T026 [US1] 串接 CLI scanner flow，確保 static deny 前不進入 sandbox install 於 `src/chainshield/cli.py`
- [X] T027 [US1] 建立 fixture-first deny demo config，引用 sanitized Snyk/Socket report 與輸出路徑於 `fixtures/configs/demo-fixture-deny.json`

**Checkpoint**: User Story 1 可獨立展示；`pytest tests/unit/test_snyk_evidence.py tests/unit/test_socket_evidence.py tests/unit/test_scanner_timeouts.py tests/integration/test_static_gate_decision.py` 應通過，且不在宿主機執行惡意 lifecycle script。

---

## Phase 4: 使用者故事 2 - 在 OrbStack 優先的容器沙箱中展示安裝期阻擋 (Priority: P2)

**Goal**: 在 demo config 明確啟用 sandbox demo override 的展示設定下，只透過 OrbStack/OpenShell sandbox flow 執行安裝期展示，並保存 file read block 與 default-deny egress block evidence；override 不得把靜態 gate 的 `deny` 改判為 `allow`。

**Independent Test**: 在 OrbStack/OpenShell 不可用時，live sandbox config 必須停止並輸出 `manual_review`；在使用 sanitized OpenShell deny log fixture 時，Supervisor 應辨識同時存在檔案讀取阻擋與網路外連阻擋 evidence。

### 使用者故事 2 的測試 (TDD mandatory)

- [X] T028 [P] [US2] 新增 sandbox readiness unit test 並確認 red，覆蓋 OrbStack/OpenShell 不可用時不得 host fallback、不得改用未經 spec 授權的一般 Docker runtime，且必須輸出 sanitized fixture evidence path 或 manual verification path；manual observation 只能支援 `manual_review` 或說明性註記，不得滿足 `allow`，於 `tests/unit/test_sandbox_readiness.py`
- [X] T029 [P] [US2] 新增 OpenShell evidence unit test 並確認 red，覆蓋 file read block 與 egress block 皆存在才可 pass，且每筆 containment evidence 需包含 event type、blocked path/target、policy/rule identifier、result、timestamp、artifact path、`source_kind` (`live` 或 `fixture`) 與 sanitized marker 於 `tests/unit/test_openshell_evidence.py`
- [X] T030 [P] [US2] 新增 sandbox gate integration test 並確認 red，驗證 `sandbox_mode=live` readiness 失敗輸出 `manual_review` 於 `tests/integration/test_sandbox_gate.py`
- [X] T031 [P] [US2] 新增 malicious PoC script safety unit test 並確認 red，驗證 `postinstall` 僅引用 synthetic canary 與 synthetic egress target，invalid config/static deny 情境不會觸發 host npm lifecycle script，`fixtures/poc-app/package-lock.json` 不指向 public registry，且惡意 package manifest 設定 `private: true`、不含 publish lifecycle script、public registry 或 publishConfig，於 `tests/unit/test_malicious_poc_safety.py`
- [X] T057 [P] [US2] 新增 live sandbox timeout/failure 測試或 manual verification path 並確認 red/manual path 已定義，覆蓋 OrbStack/OpenShell live sandbox install demo 必須在 5 分鐘內完成或輸出 timeout/failure evidence，且 evidence 包含 readiness status、start/end time、timeout reason、containment evidence status 與禁止 host fallback 的證據；若本機無 live tool，需在 `specs/001-orbstack-sandbox-gates/quickstart.md` 記錄 sanitized fixture 替代路徑與 manual observation note，且 manual observation 不得滿足 `allow`
- [X] T058 [P] [US2] 新增 sandbox-only wrapper safety test 並確認 red，覆蓋 FR-013：`--sandbox-only` 在 invalid config、缺少 override reason、readiness 失敗或 static deny 情境下不會執行 host npm lifecycle script 且不會輸出 `allow`；static deny、static skip 與 missing static gate 判斷必須呼叫 T079 shared static gate decision core，不得在 wrapper 測試或 wrapper 實作中建立第二套判斷矩陣，於 `tests/integration/test_sandbox_only_wrapper.py`

### 使用者故事 2 的實作 (Implementation)

- [X] T032 [US2] 建立 OpenShell policy 範本，定義 live demo app/package read-only path 與 default-deny network egress 於 `policies/openshell-npm-install.yaml`；live filesystem read evidence 若使用 chmod-hardened synthetic canary probe，必須在 evidence 中以 `manual_probe.permission_denied` 標記，不得誤稱為 OpenShell 原生 OCSF FILE deny
- [X] T033 [P] [US2] 建立合成 canary secret fixture，明確標示 PoC-only、只可掛載到 sandbox/container 內供 chmod-hardened canary read-block 展示使用，且不得引用真實秘密；若 canary probe 意外可讀，runtime artifact 只能保存 redacted 訊號，不得保存 canary stdout 內容，於 `fixtures/canary/canary-secret.txt`
- [X] T034 [P] [US2] 建立 sanitized OpenShell deny log fixture，包含 file read block、synthetic egress block、policy/rule identifier、timestamp、artifact path、`source_kind=fixture` 與 sanitized marker 於 `fixtures/reports/openshell-deny.log`
- [X] T035 [US2] 建立 PoC-only `postinstall` script，僅嘗試讀取已掛載於 sandbox/container 內且在 live flow 中先以 `chmod 000` harden 的合成 canary secret fixture，並連線合成測試目的地；script 必須註記禁止 host 執行與禁止真實秘密/真實外連，於 `fixtures/malicious-poc-pkg/postinstall.js`
- [X] T036 [US2] 實作 OpenShell deny log normalization 與 containment pass 判斷於 `src/chainshield/evidence.py`；parser 必須支援 sanitized JSON fixture events 與 OpenShell OCSF text log 的 `NET:OPEN ... DENIED`，並允許 live filesystem event 使用 `manual_probe.permission_denied` 作為 policy/rule identifier
- [X] T037 [US2] 實作 OrbStack-first Docker 相容 runtime 與 OpenShell/NemoClaw readiness checks 於 `src/chainshield/sandbox.py`；若 OrbStack 不可用，live sandbox install demo 必須停止並輸出 `manual_review`、sanitized fixture evidence path 或 manual verification path；manual observation 不得滿足 `allow`，且不得 fallback 到宿主機或未經 spec 授權的一般 Docker runtime
- [X] T038 [US2] 實作受控 sandbox install orchestration，禁止 host fallback 並記錄 start/end runtime 於 `src/chainshield/sandbox.py`；live OpenShell 0.0.44 flow 必須使用單一 upload bundle、`openshell sandbox create --name ... --policy ... --upload <bundle>:/tmp --no-tty -- sh -lc ...`、`sandbox exec --name ... --no-tty` 收集 log/probe evidence，且不得在 host 執行 `npm install`
- [X] T039 [US2] 串接 sandbox demo override safety 與 sandbox gate flow（依賴 T079 shared static gate decision core）；CLI 只能呼叫 shared core 取得 static gate `deny` / `manual_review` / skip 結果，不得重建 Snyk/Socket 判斷矩陣；只有 demo config 明確設定 `sandbox_demo_override.enabled=true` 且提供 reason 時才可在靜態 gate deny 後進入 P2 sandbox 展示，且最終 Supervisor 決策不得因此由 `deny` 改為 `allow` 於 `src/chainshield/cli.py`
- [X] T040 [US2] 建立 sandbox-only demo wrapper，支援 `--config` 與 `--sandbox-only` 並委派給 CLI；覆蓋 FR-013 且依賴 T079 shared static gate decision core，wrapper 不得自行判讀 Snyk/Socket static gate、不得建立第二套 allow/deny/manual_review 矩陣；`--sandbox-only` 仍必須執行 demo config 驗證、static gate 判讀、OrbStack/OpenShell readiness、安全路徑檢查與必要的 `sandbox_demo_override` reason 檢查，禁止 host lifecycle script，且不得將 static gate `deny` 改判為 `allow`；當既有 output path 已存在時，wrapper 可建立 timestamp-suffixed runtime config 旋轉 output path，但不得覆寫既有 artifact，於 `scripts/run-demo.py`
- [X] T041 [US2] 建立 live sandbox 與 fixture sandbox demo configs，引用 OpenShell policy、canary、sanitized log 與 `sandbox_demo_override` 理由於 `fixtures/configs/demo-live-sandbox.json`、`fixtures/configs/demo-fixture-sandbox.json`
- [X] T056 [US2] 依據 T057 已定義的 timeout/failure 測試或 manual verification path，實作 live sandbox install timeout、failure、log artifact 與 chmod-hardened canary probe evidence，確保 OrbStack/OpenShell live sandbox install demo 在 5 分鐘內完成或明確失敗，並輸出 readiness status、start/end time、timeout reason、containment evidence status、禁止 host fallback、sandbox log path 與 redacted canary-probe signal 於 `src/chainshield/sandbox.py`

**Checkpoint**: User Story 2 可獨立展示；OrbStack/OpenShell 不可用時不會執行惡意 install，fixture sandbox evidence 可證明 read block 與 egress block，`--sandbox-only` 不會跳過安全檢查，且 sandbox demo override 不會改寫靜態 `deny` 決策。

---

## Phase 5: 使用者故事 3 - 彙整證據並產生可追蹤的 allow/deny/manual_review 決策 (Priority: P3)

**Goal**: 將 Snyk、Socket 與必要的 OpenShell evidence 彙整為符合 schema 的 JSON decision，並可選產生 30 秒內可讀且含 demo-only scope disclaimer 的 Markdown 摘要。

**Independent Test**: 提供 deny、allow、manual_review 三種 demo config 與 fixture evidence，驗證 JSON decision 包含 result、primary reasons、gate results、missing gates、next actions、timestamps 與 artifact paths；Markdown 摘要能清楚列出相同資訊與 demo-only 範圍。

### 使用者故事 3 的測試 (TDD mandatory)

- [X] T042 [P] [US3] 新增 Supervisor decision sufficiency unit test 並確認 red，基於 T080/T079 的 shared core 補足 US3-only 規則：allow 需要 Snyk+Socket pass、必要 gate evidence 的 `source_kind` 只有 `live` 或 `fixture` 可支援 `allow`、`manual_observation`/未知 `source_kind`/skip gate 不得支援 `allow`、conflict -> `manual_review`、既有 `manual_review` decision artifact 不得被人工直接改寫或重用為 `allow`；此任務只新增測試案例，不新增第二套決策實作，於 `tests/unit/test_supervisor_decisions.py`
- [X] T043 [P] [US3] 新增 decision artifact contract test 並確認 red，驗證輸出符合 `supervisor-decision.schema.json`，且 `run_id` 可追溯到 demo config path、fixture identity、timestamp 與 evidence hash 於 `tests/contract/test_supervisor_decision_contract.py`
- [X] T044 [P] [US3] 新增 JSON 與 Markdown output integration test 並確認 red，覆蓋摘要含缺失 gate、next actions、artifact paths、demo-only scope disclaimer，且 Markdown 摘要必須在頂部固定呈現 result、主要理由、缺失 gate 與下一步，以支援 30 秒內辨識核心資訊；`manual_review` 的 next actions 必須要求補齊 sanitized evidence/config 並重新執行 Supervisor，不得提供人工直接改判為 `allow` 的操作路徑，於 `tests/integration/test_decision_outputs.py`
- [X] T054 [US3] 新增 sandbox-executed allow sufficiency unit test 並確認 red，專門覆蓋已執行 sandbox install demo 時缺少 file read block、缺少 egress block、OpenShell containment 不完整或 evidence 欄位不完整皆不得輸出 `allow`；只有 Snyk+Socket pass 且 OpenShell file/egress evidence 皆完整時才符合 `allow` 條件，於 `tests/unit/test_supervisor_decisions.py`
- [X] T060 [P] [US3] 新增 Nemotron request sanitization 與 Worker output boundary unit test 並確認 red，驗證 request 只包含 worker task packet、artifact refs、evidence checklist 與 sanitized metadata，不包含 `NVIDIA_API_KEY`、token、真實秘密、host-sensitive path 或未清理 log；同時驗證 Nemotron/subagent 回傳若包含 shell command、scanner/sandbox execution request、host lifecycle script 指令或未授權 tool invocation，系統必須拒絕採用該 Worker output，產生 sanitized boundary violation evidence，且不得觸發 scanner/sandbox 執行，於 `tests/unit/test_worker_provider.py`
- [X] T061 [P] [US3] 新增 Worker provider fallback unit test 並確認 red，覆蓋 Nemotron timeout/auth/rate limit/malformed response 後必須依 canonical `provider_chain` 繼續執行，且 `fallback_order_after_primary_failure` 固定為 `codex_subagent` -> `claude_subagent` -> `manual_review`；每個 provider 嘗試預設 60 秒 timeout 後才 fallback；所有 provider unavailable 時輸出 `manual_review` 且不啟動 unsafe sandbox install，於 `tests/unit/test_worker_provider.py`
- [X] T075 [P] [US3] 新增 Worker evidence allow-sufficiency unit test 並確認 red，覆蓋 `worker_provider.enabled=true` 時 `finding_status=clear` 只能在 Snyk/Socket/必要 OpenShell gate 皆通過時支援 `allow`，`finding_status=concern` 或 `inconclusive` 必須輸出 `manual_review` 且不得直接形成 `deny`，worker evidence 缺失、失敗或互相衝突時也必須輸出 `manual_review`，於 `tests/unit/test_supervisor_decisions.py`
- [X] T081 [P] [US3] 新增 Worker disabled/no-invocation unit test 並確認 red，覆蓋 demo config 未設定 `worker_provider` 或設定 `worker_provider.enabled=false` 時，CLI/Supervisor 不得建立 worker task packet、不得呼叫 Nemotron/Codex/Claude provider、不得產生 `agent_invocations`，且最終決策只依 Snyk、Socket 與必要 OpenShell deterministic gate evidence 判斷，於 `tests/unit/test_worker_provider.py`、`tests/unit/test_supervisor_decisions.py`

### 使用者故事 3 的實作 (Implementation)

- [X] T045 [US3] 擴充 shared Supervisor decision model，納入 `missing_gates`、`next_actions`、`artifacts` 與 `generated_at`，並沿用 T079 的唯一決策矩陣；不得重新實作與 T079/T025 衝突的 allow/deny/manual_review 判斷邏輯，於 `src/chainshield/supervisor.py`
- [X] T078 [US3] 實作 manual review rerun guard，當輸入指向既有 `manual_review` decision artifact 或嘗試重用既有 output path 產生 `allow` 時，必須拒絕並要求以更新後 sanitized evidence/config 重新執行，於 `src/chainshield/supervisor.py`、`src/chainshield/artifacts.py`
- [X] T046 [US3] 實作 Markdown summary renderer，固定顯示 result、理由、gate evidence、缺失 gate、下一步與 demo-only npm supply-chain defense PoC scope disclaimer 於 `src/chainshield/artifacts.py`
- [X] T047 [US3] 串接 CLI output path、Markdown 可選輸出與 performance timestamps 於 `src/chainshield/cli.py`
- [X] T064 [US3] 實作 Worker provider config model、disabled/no-op path、provider chain selection、預設 60 秒 provider timeout、worker task packet builder、Worker output boundary validator 與 sanitized invocation evidence writer；當 `worker_provider` 未設定或 `worker_provider.enabled=false` 時不得建立 task packet、不得呼叫任何 provider、不得產生 `agent_invocations`，且決策必須回到 deterministic Supervisor gate rules；Worker output 只能被解析為 evidence summary，若包含 shell command、scanner/sandbox execution request 或未授權 tool invocation，必須轉為 sanitized failure evidence 並阻止後續 unsafe execution，於 `src/chainshield/worker_provider.py`
- [X] T065 [US3] 實作 Nemotron 3 Nano NVIDIA API adapter，使用 `NVIDIA_API_KEY`、`NEMOTRON_BASE_URL` 與 `NEMOTRON_MODEL`，支援 timeout、401/403、429、5xx、malformed response 與 token redaction failure evidence 於 `src/chainshield/worker_provider.py`
- [X] T066 [US3] 實作 Codex/Claude subagent fallback packet 與 ChainShield Worker skill handoff，嚴格依序執行 `codex_subagent` -> `claude_subagent` -> `manual_review` fallback，產生可交給本地 subagent 的 sanitized prompt/task packet，且不要求 OpenAI/Anthropic API key 於 `src/chainshield/worker_provider.py`
- [X] T067 [US3] 建立 ChainShield Worker agent skill，定義 subagent 只能讀取 sanitized worker task packet 與 artifact refs、產生 worker evidence summary、不得執行 shell command、不得輸出要求 scanner/sandbox/host lifecycle script 執行的 tool invocation，也不得裁決 final decision 於 `.agents/skills/chainshield-worker/SKILL.md`
- [X] T068 [US3] 串接 Worker provider evidence 到 Supervisor decision，實作 T075 的 `finding_status` allow-blocking 規則，確保 `agent_invocations` 進入 JSON/Markdown summary，且 worker output 不得覆寫 Snyk/Socket/OpenShell deterministic gate rules；若 Worker evidence 標示 boundary violation、shell command request 或 scanner/sandbox execution request，Supervisor 必須輸出 `manual_review` 並不得啟動 unsafe sandbox install，於 `src/chainshield/supervisor.py`、`src/chainshield/artifacts.py`
- [X] T048 [US3] 建立 allow 與 manual_review demo configs，覆蓋 OpenShell 未執行與 evidence 缺失情境於 `fixtures/configs/demo-fixture-allow.json`、`fixtures/configs/demo-fixture-manual-review.json`
- [X] T069 [US3] 建立 worker provider demo configs，覆蓋 Nemotron success、Nemotron failure -> `codex_subagent` fallback、Codex unavailable -> `claude_subagent` fallback、所有 provider unavailable -> `manual_review` 於 `fixtures/configs/demo-worker-nemotron.json`、`fixtures/configs/demo-worker-fallback.json`
- [X] T049 [US3] 更新 README demo 指引，說明 `allow`、`deny`、`manual_review` 摘要、不重跑 demo 的 evidence 閱讀方式，以及本功能僅為 npm supply-chain defense PoC、不包含 production CI/CD rollout、SOC/SIEM 整合或一般惡意程式分析於 `README.md`

**Checkpoint**: User Story 3 可獨立展示；decision JSON 符合 schema，Markdown 摘要讓審查者可在 30 秒內辨識結果、理由、缺失 gate、下一步與 demo-only 範圍，且 sandbox install demo 已執行時的 `allow` 決策已驗證 OpenShell file/egress evidence sufficiency。

---

## Phase 6: 收尾與跨切關注 (Polish & Cross-Cutting Concerns)

**Purpose**: 完成安全清理、效能驗證、文件一致性與完整 quickstart 驗證。

- [X] T050 [P] 新增 artifact redaction integration test，驗證 T072 sanitizer 對 fixture/report/output 的保存前檢查，確保不含 token、SSH key、cloud profile 或個人 `.env` 內容於 `tests/integration/test_artifact_redaction.py`
- [X] T051 新增 fixture scanner、report processing 與 decision performance test，要求 fixture scanner 在 30 秒內完成或明確失敗、Supervisor report processing 在 30 秒內完成或明確失敗，且 fixture-first Supervisor 決策總流程在 10 秒內完成，測試需保存 start/end timestamps 與 timeout/failure reason 於 `tests/integration/test_decision_performance.py`
- [X] T052 執行完整 `pytest tests/`；若失敗，必須依根因修正 production/PoC code、測試、sanitized fixture 或文件，不得以放寬測試或改寫 fixture 掩蓋實作缺陷，直到完整測試通過或以 quickstart 記錄明確的 manual-only 驗證限制於 `tests/`
- [X] T053 執行 quickstart fixture-first 驗證並更新預期輸出、runtime、安全注意事項與 Markdown 30 秒可讀性 manual check 結果；CLI/tool verification 結論必須引用 `specs/001-orbstack-sandbox-gates/research.md` 的版本控管驗證紀錄，於 `specs/001-orbstack-sandbox-gates/quickstart.md`
- [X] T070 執行 Nemotron Worker live smoke test 或 fallback manual verification，更新 NVIDIA API setup、canonical `provider_chain` `nemotron_api` -> `codex_subagent` -> `claude_subagent` -> `manual_review`、`fallback_order_after_primary_failure` `codex_subagent` -> `claude_subagent` -> `manual_review`、agent skill 使用方式與 provider unavailable 的 `manual_review` evidence 於 `specs/001-orbstack-sandbox-gates/quickstart.md`

---

## 相依性與執行順序 (Dependencies & Execution Order)

### Phase Dependencies

- **Phase 1 Setup**: 無前置依賴，可立即開始。
- **Phase 2 Foundational**: 依賴 Phase 1；阻擋所有 user story，因為 config invalid 必須先安全失敗、shared static gate decision core 必須先建立，且工具 flags/policy schema 必須先驗證。
- **Phase 3 US1 (P1 / MVP)**: 依賴 Phase 2；完成後即可展示 Snyk/Socket fixture-first deny。
- **Phase 4 US2 (P2)**: 依賴 Phase 2 shared static gate decision core；可與 US1 平行開發，但若要展示「static gate deny 後的 sandbox demo override」敘事，需先完成 shared static gate core 與 sandbox override safety tests。
- **Phase 5 US3 (P3)**: 依賴 Phase 2；可與 US1/US2 平行開發，但最終整合需讀取前兩者產生的 evidence。
- **Phase 6 Polish**: 依賴欲交付的 user stories 完成後執行。

### User Story Dependencies

- **US1**: Foundation 完成後可獨立實作；不依賴 US2/US3。
- **US2**: Foundation 與 shared static gate decision core 完成後可獨立實作；sandbox fixture path 不需 live scanner token。
- **US3**: Foundation 完成後可獨立實作；決策矩陣可用 fixture evidence 驗證，不需 live sandbox。

### Within Each User Story

- 測試任務必須先完成並確認 red，再開始同故事的實作任務。
- Parser/normalization 先於 scanner/sandbox adapter。
- Adapter 先於 CLI orchestration。
- Supervisor allow/deny/manual_review 判斷只能由 T079 的 shared decision core 擴充；後續 story 任務不得建立平行決策矩陣，只能新增測試案例、資料欄位或呼叫 shared core。
- 每個 story checkpoint 都必須能獨立通過對應 `pytest` 範圍與 quickstart 驗證。

### Dependency Graph

```text
Phase 1 Setup
  -> Phase 2 Foundational
    -> US1 Static Snyk/Socket Gates (MVP)
    -> US2 OrbStack/OpenShell Sandbox Gate
    -> US3 Evidence Summary & Decisions
  -> Phase 6 Polish after selected stories
```

---

## 平行執行機會 (Parallel Opportunities)

- Phase 1 的 T003、T004 可與 T002 平行，因為修改不同檔案。
- Phase 2 的 T005、T006、T080、T059、T071、T073、T013、T014、T063 可平行撰寫或驗證；T007 需等 CLI skeleton 設計確認但可先寫 failing test；T072 需接續 T071，T010 需在 T072 sanitizer interface 可用後串接 artifact 寫入；T074 需接續 T073，T079 需在 T080 red state 與 shared schema/model helper 可用後執行；T062 必須在 T059 red state 已確認後執行。
- US1 的 T016、T017、T018、T055、T076、T077 可平行撰寫 tests；T019、T020、T021 可平行建立 fixture 檔。
- US2 的 T028、T029、T030、T031、T057、T058 可平行撰寫 tests 或 manual verification path；T033、T034 可平行建立 sanitized fixture。
- US3 的 T042、T043、T044、T060、T061、T075、T081 可平行撰寫 tests；T054 需接續 T042 在同一測試檔補足 sandbox-executed allow sufficiency；T064、T065、T066、T068 需依序整合 Worker provider flow，且 T064 不得早於 T081 的 red state，T068 不得早於 T075 的 red state。
- Phase 6 的 T050 可與文件驗證工作平行，T052、T053、T070 應在收尾最後執行。

## 平行執行範例 (Parallel Examples)

### User Story 1

```bash
Task: "T016 [US1] 新增 Snyk parser unit test in tests/unit/test_snyk_evidence.py"
Task: "T017 [US1] 新增 Socket parser unit test in tests/unit/test_socket_evidence.py"
Task: "T018 [US1] 新增 static gate integration test in tests/integration/test_static_gate_decision.py"
Task: "T055 [US1] 新增 live scanner timeout/failure unit test in tests/unit/test_scanner_timeouts.py"
Task: "T076 [US1] 新增 Snyk low/medium residual risk integration test in tests/integration/test_static_gate_decision.py"
Task: "T077 [US1] 新增 live scanner unavailable fallback integration test in tests/integration/test_static_gate_decision.py"
```

### User Story 2

```bash
Task: "T028 [US2] 新增 sandbox readiness unit test in tests/unit/test_sandbox_readiness.py"
Task: "T029 [US2] 新增 OpenShell evidence unit test in tests/unit/test_openshell_evidence.py"
Task: "T031 [US2] 新增 malicious PoC script safety unit test in tests/unit/test_malicious_poc_safety.py"
Task: "T057 [US2] 新增 live sandbox timeout/failure test or manual verification path"
Task: "T058 [US2] 新增 sandbox-only wrapper safety test in tests/integration/test_sandbox_only_wrapper.py"
```

### User Story 3

```bash
Task: "T042 [US3] 新增 Supervisor decision matrix unit test in tests/unit/test_supervisor_decisions.py"
Task: "T043 [US3] 新增 decision artifact contract test in tests/contract/test_supervisor_decision_contract.py"
Task: "T044 [US3] 新增 JSON 與 Markdown output integration test in tests/integration/test_decision_outputs.py"
Task: "T060 [US3] 新增 Nemotron request sanitization unit test in tests/unit/test_worker_provider.py"
Task: "T061 [US3] 新增 Worker provider fallback unit test in tests/unit/test_worker_provider.py"
Task: "T081 [US3] 新增 Worker disabled/no-invocation unit test in tests/unit/test_worker_provider.py"
```

---

## 實作策略 (Implementation Strategy)

### MVP First (User Story 1 Only)

1. 完成 Phase 1 Setup。
2. 完成 Phase 2 Foundational，特別是 invalid config 安全失敗、shared static gate decision core、工具 flags/policy schema 驗證與憲章符合性檢查。
3. 完成 Phase 3 US1：Snyk/Socket fixture-first static gates。
4. 停下來驗證：`pytest tests/unit/test_snyk_evidence.py tests/unit/test_socket_evidence.py tests/unit/test_scanner_timeouts.py tests/integration/test_static_gate_decision.py`。
5. 使用 `fixtures/configs/demo-fixture-deny.json` 展示安裝前 `deny`，確認沒有 host `npm install`。

### Incremental Delivery

1. Setup + Foundation -> config validation、schema contracts、CLI safe failure、shared static gate decision core、工具驗證與憲章符合性檢查可用。
2. US1 -> Snyk/Socket static deny MVP，可在無 token/網路下用 fixture 展示。
3. US2 -> OrbStack/OpenShell sandbox containment，live 不可用時以 sanitized log fixture 與 manual verification 補足；sandbox demo override 不覆寫靜態 gate 決策。
4. US3 -> 完整 JSON/Markdown decision evidence、Nemotron Worker evidence、Codex/Claude subagent fallback 與 demo-only scope disclaimer，讓審查者不重跑 demo 也能理解結果。
5. Polish -> redaction、performance、quickstart、本機 CLI flag 與 NVIDIA API/subagent fallback 驗證結果一致性。

### Parallel Team Strategy

1. 團隊先共同完成 Phase 1 與 Phase 2。
2. Foundation 與 shared static gate decision core 完成後，Developer A 做 US1、Developer B 做 US2、Developer C 做 US3 decision tests/model，Developer D 做 Worker provider tests/adapter/skill。
3. 每個 story 完成 checkpoint 後才整合 CLI flow，避免跨 story 互相阻塞。

---

## 驗證與注意事項 (Validation Notes)

- 所有 task line 均符合 `- [ ] T### [P?] [US?] Description with file path` 格式。
- 所有 user story phase 任務均包含 `[US1]`、`[US2]` 或 `[US3]` label；Setup、Foundational、Polish 不使用 story label。
- `[P]` 僅標示不同檔案或可平行撰寫的 tests/fixtures；同一實作檔如 `src/chainshield/evidence.py`、`src/chainshield/cli.py` 依序處理。
- 不得在宿主機直接執行 `fixtures/malicious-poc-pkg` 的 `postinstall`；任何 live install 只能經過 OrbStack/OpenShell readiness 與 sandbox orchestration。
- `sandbox_demo_override.enabled=true` 只允許第三層 sandbox 展示繼續執行，不得將靜態 Snyk/Socket gate 的 `deny` 改判為 `allow`。
- 任務完成後避免提交未清理 `reports/`、live tarball、token/auth 檔、OpenShell 原始敏感 log 或機器專屬路徑。
