# 資料模型 (Data Model): OrbStack 優先的 npm 供應鏈防禦 PoC

**Feature**: `001-orbstack-sandbox-gates`  
**日期**: 2026-05-27

## 實體：安裝評估請求 (Install Evaluation Request)

**用途**: 表示一次 npm package 評估或安裝展示請求，是 Supervisor 產生決策的最上層 context。

**Fields**:

- `request_id`: 字串；每次評估唯一，必須出現在所有輸出 artifact。
- `package_manager`: enum；本功能只允許 `npm`。
- `package_name`: 字串；可為 fixture package 名稱或待評估 package 名稱。
- `package_source`: 字串；可為 fixture path、tarball path 或 registry reference；不得指向 public publish action。
- `demo_config_path`: 字串；版本控管 demo config 路徑。
- `allow_fixture_evidence`: boolean；是否允許使用 sanitized fixture reports。
- `requested_sandbox_demo`: boolean；是否要求執行 install-time containment 展示。
- `created_at`: ISO-8601 timestamp。

**Validation Rules**:

- `package_manager` 必須為 `npm`；其他 ecosystem 屬於本 feature 範圍外。
- 若 `requested_sandbox_demo=true`，必須先通過 demo config 驗證與 OrbStack/OpenShell readiness gate。
- `package_source` 不得觸發 host 上的 `npm install` 或惡意 `postinstall`。

## 實體：Demo Config

**用途**: 版本控管的展示設定檔，指定 fixture、scanner mode、sandbox mode 與輸出路徑。

**Fields**:

- `version`: 整數；schema 版本，目前為 `1`。
- `request_id`: 字串；與安裝評估請求對應。
- `scanner_mode.snyk`: enum `fixture | live | skip`。
- `scanner_mode.socket`: enum `fixture | live | skip`。
- `sandbox_mode`: enum `disabled | fixture | live`。
- `fixtures.poc_app`: 字串；npm app fixture path。
- `fixtures.malicious_package`: 字串；PoC-only package path。
- `fixtures.snyk_report`: 字串或 null；sanitized Snyk report path。
- `fixtures.socket_report`: 字串或 null；sanitized Socket report path。
- `fixtures.openshell_log`: 字串或 null；sanitized OpenShell deny log path。
- `fixtures.canary_secret`: 字串或 null；sandbox 內合成 canary secret fixture path。
- `outputs.decision_json`: 字串；Supervisor JSON decision output path。
- `outputs.markdown_summary`: 字串或 null；可選 Markdown summary path。
- `safety.allow_static_gate_bypass`: boolean；只允許 P2 sandbox demo 明確繞過靜態 gate 時為 true。
- `safety.synthetic_egress_target`: 字串；只能是合成測試目的地，不得使用真實 C2。

**Validation Rules**:

- config validation 失敗時，Supervisor 必須產生 `manual_review` decision，並阻止 scanner 與 sandbox 執行。
- `live` scanner mode 不得要求 token 寫入 config；token/auth 應由外部 CLI/session 管理且不得保存。
- `sandbox_mode=live` 時必須有 canary secret fixture 與 OpenShell policy path，且不得引用真實宿主機秘密。
- `allow_static_gate_bypass=true` 時 decision/summary 必須明確標示這是第三層防線展示，不代表 package 可安全安裝。

## 實體：Gate 證據 (Gate Evidence)

**用途**: 正規化 Snyk、Socket 或 OpenShell 的可審查 evidence。

**Fields**:

- `gate`: enum `snyk | socket | openshell`。
- `status`: enum `pass | deny | manual_review | skipped`。
- `source_kind`: enum `live | fixture | manual_observation`。
- `source_path`: 字串或 null；report/log artifact path。
- `command`: 字串或 null；live mode 實際執行命令摘要，不含 token。
- `exit_code`: 整數或 null。
- `risk_level`: enum `none | low | medium | high | critical | unknown`。
- `reasons`: 字串陣列；拒絕或人工覆核原因。
- `observed_at`: ISO-8601 timestamp。
- `sanitized`: boolean；保存 artifact 前必須為 true。

**Validation Rules**:

- Snyk high/critical vulnerability evidence 必須正規化為 `status=deny`。
- Socket unhealthy、policy violation 或 live exit code 非 0 必須正規化為 `status=deny`，除非 report 無法解析則為 `manual_review`。
- OpenShell containment 只有同時具備 file read block 與 network egress block evidence 時才可視為 pass。
- 缺少必要欄位、格式錯誤或互相衝突時，若沒有其他 gate 明確 deny，Supervisor 應輸出 `manual_review`。

## 實體：Sandbox 展示環境 (Sandbox Demo Environment)

**用途**: 表示 live install-time containment demo 的受控執行邊界。

**Fields**:

- `runtime`: enum `orbstack | docker-compatible | unavailable`；本功能以 `orbstack` 為優先。
- `runtime_ready`: boolean。
- `openshell_ready`: boolean。
- `policy_path`: 字串或 null。
- `filesystem_policy_ready`: boolean。
- `network_policy_ready`: boolean。
- `host_protection_ready`: boolean。
- `read_block_observed`: boolean。
- `egress_block_observed`: boolean。
- `started_at`: ISO-8601 timestamp 或 null。
- `completed_at`: ISO-8601 timestamp 或 null。

**Validation Rules**:

- `runtime_ready=false` 或 `openshell_ready=false` 時，不得執行 live sandbox install。
- `host_protection_ready` 必須確認沒有真實 secret、SSH key、cloud profile 或 host env path 被納入 fixture/report。
- containment pass 必須同時滿足 `read_block_observed=true` 與 `egress_block_observed=true`。

## 實體：Supervisor 決策 (Supervisor Decision)

**用途**: 彙整所有 evidence 後的單一 allow/deny/manual_review 結論。

**Fields**:

- `request_id`: 字串。
- `decision`: enum `allow | deny | manual_review`。
- `summary`: 字串；短摘要。
- `primary_reasons`: 字串陣列。
- `gate_results`: Gate Evidence 陣列或 gate summary 陣列。
- `missing_gates`: enum 陣列；缺失或未執行的必要 gate。
- `next_actions`: 字串陣列。
- `generated_at`: ISO-8601 timestamp。
- `artifacts`: 物件；decision JSON、Markdown summary、scanner reports、OpenShell logs 的路徑。

**State Transitions**:

```text
created -> config_validating
config_validating -> manual_review   # config invalid，阻止 scanner/sandbox
config_validating -> collecting_evidence
collecting_evidence -> deny          # 任一 gate 有明確 deny
collecting_evidence -> manual_review # 無明確 deny 且證據缺失/衝突/不可解析
collecting_evidence -> allow         # Snyk + Socket pass；若執行 sandbox demo，OpenShell containment 也 pass
```

**Validation Rules**:

- `allow` 至少需要 Snyk 與 Socket 皆 pass。
- 若 sandbox install demo 已執行，`allow` 還需要 OpenShell read block 與 egress block evidence 皆 pass。
- 明確 `deny` 優先於 missing gate；摘要仍需列出缺失 gate。
- `manual_review` 必須阻止 install-time demo，直到 evidence 補齊或人工覆核。

## 實體：展示輸出 (Demo Output)

**用途**: 給觀眾或審查者查看的保存 artifact。

**Fields**:

- `decision_json_path`: 必填；符合 `supervisor-decision.schema.json`。
- `markdown_summary_path`: 選填；人類可讀摘要。
- `sanitized_report_paths`: 字串陣列。
- `openshell_log_paths`: 字串陣列。
- `redaction_notes`: 字串陣列；描述清理/遮罩規則。

**Validation Rules**:

- 不得包含真實秘密、憑證、SSH key、cloud profile、personal env file 或未遮罩 machine-specific sensitive path。
- 必須保存足夠 evidence reference，讓審查者不重跑完整 demo 也能理解決策。
