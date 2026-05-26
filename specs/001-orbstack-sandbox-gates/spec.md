# 功能規格 (Feature Specification): OrbStack 優先的 npm 供應鏈防禦 PoC

**Feature Branch**: `001-orbstack-sandbox-gates`

**Created**: 2026-05-26

**Status**: Draft

**Input**: User description: "read todo.md；看起來 NemoClaw 需要 Docker，優先採用 OrbStack"

**語言政策**: 產生的 spec.md MUST 使用繁體中文 (zh-TW)；程式碼、檔案路徑、指令、API 名稱與必要英文專有名詞可保留英文。

## Clarifications

### Session 2026-05-26

- Q: OpenShell 讀檔阻擋時，惡意 fixture 應嘗試讀取哪種敏感資料來源？ → A: 只使用合成 canary secret fixture；不得嘗試讀取任何真實宿主機敏感路徑。
- Q: 當必要證據缺失、格式錯誤或結果互相衝突時，Supervisor 應輸出哪種決策？ → A: 輸出 manual_review，並阻止安裝期展示直到證據補齊或人工覆核。
- Q: `allow` 決策需要哪些 gate 證據才算充分？ → A: Snyk 與 Socket 皆通過；OpenShell 證據只在 sandbox install demo 被執行時必需。
- Q: Supervisor 決策摘要應保存成哪種輸出 artifact？ → A: 產生機器可讀 JSON 決策檔，並可選擇產生人類可讀 Markdown 摘要。
- Q: Demo 執行設定應由哪種 artifact 定義？ → A: 使用版本控管的 demo config 檔描述 fixture、scanner mode、sandbox mode 與輸出路徑。
- Q: 當 OrbStack 不可用時，本功能的 live sandbox install demo 應如何處理？ → A: 停止 live sandbox demo，只允許使用已清理 fixture 與手動驗證說明作為替代展示。
- Q: 當 demo config 驗證失敗時，Supervisor 應產生哪種結果？ → A: 產生 manual_review 決策檔，並阻止任何 scanner 或 sandbox 執行。
- Q: OpenShell 網路限制展示應採用哪種 egress policy？ → A: 預設拒絕所有 sandbox egress，惡意 fixture 只能嘗試連到 canonical synthetic egress target 並被阻擋。
- Q: 當某個 gate 已有明確 `deny` 證據，但其他必要 gate 證據缺失時，Supervisor 應如何裁決？ → A: 輸出 deny，並在摘要標示其他必要 gate 證據缺失。
- Q: 已執行 sandbox install demo 時，OpenShell containment 應需要哪些證據才算通過？ → A: 同時具備檔案讀取阻擋證據與網路 egress 阻擋證據。
- Q: 若靜態 Snyk/Socket gate 已產生 `deny`，是否可為了展示第三層防線繼續 sandbox install demo？ → A: 只能透過 demo config 明確設定 `sandbox_demo_override.enabled=true` 並提供理由，允許進入受控 sandbox 展示；不得將原本的 `deny` 改判為 `allow`。
- Q: `--sandbox-only` 是否可以跳過 demo config 驗證、static gate 判讀或 sandbox demo override 規則？ → A: 不可以。`--sandbox-only` 僅代表只執行受控 sandbox 展示路徑；仍必須先通過 demo config 驗證、OrbStack/OpenShell readiness、安全路徑檢查與必要的 `sandbox_demo_override` reason，且不得執行 host lifecycle script、不得將既有 static gate `deny` 改判為 `allow`。
- Q: README/todo 提到的 Nemotron model、subagent 與 agent skill 是否納入本 feature？ → A: 納入。Nemotron 3 Nano 透過 NVIDIA hosted API 作為 primary Worker provider；若 Nemotron API 不可用，fallback 到本地 Codex/Claude subagent 與 ChainShield Worker agent skill。
- Q: Worker model 或 subagent 是否可以直接裁決 `allow` / `deny`？ → A: 不可以。Worker provider 只產生 sanitized worker evidence summary；最終安全裁決仍由 deterministic Supervisor gate rules 依 Snyk、Socket、OpenShell 與 worker provider evidence sufficiency 產生。

### Session 2026-05-27

- Q: Nemotron API 失敗後，Worker provider chain 應使用哪種 fallback 順序？ → A: `codex_subagent` → `claude_subagent` → `manual_review`。
- Q: Demo Config 未指定 Worker provider 設定時，是否預設啟用 Worker evidence？ → A: 預設停用；只有 `worker_provider.enabled=true` 時才執行 Worker chain。
- Q: 每次 Worker provider 嘗試在 fallback 前應使用哪個 timeout？ → A: 每個 provider 60 秒。
- Q: 啟用 Worker evidence 時，Worker providers 應接收哪種輸入邊界？ → A: 只接收 sanitized task packet 與 sanitized artifact references。
- Q: 若 `worker_provider.enabled=true` 但所有 Worker providers 皆失敗，而 Snyk/Socket/OpenShell 證據原本皆通過時，Supervisor 應如何裁決？ → A: 輸出 `manual_review`，因為要求的 Worker evidence 缺失。
- Q: 當 artifact sanitizer 偵測到真實秘密、token、SSH/cloud profile 或未遮罩 host sensitive path 時，Supervisor 應如何處理該 artifact 與決策？ → A: 阻止保存該 artifact，產生只含 sanitized failure reason 的 `manual_review` 決策，且停止後續 scanner/sandbox 執行直到清理完成。
- Q: 當 demo config 將 `scanner_mode.snyk` 或 `scanner_mode.socket` 設為 `skip`，且沒有其他 gate 已明確 `deny` 時，Supervisor 應如何裁決？ → A: 輸出 `manual_review`，並在 `missing_gates` 標示被 skip 的必要 static gate。
- Q: `manual_review` 的人工覆核完成後，系統應如何回到可判定狀態？ → A: 人工只能新增或修正 sanitized evidence/config，然後重新執行 Supervisor；不得直接把既有 `manual_review` 改成 `allow`。
- Q: Demo Config 中 Worker 設定的 canonical key 應使用哪個名稱？ → A: 使用 `worker_provider.enabled` 作為 canonical key；舊稱統一為此名稱。
- Q: 當 demo config 指定 `scanner_mode.snyk=live` 或 `scanner_mode.socket=live`，但對應 CLI 因未登入、token 缺失、網路錯誤或服務不可用而無法取得 live report 時，Supervisor 應如何處理？ → A: 若 config 同時提供對應 sanitized fixture report，fallback 使用 fixture evidence 並在摘要標示 live unavailable；否則輸出 `manual_review`。
- Q: `manual_observation` Gate Evidence 是否可滿足最終 `allow` 決策？ → A: 不可以；只有 `live` 或 `fixture` evidence 可滿足 `allow`，`manual_observation` 只能支援 `manual_review` 或說明性註記。
- Q: 惡意 fixture 應嘗試連線的 canonical synthetic egress target 是什麼？ → A: 使用 `https://chainshield-egress-test.invalid/collect`，此 reserved invalid domain 必須在真實外連前被 sandbox egress policy 阻擋。
- Q: Snyk report 只有 low 或 medium 已知漏洞、且沒有 high/critical 時，Supervisor 應如何裁決 Snyk gate？ → A: 視為 Snyk gate 通過，但決策摘要必須列出 low/medium residual risk。
- Q: Scanner 與決策報告處理的預設 runtime budget 應如何定義？ → A: 每個 live scanner 120 秒 timeout；fixture scanner 與 Supervisor report processing 各 30 秒內完成。
- Q: 若兩個 demo run 指向同一個 output path 或 decision artifact，系統應如何處理衝突？ → A: 拒絕第二個 run，輸出 `manual_review` 並要求使用新的 output path。
- Q: 每次 安裝評估請求 / Gate 證據 / Supervisor 決策 的唯一識別規則應如何定義？ → A: 使用 repository-local `run_id`，由 demo config path、fixture identity、timestamp 與 evidence hash 組成。
- Q: OpenShell/NemoClaw、Snyk 與 Socket CLI 旗標 / policy schema 的驗證結果應保存在哪裡？ → A: 保存於版本控管的 `research.md` 驗證紀錄，包含 command、version、observed behavior 與日期。
- Q: 當 Worker 成功產生 sanitized evidence summary，但摘要指出非 gate 來源疑慮或可疑觀察，而 Snyk/Socket/OpenShell 必要 gate 原本皆通過時，Supervisor 應如何裁決？ → A: 輸出 `manual_review`；Worker 疑慮不能直接 `deny`，但會阻止 `allow`。
- Q: Worker evidence summary 應使用哪個 canonical field 讓 Supervisor 判斷是否阻止 `allow`？ → A: 使用 `finding_status`，允許值為 `clear`、`concern`、`inconclusive`。


## 使用者情境與測試 (User Scenarios & Testing) *(mandatory)*

### 使用者故事 1 - 以相依套件風險先行阻擋安裝 (Priority: P1)

作為 PoC 展示者，我想在 npm 套件真正進入安裝展示前，先用已知漏洞與相依套件政策檢查做出拒絕或放行判斷，讓觀眾能清楚看到第一層與第二層防線如何降低供應鏈風險。

**優先順序理由**: 這是最小可展示價值；若靜態 gate 無法產生可追蹤決策，後續 sandbox 展示就缺少前置防線脈絡。

**獨立測試**: 可用含有高風險相依套件的 npm fixture 執行掃描流程，驗證 Supervisor 只根據掃描證據做出拒絕決策，且不需要執行惡意安裝腳本。

**BDD 驗收情境**:

1. **Given** npm fixture 的相依套件報告包含 high 或 critical 已知漏洞，**When** Supervisor 評估安裝請求，**Then** 決策必須為 `deny`，並指出拒絕原因來自 Snyk 證據。
2. **Given** npm fixture 的相依套件政策報告顯示不健康或違反組織政策，**When** Supervisor 評估安裝請求，**Then** 決策必須為 `deny`，並指出拒絕原因來自 Socket 證據。
3. **Given** Snyk 與 Socket 的 live 掃描不可用但存在已清理的報告 fixture，**When** Supervisor 評估同一個安裝請求，**Then** 決策仍必須可重現，並標明使用的是 fixture 證據。

---

### 使用者故事 2 - 在 OrbStack 優先的容器沙箱中展示安裝期阻擋 (Priority: P2)

作為 PoC 展示者，我想在 demo config 明確啟用 sandbox demo override 時，於容器化沙箱中展示安裝期惡意行為被阻止，並優先採用 OrbStack 作為本機容器執行環境，避免在宿主機直接執行惡意 PoC。

**優先順序理由**: 這展示第三層防線，證明即使 demo 為了展示而明確啟用 sandbox demo override，安裝期行為仍受到檔案與網路限制；同時回應 NemoClaw/OpenShell 需要 Docker 相容環境的限制。

**獨立測試**: 可在 OrbStack 可用的本機環境中執行受控 sandbox install demo，驗證合成 canary secret 讀取與預設拒絕的網路 egress 嘗試都被阻擋，且宿主機不被污染。

**BDD 驗收情境**:

1. **Given** 展示環境已確認具備 OrbStack 優先的容器執行能力，**When** CLI 透過 sandbox orchestration 在 sandbox 內執行受控 npm 安裝展示，**Then** 惡意 postinstall 行為只能在 sandbox 邊界內嘗試，且 OpenShell containment 只有在同時具備檔案讀取阻擋證據與網路 egress 阻擋證據時才算通過。
2. **Given** postinstall 嘗試讀取 sandbox allowlist 之外的合成 canary secret fixture，**When** OpenShell gate 套用檔案限制，**Then** 讀取必須失敗，且產生可查詢的拒絕證據。
3. **Given** postinstall 嘗試連線到 `https://chainshield-egress-test.invalid/collect`，**When** OpenShell gate 套用預設拒絕所有 sandbox egress 的網路限制，**Then** 外連必須在任何真實網路 egress 前失敗，且產生可查詢的拒絕證據。
4. **Given** 使用者以 `--sandbox-only` 執行 sandbox 展示，**When** demo config 驗證失敗、缺少 `sandbox_demo_override` reason、OrbStack/OpenShell readiness 失敗，或 static gate 已產生 `deny` 且未明確授權 sandbox demo override，**Then** 流程必須阻止 host lifecycle script 執行、不得跳過 static gate 判讀與安全路徑檢查，且不得輸出 `allow`。

---

### 使用者故事 3 - 彙整證據並產生可追蹤的 allow/deny/manual_review 決策 (Priority: P3)

作為 PoC 觀眾或審查者，我想看到 Supervisor 將 Snyk、Socket 與 OpenShell 的證據彙整成單一決策摘要，讓我能不重跑完整 demo 也理解為什麼某個安裝請求被放行、拒絕或需要人工覆核。

**優先順序理由**: PoC 的說服力來自可觀察與可追蹤的證據；此故事補足展示結論與人工審查可讀性。

**獨立測試**: 可提供一組掃描報告與 sandbox 拒絕紀錄，驗證 Supervisor 輸出的決策摘要包含結果、理由、證據來源與下一步建議。

**BDD 驗收情境**:

1. **Given** Snyk、Socket 或 OpenShell 任一 gate 產生明確拒絕證據，即使其他必要 gate 證據缺失，**When** Supervisor 產生決策摘要，**Then** 摘要必須包含 `deny` 結果、主要拒絕理由、證據來源、缺失 gate 清單與建議下一步。
2. **Given** Snyk 與 Socket 皆有通過證據且未執行 sandbox install demo，**When** Supervisor 產生決策摘要，**Then** 摘要必須包含 `allow` 結果、通過的 gate 清單，並標明 OpenShell containment 尚未在本次流程中執行。
3. **Given** 沒有明確 `deny` 證據且證據互相衝突或部分缺失，**When** Supervisor 產生決策摘要，**Then** 摘要必須輸出 `manual_review`，並阻止安裝期展示直到證據補齊或人工覆核。
4. **Given** demo config 啟用 Worker provider 且 `NVIDIA_API_KEY` 可用，**When** CLI 建立 sanitized worker task packet，**Then** Nemotron 3 Nano Worker 必須只讀取 sanitized artifact reference 並產生 worker evidence summary，不得讀取 token、秘密或直接裁決最終 decision。
5. **Given** Nemotron API timeout、auth failure、rate limit 或 response 無法解析，**When** Worker provider chain 繼續執行，**Then** 系統必須 fallback 到本地 Codex/Claude subagent 與 ChainShield Worker agent skill，並保存 fallback provider evidence 或 failure reason。
6. **Given** 所有 Worker provider 都不可用且 demo config 要求 live worker evidence，**When** Supervisor 產生決策摘要，**Then** 摘要必須輸出 `manual_review`、列出 missing worker provider evidence 與下一步，且不得啟動 unsafe sandbox install demo。
7. **Given** Worker provider 成功產生 sanitized evidence summary 且標示非 gate 來源疑慮或可疑觀察，**When** Snyk、Socket 與必要 OpenShell gate 證據原本皆通過，**Then** Supervisor 必須輸出 `manual_review`、引用 Worker summary 作為覆核原因，且不得因 Worker 疑慮直接輸出 `deny`。

### 邊界案例 (Edge Cases)

- 當 OrbStack 不可用時，流程必須明確回報容器環境未就緒，停止 live sandbox install demo，且只允許使用已清理 fixture 與手動驗證說明作為替代展示；不得退回到宿主機直接執行惡意 PoC。
- 當 Snyk 或 Socket 需要登入、token 或網路連線而無法執行 live 掃描時，若 demo config 提供對應 sanitized fixture report，流程必須 fallback 使用 fixture evidence 完成 Supervisor 判讀展示並標示 live unavailable；若缺少對應 fixture report，Supervisor 必須輸出 `manual_review`。
- 當沒有明確 `deny` 證據，且掃描報告格式不完整、無法解析、缺少必要欄位或證據互相衝突時，Supervisor 必須輸出 `manual_review`，並阻止安裝期展示直到證據補齊或人工覆核。
- 當 OpenShell 沒有同時產生檔案讀取阻擋證據與網路 egress 阻擋證據時，展示必須標示 containment 證據不足，不能宣稱第三層防線成功。
- 當 fixture、report 或暫存輸出可能包含秘密、token、SSH/cloud profile 或未遮罩 host sensitive path 時，artifact sanitizer 必須阻止保存該 artifact，Supervisor 必須產生只含 sanitized failure reason 的 `manual_review` 決策，並停止後續 scanner/sandbox 執行直到清理完成；OpenShell 讀檔阻擋展示只允許使用合成 canary secret fixture。
- 當 demo run 指向已被其他 run 使用或已存在的 output path / decision artifact 時，系統必須拒絕新的 run、產生 `manual_review`，並要求使用新的 output path；不得覆寫既有 evidence 或 decision artifact。
- 當使用者嘗試擴大到非 npm package manager、production CI/CD 或 SOC/SIEM 整合時，本功能必須視為超出本次 PoC 範圍。

## 需求 (Requirements) *(mandatory)*

### 功能需求 (Functional Requirements)

- **FR-001**: 系統必須支援一個 npm-focused 安裝評估流程，並將每次請求歸納為 `allow`、`deny` 或 `manual_review` 結果。
- **FR-002**: 系統必須在進入安裝期展示前評估 Snyk 證據；若證據顯示 high 或 critical 已知漏洞，必須拒絕安裝請求；若只包含 low 或 medium 已知漏洞且沒有 high/critical，Snyk gate 視為通過，但 Supervisor 決策摘要必須列出 low/medium residual risk。
- **FR-003**: 系統必須在進入安裝期展示前評估 Socket 證據；若 Socket 證據顯示 `unhealthy`、明確 organization policy violation、malware/supply-chain risk 命中，或 live Socket command 以可判定的 policy failure exit code 結束，必須拒絕安裝請求；若 Socket report 缺少必要欄位、格式無法解析或 exit code 無法歸類，必須輸出 `manual_review`。Socket live command 的 exit code 分類必須由實作前版本控管的 `research.md` CLI 驗證紀錄定義；未被明確分類為 policy failure 的非零 exit code 不得直接視為 `deny`，必須輸出 `manual_review`。
- **FR-004**: 系統必須支援由版本控管的 demo config 檔指定 fixture、scanner mode、sandbox mode、輸出路徑、是否啟用 sandbox demo override 與可選 Worker 設定。
  - **FR-004a**: 未指定 Worker 設定時，Worker evidence 預設停用；只有 `worker_provider.enabled=true` 時才執行 Worker provider chain。
  - **FR-004b**: 當 `scanner_mode.snyk=live` 或 `scanner_mode.socket=live` 但對應 CLI 因未登入、token 缺失、網路錯誤或服務不可用而無法取得 live report 時，若 config 同時提供對應 sanitized fixture report，系統必須 fallback 使用 fixture evidence 並在決策摘要標示 live unavailable，否則必須輸出 `manual_review`。
  - **FR-004c**: 當 demo config 驗證失敗時，系統必須產生 `manual_review` 決策檔，並阻止任何 scanner 或 sandbox 執行。
  - **FR-004d**: 當 `scanner_mode.snyk` 或 `scanner_mode.socket` 設為 `skip` 且沒有其他 gate 已明確 `deny` 時，Supervisor 必須輸出 `manual_review`，並在 `missing_gates` 標示被 skip 的必要 static gate。
  - **FR-004e**: `sandbox_demo_override` 僅能用於展示第三層 sandbox containment，不得將靜態 gate 的 `deny` 改判為 `allow`。
  - **FR-004f**: Demo config 的 fixture、policy 與輸出路徑必須通過安全路徑檢查：fixture/policy path 必須位於 repository 內的受控 fixture 或 policy 目錄；output path 必須位於 `reports/` 或 config 明確指定的 repository-local output 目錄；不得使用 parent traversal、home expansion、絕對敏感路徑、auth/token/SSH/cloud profile 檔案路徑，且不得經由 symlink 指向 repository 外部或敏感位置。
  - **FR-004g**: 若 output path 或 decision artifact 已存在或被其他 run 使用，系統必須拒絕新的 run、產生 `manual_review`，並要求使用新的 output path，不得覆寫既有 evidence 或 decision artifact。
- **FR-005**: 系統必須只在受控 sandbox/container 流程中展示安裝期惡意 PoC，且不得在宿主機直接執行惡意 postinstall 行為；PoC-only `postinstall` script 只能執行合成 canary secret 讀取嘗試與 `https://chainshield-egress-test.invalid/collect` egress 嘗試，不得引用真實宿主機敏感路徑、真實 token、真實外部 exfiltration 目的地或 public registry 發布流程。
- **FR-006**: 系統必須以 OrbStack-first 且唯一授權的 live sandbox Docker 相容 runtime 執行本機安裝期展示；不得在 OrbStack 不可用時改用宿主機直接執行或未經本 spec 明確授權的一般 Docker runtime。OpenShell/NemoClaw、Snyk 與 Socket CLI 旗標、版本與 policy schema 的實測結果必須保存於版本控管的 `research.md` 驗證紀錄，且每筆紀錄包含 command、version、observed behavior 與日期；若 OrbStack 不可用，必須停止 live sandbox install demo，且只允許使用已清理 fixture 與手動驗證說明作為替代展示。
- **FR-007**: 系統必須在 OpenShell gate 中展示檔案讀取限制；惡意 fixture 只能嘗試讀取 sandbox 內的合成 canary secret fixture，且不得嘗試讀取任何真實宿主機敏感路徑，讀取失敗時必須留下可查詢證據。
- **FR-008**: 系統必須在 OpenShell gate 中展示預設拒絕所有 sandbox egress 的網路外連限制；惡意 fixture 只能嘗試連到 canonical synthetic egress target `https://chainshield-egress-test.invalid/collect`，且連線嘗試必須在任何真實網路 egress 前失敗並留下可查詢證據。
- **FR-009**: 系統必須彙整 Snyk、Socket 與必要的 OpenShell 證據，產生機器可讀 JSON 決策檔，並可選擇產生人類可讀 Markdown 摘要；輸出必須包含 repository-local `run_id`、結果、理由、證據來源、時間點與下一步建議，且 `allow` 決策至少需要 Snyk 與 Socket 皆通過；用於滿足 `allow` 的必要 gate evidence `source_kind` 必須為 `live` 或 `fixture`，不得使用 `manual_observation`；若任一必要 static gate 被 skip 且沒有其他 gate 明確 `deny`，不得輸出 `allow`；sandbox install demo 被執行時，OpenShell containment 必須同時具備檔案讀取阻擋證據與網路 egress 阻擋證據才算通過。
- **FR-010**: 系統必須在無明確 `deny` 證據且必要證據缺失、格式無法解析或結果互相衝突時輸出 `manual_review`，並阻止安裝期展示直到證據補齊或人工覆核；人工覆核只能新增或修正 sanitized evidence/config，然後重新執行 Supervisor，不得直接把既有 `manual_review` 決策檔改成 `allow`；若任一 gate 已有明確 `deny` 證據，系統必須輸出 `deny` 並在摘要標示其他必要 gate 證據缺失。
- **FR-011**: 系統必須明確標示本功能只涵蓋展示型 npm 供應鏈防禦 PoC，不包含 production CI/CD rollout、SOC/SIEM 整合或一般惡意程式分析。
- **FR-012**: 系統必須保留足夠的結構化證據，使審查者可以在不重跑完整 demo 的情況下理解每個 `allow`、`deny` 或 `manual_review` 決策；若 artifact sanitizer 偵測到真實秘密、token、SSH/cloud profile 或未遮罩 host sensitive path，系統必須阻止保存該 artifact，產生只含 sanitized failure reason 的 `manual_review` 決策，並停止後續 scanner/sandbox 執行直到清理完成。
- **FR-013**: 系統提供 `--sandbox-only` 展示路徑時，仍必須先通過 demo config 驗證、static gate 判讀、OrbStack/OpenShell readiness、安全路徑檢查與必要的 `sandbox_demo_override` reason；`--sandbox-only` 不得跳過任何安全 gate、不得執行 host lifecycle script，且不得將既有 static gate `deny` 改判為 `allow`。
- **FR-014**: 系統必須支援可選的 Worker provider chain：primary provider 為 Nemotron 3 Nano via NVIDIA hosted API；fallback provider 順序必須為 `codex_subagent`、`claude_subagent`、`manual_review`，並使用 ChainShield Worker agent skill；每個 provider 嘗試的預設 timeout 必須為 60 秒；Worker providers 只能接收 sanitized task packet 與 sanitized artifact references，不得接收原始 scanner/sandbox logs、未清理 prompt、API key、token 或 host sensitive path；provider chain 的每次嘗試都必須保存 sanitized invocation evidence；成功的 worker evidence summary 必須包含 `finding_status`，允許值為 `clear`、`concern` 或 `inconclusive`。
- **FR-015**: Worker provider 只能產生工具任務與 evidence summary，不得直接執行 scanner/sandbox shell command、不得直接裁決 `allow` / `deny`，也不得覆寫 Supervisor deterministic gate rules；若 `worker_provider.enabled=true` 且 worker evidence 缺失、失敗、互相衝突，或成功產生的 sanitized evidence summary 將 `finding_status` 標示為 `concern` 或 `inconclusive`，且無明確 gate `deny`，Supervisor 必須輸出 `manual_review`，即使 Snyk/Socket/OpenShell 證據原本皆通過；Worker 疑慮不得直接形成 `deny`，只有 `finding_status=clear` 可支援既有 gate 通過後的 `allow`。

### 主要實體 (Key Entities)

- **安裝評估請求**: 表示使用者想評估或安裝的 npm 套件情境；包含 repository-local `run_id`、套件來源、展示模式、是否允許使用 fixture 證據、目前安全邊界狀態，以及引用的版本控管 demo config；`run_id` 必須由 demo config path、fixture identity、timestamp 與 evidence hash 組成。
- **Gate 證據**: 表示 Snyk、Socket 或 OpenShell 產生的可審查結果；包含 `run_id`、來源、狀態、風險等級、拒絕原因、residual risk、時間點與是否為 live、fixture 或 manual observation；Snyk low/medium residual risk 必須保留在決策摘要中；`manual_observation` 不得滿足最終 `allow` 決策，只能支援 `manual_review` 或說明性註記。
- **Worker Provider**: 表示可選的 AI Worker 執行角色；包含 provider kind、model、timeout、fallback order、source marker 與是否可用；fallback order 固定為 `nemotron_api` → `codex_subagent` → `claude_subagent` → `manual_review`，每個 provider 嘗試的預設 timeout 為 60 秒。支援值包含 `nemotron_api`、`codex_subagent`、`claude_subagent` 與 `manual_review` fallback。
- **Agent Invocation Evidence**: 表示 Nemotron/Codex/Claude Worker provider 的可審查 invocation 結果；包含 provider、model、status、sanitized task packet path、sanitized input artifact refs、output artifact path、`finding_status`、timeout/error、observed_at 與 sanitized marker；`finding_status` 的允許值為 `clear`、`concern` 或 `inconclusive`，且不得包含 API key、未清理 prompt/log、原始 scanner/sandbox logs 或 host sensitive path。
- **Agent Skill**: 表示本地 subagent fallback 使用的 ChainShield Worker skill；定義 subagent 只能讀取 sanitized task packet 與 sanitized artifact reference、產生 worker evidence summary，不能讀取原始 logs、執行惡意 PoC 或做最終安全裁決。
- **OpenShell containment evidence**: 表示 OpenShell 對安裝期行為產生的 containment 證據；至少包含 event type、blocked path 或 blocked target、policy/rule identifier、result、timestamp、artifact path、live/fixture source marker 與 sanitized marker；缺少任一必要欄位時，Supervisor 不得宣稱 OpenShell containment 通過。
- **Supervisor 決策**: 表示彙整後的 `allow`、`deny` 或 `manual_review` 結論；包含 `run_id`、主要理由、引用證據、保留風險與下一步建議；`allow` 只能由 `live` 或 `fixture` gate evidence 滿足；`manual_review` 只能透過補齊 sanitized evidence/config 並重新執行 Supervisor 轉入新決策，不支援人工直接改判為 `allow`。
- **Sandbox 展示環境**: 表示用於安裝期展示的受控執行邊界；包含容器環境就緒狀態、檔案限制狀態、網路限制狀態與宿主機保護狀態。
- **Demo Config**: 表示版本控管的展示設定檔；描述 fixture、scanner mode、sandbox mode、輸出路徑、可選的 sandbox demo override 理由與可選 Worker 設定；`safety.synthetic_egress_target` 必須為 canonical 值 `https://chainshield-egress-test.invalid/collect`；Worker 設定未指定時預設停用，只有 `worker_provider.enabled=true` 時才執行 Worker provider chain；且不得包含 token、憑證或機器專屬秘密；sandbox demo override 只能允許進入受控 sandbox 展示，不能覆寫 Supervisor 對 Snyk/Socket gate 的最終 `deny` 決策。Demo Config 的所有路徑欄位都必須保存為可審查的相對路徑或經驗證的 repository-local 路徑；任何無法解析、指向 repository 外部、指向敏感檔名樣式或經 symlink 逃逸的路徑，必須使 config 驗證失敗並產生 `manual_review`。
- **展示輸出**: 表示可交付給觀眾或審查者的報告、log 摘要或決策摘要；Supervisor 決策必須至少保存為機器可讀 JSON 檔，並可選擇輸出人類可讀 Markdown 摘要；所有展示輸出必須避免包含真實秘密、憑證或未遮罩的敏感本機資訊；若 sanitizer 偵測到敏感內容，展示輸出只能保存 sanitized failure reason，不得保存原始 artifact；既有 output path 或 decision artifact 不得被後續 run 覆寫。

## 成功標準 (Success Criteria) *(mandatory)*

### 可衡量成果 (Measurable Outcomes)

- **SC-001**: 對含有 high 或 critical 已知漏洞的 npm fixture，100% 的評估必須在安裝期展示前產生 `deny` 決策，且拒絕理由可追溯到 Snyk 證據；對只含 low/medium 且無 high/critical 的 Snyk fixture，測試必須驗證 Snyk gate 通過且決策摘要列出 residual risk。
- **SC-002**: 對 Socket 證據顯示不健康或政策不合規的 npm fixture，100% 的評估必須在安裝期展示前產生 `deny` 決策，且拒絕理由可追溯到 Socket 證據。
- **SC-003**: 在 OrbStack 就緒的展示環境中，受控 sandbox install 必須於 5 分鐘內完成或明確失敗，並產生足以判斷 containment 成敗的證據；每個 live scanner 必須設定 120 秒 timeout，fixture scanner 與 Supervisor report processing 必須各在 30 秒內完成或明確失敗；OrbStack 不可用時必須停止 live sandbox install demo，並改以已清理 fixture 與手動驗證說明呈現。
- **SC-004**: 安裝期惡意 PoC 嘗試讀取未授權的合成 canary secret fixture 時，展示結果必須顯示讀取失敗，且至少保留一筆可審查的拒絕或失敗證據；測試不得使用真實宿主機秘密或敏感路徑內容。
- **SC-005**: 安裝期惡意 PoC 嘗試連線 `https://chainshield-egress-test.invalid/collect` 時，展示結果必須顯示預設拒絕所有 sandbox egress 造成外連在任何真實網路 egress 前失敗，且至少保留一筆可審查的拒絕或失敗證據。
- **SC-006**: 每一份 Supervisor JSON 決策檔都必須可由自動化測試驗證 `run_id`、結果、主要理由、證據來源、缺失 gate 清單與下一步建議；`run_id` 必須可追溯到 demo config path、fixture identity、timestamp 與 evidence hash；`manual_review` 的下一步必須要求補齊 sanitized evidence/config 並重新執行 Supervisor，且不得提供人工直接改判為 `allow` 的路徑；若產生 Markdown 摘要，審查者必須能在 30 秒內辨識相同資訊。
- **SC-007**: Demo 輸出與保存的 fixture/report 必須 100% 不包含真實秘密、憑證、SSH key、cloud profile 或未遮罩的個人環境檔案內容；sanitizer 命中時必須可由自動化測試驗證原始 artifact 未保存、decision 為 `manual_review`、且後續 scanner/sandbox 未執行。
- **SC-008**: 主要展示流程必須能在無 live Snyk/Socket 登入的情況下，使用已清理 fixture 證據完成至少一個可重現的拒絕決策展示；live scanner unavailable、120 秒 timeout 或服務錯誤且有對應 fixture report 時，測試必須驗證 fallback 到 fixture evidence 並標示 live unavailable；缺少對應 fixture report 時，決策必須為 `manual_review`。
- **SC-009**: 所有 `allow` 決策都必須由自動化測試驗證符合 FR-009 的 gate sufficiency 規則，且必要 gate evidence 的 `source_kind` 為 `live` 或 `fixture`；必要 static gate 被 skip 且沒有其他 gate 明確 `deny` 時，測試必須驗證決策為 `manual_review` 且 `missing_gates` 含被 skip 的 gate；未執行 sandbox install demo 時，摘要必須明確標示 OpenShell containment 未執行；已執行 sandbox install demo 時，摘要必須納入檔案讀取阻擋與網路 egress 阻擋兩類 evidence，且自動化測試必須覆蓋任一 OpenShell evidence 缺失或只具備 `manual_observation` 時不得輸出 `allow`。
- **SC-010**: 主要 demo 流程必須能從版本控管的 demo config 讀取 fixture、scanner mode、sandbox mode、輸出路徑與可選 Worker 設定；未設定 Worker 時不得執行 Worker provider chain；config 驗證失敗時必須產生 `manual_review` 決策檔並阻止任何 scanner 或 sandbox 執行，且不得回退到隱含預設執行惡意 PoC；實作前必須存在 `research.md` CLI 驗證紀錄，涵蓋 OpenShell/NemoClaw、Snyk 與 Socket 的 command、version、observed behavior 與日期。
- **SC-011**: 啟用 Worker provider 時，Nemotron API success、Nemotron failure -> Codex/Claude subagent fallback、provider timeout 60 秒後 fallback、`worker_provider.enabled=true` 且所有 providers unavailable -> `manual_review`，以及 `finding_status=concern` 或 `inconclusive` 時阻止 `allow` 但不直接 `deny` 的路徑，都必須可由自動化測試或 quickstart manual verification 驗證；所有 worker invocation artifacts 必須 100% 不包含 API key、token、真實秘密、原始 scanner/sandbox logs 或未清理 host path。

## 假設 (Assumptions)

- 本功能聚焦 npm supply-chain defense demo，package manager 範圍不擴大到 pnpm、Yarn、PyPI、Cargo 或其他 ecosystem。
- OrbStack 是 macOS 本機展示的優先 Docker 相容執行環境；若未安裝或不可用，流程會停止 live sandbox install demo，只允許使用已清理 fixture 與手動驗證說明作為替代展示。
- NemoClaw/OpenShell 需要容器化或 Linux sandbox 能力才能展示安裝期 containment；實作規劃階段需確認本機版本支援的 CLI 旗標與 policy schema，並將 command、version、observed behavior 與日期保存於版本控管的 `research.md` 驗證紀錄。
- Snyk 與 Socket 的 live 掃描可能需要帳號、token 與網路；因此 fixture report 與手動驗證路徑是本 PoC 的必要備援。
- Nemotron 3 Nano live Worker 需要 NVIDIA hosted API 與 `NVIDIA_API_KEY`；若不可用，流程會依序 fallback 到本地 Codex subagent、Claude subagent 與 `manual_review`，並透過 ChainShield Worker agent skill 產生 sanitized worker evidence summary；不會要求 OpenAI/Anthropic API key。
- 惡意 fixture 僅供本機 PoC 使用，不會發布到 public registry，也不會保存真實秘密或宿主機敏感資料。
- Supervisor 負責證據彙整與 allow/deny 判斷；CLI、scanner adapter 與 sandbox orchestration 負責受控工具任務、報告收集與 sandbox 展示，不承擔主要安全推理。
- 本功能不承諾 Socket 能完整分析本地任意 JavaScript 惡意行為；Socket gate 的展示重點是 dependency metadata 與組織政策風險。
