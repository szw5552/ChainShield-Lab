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
- Q: OpenShell 網路限制展示應採用哪種 egress policy？ → A: 預設拒絕所有 sandbox egress，惡意 fixture 只能嘗試連到合成測試目的地並被阻擋。
- Q: 當某個 gate 已有明確 `deny` 證據，但其他必要 gate 證據缺失時，Supervisor 應如何裁決？ → A: 輸出 deny，並在摘要標示其他必要 gate 證據缺失。
- Q: 已執行 sandbox install demo 時，OpenShell containment 應需要哪些證據才算通過？ → A: 同時具備檔案讀取阻擋證據與網路 egress 阻擋證據。


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

作為 PoC 展示者，我想在相依套件 gate 被刻意繞過時，於容器化沙箱中展示安裝期惡意行為被阻止，並優先採用 OrbStack 作為本機容器執行環境，避免在宿主機直接執行惡意 PoC。

**優先順序理由**: 這展示第三層防線，證明即使前置掃描被繞過，安裝期行為仍受到檔案與網路限制；同時回應 NemoClaw/OpenShell 需要 Docker 相容環境的限制。

**獨立測試**: 可在 OrbStack 可用的本機環境中執行受控 sandbox install demo，驗證合成 canary secret 讀取與預設拒絕的網路 egress 嘗試都被阻擋，且宿主機不被污染。

**BDD 驗收情境**:

1. **Given** 展示環境已確認具備 OrbStack 優先的容器執行能力，**When** Worker 在 sandbox 內執行受控 npm 安裝展示，**Then** 惡意 postinstall 行為只能在 sandbox 邊界內嘗試，且 OpenShell containment 只有在同時具備檔案讀取阻擋證據與網路 egress 阻擋證據時才算通過。
2. **Given** postinstall 嘗試讀取 sandbox allowlist 之外的合成 canary secret fixture，**When** OpenShell gate 套用檔案限制，**Then** 讀取必須失敗，且產生可查詢的拒絕證據。
3. **Given** postinstall 嘗試連線到合成測試目的地，**When** OpenShell gate 套用預設拒絕所有 sandbox egress 的網路限制，**Then** 外連必須失敗，且產生可查詢的拒絕證據。

---

### 使用者故事 3 - 彙整證據並產生可追蹤的 allow/deny/manual_review 決策 (Priority: P3)

作為 PoC 觀眾或審查者，我想看到 Supervisor 將 Snyk、Socket 與 OpenShell 的證據彙整成單一決策摘要，讓我能不重跑完整 demo 也理解為什麼某個安裝請求被放行、拒絕或需要人工覆核。

**優先順序理由**: PoC 的說服力來自可觀察與可追蹤的證據；此故事補足展示結論與人工審查可讀性。

**獨立測試**: 可提供一組掃描報告與 sandbox 拒絕紀錄，驗證 Supervisor 輸出的決策摘要包含結果、理由、證據來源與下一步建議。

**BDD 驗收情境**:

1. **Given** Snyk、Socket 或 OpenShell 任一 gate 產生明確拒絕證據，即使其他必要 gate 證據缺失，**When** Supervisor 產生決策摘要，**Then** 摘要必須包含 `deny` 結果、主要拒絕理由、證據來源、缺失 gate 清單與建議下一步。
2. **Given** Snyk 與 Socket 皆有通過證據且未執行 sandbox install demo，**When** Supervisor 產生決策摘要，**Then** 摘要必須包含 `allow` 結果、通過的 gate 清單，並標明 OpenShell containment 尚未在本次流程中執行。
3. **Given** 沒有明確 `deny` 證據且證據互相衝突或部分缺失，**When** Supervisor 產生決策摘要，**Then** 摘要必須輸出 `manual_review`，並阻止安裝期展示直到證據補齊或人工覆核。

### 邊界案例 (Edge Cases)

- 當 OrbStack 不可用時，流程必須明確回報容器環境未就緒，停止 live sandbox install demo，且只允許使用已清理 fixture 與手動驗證說明作為替代展示；不得退回到宿主機直接執行惡意 PoC。
- 當 Snyk 或 Socket 需要登入、token 或網路連線而無法執行 live 掃描時，流程必須允許使用已清理的 fixture 報告完成 Supervisor 判讀展示。
- 當沒有明確 `deny` 證據，且掃描報告格式不完整、無法解析、缺少必要欄位或證據互相衝突時，Supervisor 必須輸出 `manual_review`，並阻止安裝期展示直到證據補齊或人工覆核。
- 當 OpenShell 沒有同時產生檔案讀取阻擋證據與網路 egress 阻擋證據時，展示必須標示 containment 證據不足，不能宣稱第三層防線成功。
- 當 fixture、report 或暫存輸出可能包含秘密或本機敏感路徑時，流程必須要求清理或遮罩後才能保存為展示證據；OpenShell 讀檔阻擋展示只允許使用合成 canary secret fixture。
- 當使用者嘗試擴大到非 npm package manager、production CI/CD 或 SOC/SIEM 整合時，本功能必須視為超出本次 PoC 範圍。

## 需求 (Requirements) *(mandatory)*

### 功能需求 (Functional Requirements)

- **FR-001**: 系統必須支援一個 npm-focused 安裝評估流程，並將每次請求歸納為 `allow`、`deny` 或 `manual_review` 結果。
- **FR-002**: 系統必須在進入安裝期展示前評估 Snyk 證據；若證據顯示 high 或 critical 已知漏洞，必須拒絕安裝請求。
- **FR-003**: 系統必須在進入安裝期展示前評估 Socket 證據；若證據顯示相依套件風險或組織政策不合規，必須拒絕安裝請求。
- **FR-004**: 系統必須支援由版本控管的 demo config 檔指定 fixture、scanner mode、sandbox mode 與輸出路徑；當 live 掃描不可用時，系統必須可使用已清理的報告 fixture，並在決策摘要中清楚標示證據來源為 fixture；當 demo config 驗證失敗時，系統必須產生 `manual_review` 決策檔，並阻止任何 scanner 或 sandbox 執行。
- **FR-005**: 系統必須只在受控 sandbox/container 流程中展示安裝期惡意 PoC，且不得在宿主機直接執行惡意 postinstall 行為。
- **FR-006**: 系統必須優先支援 OrbStack 作為本機 Docker 相容容器環境；若 OrbStack 不可用，必須停止 live sandbox install demo，且只允許使用已清理 fixture 與手動驗證說明作為替代展示。
- **FR-007**: 系統必須在 OpenShell gate 中展示檔案讀取限制；惡意 fixture 只能嘗試讀取 sandbox 內的合成 canary secret fixture，且不得嘗試讀取任何真實宿主機敏感路徑，讀取失敗時必須留下可查詢證據。
- **FR-008**: 系統必須在 OpenShell gate 中展示預設拒絕所有 sandbox egress 的網路外連限制；惡意 fixture 只能嘗試連到合成測試目的地，且連線嘗試必須失敗並留下可查詢證據。
- **FR-009**: 系統必須彙整 Snyk、Socket 與必要的 OpenShell 證據，產生機器可讀 JSON 決策檔，並可選擇產生人類可讀 Markdown 摘要；輸出必須包含結果、理由、證據來源、時間點與下一步建議，且 `allow` 決策至少需要 Snyk 與 Socket 皆通過；sandbox install demo 被執行時，OpenShell containment 必須同時具備檔案讀取阻擋證據與網路 egress 阻擋證據才算通過。
- **FR-010**: 系統必須在無明確 `deny` 證據且必要證據缺失、格式無法解析或結果互相衝突時輸出 `manual_review`，並阻止安裝期展示直到證據補齊或人工覆核；若任一 gate 已有明確 `deny` 證據，系統必須輸出 `deny` 並在摘要標示其他必要 gate 證據缺失。
- **FR-011**: 系統必須明確標示本功能只涵蓋展示型 npm 供應鏈防禦 PoC，不包含 production CI/CD rollout、SOC/SIEM 整合或一般惡意程式分析。
- **FR-012**: 系統必須保留足夠的結構化證據，使審查者可以在不重跑完整 demo 的情況下理解每個 `allow`、`deny` 或 `manual_review` 決策。

### 主要實體 (Key Entities)

- **安裝評估請求**: 表示使用者想評估或安裝的 npm 套件情境；包含套件來源、展示模式、是否允許使用 fixture 證據、目前安全邊界狀態，以及引用的版本控管 demo config。
- **Gate 證據**: 表示 Snyk、Socket 或 OpenShell 產生的可審查結果；包含來源、狀態、風險等級、拒絕原因、時間點與是否為 live 或 fixture。
- **Supervisor 決策**: 表示彙整後的 `allow`、`deny` 或 `manual_review` 結論；包含主要理由、引用證據、保留風險與下一步建議。
- **Sandbox 展示環境**: 表示用於安裝期展示的受控執行邊界；包含容器環境就緒狀態、檔案限制狀態、網路限制狀態與宿主機保護狀態。
- **Demo Config**: 表示版本控管的展示設定檔；描述 fixture、scanner mode、sandbox mode 與輸出路徑，且不得包含 token、憑證或機器專屬秘密。
- **展示輸出**: 表示可交付給觀眾或審查者的報告、log 摘要或決策摘要；Supervisor 決策必須至少保存為機器可讀 JSON 檔，並可選擇輸出人類可讀 Markdown 摘要；所有展示輸出必須避免包含真實秘密、憑證或未遮罩的敏感本機資訊。

## 成功標準 (Success Criteria) *(mandatory)*

### 可衡量成果 (Measurable Outcomes)

- **SC-001**: 對含有 high 或 critical 已知漏洞的 npm fixture，100% 的評估必須在安裝期展示前產生 `deny` 決策，且拒絕理由可追溯到 Snyk 證據。
- **SC-002**: 對 Socket 證據顯示不健康或政策不合規的 npm fixture，100% 的評估必須在安裝期展示前產生 `deny` 決策，且拒絕理由可追溯到 Socket 證據。
- **SC-003**: 在 OrbStack 就緒的展示環境中，受控 sandbox install 必須於 5 分鐘內完成或明確失敗，並產生足以判斷 containment 成敗的證據；OrbStack 不可用時必須停止 live sandbox install demo，並改以已清理 fixture 與手動驗證說明呈現。
- **SC-004**: 安裝期惡意 PoC 嘗試讀取未授權的合成 canary secret fixture 時，展示結果必須顯示讀取失敗，且至少保留一筆可審查的拒絕或失敗證據；測試不得使用真實宿主機秘密或敏感路徑內容。
- **SC-005**: 安裝期惡意 PoC 嘗試連線合成測試目的地時，展示結果必須顯示預設拒絕所有 sandbox egress 造成外連失敗，且至少保留一筆可審查的拒絕或失敗證據。
- **SC-006**: 每一份 Supervisor JSON 決策檔都必須可由自動化測試驗證結果、主要理由、證據來源、缺失 gate 清單與下一步建議；若產生 Markdown 摘要，審查者必須能在 30 秒內辨識相同資訊。
- **SC-007**: Demo 輸出與保存的 fixture/report 必須 100% 不包含真實秘密、憑證、SSH key、cloud profile 或未遮罩的個人環境檔案內容。
- **SC-008**: 主要展示流程必須能在無 live Snyk/Socket 登入的情況下，使用已清理 fixture 證據完成至少一個可重現的拒絕決策展示。
- **SC-009**: 未執行 sandbox install demo 的 `allow` 決策必須 100% 同時具備 Snyk 與 Socket 通過證據，且摘要必須明確標示 OpenShell containment 未執行；已執行 sandbox install demo 時，OpenShell containment 必須同時具備檔案讀取阻擋證據與網路 egress 阻擋證據才算通過，摘要也必須納入兩類證據。
- **SC-010**: 主要 demo 流程必須能從版本控管的 demo config 讀取 fixture、scanner mode、sandbox mode 與輸出路徑；config 驗證失敗時必須產生 `manual_review` 決策檔並阻止任何 scanner 或 sandbox 執行，且不得回退到隱含預設執行惡意 PoC。

## 假設 (Assumptions)

- 本功能聚焦 npm supply-chain defense demo，package manager 範圍不擴大到 pnpm、Yarn、PyPI、Cargo 或其他 ecosystem。
- OrbStack 是 macOS 本機展示的優先 Docker 相容執行環境；若未安裝或不可用，流程會停止 live sandbox install demo，只允許使用已清理 fixture 與手動驗證說明作為替代展示。
- NemoClaw/OpenShell 需要容器化或 Linux sandbox 能力才能展示安裝期 containment；實作規劃階段需確認本機版本支援的 CLI 旗標與 policy schema。
- Snyk 與 Socket 的 live 掃描可能需要帳號、token 與網路；因此 fixture report 與手動驗證路徑是本 PoC 的必要備援。
- 惡意 fixture 僅供本機 PoC 使用，不會發布到 public registry，也不會保存真實秘密或宿主機敏感資料。
- Supervisor 負責證據彙整與 allow/deny 判斷；Worker 負責受控工具任務、報告收集與 sandbox 展示，不承擔主要安全推理。
- 本功能不承諾 Socket 能完整分析本地任意 JavaScript 惡意行為；Socket gate 的展示重點是 dependency metadata 與組織政策風險。
