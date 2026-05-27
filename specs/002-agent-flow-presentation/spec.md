# 功能規格 (Feature Specification): Agent Flow 網頁簡報

**Feature Branch**: `002-agent-flow-presentation`

**Created**: 2026-05-27

**Status**: Draft

**Input**: User description: "用 UIUX promax 把這個 repo 的 agent flow 做成網頁 PPT，節點和節點之間要清楚，用明確條件說明 gate 條件以及最後產出，風格明亮活潑、有動感、描述清楚、產出明確。"

**語言政策**: 產生的 spec.md MUST 使用繁體中文 (zh-TW)；程式碼、檔案路徑、指令、API 名稱與必要英文專有名詞可保留英文。

## 使用者情境與測試 (User Scenarios & Testing) *(mandatory)*

### 使用者故事 1 - 讓評審快速理解 Agent Flow (Priority: P1)

Hackathon 評審打開網頁簡報後，應能在第一分鐘內看懂 ChainShield Lab 的輸入、三道 gate、Supervisor 決策與輸出 artifact。

**優先順序理由**: 這是影片與現場 demo 的核心價值；若流程看不懂，後續 gate 條件與 AI Worker 邊界都無法建立信任。

**獨立測試**: 打開 `docs/agent-flow-ppt/index.html`，首頁與流程頁必須清楚呈現 Demo Config、Snyk、Socket、OpenShell、AI Worker、Supervisor、JSON/Markdown 輸出。

**BDD 驗收情境**:

1. **Given** 評審第一次打開簡報，**When** 觀看標題與流程總覽，**Then** 應能看到一條清楚的節點路徑，從 Demo Config 到 Supervisor Decision 與最終輸出。
2. **Given** 評審停在 workflow slide，**When** 比對節點與箭頭，**Then** 每個 gate 與下一步之間的條件應被明確標示，而不是只用抽象箭頭連接。

---

### 使用者故事 2 - 明確說明 Gate 條件 (Priority: P2)

Presenter 需要在影片中逐段說明 Snyk、Socket、OpenShell gate 的 allow、deny、manual_review 條件，並避免讓 AI 看起來像直接做安全裁決。

**優先順序理由**: Gate 條件是 ChainShield 的可信度來源；必須比一般架構圖更具體。

**獨立測試**: 簡報中每個 gate 卡片必須列出 deny、pass 或 manual_review 條件，且 Supervisor 規則必須明確提到 deterministic。

**BDD 驗收情境**:

1. **Given** Presenter 切到 gate matrix，**When** 講解 Snyk Gate，**Then** 畫面必須指出 high/critical vulnerability 會造成 deny。
2. **Given** Presenter 切到 OpenShell slide，**When** 講解 sandbox containment，**Then** 畫面必須指出 filesystem read block 與 network egress block 都要存在，才算 containment evidence 足夠。
3. **Given** Presenter 切到 AI Worker slide，**When** 講解 Nemotron/Codex/Claude Worker，**Then** 畫面必須指出 Worker 只產生 sanitized summary，不能決定 allow 或 deny。

---

### 使用者故事 3 - 明亮活潑且可用於錄影 (Priority: P3)

Presenter 需要一個不沉悶的網頁 PPT，具備動感、節點 highlight、鍵盤切換與錄影友善的視覺層級。

**優先順序理由**: Hackathon demo 需要快速抓住注意力，但不能犧牲安全流程的清楚度。

**獨立測試**: 使用鍵盤方向鍵或畫面控制可切換 slide；視覺呈現明亮、節點穩定、不重疊，且在桌面與手機寬度下可閱讀。

**BDD 驗收情境**:

1. **Given** Presenter 使用瀏覽器錄影，**When** 用方向鍵切換 slides，**Then** slide 進度與目前段落必須即時更新。
2. **Given** 視窗縮小到手機寬度，**When** 瀏覽 gate 卡片與流程節點，**Then** 文字不得互相遮擋，節點仍能垂直掃描。

### 邊界案例 (Edge Cases)

- 若瀏覽器停用 JavaScript，頁面仍應顯示所有 slide 內容；只是切換控制不可用。
- 若使用小螢幕，流程圖應改為垂直排列，避免箭頭與卡片重疊。
- 若錄影時不想操作鍵盤，畫面控制按鈕仍應可完成上一頁/下一頁切換。
- 若評審只看最後一頁，仍應能看到明確產出：decision JSON、Markdown summary、allow/deny/manual_review 三種結果。

## 需求 (Requirements) *(mandatory)*

### 功能需求 (Functional Requirements)

- **FR-001**: 網頁簡報 MUST 以繁體中文清楚呈現 ChainShield Agent Flow。
- **FR-002**: 簡報 MUST 包含 Demo Config、Snyk Gate、Socket Gate、OpenShell Gate、AI Worker Summary、Supervisor Decision、JSON + Markdown Evidence 等節點。
- **FR-003**: 每個 gate MUST 呈現可驗證條件，包括 deny、pass 或 manual_review 的觸發原因。
- **FR-004**: Supervisor 區塊 MUST 明確指出安全裁決由 deterministic rules 產生，AI Worker 不能直接裁決 allow/deny。
- **FR-005**: 簡報 MUST 提供 keyboard navigation 與 visible navigation controls。
- **FR-006**: 視覺設計 MUST 明亮、活潑、有動感，且不可犧牲文字可讀性。
- **FR-007**: 簡報 MUST 提供清楚的最終產出頁，列出 decision JSON、Markdown summary、gate evidence、worker invocation evidence 與三種 decision states。
- **FR-008**: 靜態頁面 MUST 不執行 npm install、不呼叫 scanner、不讀取 token、不執行 sandbox，只呈現 demo 說明。

### 主要實體 (Key Entities)

- **Slide**: 一頁簡報，包含標題、敘事重點、流程節點或 gate 條件。
- **Flow Node**: Agent flow 的節點，例如 Demo Config、Snyk Gate、Supervisor Decision。
- **Gate Condition**: gate 的 pass、deny、manual_review 條件。
- **Output Artifact**: 最終展示產物，例如 decision JSON、Markdown summary、evidence references。

## 成功標準 (Success Criteria) *(mandatory)*

### 可衡量成果 (Measurable Outcomes)

- **SC-001**: 第一次觀看者可在 60 秒內指出三道 gate 與最終 Supervisor 輸出。
- **SC-002**: 每個 gate 至少有 2 個明確條件文字，且包含 deny 或 manual_review 的觸發條件。
- **SC-003**: 桌面與手機寬度下，主要標題、節點文字與 gate 條件無重疊。
- **SC-004**: 使用鍵盤或按鈕可在 5 秒內切換到任一相鄰 slide。
- **SC-005**: Presentation contract test 可驗證必備節點、gate 條件與輸出 artifact 文字存在。

## 假設 (Assumptions)

- 簡報是 repo 內靜態頁面，不需要部署、登入或外部 API。
- 目標使用者是 Hackathon 評審、demo 觀眾與 Presenter。
- 本功能只負責展示 agent flow，不改變 ChainShield CLI、scanner、sandbox 或 Worker provider 行為。
- 影片主要以桌面瀏覽器錄製，但手機尺寸也應可閱讀。
