# 任務 (Tasks): Agent Flow 網頁簡報

**語言政策**: 產生的 tasks.md MUST 使用繁體中文 (zh-TW)；程式碼、檔案路徑、指令、任務 ID 與必要英文專有名詞可保留英文。

**Input**: Design documents from `specs/002-agent-flow-presentation/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, quickstart.md

**Tests**: TDD is mandatory. 本功能先以 integration contract test 驗證內容與互動 hook，再實作靜態頁。

## Phase 1: 設定 (Setup / Shared Infrastructure)

**Purpose**: 建立簡報與測試檔案位置。

- [x] T001 Create `docs/agent-flow-ppt/` structure
- [x] T002 Create `tests/integration/test_agent_flow_ppt.py` test file

---

## Phase 2: 基礎建設 (Foundational / Blocking Prerequisites)

**Purpose**: 先定義 presentation contract，阻止後續少放必要節點或安全邊界。

- [x] T003 [P] Write failing contract assertions for required flow nodes, gate conditions, outputs, and navigation hooks in `tests/integration/test_agent_flow_ppt.py`
- [x] T004 Verify red state with `pytest tests/integration/test_agent_flow_ppt.py`

---

## Phase 3: 使用者故事 1 - 讓評審快速理解 Agent Flow (Priority: P1) 🎯 MVP

**Goal**: 網頁第一組 slides 能清楚說明 ChainShield 的輸入、流程節點、Supervisor 與輸出。

**Independent Test**: 開啟 `docs/agent-flow-ppt/index.html`，能看到完整節點路徑與最後產出。

### 使用者故事 1 的實作

- [x] T005 [US1] Implement core slide markup and full agent flow nodes in `docs/agent-flow-ppt/index.html`
- [x] T006 [US1] Implement responsive flow layout in `docs/agent-flow-ppt/styles.css`

---

## Phase 4: 使用者故事 2 - 明確說明 Gate 條件 (Priority: P2)

**Goal**: 每個 gate 都有明確 pass/deny/manual_review 條件與 evidence reference。

**Independent Test**: Gate matrix 能獨立說明 Snyk、Socket、OpenShell、Worker 與 Supervisor 規則。

### 使用者故事 2 的實作

- [x] T007 [US2] Add gate condition matrix and sandbox containment slides in `docs/agent-flow-ppt/index.html`
- [x] T008 [US2] Style gate condition cards and decision states in `docs/agent-flow-ppt/styles.css`

---

## Phase 5: 使用者故事 3 - 明亮活潑且可用於錄影 (Priority: P3)

**Goal**: 增加 keyboard navigation、progress、動態背景與錄影友善視覺。

**Independent Test**: 使用鍵盤與按鈕可切換 slide；桌面與手機版文字不重疊。

### 使用者故事 3 的實作

- [x] T009 [US3] Implement slide navigation and canvas motion in `docs/agent-flow-ppt/app.js`
- [x] T010 [US3] Add bright visual treatment, motion states, and mobile layout refinements in `docs/agent-flow-ppt/styles.css`

---

## Phase 6: 收尾與跨切關注 (Polish & Cross-Cutting Concerns)

**Purpose**: 驗證內容、效能與操作說明。

- [x] T011 Run `pytest tests/integration/test_agent_flow_ppt.py`
- [x] T012 Check static asset size and update final usage notes

## 相依性與執行順序 (Dependencies & Execution Order)

- Phase 1 → Phase 2 → US1 → US2 → US3 → Polish。
- T003 必須在 T005-T010 前完成並確認 red state。
- US1 是 MVP；US2 與 US3 可在 US1 完成後獨立調整。

## 實作策略 (Implementation Strategy)

1. 先完成 contract test，確認頁面尚未存在時失敗。
2. 完成靜態 HTML 結構與必備文案。
3. 補上 CSS responsive layout 與明亮動態風格。
4. 補上 JavaScript navigation 與 canvas 背景。
5. 跑測試並做人工檢查。
