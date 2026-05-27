# 實作計畫 (Implementation Plan): Agent Flow 網頁簡報

**Branch**: `002-agent-flow-presentation` | **Date**: 2026-05-27 | **Spec**: `specs/002-agent-flow-presentation/spec.md`

**Input**: Feature specification from `specs/002-agent-flow-presentation/spec.md`

**語言政策**: 產生的 plan.md、research.md、data-model.md、quickstart.md 與相關使用者可見內容 MUST 使用繁體中文 (zh-TW)；程式碼、檔案路徑、指令、API 名稱與憲章引用可保留英文。

## 摘要 (Summary)

本功能新增一個純靜態網頁 PPT，用明亮、活潑且錄影友善的方式呈現 ChainShield Lab 的 Agent Flow。頁面會清楚標示 Demo Config、Snyk、Socket、OpenShell、AI Worker、Supervisor 與最後 JSON/Markdown evidence outputs，並以 gate matrix 說明 allow、deny、manual_review 條件。實作不呼叫 scanner、不執行 npm install、不啟動 sandbox，只讀取寫死於頁面中的展示文案。

## 技術背景 (Technical Context)

**Language/Version**: HTML5、CSS3、vanilla JavaScript；Python 3.11+ 僅用於測試靜態檔內容。

**Primary Dependencies**: 無 runtime dependency；測試使用現有 `pytest`。

**Storage**: N/A，靜態檔案位於 `docs/agent-flow-ppt/`。

**Testing**: TDD 使用 `tests/integration/test_agent_flow_ppt.py` 驗證必備節點、gate 條件、輸出 artifact、navigation hooks 與安全邊界文字。

**Target Platform**: 現代桌面瀏覽器與手機瀏覽器；可直接開啟本機 HTML。

**Project Type**: 靜態網頁簡報。

**Performance Goals**: 頁面初始靜態資源少於 500KB；互動切換無需網路；相鄰 slide 切換應在 1 秒內完成。

**Constraints**: 不新增前端 build tool、不使用外部 CDN、不執行任何 ChainShield scanner/sandbox/Worker code、不讀取 runtime reports 或 token。

**Scale/Scope**: 單一網頁簡報，包含 6 到 8 個 slides；不建立完整投影片管理系統或 presentation framework。

## 憲章檢查 (Constitution Check)

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **TDD**: PASS。先新增 integration test 驗證靜態簡報必備內容，確認 red state 後再實作 HTML/CSS/JS。
- **BDD**: PASS。`spec.md` 已列出 P1/P2/P3 Given/When/Then，對應流程理解、gate 條件與錄影互動。
- **KISS**: PASS。使用純靜態 HTML/CSS/JS，不引入 React、Vite、slide framework 或 build step。
- **UX / Language**: PASS。Spec Kit artifacts 使用繁體中文，頁面主要展示文字使用繁體中文；專有名詞保留英文。
- **Performance / Evidence**: PASS。定義靜態資源大小與切換時間；presentation contract test 作為可重現 evidence。

## 專案結構 (Project Structure)

### 文件 (this feature)

```text
specs/002-agent-flow-presentation/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### 原始碼 (repository root)

```text
docs/
└── agent-flow-ppt/
    ├── index.html
    ├── styles.css
    └── app.js

tests/
└── integration/
    └── test_agent_flow_ppt.py
```

**Structure Decision**: 選擇 `docs/agent-flow-ppt/`，因為這是 demo presentation artifact，不屬於 CLI runtime；純靜態檔案可直接打開並易於錄影。

## 複雜度追蹤 (Complexity Tracking)

無憲章違規；不需複雜度例外。

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| N/A | N/A | N/A |
