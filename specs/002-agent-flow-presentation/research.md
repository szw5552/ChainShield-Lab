# 研究紀錄 (Research): Agent Flow 網頁簡報

## Decision: 使用純靜態 HTML/CSS/JavaScript

**Rationale**: 簡報只需要本機錄影與評審瀏覽，不需要 build step、狀態管理或 framework。純靜態檔案降低 demo 前安裝失敗風險，也符合 PoC 的 KISS 原則。

**Alternatives considered**:

- React/Vite：互動彈性較高，但需要 dependency install 與 build step，對 demo artifact 過重。
- Markdown slide framework：產出快，但 gate matrix、節點連線與動感控制較受限。

## Decision: 使用 CSS layout 與 canvas 動態背景

**Rationale**: 需要明亮活潑與動感，但 presentation 主體仍需清楚。Canvas 只做背景粒線與流動感，不承載核心資訊；核心流程節點使用 HTML，方便測試與 responsive layout。

**Alternatives considered**:

- 只用靜態圖：好錄影但互動不足，且小螢幕文字容易不可控。
- 外部圖片或 CDN asset：增加網路依賴，不符合 fixture-first demo 的可重現性。

## Decision: 以 contract test 驗證內容完整性

**Rationale**: 視覺細節需要人工檢查，但必備節點、gate 條件、安全邊界與輸出 artifact 可自動化驗證。這能滿足 TDD，同時不引入 browser test dependency。

**Alternatives considered**:

- Playwright：畫面驗證更完整，但需額外 browser/runtime，對本功能過重。
- 完全人工驗證：不符合憲章的 test-first 要求。
