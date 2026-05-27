# 快速開始 (Quickstart): Agent Flow 網頁簡報

## 1. 開啟簡報

直接用瀏覽器打開：

```text
docs/agent-flow-ppt/index.html
```

不需要 npm install、不需要 dev server、不需要 scanner token。

## 2. 操作方式

- 使用鍵盤 `ArrowRight` / `Space` 前往下一頁。
- 使用鍵盤 `ArrowLeft` 返回上一頁。
- 使用畫面右下角按鈕切換上一頁/下一頁。
- 使用上方 progress dots 觀察目前 slide。

## 3. 錄影建議流程

1. 開場頁：說明 ChainShield Lab 是 AI-assisted npm supply-chain defense agent。
2. Flow 頁：從 Demo Config 走到 Supervisor Decision。
3. Gate Matrix 頁：逐一說明 Snyk、Socket、OpenShell 條件。
4. Sandbox 頁：強調 synthetic canary 與 network egress block。
5. AI Worker 頁：強調 Nemotron/Codex/Claude 只做 sanitized summary。
6. Output 頁：展示 JSON decision、Markdown summary、allow/deny/manual_review。

## 4. 驗證

執行 presentation contract test：

```bash
pytest tests/integration/test_agent_flow_ppt.py
```

預期結果：

- 必備節點文字存在。
- gate 條件文字存在。
- final output artifact 文字存在。
- 安全邊界文字存在。
- navigation hooks 存在。
