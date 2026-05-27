# 資料模型 (Data Model): Agent Flow 網頁簡報

## Slide

代表一頁網頁 PPT。

- `id`: 穩定識別碼，例如 `flow`、`gates`、`outputs`
- `title`: slide 標題
- `kicker`: 簡短分類或時間軸提示
- `content`: 可視化節點、gate matrix、artifact cards 或 speaker notes
- `state`: `active` 或 `inactive`

## Flow Node

代表 ChainShield Agent Flow 的一個節點。

- `name`: 節點名稱，例如 `Demo Config`、`Snyk Gate`
- `role`: 節點負責的行為
- `condition`: 進入下一步或產生決策的條件
- `visual_status`: `input`、`gate`、`worker`、`decision`、`output`

## Gate Condition

代表 gate 的可驗證條件。

- `gate`: `snyk`、`socket`、`openshell`、`worker`、`supervisor`
- `decision_effect`: `allow_support`、`deny`、`manual_review`
- `plain_text`: 給評審看的白話說明
- `evidence_ref`: 可對應的 evidence artifact 類型

## Output Artifact

代表最後展示輸出。

- `name`: 例如 `decision JSON`、`Markdown summary`
- `purpose`: 評審可用它理解什麼
- `must_show`: 錄影時是否必須露出
