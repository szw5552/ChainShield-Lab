# ChainShield Lab Demo Video 小抄

> 目標：4-5 分鐘 NVIDIA Taipei Hackathon demo video。  
> 主軸：npm supply-chain attack 在 `npm install` 前、中、後三層被 evidence-driven gate 擋下。  
> 展示路徑：fixture-first 保證穩定，搭配 live OpenShell / Nemotron 片段凸顯 NVIDIA 加分點。

## 錄影前準備

建議開三個 terminal tab：

1. README / 架構：展示專案定位、Demo Gates、架構圖。
2. Demo commands：執行 ChainShield CLI。
3. Evidence artifacts：展示 Markdown summary / JSON decision / OpenShell log。

進入 repo 並啟用 venv：

```bash
cd /Users/vincent5552/Project/ChainShield-Lab
. .venv/bin/activate
```

確認環境就緒，不要印出 API key：

```bash
orb status
docker info --format '{{.OperatingSystem}}'
openshell --version
test -n "$NVIDIA_API_KEY" && echo "NVIDIA_API_KEY=set (value hidden)"
```

預期重點：

- `orb status` 顯示 `Running`
- Docker runtime 顯示 `OrbStack`
- `openshell --version` 顯示 OpenShell 版本，例如 `openshell 0.0.44`
- API key 只顯示 `set`，不要顯示實際值

## Command Cheat Sheet

錄影時優先複製這組指令。若 `run-demo.py` 因舊 artifact 存在而自動產生 timestamp-suffixed output，請以 CLI JSON 裡的 `artifacts.markdown_summary` 為準。

```bash
cd /Users/vincent5552/Project/ChainShield-Lab
. .venv/bin/activate

orb status
docker info --format '{{.OperatingSystem}}'
openshell --version
test -n "$NVIDIA_API_KEY" && echo "NVIDIA_API_KEY=set (value hidden)"

python scripts/run-demo.py --config fixtures/configs/demo-fixture-deny.json
sed -n '1,45p' reports/demo-fixture-deny-summary.md

python scripts/run-demo.py --config fixtures/configs/demo-fixture-manual-review.json
sed -n '1,45p' reports/demo-fixture-manual-review-summary.md

python scripts/run-demo.py --config fixtures/configs/demo-fixture-allow.json
sed -n '1,45p' reports/demo-fixture-allow-summary.md

python scripts/run-demo.py --config fixtures/configs/demo-live-sandbox.json --sandbox-only
LIVE_SANDBOX_SUMMARY=$(ls -t reports/demo-live-sandbox-summary*.md | head -n 1)
sed -n '1,80p' "$LIVE_SANDBOX_SUMMARY"

python scripts/run-demo.py --config fixtures/configs/demo-worker-nemotron.json
sed -n '1,70p' reports/demo-worker-nemotron-summary.md
```

如果 summary 檔案被旋轉，從 CLI JSON 找新的路徑：

```text
"artifacts": {
  "markdown_summary": "reports/<actual-summary-file>.md"
}
```

然後執行：

```bash
sed -n '1,70p' reports/<actual-summary-file>.md
```

## 分段流程

| 段落 | 畫面 | 指令 | 時間 |
| --- | --- | --- | --- |
| 1. 開場 | README 專案定位 | `sed -n '1,80p' README.md` | 35 秒 |
| 2. 架構 | Demo Gates / 架構圖 | `sed -n '35,105p' README.md` | 40 秒 |
| 3. Static deny | Snyk + Socket deny | `demo-fixture-deny` | 60 秒 |
| 4. Manual review | 缺 evidence 不放行 | `demo-fixture-manual-review` | 35 秒 |
| 5. Allow | 全部 static gate pass | `demo-fixture-allow` | 35 秒 |
| 6. OpenShell sandbox | OrbStack + OpenShell containment | `demo-live-sandbox --sandbox-only` | 70 秒 |
| 7. Nemotron Worker | Nemotron-3 evidence summary | `demo-worker-nemotron` | 55 秒 |
| 8. 結尾 | 任一 summary / README | 無 | 35 秒 |

## 逐字稿

### 1. 開場：問題與解法定位

畫面建議：

```bash
sed -n '1,80p' README.md
```

逐字稿：

> 大家好，我是 Vincent。這個專案叫 ChainShield Lab，是我為 NVIDIA Taipei Hackathon 做的 npm supply-chain defense PoC。  
> 最近 npm supply-chain attack 越來越嚴重，攻擊者常常利用 `postinstall`，在 developer 執行 `npm install` 的瞬間掃描 secrets、偷 token，甚至把惡意版本散播到更多 package。  
> 傳統工具常常是在 advisory 出來之後才告訴你有問題，但 supply-chain attack 的危險點是：安裝腳本已經先跑完了。  
> 所以 ChainShield 的目標是把防線往前推：在 install 之前做 static gate，在 install 之中做 sandbox containment，最後把所有 evidence 轉成可追蹤的 allow、deny 或 manual review decision。

### 2. 架構總覽：三個 demo gates

畫面建議：

```bash
sed -n '35,105p' README.md
```

逐字稿：

> ChainShield 有三個 demo gates。  
> 第一層是 Snyk Gate，負責讀 Snyk dependency vulnerability report。如果有 high 或 critical vulnerability，Supervisor 直接 deny。  
> 第二層是 Socket Gate，負責看 dependency health、policy violation、malware 或 supply-chain risk。  
> 第三層是 NVIDIA NemoClaw / OpenShell install-time containment。這一層的重點不是把 deny 改成 allow，而是證明：就算 payload 真的進入 install 階段，它也只能在受控 sandbox 中執行，network egress 會被 default-deny policy 擋下，synthetic canary 也不會被讀出。  
> 最後，Nemotron-3 不是用來取代安全決策，而是把 scanner 和 sandbox evidence 整理成 reviewer 看得懂的 sanitized summary。真正的 final decision 還是 deterministic Supervisor rules。

### 3. Static Gate Demo：Snyk + Socket 先阻擋

操作：

```bash
sed -n '1,120p' fixtures/configs/demo-fixture-deny.json
python scripts/run-demo.py --config fixtures/configs/demo-fixture-deny.json
sed -n '1,45p' reports/demo-fixture-deny-summary.md
```

逐字稿：

> 這裡我先跑最穩定的 fixture-first demo。這條路徑不需要 live token，也不會執行 npm install，只讀取已經 sanitized 的 Snyk 和 Socket reports。  
> 這個 config 指向一份 Snyk high / critical report，以及一份 Socket unhealthy report。現在我執行 ChainShield Supervisor。  
> 可以看到 final decision 是 `deny`。這不是 LLM 猜的，而是 deterministic gate rule：只要 Snyk 有 high 或 critical，或 Socket 出現 unhealthy / policy / malware risk，就直接 deny。  
> 更重要的是，static deny 之後不會進入 host install，也不會執行惡意 package 的 `postinstall`。這是 supply-chain defense 裡最重要的安全邊界。

畫面要指給評審看的重點：

- `Result: deny`
- `Primary reasons`
- `snyk: deny`
- `socket: deny`
- `Do not run npm install on host.`

### 4. Manual Review Demo：缺 evidence 不會假裝 allow

操作：

```bash
python scripts/run-demo.py --config fixtures/configs/demo-fixture-manual-review.json
sed -n '1,45p' reports/demo-fixture-manual-review-summary.md
```

逐字稿：

> 接著我展示另一個安全行為：如果 evidence 不完整，ChainShield 不會為了 demo 好看而放行。  
> 這個 config 故意 skip Socket gate。Snyk 是 pass，但 Socket evidence 缺失。  
> 所以 final decision 不是 allow，而是 `manual_review`，並且 missing gates 會指出 socket。  
> 這代表 ChainShield 的判斷是 evidence-driven：有明確風險就 deny，證據不足就 manual review，只有必要 gate 都通過才 allow。

畫面重點：

- `Result: manual_review`
- `Missing gates: socket`
- `Next actions`

### 5. Allow Demo：全部 static evidence 通過才 allow

操作：

```bash
python scripts/run-demo.py --config fixtures/configs/demo-fixture-allow.json
sed -n '1,45p' reports/demo-fixture-allow-summary.md
```

逐字稿：

> 現在是正常 dependency flow。這裡 Snyk report 是 pass，Socket report 也是 pass，而且沒有要求 sandbox evidence。  
> Supervisor 會輸出 deterministic `allow`。  
> 所以這個 PoC 不是只有阻擋，它可以清楚區分 allow、deny 和 manual review，並且每一個 decision 都會留下 JSON 和 Markdown artifacts，讓 reviewer 不用重跑 demo 也能在 30 秒內看懂理由。

畫面重點：

- `Result: allow`
- `snyk: pass`
- `socket: pass`
- Markdown summary 的 demo-only scope disclaimer

### 6. NVIDIA OpenShell / NemoClaw Sandbox Demo

操作：

```bash
orb status
docker info --format '{{.OperatingSystem}}'
openshell --version
sed -n '1,140p' fixtures/configs/demo-live-sandbox.json
python scripts/run-demo.py --config fixtures/configs/demo-live-sandbox.json --sandbox-only
LIVE_SANDBOX_SUMMARY=$(ls -t reports/demo-live-sandbox-summary*.md | head -n 1)
echo "$LIVE_SANDBOX_SUMMARY"
sed -n '1,80p' "$LIVE_SANDBOX_SUMMARY"
```

注意：`run-demo.py` 會避免覆寫既有 artifacts；如果 `reports/demo-live-sandbox-summary.md` 已存在，這次 run 會產生 timestamp-suffixed summary，例如 `reports/demo-live-sandbox-summary-20260527184430263547.md`。錄影時不要固定看舊的 base summary；請看 CLI JSON output 裡的 `artifacts.markdown_summary`，或用上面的 `LIVE_SANDBOX_SUMMARY` 指令抓最新檔案。

逐字稿：

> 接下來是 NVIDIA 加分點裡我最想強調的部分：install-time containment。  
> 我這裡使用 OrbStack 作為 Docker-compatible runtime，搭配 OpenShell policy。這個 demo 對 host fallback 是 default deny 的：如果不是 OrbStack，或 OpenShell 不可用，ChainShield 會停止 live sandbox demo，而不是偷偷在 host 上跑 npm install。  
> 這個 config 裡 static gate 其實已經是 deny，但我明確打開 `sandbox_demo_override`，目的只有一個：展示第三層 sandbox containment evidence。這個 override 不會把 final decision 從 deny 改成 allow。  
> 在 sandbox 裡，PoC package 的 `postinstall` 會嘗試兩件事：第一，讀取 synthetic canary secret；第二，連到 synthetic egress target。  
> OpenShell policy 會 default-deny network egress；file read 的部分，在目前 OpenShell 0.0.44 限制下，我誠實標記為 chmod-hardened synthetic canary probe，也就是 `manual_probe.permission_denied`，不把它誇大成原生 OCSF FILE deny。  
> 這裡的重點是：即使 payload 進入 install 階段，它也被限制在 sandbox evidence flow 裡，不會碰 host secrets，也不會 host outbound exfiltration。

畫面重點：

- readiness 顯示 OrbStack + OpenShell
- config 中 `sandbox_demo_override.enabled=true`
- summary 中 final decision 仍是 `deny`
- OpenShell gate / logs / `network_egress` / `filesystem_read`
- `manual_probe.permission_denied`
- `host fallback prohibited`

### 7. Nemotron-3 Worker Evidence Summary

操作：

```bash
test -n "$NVIDIA_API_KEY" && echo "NVIDIA_API_KEY=set (value hidden)"
echo "${NEMOTRON_BASE_URL:-https://integrate.api.nvidia.com/v1}"
echo "${NEMOTRON_MODEL:-nvidia/nemotron-3-nano-30b-a3b}"
python scripts/run-demo.py --config fixtures/configs/demo-worker-nemotron.json
```

執行後，從 JSON output 找實際 summary：

```text
"markdown_summary": "reports/demo-worker-nemotron-summary-<timestamp>.md"
```

再展示：

```bash
sed -n '1,70p' reports/demo-worker-nemotron-summary-<timestamp>.md
```

逐字稿：

> 最後是 Nemotron-3。這一層我刻意把它設計成 Worker evidence summary，而不是 security decision maker。  
> Worker 只能讀 sanitized task packet 和 artifact references，不能執行 shell command，不能跑 scanner，也不能啟動 sandbox。  
> 這裡我使用 NVIDIA hosted API，model 是 Nemotron-3 Nano。如果 API timeout、auth failure、rate limit 或 response 不可解析，系統會產生 provider failure evidence，然後 fallback 到本地 Codex 或 Claude subagent handoff；如果所有 provider 都不可用，就回到 manual review。  
> 也就是說，LLM 在這個系統裡只負責幫 reviewer 看懂 evidence，不負責放行或封鎖 package。final allow、deny、manual review 仍然由 deterministic Supervisor gate rules 產生。  
> 這樣可以同時利用 Nemotron 的摘要能力，也避免把安全決策交給不可預期的模型輸出。

如果像剛剛實測一樣成功，畫面重點：

- `provider: nemotron_api`
- `model: nvidia/nemotron-3-nano-30b-a3b`
- `status: pass`
- `finding_status: clear`
- `boundary_violation: false`
- `errors: []`
- worker artifact path

可加一句：

> 這裡可以看到 Worker provider 是 `nemotron_api`，model 是 `nvidia/nemotron-3-nano-30b-a3b`，status 是 `pass`，finding_status 是 `clear`。這代表 Nemotron-3 live evidence summary 成功產生。

### 8. 結尾：30 秒總結

畫面建議：任一 Markdown summary 頂部，或 README 架構圖。

逐字稿：

> 總結一下，ChainShield Lab 是一個 npm supply-chain defense PoC。  
> 它把防線拆成三層：install 前，Snyk 和 Socket 做 deterministic static gates；install 中，NVIDIA NemoClaw / OpenShell 在 sandbox 裡阻擋 egress 並產生 containment evidence；install 後，Nemotron-3 把 evidence 整理成 reviewer 看得懂的 summary。  
> 整個流程的核心原則是 evidence-driven：有明確風險就 deny，證據不足就 manual review，只有必要 gates 都通過才 allow。  
> 而且惡意 `postinstall` 不會直接在 host 上執行，所有 demo artifacts 都是 sanitized、可追蹤、可重現的。  
> 這就是 ChainShield：用 NVIDIA stack 把 npm install 從 blind trust 變成 evidence-based gatekeeping。謝謝。

## Sandbox 備案

如果 live sandbox 不穩、跑太久，或 OpenShell / OrbStack 狀態不適合錄影，改用 fixture sandbox：

```bash
python scripts/run-demo.py --config fixtures/configs/demo-fixture-sandbox.json --sandbox-only
sed -n '1,60p' reports/demo-fixture-sandbox-summary.md
```

備案話術：

> 這裡我切到 sanitized fixture sandbox evidence，因為 live sandbox 會受本機 runtime 和網路狀態影響。  
> PoC 的安全設計不會在 live tool 不可用時 fallback 到 host。相反地，它會保留 fixture evidence 或 manual review path，確保 demo 不會為了成功畫面而犧牲安全邊界。

## Nemotron 備案

如果 Nemotron API 不穩，看到 `nemotron_http_401`、`nemotron_http_403`、`nemotron_http_429`、`nemotron_unavailable` 或 fallback：

逐字稿改成：

> 這裡 live provider unavailable，所以 ChainShield 沒有硬拗成 allow，而是產生 provider failure evidence，進入 fallback 或 manual review。這正是安全系統應該有的行為。  
> Worker provider chain 是 `nemotron_api` 到 `codex_subagent`，再到 `claude_subagent`，最後才是 `manual_review`。無論哪個 provider 成功，Worker 都只能產生 sanitized evidence summary，不能執行 shell，也不能覆寫 Supervisor final decision。

## 錄影安全注意事項

- 不要在 host 上手動執行 `npm install`。
- 不要進入 `fixtures/poc-app` 後直接跑 npm lifecycle scripts。
- 不要印出 `NVIDIA_API_KEY` 的值。
- 不要把 live sandbox logs、tokens、auth files 或 machine-specific sensitive paths commit。
- 不要說 OpenShell 原生阻擋 file read；目前 live file-read evidence 應誠實說成 chmod-hardened synthetic canary probe。
- 如果 output path 被旋轉，錄影時直接講「ChainShield 會避免覆寫既有 artifacts，所以產生 timestamp-suffixed report」。

## 一句話版 Pitch

> ChainShield uses Snyk and Socket before install, NVIDIA NemoClaw / OpenShell during install, and Nemotron-3 after install to turn npm supply-chain risk from blind trust into evidence-based gatekeeping.
