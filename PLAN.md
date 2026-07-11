# Tenex SOC Log Analysis Platform — Build Plan

## Overview
Full-stack cybersecurity app: upload Zscaler NSS logs → parse → detect anomalies → display SOC-analyst dashboard.

**Stack:** Next.js (TypeScript) + Flask (Python) + PostgreSQL + Docker Compose
**Timeline:** 6–8 hours
**Deployment:** Docker Compose locally + optional VPS

---

## Phase 1: Project Setup & Scaffolding (30 min) ✅ COMPLETE

**Files Created:**
- ✅ docker-compose.yml (postgres, backend, frontend services)
- ✅ .env (DB credentials, JWT secret, LLM settings)
- ✅ .env.example (template)
- ✅ .gitignore (excludes .env, node_modules, __pycache__, .next, postgres_data)
- ✅ environment.yml (conda export)
- ✅ backend/Dockerfile
- ✅ frontend/Dockerfile
- ✅ backend/requirements.txt (Flask deps installed via pip)
- ✅ frontend/package.json (Next.js scaffolded)

---

## Phase 2: Backend Core (2 hours) ✅ COMPLETE

**Files Created:**
- ✅ backend/app/models/{__init__,user,log_file,log_entry,anomaly}.py
- ✅ backend/app/{__init__,config,database,auth,main}.py
- ✅ backend/app/routers/{__init__,auth,documents}.py
- ✅ backend/app/parsers/{__init__,zscaler_nss}.py
- ✅ backend/app/detection/{__init__,rules,llm_explainer}.py
- ✅ backend/rules.yaml
- ✅ backend/.flaskenv (FLASK_APP=app.main:create_app)

**Verified:** signup/login, log upload → parse → detect, GET entries/timeline/anomalies all tested end-to-end against Dockerized Postgres. All 4 rules fire correctly.

---

## Phase 3: Frontend (SOC Dashboard) ✅ COMPLETE

**Files Created:**
- ✅ frontend/src/lib/{api,auth}.ts
- ✅ frontend/src/app/page.tsx (login), signup/page.tsx, dashboard/page.tsx
- ✅ frontend/src/components/{Navbar,Upload,LogList,Timeline,AnomalyTable}.tsx

**Notes:**
- Repo scaffolded on Next.js 16 (not 14 as CLAUDE.md says) — App Router conventions differ from training data; see `frontend/AGENTS.md`. Migrated `app/` → `src/app/` per this version's docs, updated `tsconfig.json` `paths`.
- Auth state (token/user) read via `useSyncExternalStore`, not effect+setState — required by this repo's stricter `react-hooks/set-state-in-effect` ESLint rule (React Compiler lint rules, `eslint-plugin-react-hooks` v7). Data-fetch loading state resets via parent-supplied `key` (remount) instead of resetting in the effect body.
- Timeline chart is a hand-built SVG/CSS bar chart (no charting lib installed) using the dataviz skill's reference palette hex values directly.

**Verified:** `tsc --noEmit` and `npm run lint` clean. Full browser flow driven with Playwright (chromium): signup → dashboard redirect → Navbar shows username/role → file upload → Timeline + AnomalyTable populate with correct severity colors → logout. Zero console/page/network errors. Checked both light and dark color schemes.

---

## Phase 4: Sample Data, Docs & Polish ✅ COMPLETE

**Files Created:**
- ✅ sample_logs/{normal,suspicious,mixed}.log (100 / 50 / 200 lines)
- ✅ README.md (overview, architecture, setup, API reference, detection rules, AI usage, RBAC, threat model, troubleshooting)
- ✅ backend/tests/{conftest,test_parser}.py

**Polish:**
- ✅ Removed obsolete `version: '3.9'` from docker-compose.yml
- ✅ `.gitignore` now also excludes `.pytest_cache/`, `.coverage`
- ✅ `backend/.flaskenv` confirmed present (added in Phase 2)
- ✅ Added `"Spyware Callback"` to `rules.yaml`'s `risky_categories` (a real Zscaler category; needed so the off-hours sample entry actually trips the rule)
- ✅ Added `pytest==8.3.3` to `backend/requirements.txt`

**Corrections made vs. the Phase 4 request:**
- The requested field order (`...|action|urlcat|threatname|respcode|...`) didn't match what `zscaler_nss.py` actually parses (`...|respcode|action|urlcat|threatname|...`). Generated all sample logs against the parser's real, tested order rather than silently changing the parser.
- `high_request_volume`'s z-score rule mathematically cannot fire with only ~3-5 distinct source IPs (max possible z ≈ 2.0 vs. the 2.5 threshold, regardless of the outlier's count). `suspicious.log`/`mixed.log` use a wider pool of low-volume background IPs (`normal.log` still uses only the 3 specified IPs) so the brute-force IP actually stands out statistically — confirmed by running the real detector against each file.
- The Phase 4 request labeled the blocked-threat example as T1189 (Drive-by Compromise); the actual configured `threat_detected` rule tag is T1566 (Phishing), set and verified in Phase 2. Left as-is (it's a single fixed tag per rule, not per-entry) and documented as T1566 in the README.

**Verified:** all 350 sample lines parse with zero bad timestamps; `detect_anomalies` produces the exact expected hit counts per file (normal: 0/0/0/0, suspicious: 25/1/3/2, mixed: 15/5/10/10); `pytest tests/` passes (6/6); `normal.log` uploaded through the live UI (Playwright) — 100 entries, 36-bucket timeline summing to 100, 0 anomalies, zero console/network errors.

---

## Phase 5: Attack Chain Reconstruction ✅ COMPLETE

**Files Created:**
- ✅ backend/app/detection/chains.py (`build_attack_chains`)
- ✅ backend/tests/test_chains.py (5 tests, LLM call mocked)
- ✅ frontend/src/components/ChainList.tsx

**Files Changed:**
- ✅ backend/app/routers/documents.py — new `GET /api/logs/:id/chains`
- ✅ backend/app/detection/llm_explainer.py — refactored hosted/ollama call into a shared `_call_llm(system_prompt, prompt)`; added `synthesize_chain()`
- ✅ backend/rules.yaml — `threat_detected` MITRE tag changed T1566 → T1189 (Drive-by Compromise), per this request's example (mentioned twice now across Phase 4 and this request — treated as a deliberate correction, unlike Phase 4 where it was left alone)
- ✅ sample_logs/suspicious.log, mixed.log — regenerated so `blocked_threat`/`large_transfer`/`off_hours` events use a fixed dedicated IP per scenario (10.1.1.60 / .65 / .77) instead of scattering across the background IP pool, so each rule's anomalies actually group into one coherent chain. `normal.log` untouched. Rule hit counts unchanged (chains only group anomaly rows, not filler traffic, so this didn't affect `high_request_volume`'s z-score population).
- ✅ frontend/src/app/dashboard/page.tsx — renders `ChainList` between `Timeline` and `AnomalyTable`
- ✅ README.md — new "Attack chain reconstruction" section, API reference row, AI usage split between `explain_anomaly`/`synthesize_chain`, T1566→T1189 references updated

**Grouping algorithm** (`build_attack_chains`): IP first (primary) — any source IP with 2+ anomalies becomes a chain. Anomalies left over from IP groups of size 1 are then grouped by user login (secondary, excluding placeholder logins `-`/empty) — catches an attacker rotating IPs under the same compromised account. A given anomaly is only ever claimed by one grouping, so no duplicate chains. Groups under 2 anomalies aren't chains (stay out of the endpoint, still visible in the flat `/anomalies` list).

**Bug found and fixed during UI verification:** the 25-event brute-force chain rendered all 25 near-identical timeline entries, ballooning the card and burying the AnomalyTable below it — fixed with a "show first 6 / show all N" toggle per card (`ChainList.tsx`).

**Known limitation, not fixed (flagged, not silently ignored):** the Anthropic API key in `.env` returns `401 invalid x-api-key` — confirmed by calling the Anthropic SDK directly, not a code bug. Every `chain_synthesis` in this session's testing is the templated fallback, not real Claude output. The graceful-degradation path (`synthesize_chain` never returns blank) worked exactly as designed, but this needs a valid key from the user to actually exercise LLM-generated narratives. `synthesize_chain` is not cached/persisted — every `GET .../chains` call re-invokes the LLM once per chain.

**Verified:** `pytest tests/` passes (11/11, includes 5 new chain-grouping tests with the LLM call mocked); `tsc --noEmit` and `npm run lint` clean; uploaded `suspicious.log` through the live UI (Playwright) — exactly 4 chains, one per rule/MITRE technique (T1110×25, T1133×3, T1189×3, T1041×3), correct entities/severities/chronological order, expand/collapse works, zero console/page/network errors, checked light and dark mode.

### Backend Structure
