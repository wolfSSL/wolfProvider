#!/usr/bin/env python3
"""Triage a nightly-osp run and post one clean Slack health report.

Classification is by RETRY OUTCOME, not guesswork: every job that did not
succeed is retried once. Cleared on retry = flake; failed twice = a real
failure. A reproducing test failure is REAL even if it is low-impact or
unrelated to crypto — that is what severity (P0-P3) is for. "flake" means
ONLY a transient infra/network/registry hiccup. Claude validates the
survivors, assigns severity, and writes the symptom/hypothesis/next lines.

Env:
  GH_REPO            owner/repo (required)
  RUN_ID             run to analyze (required)
  GITHUB_TOKEN       token with actions:read (+ actions:write to retry)
  SLACK_WEBHOOK_URL  optional; if unset or DRY_RUN=true, payload is printed
  ANTHROPIC_API_KEY  optional; without it survivors report without notes
  CLAUDE_MODEL       optional; default claude-sonnet-4-6
  AUTO_RETRY         "true" to rerun non-passing jobs once before reporting
  DRY_RUN            "true" to print the payload instead of posting
  ANALYZE_ATTEMPT    optional; report a specific past attempt as-is
"""
import datetime
import json
import os
import re
import urllib.error
import urllib.request
from collections import OrderedDict

GH_API = "https://api.github.com"
REPO = os.environ["GH_REPO"]
RUN_ID = os.environ["RUN_ID"]
GH_TOKEN = os.environ.get("GITHUB_TOKEN", "")
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
AUTO_RETRY = os.environ.get("AUTO_RETRY", "false").lower() == "true"
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true" or not SLACK_WEBHOOK
FORCE_ATTEMPT = os.environ.get("ANALYZE_ATTEMPT")

LOG_TAIL_LINES = 300
AI_LOG_CHARS = 4000
WAVE_SUFFIX = re.compile(r"-(?:591|584|\d{3})$")

INFRA_STEPS = {"Set up job", "Initialize containers", "Stop containers"}

# Per-suite tier hint: 1 = crypto/security-critical, 2 = important, 3 = cosmetic.
# The AI sets per-failure severity (P0-P3) from this tier + the log. Edit freely.
SUITE_TIER = {
    "krb5": 1, "openssl-version": 1, "openvpn": 1, "openssh": 1,
    "stunnel": 1, "nginx": 1, "curl": 1, "net-snmp": 2, "openldap": 2,
    "socat": 2, "libssh2": 2, "pam-pkcs11": 2, "sssd": 2, "tpm2-tools": 2,
    "libfido2": 2, "static-analysis": 3, "multi-compiler": 2,
}
DEFAULT_TIER = 2

SEV_ORDER = ["Critical", "High", "Medium", "Low"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}
TIER_SEV = {1: "High", 2: "Medium", 3: "Low"}  # fallback when AI absent
SPARK = "▁▂▃▄▅▆▇█"

# Secrets scrubbed before any log leaves this process (Slack or Claude).
SCRUB = [
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "***token***"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "Bearer ***"),
    (re.compile(r"(?i)(x-api-key|authorization|password|secret|token)"
                r"(['\"\s:=]+)\S+"), r"\1\2***"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
     "***jwt***"),
]


def gh(path, method="GET", data=None):
    url = path if path.startswith("http") else GH_API + path
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {GH_TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.data = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read()
    return json.loads(body) if body else {}


def all_jobs(run_id, attempt=None):
    jobs = []
    base = f"/repos/{REPO}/actions/runs/{run_id}"
    if attempt:
        base += f"/attempts/{attempt}"
    page = 1
    while True:
        d = gh(f"{base}/jobs?per_page=100&page={page}")
        batch = d.get("jobs", [])
        jobs += batch
        if len(batch) < 100:
            break
        page += 1
    return jobs


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_log(job_id):
    """The logs endpoint 302s to a signed blob URL that rejects the GitHub
    auth header, so capture the redirect and fetch the Location unauthenticated."""
    url = f"{GH_API}/repos/{REPO}/actions/jobs/{job_id}/logs"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {GH_TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=60) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location") if e.code in (301, 302, 303, 307, 308) else None
        if not loc:
            return ""
        try:
            with urllib.request.urlopen(loc, timeout=60) as r2:
                return r2.read().decode("utf-8", "replace")
        except urllib.error.HTTPError:
            return ""


def step_body(text):
    idx = text.find("Post job cleanup.")
    body = text[:idx] if idx > 0 else text
    return "\n".join(body.splitlines()[-LOG_TAIL_LINES:])


def scrub(text):
    for pat, repl in SCRUB:
        text = pat.sub(repl, text)
    return text


def prefix_of(name):
    return name.split(" / ")[0].strip()


def suite_of(prefix):
    return WAVE_SUFFIX.sub("", prefix)


def tier_of(prefix):
    return SUITE_TIER.get(suite_of(prefix), DEFAULT_TIER)


def failing_steps(job):
    return [s.get("name", "").strip() for s in job.get("steps", [])
            if s.get("conclusion") == "failure"]


def ai_triage(failures):
    """One Claude call. Returns {"headline","jobs":{name:{verdict,severity,
    symptom,hypothesis,next}}} or None."""
    if not ANTHROPIC_KEY or not failures:
        return None
    parts = []
    for f in failures:
        parts.append(f"### {f['name']}  (suite tier {f['tier']})\n"
                     f"failing steps: {', '.join(f['steps']) or 'n/a'}\n"
                     f"log tail:\n{f['log'][-AI_LOG_CHARS:]}\n")
    prompt = (
        "You are triaging failures in the wolfProvider nightly OSP CI suite. "
        "Each job below failed twice (an auto-retry did not clear it). Infra "
        "setup failures are already filtered out.\n"
        "Judge each job ONLY from its own log; do not speculate about outages "
        "or reference other jobs.\n"
        "verdict: \"flake\" ONLY if THIS log shows a transient network/registry/"
        "download hiccup. A test that reproducibly FAILS is \"real\" even if it "
        "is cosmetic or unrelated to crypto — use severity for that, never flake.\n"
        "severity (real only): Critical = crypto/security regression or broad "
        "breakage; High = functional regression in a tier-1 suite; Medium = "
        "real but contained / test-harness bug; Low = cosmetic (lint/man-page/"
        "docs). Use the suite tier as a hint but judge by the actual failure.\n"
        "symptom: one line, the concrete error. hypothesis: one line, likely "
        "cause. next: one line, the concrete next action.\n"
        "headline: <=120 chars, plain, summarizing the real regressions.\n"
        "Respond with ONLY compact JSON: {\"headline\":\"...\",\"jobs\":{\"<name>\":"
        "{\"verdict\":\"real|flake\",\"severity\":\"Critical|High|Medium|Low\","
        "\"symptom\":\"...\",\"hypothesis\":\"...\",\"next\":\"...\"}}}\n\n"
        + "\n".join(parts)
    )
    body = {"model": CLAUDE_MODEL, "max_tokens": 1200,
            "messages": [{"role": "user", "content": prompt}]}
    req = urllib.request.Request("https://api.anthropic.com/v1/messages",
                                 method="POST")
    req.add_header("x-api-key", ANTHROPIC_KEY)
    req.add_header("anthropic-version", "2023-06-01")
    req.add_header("content-type", "application/json")
    req.data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            resp = json.loads(r.read())
        text = resp["content"][0]["text"]
        m = re.search(r"\{.*\}", text, re.S)
        return json.loads(m.group(0)) if m else None
    except urllib.error.HTTPError as e:
        return {"headline": f"AI triage unavailable (HTTP {e.code})", "jobs": {}}
    except Exception as e:
        return {"headline": f"AI triage unavailable ({type(e).__name__})", "jobs": {}}


def post_slack(color, fallback, blocks):
    payload = {"attachments": [{"color": color, "fallback": fallback,
                                "blocks": blocks}]}
    if DRY_RUN:
        print("=== DRY RUN (no Slack post) ===\n")
        print(render_text(blocks))
        return
    data = json.dumps(payload).encode()
    req = urllib.request.Request(SLACK_WEBHOOK, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def render_text(blocks):
    out = []
    for b in blocks:
        t = b.get("type")
        if t == "header":
            out.append(b["text"]["text"])
        elif t == "divider":
            out.append("-" * 48)
        elif t == "section" and "fields" in b:
            out.append("  ".join(f["text"].replace("\n", " ") for f in b["fields"]))
        elif t == "section":
            out.append(b["text"]["text"])
        elif t == "context":
            out.append(" ".join(e["text"] for e in b["elements"]))
    return "\n".join(out)


def section(text):
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def chunk_lines(lines, limit=2900):
    buf, size = [], 0
    for ln in lines:
        if size + len(ln) + 1 > limit and buf:
            yield "\n".join(buf)
            buf, size = [], 0
        buf.append(ln)
        size += len(ln) + 1
    if buf:
        yield "\n".join(buf)


def run_url():
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{REPO}/actions/runs/{RUN_ID}"


def pass_rate(run_id):
    js = all_jobs(run_id)
    s = sum(1 for j in js if j.get("conclusion") == "success")
    f = sum(1 for j in js if j.get("conclusion") == "failure")
    return (s, s + f) if (s + f) else None


def history(n=6):
    """Pass rates of the last n real nightly-osp runs (newest first), for the
    trend sparkline. Best-effort: returns [] on any error or sparse history."""
    try:
        runs = gh(f"/repos/{REPO}/actions/workflows/nightly-osp.yml/runs"
                  f"?per_page=20&status=completed").get("workflow_runs", [])
    except Exception:
        return []
    out = []
    for r in runs:
        if str(r["id"]) == str(RUN_ID) or r.get("conclusion") not in ("success", "failure"):
            continue
        try:
            pr = pass_rate(r["id"])
        except Exception:
            continue
        if pr and pr[1] >= 50:
            out.append(pr[0] / pr[1])
        if len(out) >= n:
            break
    return out


def sparkline(rates):
    if not rates:
        return ""
    chars = []
    for x in rates:
        # map a 90-100% band onto the 8 spark levels (clamped)
        idx = min(7, max(0, int((x - 0.90) / 0.10 * 7)))
        chars.append(SPARK[idx])
    return "".join(chars)


def merged_jobs(attempt):
    if FORCE_ATTEMPT:
        return all_jobs(RUN_ID, attempt=int(FORCE_ATTEMPT))
    latest = all_jobs(RUN_ID)
    if attempt < 2:
        return latest
    merged = {j["name"]: j for j in all_jobs(RUN_ID, attempt=1)}
    for j in latest:
        merged[j["name"]] = j
    return list(merged.values())


def main():
    run = gh(f"/repos/{REPO}/actions/runs/{RUN_ID}")
    attempt = int(FORCE_ATTEMPT) if FORCE_ATTEMPT else run.get("run_attempt", 1)

    # Phase 1 — retry everything that did not pass, exactly once.
    if AUTO_RETRY and not FORCE_ATTEMPT and attempt == 1:
        nonpass = [j for j in all_jobs(RUN_ID)
                   if j.get("conclusion") in ("failure", "cancelled")]
        if nonpass:
            gh(f"/repos/{REPO}/actions/runs/{RUN_ID}/rerun-failed-jobs",
               method="POST")
            note = (f"*wolfProvider Nightly OSP* — {len(nonpass)} job(s) didn't "
                    f"pass on attempt 1; retrying once before triage. "
                    f"<{run_url()}|View run>")
            post_slack("warning", note, [section(note)])
            return

    jobs = merged_jobs(attempt)
    failed = [j for j in jobs if j.get("conclusion") == "failure"]
    n_success = sum(1 for j in jobs if j.get("conclusion") == "success")
    n_cancelled = sum(1 for j in jobs if j.get("conclusion") == "cancelled")

    # Cleared on retry (failed/cancelled on attempt 1, passing now) = flakes.
    recovered = []
    if attempt >= 2:
        prev = {prefix_of(j["name"]) for j in all_jobs(RUN_ID, attempt=1)
                if j.get("conclusion") in ("failure", "cancelled")}
        recovered = sorted(prev - {prefix_of(j["name"]) for j in failed})

    # Group failed jobs per suite. Infra-setup failures are obvious flakes and
    # are NOT sent to the AI; everything else gets a verdict + severity.
    survivors = OrderedDict()
    for j in failed:
        survivors.setdefault(prefix_of(j["name"]), []).append(j)

    flakes = []          # (prefix, note)
    flake_jobs = 0
    candidates = []      # non-infra survivors -> AI
    for prefix, gjobs in survivors.items():
        steps = failing_steps(gjobs[0])
        infra = next((s for s in steps if s in INFRA_STEPS), None)
        if infra:
            flakes.append((prefix, f"infra setup failed ({infra})"))
            flake_jobs += len(gjobs)
        else:
            candidates.append({"name": prefix, "tier": tier_of(prefix),
                               "steps": steps, "jobs": gjobs,
                               "url": gjobs[0].get("html_url", ""),
                               "log": scrub(step_body(fetch_log(gjobs[0]["id"])))})

    ai = ai_triage(candidates)
    headline = scrub(ai.get("headline", "")) if ai else ""
    verdicts = ai.get("jobs", {}) if ai else {}

    reals = []           # (severity, prefix, url, symptom, hypothesis, next)
    real_jobs = 0
    for fd in candidates:
        name = fd["name"]
        v = verdicts.get(name, {})
        if v.get("verdict") == "flake":
            flakes.append((name, scrub(v.get("symptom", "") or "transient issue")))
            flake_jobs += len(fd["jobs"])
            continue
        sev = v.get("severity") if v.get("severity") in SEV_RANK else \
            TIER_SEV.get(fd["tier"], "Medium")
        reals.append((sev, name, fd["url"],
                      scrub(v.get("symptom", "") or "failed twice"),
                      scrub(v.get("hypothesis", "")),
                      scrub(v.get("next", ""))))
        real_jobs += len(fd["jobs"])
    reals.sort(key=lambda r: SEV_RANK.get(r[0], 9))

    total_pf = n_success + len(failed)            # pass-rate denominator
    total_all = total_pf + n_cancelled            # every job (breakdown sums to this)
    pct = round(100 * n_success / total_pf) if total_pf else 100

    if not reals:
        color, status = "good", "healthy"
    elif pct >= 90:
        color, status = "warning", f"{len(reals)} real — action needed"
    else:
        color, status = "danger", f"{len(reals)} real — degraded"

    date_str = (run.get("created_at") or "")[:10] or datetime.date.today().isoformat()

    # Trend vs prior nightlies (best-effort).
    hist = history()
    trend = ""
    if hist:
        spark = sparkline(list(reversed(hist)) + [n_success / total_pf if total_pf else 1])
        delta = (n_success / total_pf - hist[0]) * 100 if total_pf else 0
        arrow = "▲" if delta > 0.05 else "▼" if delta < -0.05 else "▬"
        trend = f"{spark}  {arrow}{abs(delta):.1f}pp vs last"

    fields = [
        {"type": "mrkdwn", "text": f"*Date:*\n{date_str}"},
        {"type": "mrkdwn", "text": f"*Status:*\n{status}"},
        {"type": "mrkdwn",
         "text": f"*Pass rate:*\n{n_success} / {total_pf} jobs  ({pct}%)"},
        {"type": "mrkdwn", "text": f"*Trend:*\n{trend or 'building history'}"},
    ]
    breakdown = (f"\U0001F7E2 {n_success} passed"
                 + (f" ({len(recovered)} recovered)" if recovered else "")
                 + f"     \U0001F7E1 {flake_jobs} flaked"
                 f"     \U0001F534 {real_jobs} real"
                 f"     ⚪ {n_cancelled} cancelled")
    blocks = [
        {"type": "header", "text": {"type": "plain_text",
                                    "text": "wolfProvider Nightly OSP", "emoji": True}},
        {"type": "section", "fields": fields},
        section(breakdown),
    ]

    if reals:
        meter = " · ".join(f"{sum(1 for r in reals if r[0] == s)} {s}"
                           for s in SEV_ORDER if any(r[0] == s for r in reals))
        blocks.append(section(f"*Severity:*   {meter}"))
    if headline:
        blocks.append(section(headline))

    if reals:
        blocks.append({"type": "divider"})
        n_real_suites = len(reals)
        blocks.append(section(f"*Real failures — {n_real_suites} suite(s), action needed*"))
        for sev, name, url, symptom, hyp, nxt in reals:
            link = f"  <{url}|logs>" if url else ""
            lines = [f"*{sev} · `{name}`*{link}",
                     f"   • {symptom}"]
            if hyp:
                lines.append(f"   • _cause:_ {hyp}")
            if nxt:
                lines.append(f"   • _next:_ {nxt}")
            blocks.append(section("\n".join(lines)))

    if flakes:
        blocks.append({"type": "divider"})
        flake_lines = ["*Flakes — infra, auto-retried (glance only)*"]
        flake_lines += [f"   `{p}` — {w}" for p, w in flakes]
        for chunk in chunk_lines(flake_lines):
            blocks.append(section(chunk))

    blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
        "text": f"wolfSSL v5.9.1 (Wave 1) + v5.8.4 (Wave 2)  ·  "
                f"attempt {attempt}  ·  {total_all} jobs  ·  <{run_url()}|View run>"}]})

    fallback = f"wolfProvider Nightly OSP: {status} ({n_success}/{total_pf} passed)"
    post_slack(color, fallback, blocks)


if __name__ == "__main__":
    main()
