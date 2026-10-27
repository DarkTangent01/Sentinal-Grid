"""AI assistant on the Claude API: plain-English question → pipeline query, and incident summaries.

Privacy model:
  * ask_query sends the analyst's question plus the static field/command catalogue — no event data.
  * summarize_incident sends incident, alert and comment content (IPs, users, hostnames) and is refused unless
    AI_ALLOW_DATA_SHARING=true. Both are off unless ANTHROPIC_API_KEY is set.
The model never executes anything: generated queries are compiled by the same allow-listing compiler as hand-written
ones, and the analyst runs them.
"""
from __future__ import annotations

import json
import logging

import anthropic

from .analytics.pipeline import EVENT_COLUMNS, PipelineError, compile_pipeline
from .analytics.ql import FIELDS as QL_FIELDS
from .config import get_settings

log = logging.getLogger("ai")
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AIError(RuntimeError):
    pass


def status() -> dict:
    s = get_settings()
    return {"enabled": bool(s.anthropic_api_key), "data_sharing": bool(s.anthropic_api_key and s.ai_allow_data_sharing), "model": s.ai_model}


def _client() -> anthropic.AsyncAnthropic:
    s = get_settings()
    if not s.anthropic_api_key:
        raise AIError("the AI assistant is not configured (set ANTHROPIC_API_KEY)")
    return anthropic.AsyncAnthropic(api_key=s.anthropic_api_key, timeout=120.0, max_retries=2)


# Stable catalogue: identical bytes on every request so the prefix can be cached.
CATALOGUE = f"""You translate a security analyst's question into ONE query for Sentinel Grid, a SIEM for FortiGate and Palo Alto firewalls.

Query language: `<filter> | command | command ...`
Filter (before the first pipe, optional): field:value terms, AND / OR / NOT, parentheses, CIDR (src_ip:10.0.0.0/8),
ranges (port:1-1024), wildcards (app:*cloud*), field:* (present), "quoted text" (searches the raw log).
Filter fields: {", ".join(sorted(QL_FIELDS))}

Commands:
  where <expr>                       comparisons = != < > <= >=, IN (...), LIKE "*x*", AND/OR/NOT
  eval name = <expr>[, ...]
  stats <agg> [as n], ... [by f, ...] aggs: count, count(f), dc(f), sum, avg, min, max, median, p50..p99, values, list,
                                     earliest, latest, range, stdev, countif(cond), sumif(f, cond)
  timechart [span=5m] [limit=N] <agg> [by f]
  top [N] f / rare f [limit=N]
  sort -f, f      head N      dedup f      fields f, ...      fields - f      rename a as b
  lookup <watchlist> <field>         adds <watchlist>_match and <watchlist>_label
Functions: lower upper len round if case coalesce isnull isnotnull concat substr contains startswith endswith
  match (regex) cidrmatch("cidr", ip) isprivate(ip) domain(host) tonumber tostring hour dayofweek strftime now
  inwatchlist(field, "name")
Event columns (usable after the filter and before stats): {", ".join(EVENT_COLUMNS)}
Categories: traffic, dns, web, security, system. Traffic actions: accept, close, timeout, deny, block.
Windows events: category:system type:windows, event_subtype = EventID, action logon / logon-fail / lockout / group-add /
  service-installed / log-cleared, user, src_ip, hostname (computer), app (group / service name).
FortiGate SD-WAN, VPN and system events are category:system with event_subtype sdwan / vpn / system.
Strings in where/eval must be double-quoted. Prefer aggregations with stats/top/timechart and finish with sort and head
so the result is small. The time range is applied separately - never filter on time yourself.

Examples:
Q: top talkers to the internet
A: category:traffic | where isprivate(src_ip) AND NOT isprivate(dst_ip) | stats sum(sent_bytes) as sent, dc(dst_ip) as dsts by src_ip | sort -sent | head 20
Q: denied traffic over time by firewall
A: action:deny | timechart count by firewall_name
Q: which users failed windows logon most
A: category:system type:windows | where action = "logon-fail" | stats count, dc(src_ip) as sources by user | sort -count | head 20
"""

QUERY_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "the pipeline query"},
        "explanation": {"type": "string", "description": "one or two sentences on what the query returns"},
        "visualisation": {"type": "string", "enum": ["auto", "table", "line", "bar", "pie", "kpi"]},
    },
    "required": ["query", "explanation", "visualisation"],
    "additionalProperties": False,
}


async def _call(system: list[dict], messages: list[dict], schema: dict | None, max_tokens: int, effort: str) -> tuple[str, str]:
    """One Messages request. Returns (text, model that served it). Refusals and API errors become AIError."""
    s = get_settings()
    kwargs: dict = {"model": s.ai_model, "max_tokens": max_tokens, "system": system, "messages": messages,
                    "output_config": {"effort": effort, **({"format": {"type": "json_schema", "schema": schema}} if schema else {})},
                    # route a policy decline to a fallback model inside the same call
                    "betas": [FALLBACK_BETA], "fallbacks": "default"}
    try:
        resp = await _client().beta.messages.create(**kwargs)
    except anthropic.AuthenticationError:
        raise AIError("the configured ANTHROPIC_API_KEY was rejected") from None
    except anthropic.RateLimitError:
        raise AIError("the AI service is rate limiting requests; try again shortly") from None
    except anthropic.BadRequestError as e:
        raise AIError(f"the AI request was rejected: {e.message}") from None
    except anthropic.APIStatusError as e:
        raise AIError(f"AI service error ({e.status_code})") from None
    except anthropic.APIConnectionError:
        raise AIError("cannot reach the AI service (check outbound HTTPS from the SIEM)") from None
    if resp.stop_reason == "refusal":
        raise AIError("the model declined this request")
    if resp.stop_reason == "max_tokens":
        raise AIError("the answer was too long; narrow the question")
    text = "".join(b.text for b in resp.content if b.type == "text")
    return text, resp.model


async def ask_query(question: str, watchlists: list[str]) -> dict:
    question = question.strip()[:1000]
    if not question:
        raise AIError("empty question")
    system = [{"type": "text", "text": CATALOGUE, "cache_control": {"type": "ephemeral"}}]
    wl = f"\nAvailable watchlists: {', '.join(watchlists) or 'none'}" if watchlists else ""
    messages = [{"role": "user", "content": f"Question: {question}{wl}"}]
    last_err = ""
    for attempt in range(2):  # one repair round if the compiler rejects the first answer
        text, model = await _call(system, messages, QUERY_SCHEMA, 4000, "low")
        try:
            out = json.loads(text)
        except ValueError:
            raise AIError("the model returned an unreadable answer") from None
        try:
            compile_pipeline(out["query"], {n: {"kind": "string", "values": []} for n in watchlists})
            return {**out, "model": model, "repaired": attempt > 0}
        except PipelineError as e:
            last_err = str(e)
            messages += [{"role": "assistant", "content": text},
                         {"role": "user", "content": f"That query does not compile: {last_err}. Return a corrected query."}]
    raise AIError(f"could not produce a valid query ({last_err})")


SUMMARY_SYSTEM = """You are a senior SOC analyst writing for another analyst. Using only the incident data provided, write:
1. What happened (2-4 sentences, plain language, cite counts, times and entities from the data).
2. Assessment: likely benign / suspicious / likely malicious, with the reason. Say what evidence is missing.
3. Next steps: 3-6 concrete checks or containment actions, most important first.
Do not invent facts that are not in the data. The SIEM is read-only toward firewalls: phrase containment as a recommendation.
Keep it under 300 words. Use short markdown headings."""


async def summarize_incident(payload: dict) -> dict:
    if not get_settings().ai_allow_data_sharing:
        raise AIError("incident summaries send incident data to the AI service; an administrator must set AI_ALLOW_DATA_SHARING=true")
    data = json.dumps(payload, default=str, sort_keys=True)[:60_000]
    text, model = await _call([{"type": "text", "text": SUMMARY_SYSTEM}],
                              [{"role": "user", "content": f"<incident_data>\n{data}\n</incident_data>"}], None, 8000, "medium")
    return {"summary": text.strip(), "model": model}
