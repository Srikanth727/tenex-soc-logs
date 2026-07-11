from typing import Optional

from app.config import Config

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant. Given structured details about a detected "
    "security anomaly, write a concise (2-3 sentence) plain-English explanation "
    "of what happened and why it matters, suitable for display on a SOC dashboard."
)

CHAIN_SYSTEM_PROMPT = (
    "You are a SOC analyst assistant. Given an ordered list of correlated security "
    "anomalies from the same source IP or user account, write a concise (1-2 sentence) "
    "narrative that connects them into a single attack-chain story a SOC analyst would "
    "recognize — name the pattern (e.g. recon, brute force, initial access, exfiltration), "
    "not just the rule names."
)


def _build_prompt(anomaly_context: dict) -> str:
    lines = [f"{key}: {value}" for key, value in anomaly_context.items() if value is not None]
    return "Anomaly details:\n" + "\n".join(lines)


def _build_chain_prompt(entity_type: str, entity_value: str, events: list[dict]) -> str:
    lines = [
        f"{i + 1}. {e['rule']} ({e.get('mitre_tag') or 'no MITRE tag'}) at {e.get('timestamp') or 'unknown time'}"
        for i, e in enumerate(events)
    ]
    return (
        f"Source {entity_type}: {entity_value}\n"
        f"{len(events)} correlated anomalies in chronological order:\n" + "\n".join(lines)
    )


def _call_hosted(system_prompt: str, prompt: str) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=Config.LLM_API_KEY)
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=200,
        system=system_prompt,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def _call_ollama(system_prompt: str, prompt: str) -> str:
    import requests

    response = requests.post(
        f"{Config.OLLAMA_BASE_URL}/api/generate",
        json={
            "model": "llama3.2",
            "prompt": f"{system_prompt}\n\n{prompt}",
            "stream": False,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json().get("response", "").strip()


def _call_llm(system_prompt: str, prompt: str) -> Optional[str]:
    try:
        if Config.LLM_MODE == "ollama":
            return _call_ollama(system_prompt, prompt)
        if Config.LLM_MODE == "hosted" and Config.LLM_API_KEY:
            return _call_hosted(system_prompt, prompt)
    except Exception:
        return None
    return None


def explain_anomaly(anomaly_context: dict) -> Optional[str]:
    """Generate a plain-English explanation for an anomaly via Claude (hosted)
    or a local Ollama model, selected by Config.LLM_MODE.

    This is optional per project spec: on any failure or missing config it
    returns None so the caller can fall back to the rule's static description.
    """
    return _call_llm(SYSTEM_PROMPT, _build_prompt(anomaly_context))


def _fallback_chain_synthesis(entity_value: str, events: list[dict]) -> str:
    tags = sorted({e["mitre_tag"] for e in events if e.get("mitre_tag")})
    tag_list = ", ".join(tags) if tags else "multiple techniques"
    first_ts = events[0].get("timestamp") or "an unknown time"
    last_ts = events[-1].get("timestamp") or "an unknown time"
    return (
        f"{entity_value} triggered {len(events)} correlated anomalies ({tag_list}) "
        f"between {first_ts} and {last_ts}, consistent with a multi-stage attack chain."
    )


def synthesize_chain(entity_type: str, entity_value: str, events: list[dict]) -> str:
    """Turn an ordered list of correlated anomalies (each a dict with at least
    "rule", "mitre_tag", "timestamp") into a short attack-chain narrative via
    Claude or Ollama.

    Unlike explain_anomaly, this never returns None — the chain UI always
    needs something to show, so on any LLM failure or missing config it falls
    back to a templated summary instead (same optionality principle, applied
    so the caller doesn't need a separate "no synthesis" UI state).
    """
    prompt = _build_chain_prompt(entity_type, entity_value, events)
    result = _call_llm(CHAIN_SYSTEM_PROMPT, prompt)
    return result if result else _fallback_chain_synthesis(entity_value, events)
