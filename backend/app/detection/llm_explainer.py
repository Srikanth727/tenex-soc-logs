from typing import Optional

from app.config import Config

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant. Given structured details about a detected "
    "security anomaly, write a concise (2-3 sentence) plain-English explanation "
    "of what happened and why it matters, suitable for display on a SOC dashboard."
)


def _build_prompt(anomaly_context: dict) -> str:
    lines = [f"{key}: {value}" for key, value in anomaly_context.items() if value is not None]
    return "Anomaly details:\n" + "\n".join(lines)


def _explain_hosted(prompt: str) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=Config.LLM_API_KEY)
    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=200,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


def _explain_ollama(prompt: str) -> str:
    import requests

    response = requests.post(
        f"{Config.OLLAMA_BASE_URL}/api/generate",
        json={
            "model": "llama3.2",
            "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
            "stream": False,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json().get("response", "").strip()


def explain_anomaly(anomaly_context: dict) -> Optional[str]:
    """Generate a plain-English explanation for an anomaly via Claude (hosted)
    or a local Ollama model, selected by Config.LLM_MODE.

    This is optional per project spec: on any failure or missing config it
    returns None so the caller can fall back to the rule's static description.
    """
    prompt = _build_prompt(anomaly_context)

    try:
        if Config.LLM_MODE == "ollama":
            return _explain_ollama(prompt)
        if Config.LLM_MODE == "hosted" and Config.LLM_API_KEY:
            return _explain_hosted(prompt)
    except Exception:
        return None

    return None
