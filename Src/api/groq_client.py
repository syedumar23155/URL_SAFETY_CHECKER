# src/api/groq_client.py
from langchain_groq import ChatGroq
from config import GROQ_API_KEY


def get_explanation(url: str, verdict: str, risk_score: int,
                    reasons: list, api_key: str = "") -> str:
    """
    Call Groq LLaMA3 to get a plain-language explanation.
    Returns empty string gracefully if API key is missing.
    """
    key = api_key or GROQ_API_KEY
    if not key:
        return ""

    try:
        llm = ChatGroq(model="llama-3.1-8b-instant", groq_api_key=key,
                       temperature=0.2, max_tokens=200)

        reasons_text = "\n".join(f"- {r}" for r in reasons[:5])
        prompt = f"""You are a cybersecurity expert. A URL analysis system produced this result:

URL: {url}
Verdict: {verdict}
Risk Score: {risk_score}/100
Flags detected:
{reasons_text}

Write a 2-3 sentence plain-English explanation for a non-technical user explaining 
why this URL got this verdict and what they should do. Be direct and clear."""

        result = llm.invoke(prompt)
        return result.content.strip()

    except Exception:
        return ""