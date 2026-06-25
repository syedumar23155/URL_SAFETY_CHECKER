# src/api/groq_client.py
import os

def get_explanation(url: str, verdict: str, risk_score: int,
                    reasons: list, api_key: str = "") -> str:
    key = api_key or os.getenv("GROQ_API_KEY", "")
    if not key:
        return ""
    try:
        from groq import Groq
        client = Groq(api_key=key)

        reasons_text = "\n".join(f"- {r}" for r in reasons[:5])
        prompt = f"""You are a cybersecurity expert. Analyse this URL result and write a 2-3 sentence plain-English explanation for a non-technical user.

URL: {url}
Verdict: {verdict}
Risk Score: {risk_score}/100
Flags:
{reasons_text}

Be direct. Tell them what the risk is and what they should do. Do not use technical jargon."""

        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return ""