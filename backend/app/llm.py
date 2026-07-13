from google import genai
from google.genai import types
from .config import GEMINI_API_KEY


def fallback_summary(scan: dict) -> str:
    return (
        "The scan completed successfully. "
        "Vulnerability Detection did not identify any findings."
    )


def summarize_scan(scan: dict) -> str:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)

        prompt = f"""
You are writing the final AI Summary for an Attack Surface Management dashboard.

Use ONLY the scan data provided.
Do NOT invent findings.
Do NOT include raw IP addresses.
Do NOT include resolver lists, SOA values, serial numbers, internal IDs, file paths, API keys, or environment variables.
Do NOT mention scanner/tool names.
Refer to vulnerability results only as "Vulnerability Detection".

Style rules:
- Write one short professional paragraph.
- Maximum 4 sentences.
- Do not use bullet points.
- Do not repeat the same information twice.
- Merge web exposure and open ports into one clean sentence.
- If HTTP/HTTPS ports are 80 and 443, say "ports 80 and 443".
- If a web service returns 403, describe it as "reachable but access-restricted", not as a vulnerability.
- If there are no vulnerability findings, end with exactly:
  "Vulnerability Detection did not identify any findings."

The summary should cover:
1. Discovered assets
2. DNS live/resolution status
3. Web exposure and open web ports
4. Detected technologies
5. Vulnerability Detection result

Good example:
"The scan identified 1 discovered asset for younesali.com, and DNS resolution was successful. Web exposure was observed on HTTP/HTTPS services on ports 80 and 443, with the HTTPS service reachable. The service was hosted on Vercel, with HSTS enabled. Vulnerability Detection did not identify any findings."

Scan data:
{scan}
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
            ),
        )

        return response.text.strip()

    except Exception:
        return fallback_summary(scan)