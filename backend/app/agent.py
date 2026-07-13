import json
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Dict, Optional, List

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI

from .config import GEMINI_API_KEY
from .db import domains
from .scanner import (
    subfinder_scan,
    assetfinder_scan,
    shuffledns_scan,
    dnsx_scan,
    httpx_scan,
    nmap_scan,
    nuclei_scan,
)
from .llm import summarize_scan


DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

pending_scans = {}
approved_scans = {}
workflow_state = {}
latest_data = {}

# Conversation memory for database-history actions
last_history_domain = {}
pending_history_requests = {}
pending_previous_scan_requests = {}
pending_compare_requests = {}

def run_authorized_scan(domain: str, session_id: str) -> Dict:
    """
    Runs the full ASM workflow deterministically.
    This avoids depending on the LLM to call tools in the correct order.
    """
    domain = domain.lower().strip()

    subdomains = set()
    subdomains.add(domain)

    try:
        subdomains.update(subfinder_scan(domain))
    except Exception as e:
        print(f"[subfinder_scan error] {e}")

    try:
        subdomains.update(assetfinder_scan(domain))
    except Exception as e:
        print(f"[assetfinder_scan error] {e}")

    try:
        subdomains.update(shuffledns_scan(domain))
    except Exception as e:
        print(f"[shuffledns_scan error] {e}")

    subdomains = sorted(subdomains)

    dns_results = []
    http_results = []
    nmap_results = []
    nuclei_results = []

    live_assets = set()
    ips = set()

    try:
        dns_results = dnsx_scan(subdomains)
    except Exception as e:
        print(f"[dnsx_scan error] {e}")
        dns_results = []

    for item in dns_results:
        host = item.get("host") or item.get("input") or item.get("domain")

        if host:
            live_assets.add(host)

        for ip in item.get("a", []):
            ips.add(ip)

    # Important fallback: even if dnsx returns nothing, keep the authorized root domain
    if not live_assets:
        live_assets.add(domain)

    try:
        http_results = httpx_scan(sorted(live_assets))
    except Exception as e:
        print(f"[httpx_scan error] {e}")
        http_results = []

    # Important fallback: retry root domain directly
    if not http_results:
        try:
            http_results = httpx_scan([domain])
        except Exception as e:
            print(f"[httpx_scan root fallback error] {e}")
            http_results = []

    try:
        if ips:
            nmap_results = nmap_scan(sorted(ips))
        else:
            nmap_results = []
    except Exception as e:
        print(f"[nmap_scan error] {e}")
        nmap_results = []

    urls = [
        item.get("url")
        for item in http_results
        if item.get("url")
    ]

    try:
        nuclei_results = nuclei_scan(urls)
    except Exception as e:
        print(f"[nuclei_scan error] {e}")
        nuclei_results = []

    scan_result = {
        "domain": domain,
        "scannedAt": utc_now_iso(),
        "subdomains": subdomains,
        "dns": dns_results,
        "http": http_results,
        "nmap": nmap_results,
        "nuclei": nuclei_results,
        "summary": {
            "total_subdomains": len(subdomains),
            "live_dns": len(live_assets),
            "http_services": len(http_results),
            "unique_ips": len(ips),
            "nuclei_findings": len(nuclei_results),
        },
    }

    document = save_scan(domain, scan_result)

    latest_data[session_id] = document

    approved_scans.pop(session_id, None)
    pending_scans.pop(session_id, None)
    workflow_state.pop(session_id, None)

    print(
        f"[scan complete] {domain} | "
        f"assets={len(subdomains)} | "
        f"live_dns={len(live_assets)} | "
        f"http={len(http_results)} | "
        f"ips={len(ips)} | "
        f"nuclei={len(nuclei_results)}"
    )

    return document

def serialize_doc(doc):
    return json.loads(json.dumps(doc, default=str))


def extract_domain(text: str) -> Optional[str]:
    match = DOMAIN_REGEX.search(text)

    if not match:
        return None

    return match.group(0).lower().strip()


def extract_scan_numbers(text: str) -> List[int]:
    """
    Supports:
    - compare scan 1 and scan 2
    - compare 1 and 2
    - show me scan 3
    """
    numbers = re.findall(r"\b\d+\b", text)
    return [int(number) for number in numbers]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def format_scan_time(value: str) -> str:
    try:
        if not value:
            return "unknown date"

        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        local_dt = dt.astimezone(ZoneInfo("America/Detroit"))
        return local_dt.strftime("%B %d, %Y at %I:%M %p %Z")

    except Exception:
        return value or "unknown date"


def get_scan_time(scan_entry: Dict) -> str:
    return (
        scan_entry.get("scannedAt")
        or scan_entry.get("savedAt")
        or scan_entry.get("updatedAt")
        or ""
    )


def save_scan(domain: str, scan_result: Dict) -> Dict:
    existing = domains.find_one({"domain": domain})
    ai_summary = summarize_scan(scan_result)

    now = utc_now_iso()

    scan_entry = {
        "scan_id": now,
        "scannedAt": scan_result.get("scannedAt", now),
        "savedAt": now,
        "scan": scan_result,
        "ai_summary": ai_summary,
    }

    scan_history = []

    if existing:
        scan_history = existing.get("scan_history", [])

        if not scan_history and existing.get("scan"):
            old_time = existing.get("updatedAt") or existing.get("scan", {}).get("scannedAt") or now

            scan_history.append(
                {
                    "scan_id": old_time,
                    "scannedAt": existing.get("scan", {}).get("scannedAt", old_time),
                    "savedAt": old_time,
                    "scan": existing.get("scan"),
                    "ai_summary": existing.get("ai_summary", ""),
                }
            )

    scan_history.append(scan_entry)

    document = {
        "domain": domain,
        "createdAt": existing.get("createdAt") if existing else now,
        "updatedAt": now,
        "scan": scan_result,
        "ai_summary": ai_summary,
        "scan_history": scan_history,
    }

    domains.update_one(
        {"domain": domain},
        {"$set": document},
        upsert=True,
    )

    saved = domains.find_one({"domain": domain})
    return serialize_doc(saved)


def get_text_reply(content) -> str:
    if isinstance(content, list):
        return " ".join(
            item.get("text", "")
            for item in content
            if isinstance(item, dict)
        ).strip()

    return str(content)


def build_history_list(existing: Dict) -> str:
    history = existing.get("scan_history", [])

    if not history and existing.get("scan"):
        history = [
            {
                "scannedAt": existing.get("scan", {}).get("scannedAt", existing.get("updatedAt", "")),
                "scan": existing.get("scan"),
                "ai_summary": existing.get("ai_summary", ""),
            }
        ]

    if not history:
        return "No scan history is available for this domain."

    lines = []

    for index, entry in enumerate(reversed(history), start=1):
        scan = entry.get("scan", {})
        summary = scan.get("summary", {})

        lines.append(
            f"{index}. {format_scan_time(get_scan_time(entry))} — "
            f"Assets: {summary.get('total_subdomains', 0)}, "
            f"HTTP Services: {summary.get('http_services', 0)}, "
            f"Vulnerability Findings: {summary.get('nuclei_findings', 0)}"
        )

    return "\n".join(lines)


def get_history_entry(existing: Dict, scan_number: int) -> Optional[Dict]:
    history = existing.get("scan_history", [])

    if not history and existing.get("scan"):
        history = [
            {
                "scannedAt": existing.get("scan", {}).get("scannedAt", existing.get("updatedAt", "")),
                "scan": existing.get("scan"),
                "ai_summary": existing.get("ai_summary", ""),
            }
        ]

    history_latest_first = list(reversed(history))

    if scan_number < 1 or scan_number > len(history_latest_first):
        return None

    return history_latest_first[scan_number - 1]


def compare_scan_summaries(
    first: Dict,
    second: Dict,
    first_scan_number: int,
    second_scan_number: int,
) -> str:
    first_scan = first.get("scan", {})
    second_scan = second.get("scan", {})

    first_summary = first_scan.get("summary", {})
    second_summary = second_scan.get("summary", {})

    first_time = format_scan_time(get_scan_time(first))
    second_time = format_scan_time(get_scan_time(second))

    lines = [
        f"Comparison between scan {first_scan_number} ({first_time}) and scan {second_scan_number} ({second_time}):",
        f"- Discovered assets: {first_summary.get('total_subdomains', 0)} → {second_summary.get('total_subdomains', 0)}",
        f"- Live DNS assets: {first_summary.get('live_dns', 0)} → {second_summary.get('live_dns', 0)}",
        f"- HTTP services: {first_summary.get('http_services', 0)} → {second_summary.get('http_services', 0)}",
        f"- Unique IP count: {first_summary.get('unique_ips', 0)} → {second_summary.get('unique_ips', 0)}",
        f"- Vulnerability findings: {first_summary.get('nuclei_findings', 0)} → {second_summary.get('nuclei_findings', 0)}",
    ]

    return "\n".join(lines)


def wants_history(message: str) -> bool:
    text = message.lower()

    return any(
        phrase in text
        for phrase in [
            "database history",
            "scan history",
            "history",
            "previous scans",
            "old scans",
            "available scans",
            "scan versions",
        ]
    )


def wants_compare(message: str) -> bool:
    text = message.lower()

    return any(
        phrase in text
        for phrase in [
            "compare",
            "difference",
            "diff",
            "changes between",
            "between scan",
        ]
    )


def wants_previous_scan(message: str) -> bool:
    text = message.lower()

    return any(
        phrase in text
        for phrase in [
            "show me scan",
            "show scan",
            "open scan",
            "previous scan",
            "old scan",
            "scan number",
        ]
    )


def history_response(domain: str, session_id: str) -> Dict:
    domain = domain.lower().strip()
    existing = domains.find_one({"domain": domain})

    pending_history_requests.pop(session_id, None)
    pending_previous_scan_requests.pop(session_id, None)
    pending_compare_requests.pop(session_id, None)

    if not existing:
        latest_data[session_id] = None
        return {
            "reply": f"There is no historical record for {domain}.",
            "data": None,
        }

    serialized = serialize_doc(existing)
    latest_data[session_id] = serialized
    last_history_domain[session_id] = domain

    reply = (
        f"Available scans for {domain}:\n\n"
        f"{build_history_list(existing)}\n\n"
        "You can ask to show any scan number, or compare any two scan numbers."
    )

    return {
        "reply": reply,
        "data": serialized,
    }


def previous_scan_response(domain: str, scan_number: int, session_id: str) -> Dict:
    domain = domain.lower().strip()
    existing = domains.find_one({"domain": domain})

    pending_previous_scan_requests.pop(session_id, None)
    pending_history_requests.pop(session_id, None)
    pending_compare_requests.pop(session_id, None)

    if not existing:
        latest_data[session_id] = None
        return {
            "reply": f"There is no historical record for {domain}.",
            "data": None,
        }

    entry = get_history_entry(existing, scan_number)

    if not entry:
        return {
            "reply": (
                f"Scan number {scan_number} was not found for {domain}. "
                "Ask for the database history to see the available scan numbers."
            ),
            "data": serialize_doc(existing),
        }

    selected_doc = {
        "domain": domain,
        "createdAt": existing.get("createdAt"),
        "updatedAt": entry.get("savedAt") or entry.get("scannedAt"),
        "scan": entry.get("scan"),
        "ai_summary": entry.get("ai_summary", ""),
        "scan_history": existing.get("scan_history", []),
    }

    serialized = serialize_doc(selected_doc)
    latest_data[session_id] = serialized
    last_history_domain[session_id] = domain

    return {
        "reply": (
            f"Showing scan {scan_number} for {domain}, "
            f"from {format_scan_time(get_scan_time(entry))}."
        ),
        "data": serialized,
    }


def compare_scans_response(
    domain: str,
    first_scan_number: int,
    second_scan_number: int,
    session_id: str,
) -> Dict:
    domain = domain.lower().strip()
    existing = domains.find_one({"domain": domain})

    pending_compare_requests.pop(session_id, None)
    pending_previous_scan_requests.pop(session_id, None)
    pending_history_requests.pop(session_id, None)

    if not existing:
        latest_data[session_id] = None
        return {
            "reply": f"There is no historical record for {domain}.",
            "data": None,
        }

    first = get_history_entry(existing, first_scan_number)
    second = get_history_entry(existing, second_scan_number)

    serialized = serialize_doc(existing)
    latest_data[session_id] = serialized
    last_history_domain[session_id] = domain

    if not first or not second:
        return {
            "reply": (
                "One or both scan numbers were not found. "
                "Ask for the database history to see the available scan numbers."
            ),
            "data": serialized,
        }

    return {
        "reply": compare_scan_summaries(
            first,
            second,
            first_scan_number,
            second_scan_number,
        ),
        "data": serialized,
    }


def build_agent(session_id: str):
    @tool
    def DB_Query_Tool(domain: str) -> str:
        """Retrieves the latest scan data and metadata from MongoDB."""
        domain = domain.lower().strip()
        existing = domains.find_one({"domain": domain})

        pending_scans[session_id] = domain

        if existing:
            latest_data[session_id] = serialize_doc(existing)
            last_scan = format_scan_time(existing.get("updatedAt", ""))

            return (
                f"A historical record exists for {domain}. "
                f"The last scan was on {last_scan}."
            )

        latest_data[session_id] = None
        return f"There is no historical record for {domain}."

    @tool
    def Scan_History_Tool(domain: str) -> str:
        """Lists available historical scans for a domain."""
        return history_response(domain, session_id)["reply"]

    @tool
    def Previous_Scan_Tool(domain: str, scan_number: int) -> str:
        """Retrieves a specific previous scan by number from the scan history list."""
        return previous_scan_response(domain, scan_number, session_id)["reply"]

    @tool
    def Compare_Scans_Tool(domain: str, first_scan_number: int, second_scan_number: int) -> str:
        """Compares two historical scans by their scan numbers."""
        return compare_scans_response(
            domain,
            first_scan_number,
            second_scan_number,
            session_id,
        )["reply"]

    @tool
    def Asset_Discovery_Tool(domain: str) -> str:
        """Discovers all visible subdomains and infrastructure assets associated with the domain."""
        domain = domain.lower().strip()

        if approved_scans.get(session_id) != domain:
            return f"Scan blocked. The user has not approved scanning {domain}."

        subdomains = set()
        subdomains.add(domain)

        try:
            subdomains.update(subfinder_scan(domain))
        except Exception:
            pass

        try:
            subdomains.update(assetfinder_scan(domain))
        except Exception:
            pass

        try:
            subdomains.update(shuffledns_scan(domain))
        except Exception:
            pass

        subdomains = sorted(subdomains)

        workflow_state[session_id] = {
            "domain": domain,
            "subdomains": subdomains,
        }

        return (
            f"Asset discovery completed for {domain}. "
            f"Discovered hosts: {len(subdomains)}."
        )

    @tool
    def Enumeration_Fingerprinting_Tool(domain: str) -> str:
        """Enumerates services and fingerprints technologies for discovered assets."""
        domain = domain.lower().strip()

        if approved_scans.get(session_id) != domain:
            return "Scan blocked. User approval is required before running Enumeration & Fingerprinting."

        state = workflow_state.get(session_id, {})
        subdomains = state.get("subdomains", [])

        if isinstance(subdomains, set):
            subdomains = sorted(subdomains)

        if not subdomains:
            subdomains = [domain]

        if domain not in subdomains:
            subdomains.append(domain)

        dns_results = []
        http_results = []
        nmap_results = []

        live_assets = set()
        ips = set()

        try:
            dns_results = dnsx_scan(subdomains)
        except Exception:
            dns_results = []

        for item in dns_results:
            host = item.get("host") or item.get("input") or item.get("domain")

            if host:
                live_assets.add(host)

            for ip in item.get("a", []):
                ips.add(ip)

        if not live_assets:
            live_assets.update(subdomains)

        live_assets.add(domain)

        try:
            http_results = httpx_scan(sorted(live_assets))
        except Exception:
            http_results = []

        if not http_results:
            try:
                http_results = httpx_scan([domain])
            except Exception:
                http_results = []

        try:
            nmap_results = nmap_scan(sorted(ips))
        except Exception:
            nmap_results = []

        workflow_state[session_id] = {
            **state,
            "domain": domain,
            "subdomains": sorted(set(subdomains)),
            "dns": dns_results,
            "live_subdomains": sorted(live_assets),
            "ips": sorted(ips),
            "http": http_results,
            "nmap": nmap_results,
        }

        return (
            f"Enumeration & Fingerprinting completed for {domain}. "
            f"Live DNS assets: {len(dns_results)}. "
            f"HTTP services: {len(http_results)}. "
            f"Open port records: {len(nmap_results)}."
        )

    @tool
    def Vulnerability_Detection_Tool(domain: str) -> str:
        """Scans enumerated HTTP services for security findings."""
        domain = domain.lower().strip()

        if approved_scans.get(session_id) != domain:
            return f"Vulnerability scan blocked. The user has not approved scanning {domain}."

        state = workflow_state.get(session_id, {})
        http_results = state.get("http", [])

        urls = [
            item.get("url")
            for item in http_results
            if item.get("url")
        ]

        nuclei_results = nuclei_scan(urls)

        scan_result = {
            "domain": domain,
            "scannedAt": utc_now_iso(),
            "subdomains": state.get("subdomains", []),
            "dns": state.get("dns", []),
            "http": http_results,
            "nmap": state.get("nmap", []),
            "nuclei": nuclei_results,
            "summary": {
                "total_subdomains": len(state.get("subdomains", [])),
                "live_dns": len(state.get("live_subdomains", [])),
                "http_services": len(http_results),
                "unique_ips": len(state.get("ips", [])),
                "nuclei_findings": len(nuclei_results),
            },
        }

        document = save_scan(domain, scan_result)
        latest_data[session_id] = document

        approved_scans.pop(session_id, None)
        pending_scans.pop(session_id, None)
        workflow_state.pop(session_id, None)

        return (
            f"Vulnerability Detection completed for {domain}. "
            f"Findings: {len(nuclei_results)}. "
            "The full scan result, AI summary, and scan history were stored in MongoDB."
        )

    now = datetime.now(ZoneInfo("America/Detroit")).isoformat()

    system_prompt = f"""
Current time: {now}

## System Prompt: Attack Surface Management ASM Agent

You are an Attack Surface Management ASM Agent responsible for coordinating an authorized domain scanning workflow.

You are connected to the following tools:

- DB_Query_Tool: Retrieves the latest scan data and metadata from MongoDB.
- Scan_History_Tool: Lists available historical scans for a domain.
- Previous_Scan_Tool: Retrieves a specific historical scan by number.
- Compare_Scans_Tool: Compares two historical scans by number.
- Asset_Discovery_Tool: Discovers visible subdomains and infrastructure assets.
- Enumeration_Fingerprinting_Tool: Enumerates services and fingerprints technologies.
- Vulnerability_Detection_Tool: Scans enumerated HTTP services for security findings.

Behavior:

1. When the user gives a plain domain, first call DB_Query_Tool.
2. If a record exists, say:
"The last scan for this domain was on [full timestamp]. Would you like me to initiate a new scan?"
3. Do not scan unless the user approves.
4. If approved, run:
Asset_Discovery_Tool, Enumeration_Fingerprinting_Tool, Vulnerability_Detection_Tool.
5. Once complete, say:
"The attack surface scan for [domain] is complete. Assets have been discovered, fingerprinted, and scanned for vulnerabilities."

History behavior:

- If the user asks for database history, previous scans, old scans, scan versions, or available scans, call Scan_History_Tool.
- If the user asks to show a specific old scan, call Previous_Scan_Tool.
- If the user asks to compare scans and gives two scan numbers, call Compare_Scans_Tool.
- Use the exact domain and scan numbers provided.
- Do not invent scan results.
- Use only tool outputs.
"""

    model = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash-lite",
        google_api_key=GEMINI_API_KEY,
        temperature=0,
    )

    return create_agent(
        model=model,
        tools=[
            DB_Query_Tool,
            Scan_History_Tool,
            Previous_Scan_Tool,
            Compare_Scans_Tool,
            Asset_Discovery_Tool,
            Enumeration_Fingerprinting_Tool,
            Vulnerability_Detection_Tool,
        ],
        system_prompt=system_prompt,
    )


def is_approval(message: str) -> bool:
    text = message.lower().strip()

    return text in [
        "yes",
        "y",
        "yeah",
        "yep",
        "ok",
        "okay",
        "sure",
        "go ahead",
        "start",
        "run",
        "run it",
        "scan it",
    ]


def handle_agent_message(message: str, session_id: str = "default") -> Dict:
    message = message.strip()
    lowered = message.lower()
    domain = extract_domain(message)
    scan_numbers = extract_scan_numbers(message)

    # 1. If the agent previously asked for a domain for history
    if session_id in pending_history_requests and domain:
        return history_response(domain, session_id)

    # 2. If the agent previously asked for a domain for previous scan
    if session_id in pending_previous_scan_requests and domain:
        scan_number = pending_previous_scan_requests[session_id]
        return previous_scan_response(domain, scan_number, session_id)

    # 3. If the agent previously asked for a domain for comparison
    if session_id in pending_compare_requests and domain:
        compare_request = pending_compare_requests[session_id]

        return compare_scans_response(
            domain,
            compare_request["first_scan_number"],
            compare_request["second_scan_number"],
            session_id,
        )

    # 4. Direct history request
    if wants_history(message):
        if domain:
            return history_response(domain, session_id)

        pending_history_requests[session_id] = True

        return {
            "reply": "I need a domain name to retrieve the database history. Which domain are you interested in?",
            "data": latest_data.get(session_id),
        }

    # 5. Direct previous scan request
    if wants_previous_scan(message) and scan_numbers:
        scan_number = scan_numbers[0]
        selected_domain = domain or last_history_domain.get(session_id)

        if selected_domain:
            return previous_scan_response(selected_domain, scan_number, session_id)

        pending_previous_scan_requests[session_id] = scan_number

        return {
            "reply": "I need a domain name to retrieve that scan.",
            "data": latest_data.get(session_id),
        }

    # 6. Direct compare request
    if wants_compare(message):
        if len(scan_numbers) >= 2:
            first_scan_number = scan_numbers[0]
            second_scan_number = scan_numbers[1]
            selected_domain = domain or last_history_domain.get(session_id)

            if selected_domain:
                return compare_scans_response(
                    selected_domain,
                    first_scan_number,
                    second_scan_number,
                    session_id,
                )

            pending_compare_requests[session_id] = {
                "first_scan_number": first_scan_number,
                "second_scan_number": second_scan_number,
            }

            return {
                "reply": "I need a domain name to compare scans.",
                "data": latest_data.get(session_id),
            }

        selected_domain = domain or last_history_domain.get(session_id)

        if selected_domain:
            return {
                "reply": (
                    f"Which two scans do you want to compare for {selected_domain}? "
                    "Example: compare scan 1 and scan 2."
                ),
                "data": latest_data.get(session_id),
            }

        return {
            "reply": "I need a domain name and two scan numbers to compare scans.",
            "data": latest_data.get(session_id),
        }

    # 7. Scan approval
    if is_approval(message) and session_id in pending_scans:
        approved_domain = pending_scans[session_id]

        document = run_authorized_scan(approved_domain, session_id)

        return {
            "reply": (
                f"The attack surface scan for {approved_domain} is complete. "
                "Assets have been discovered, fingerprinted, and scanned for vulnerabilities."
            ),
            "data": document,
        }

    # 8. Default agent path
    agent = build_agent(session_id)

    result = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": message,
                }
            ]
        }
    )

    reply_content = result["messages"][-1].content
    reply = get_text_reply(reply_content)

    return {
        "reply": reply,
        "data": latest_data.get(session_id),
    }