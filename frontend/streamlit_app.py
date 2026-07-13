import uuid
import requests
import pandas as pd
import streamlit as st


API_URL = "http://localhost:8000"

st.set_page_config(
    page_title="🛡️ Agentic AI for Attack Surface Management",
    layout="wide",
)

st.html(
    """
    <style>
        .hero-box {
            background: linear-gradient(135deg, #111827 0%, #1F2937 40%, #2A1115 100%);
            padding: 36px 32px;
            border-radius: 22px;
            border: 1px solid #374151;
            margin-bottom: 30px;
            box-shadow: 0 10px 32px rgba(0, 0, 0, 0.35);
            text-align: center;
        }

        .main-title {
            font-size: 52px;
            font-weight: 800;
            color: #F8FAFC;
            margin-bottom: 16px;
            line-height: 1.15;
        }

        .main-title span {
            color: #EF4444;
        }

        .subtitle {
            font-size: 19px;
            color: #CBD5E1;
            max-width: 950px;
            margin: 0 auto;
            line-height: 1.6;
            text-align: center;
            white-space: normal;
        }
    </style>

    <div class="hero-box">
        <div class="main-title">
            🛡️ Agentic AI for <span>Attack Surface Management</span>
        </div>
        <p class="subtitle">
            Chat-based ASM Agent for authorized domain scanning, DB Query,
           Asset Discovery, Enumeration & Fingerprinting, Vulnerability Detection,
           MongoDB storage, and AI reporting.
        </p>
    </div>
    """
)


def should_render_scan_details(reply, data):
    """
    Render the detailed scan panel when the assistant is returning:
    - the latest saved scan after a domain lookup
    - a newly completed scan
    - a selected historical scan

    Do not render it for history lists or comparison-only answers.
    """
    if not data or not isinstance(data, dict):
        return False

    text = reply.lower().strip()

    text_only_replies = [
        "available scans for",
        "comparison between scan",
        "i need a domain",
        "which two scans",
        "there is no historical record",
        "one or both scan numbers were not found",
        "scan number",
    ]

    if any(text.startswith(marker) for marker in text_only_replies):
        return False

    scan = data.get("scan")

    if not isinstance(scan, dict):
        return False

    summary = scan.get("summary")

    if not isinstance(summary, dict):
        return False

    return True


def clean_value(value):
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)

    if value is None:
        return ""

    return value


def render_scan_result(data):
    scan = data.get("scan", {})
    summary = scan.get("summary", {})

    st.divider()

    st.subheader("Scan Result")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Discovered Assets", summary.get("total_subdomains", 0))
    col2.metric("Live DNS Assets", summary.get("live_dns", 0))
    col3.metric("HTTP Services", summary.get("http_services", 0))
    col4.metric("Unique IP Count", summary.get("unique_ips", 0))
    col5.metric("Vulnerability Findings", summary.get("nuclei_findings", 0))

    st.subheader("AI Summary")
    st.write(data.get("ai_summary", "No AI summary available."))

    st.subheader("Asset Discovery")

    assets = scan.get("subdomains", [])

    if assets:
        asset_df = pd.DataFrame(
            {
                "Discovered Asset": assets,
                "Type": [
                    "Root domain" if asset == data.get("domain") else "Subdomain"
                    for asset in assets
                ],
            }
        )

        st.dataframe(
            asset_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No discovered assets found.")

    st.subheader("Live DNS Assets")

    dns_results = scan.get("dns", [])

    if dns_results:
        dns_rows = []

        for item in dns_results:
            dns_rows.append(
                {
                    "Asset": item.get("host", "") or item.get("input", ""),
                    "DNS Status": item.get("status_code", ""),
                    "Nameservers": clean_value(item.get("ns", [])),
                    "Allowed Certificate Authorities": clean_value(item.get("caa", [])),
                    "Unique IP Count": len(item.get("a", [])),
                }
            )

        st.dataframe(
            pd.DataFrame(dns_rows),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No live DNS assets detected.")

    st.subheader("Enumeration & Fingerprinting")

    st.write("HTTP Service Discovery")

    http_results = scan.get("http", [])

    if http_results:
        http_rows = []

        for item in http_results:
            http_rows.append(
                {
                    "URL": item.get("url", ""),
                    "Page Title": item.get("title", ""),
                    "Status Code": item.get("status_code", ""),
                    "Web Server": item.get("webserver", ""),
                    "Detected Technologies": clean_value(item.get("tech", [])),
                    "Content Type": item.get("content_type", ""),
                }
            )

        st.dataframe(
            pd.DataFrame(http_rows),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No HTTP Service Discovery details available in this saved scan.")

    st.write("Port Scanning")

    nmap_results = scan.get("nmap", [])

    if nmap_results:
        port_rows = []
        seen_ports = set()

        for item in nmap_results:
            port = item.get("port", "")
            service = item.get("service", "")
            state = item.get("state", "")
            protocol = item.get("protocol", "")

            key = (port, service, state, protocol)

            if key in seen_ports:
                continue

            seen_ports.add(key)

            port_rows.append(
                {
                    "Port": port,
                    "Protocol": protocol,
                    "State": state,
                    "Service": service,
                }
            )

        st.dataframe(
            pd.DataFrame(port_rows),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No open web ports detected.")

    st.subheader("Vulnerability Detection")

    findings_count = summary.get("nuclei_findings", 0)

    if findings_count > 0:
        st.warning(
            f"{findings_count} vulnerability finding(s) detected. "
            "Details are hidden in the public demo view."
        )
    else:
        st.success("✅ No vulnerability findings detected.")


def load_saved_scan(domain):
    response = requests.get(
        f"{API_URL}/domains/{domain}",
        timeout=30,
    )

    if response.status_code == 200:
        return response.json()

    return None


if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

if "messages" not in st.session_state:
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": "Enter an authorized domain to scan. Example: scan example.com",
            "scan_data": None,
        }
    ]

if "latest_data" not in st.session_state:
    st.session_state.latest_data = None


# Optional demo loader
# with st.sidebar:
#     st.subheader("Demo Mode")
#
#     demo_domain = st.text_input(
#         "Load saved scan",
#         value="younesali.com",
#     )
#
#     if st.button("Load from MongoDB"):
#         saved = load_saved_scan(demo_domain.strip().lower())
#
#         if saved:
#             st.session_state.latest_data = saved
#             st.session_state.messages.append(
#                 {
#                     "role": "assistant",
#                     "content": f"Loaded saved scan for {demo_domain}.",
#                     "scan_data": saved,
#                 }
#             )
#             st.success("Saved scan loaded without calling the LLM.")
#         else:
#             st.error("No saved scan found for this domain.")


for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.write(message["content"])

        scan_data = message.get("scan_data")

        if scan_data:
            render_scan_result(scan_data)


user_message = st.chat_input("Ask the ASM Agent...")

if user_message:
    st.session_state.messages.append(
        {
            "role": "user",
            "content": user_message,
            "scan_data": None,
        }
    )

    with st.chat_message("user"):
        st.write(user_message)

    with st.chat_message("assistant"):
        with st.spinner("ASM Agent is working..."):
            try:
                response = requests.post(
                    f"{API_URL}/agent/chat",
                    json={
                        "message": user_message,
                        "session_id": st.session_state.session_id,
                    },
                    timeout=1200,
                )

                response.raise_for_status()
                result = response.json()

                reply = result.get("reply", "")
                data = result.get("data")

                st.write(reply)

                scan_data = None

                if should_render_scan_details(reply, data):
                    scan_data = data
                    st.session_state.latest_data = data
                    render_scan_result(data)

                st.session_state.messages.append(
                    {
                        "role": "assistant",
                        "content": reply,
                        "scan_data": scan_data,
                    }
                )

            except requests.exceptions.ConnectionError:
                reply = (
                    "Backend is not running. Start it with: "
                    "`cd backend && source .venv/bin/activate && "
                    "python -m uvicorn app.main:app --reload --port 8000`"
                )

                st.error(reply)

                st.session_state.messages.append(
                    {
                        "role": "assistant",
                        "content": reply,
                        "scan_data": None,
                    }
                )

            except requests.exceptions.Timeout:
                reply = "Backend request timed out. The scan may still be running."

                st.error(reply)

                st.session_state.messages.append(
                    {
                        "role": "assistant",
                        "content": reply,
                        "scan_data": None,
                    }
                )

            except requests.exceptions.RequestException as e:
                reply = f"Backend error: {e}"

                st.error(reply)

                st.session_state.messages.append(
                    {
                        "role": "assistant",
                        "content": reply,
                        "scan_data": None,
                    }
                )