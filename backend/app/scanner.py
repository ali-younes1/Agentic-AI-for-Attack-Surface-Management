import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from pathlib import Path
import shutil

BASE_DIR = Path(__file__).resolve().parents[2]
WORDLIST = str(BASE_DIR / "data" / "wordlists" / "2m-subdomains.txt")
RESOLVERS = str(BASE_DIR / "data" / "wordlists" / "resolvers.txt")




def resolve_tool(tool_name: str) -> str:
    home_go_bin = str(Path.home() / "go" / "bin" / tool_name)

    preferred_paths = [
        home_go_bin,
        f"/usr/local/bin/{tool_name}",
        f"/usr/bin/{tool_name}",
    ]

    for path in preferred_paths:
        if Path(path).exists():
            return path

    found = shutil.which(tool_name)

    if found:
        return found

    return tool_name

def run_command(command: List[str], input_data: str = None, timeout: int = 180) -> str:
    result = subprocess.run(
        command,
        input=input_data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode not in [0, 1]:
        raise RuntimeError(result.stderr)

    return result.stdout.strip()


def parse_json_lines(output: str) -> List[Dict]:
    results = []

    for line in output.splitlines():
        try:
            results.append(json.loads(line))
        except Exception:
            pass

    return results


def extract_hosts(items: List[Dict]) -> List[str]:
    hosts = []

    for item in items:
        host = (
            item.get("host")
            or item.get("input")
            or item.get("domain")
            or item.get("name")
        )

        if host:
            hosts.append(host.strip())

    return list(set(hosts))


def subfinder_scan(domain: str) -> List[str]:
    output = run_command(
        ["subfinder", "-silent", "-duc", "-d", domain, "-oJ"],
        timeout=180,
    )

    return extract_hosts(parse_json_lines(output))


def assetfinder_scan(domain: str) -> List[str]:
    output = run_command(
        ["assetfinder", "--subs-only", domain],
        timeout=120,
    )

    return list(set(line.strip() for line in output.splitlines() if line.strip()))


def shuffledns_scan(domain: str) -> List[str]:
    output = run_command(
        [
            "shuffledns",
            "-duc",
            "-silent",
            "-r", RESOLVERS,
            "-d", domain,
            "-w", WORDLIST,
            "-j",
            "-mode", "bruteforce",
        ],
        timeout=900,
    )

    return extract_hosts(parse_json_lines(output))


def dnsx_scan(subdomains: List[str]) -> List[Dict]:
    if not subdomains:
        return []

    output = run_command(
        ["dnsx", "-all", "-cdn", "-asn", "-silent", "-j"],
        input_data="\n".join(subdomains),
        timeout=300,
    )

    return parse_json_lines(output)


# def httpx_scan(subdomains: List[str]) -> List[Dict]:
#     if not subdomains:
#         return []

#     output = run_command(
#         ["httpx", "-json", "-silent", "-tech-detect", "-status-code", "-title"],
#         input_data="\n".join(subdomains),
#         timeout=300,
#     )

#     return parse_json_lines(output)
def httpx_scan(subdomains):
    if not subdomains:
        return []

    input_data = "\n".join(subdomains)

    httpx_bin = resolve_tool("httpx")

    print(f"[SCANNER] Using httpx binary: {httpx_bin}")
    print(f"[SCANNER] httpx input: {subdomains}")

    output = run_command(
        [
            httpx_bin,
            "-json",
            "-silent",
            "-tech-detect",
            "-status-code",
            "-title",
            "-timeout",
            "15",
            "-retries",
            "2",
        ],
        input_data=input_data,
        timeout=300,
    )

    results = parse_json_lines(output)

    print(f"[SCANNER] httpx parsed results: {len(results)}")

    return results


def parse_nmap_xml(xml_output: str) -> List[Dict]:
    results = []

    try:
        root = ET.fromstring(xml_output)

        for host in root.findall("host"):
            address = host.find("address")
            ip = address.attrib.get("addr", "") if address is not None else ""

            for port in host.findall(".//port"):
                state = port.find("state")
                service = port.find("service")

                results.append({
                    "ip": ip,
                    "port": port.attrib.get("portid", ""),
                    "protocol": port.attrib.get("protocol", ""),
                    "state": state.attrib.get("state", "") if state is not None else "",
                    "service": service.attrib.get("name", "") if service is not None else "",
                })

    except Exception:
        pass

    return results


def nmap_scan(ips: List[str]) -> List[Dict]:
    results = []

    for ip in ips[:10]:
        try:
            output = run_command(
                ["nmap", "-Pn", "-p", "80,443", "-oX", "-", ip],
                timeout=90,
            )

            results.extend(parse_nmap_xml(output))

        except Exception:
            pass

    return results


def nuclei_scan(urls: List[str]) -> List[Dict]:
    if not urls:
        return []

    output = run_command(
        [
            "nuclei",
            "-jsonl",
            "-silent",
            "-severity", "low,medium,high,critical",
        ],
        input_data="\n".join(urls[:20]),
        timeout=600,
    )

    return parse_json_lines(output)


def full_scan(domain: str) -> Dict:
    subdomains = set()

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

    dns_results = dnsx_scan(subdomains)

    live_subdomains = []
    ips = []

    for item in dns_results:
        host = item.get("host") or item.get("input")

        if host:
            live_subdomains.append(host)

        for ip in item.get("a", []):
            ips.append(ip)

    live_subdomains = sorted(set(live_subdomains))
    ips = sorted(set(ips))

    http_results = httpx_scan(live_subdomains)

    urls = [
        item.get("url")
        for item in http_results
        if item.get("url")
    ]

    nmap_results = nmap_scan(ips)
    nuclei_results = nuclei_scan(urls)

    return {
        "domain": domain,
        "scannedAt": datetime.utcnow().isoformat(),
        "subdomains": subdomains,
        "dns": dns_results,
        "http": http_results,
        "nmap": nmap_results,
        "nuclei": nuclei_results,
        "summary": {
            "total_subdomains": len(subdomains),
            "live_dns": len(live_subdomains),
            "http_services": len(http_results),
            "unique_ips": len(ips),
            "nuclei_findings": len(nuclei_results),
        },
    }