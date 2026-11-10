"""Offline parsers for Wireshark (PCAP/PCAPNG), Nmap and Atomic Red Team artifacts.

Every function here is pure: it turns an uploaded artifact into normalized
observations and then into integration events. The caller feeds those events
through the existing ingestion pipeline so they are correlated against the
threat indicator index and routed to the platform modules.

Nothing in this module performs network access or executes a tool.
"""

import ipaddress
import json
import re
import socket
import struct
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_MAGIC = 0x0A0D0D0A

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IP_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp"}

MAX_PCAP_PACKETS = 200000
MAX_OBSERVATIONS = 5000
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

# OT/ICS protocol ports surfaced so operators can see control-system traffic.
OT_SERVICE_PORTS = {
    102: "s7comm/iso-tsap",
    502: "modbus",
    2222: "ethernet-ip-io",
    4000: "omron-fins",
    18245: "ge-srtp",
    20000: "dnp3",
    34962: "profinet-rt",
    34963: "profinet-rt",
    44818: "ethernet-ip",
    47808: "bacnet",
}


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value, limit=512):
    return str(value or "").strip()[:limit]


def _is_routable(address):
    """Keep correlation focused on addresses that can appear in threat feeds."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_unspecified
        or parsed.is_reserved
    )


# --------------------------------------------------------------------------
# PCAP / PCAPNG
# --------------------------------------------------------------------------

def _iter_classic_pcap(data):
    if len(data) < 24:
        raise ValueError("PCAP file is too small to contain a global header")
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian = ">"
    else:
        raise ValueError("Unrecognized PCAP magic number")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    count = 0
    while offset + 16 <= len(data) and count < MAX_PCAP_PACKETS:
        ts_sec, _ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if incl_len > len(data) - offset:
            break
        yield linktype, ts_sec, data[offset:offset + incl_len]
        offset += incl_len
        count += 1


def _iter_pcapng(data):
    offset = 0
    endian = "<"
    linktypes = {}
    interface_index = 0
    count = 0
    while offset + 12 <= len(data) and count < MAX_PCAP_PACKETS:
        block_type = struct.unpack(endian + "I", data[offset:offset + 4])[0]
        if block_type == PCAPNG_MAGIC:
            byte_order = struct.unpack("<I", data[offset + 8:offset + 12])[0]
            endian = "<" if byte_order == 0x1A2B3C4D else ">"
            interface_index = 0
            linktypes = {}
        block_length = struct.unpack(endian + "I", data[offset + 4:offset + 8])[0]
        if block_length < 12 or offset + block_length > len(data):
            break
        body = data[offset + 8:offset + block_length - 4]
        if block_type == 0x00000001 and len(body) >= 4:  # Interface Description Block
            linktypes[interface_index] = struct.unpack(endian + "H", body[:2])[0]
            interface_index += 1
        elif block_type == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block
            iface, ts_high, ts_low, caplen, _origlen = struct.unpack(endian + "IIIII", body[:20])
            packet = body[20:20 + caplen]
            timestamp = ((ts_high << 32) | ts_low) // 1000000
            yield linktypes.get(iface, LINKTYPE_ETHERNET), timestamp, packet
            count += 1
        elif block_type == 0x00000003 and len(body) >= 4:  # Simple Packet Block
            packet = body[4:]
            yield linktypes.get(0, LINKTYPE_ETHERNET), 0, packet
            count += 1
        offset += block_length


def _strip_link_layer(linktype, packet):
    """Return (ethertype, payload) for the network layer."""
    if linktype == LINKTYPE_ETHERNET:
        if len(packet) < 14:
            return None, b""
        ethertype = struct.unpack("!H", packet[12:14])[0]
        payload = packet[14:]
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and len(payload) >= 4:
            ethertype = struct.unpack("!H", payload[2:4])[0]
            payload = payload[4:]
        return ethertype, payload
    if linktype == LINKTYPE_LINUX_SLL:
        if len(packet) < 16:
            return None, b""
        return struct.unpack("!H", packet[14:16])[0], packet[16:]
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not packet:
            return None, b""
        version = packet[0] >> 4
        if version == 4:
            return ETHERTYPE_IPV4, packet
        if version == 6:
            return ETHERTYPE_IPV6, packet
    return None, b""


def _parse_dns_names(payload):
    """Extract QNAMEs from a DNS message; ignores compression pointers."""
    names = []
    if len(payload) < 12:
        return names
    try:
        question_count = struct.unpack("!H", payload[4:6])[0]
        offset = 12
        for _ in range(min(question_count, 8)):
            labels = []
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if length & 0xC0:  # compressed pointer; stop parsing this name
                    offset += 2
                    break
                offset += 1
                labels.append(payload[offset:offset + length].decode("ascii", "ignore"))
                offset += length
            if labels:
                names.append(".".join(labels).strip(".").casefold()[:253])
            offset += 4  # QTYPE + QCLASS
    except (struct.error, IndexError):
        return names
    return [name for name in names if re.fullmatch(r"[a-z0-9.\-_]{1,253}", name or "")]


def _parse_ip_packet(ethertype, payload):
    if ethertype == ETHERTYPE_IPV4:
        if len(payload) < 20:
            return None
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return None
        protocol = payload[9]
        src = socket.inet_ntop(socket.AF_INET, payload[12:16])
        dst = socket.inet_ntop(socket.AF_INET, payload[16:20])
        transport = payload[ihl:]
    elif ethertype == ETHERTYPE_IPV6:
        if len(payload) < 40:
            return None
        protocol = payload[6]
        src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
        transport = payload[40:]
    else:
        return None

    src_port = dst_port = None
    dns_names = []
    if protocol in (6, 17) and len(transport) >= 4:
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        if protocol == 17 and 53 in (src_port, dst_port) and len(transport) > 8:
            dns_names = _parse_dns_names(transport[8:])
    return {
        "protocol": IP_PROTOCOLS.get(protocol, str(protocol)),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "dns_names": dns_names,
        "bytes": len(payload),
    }


def parse_pcap(data):
    """Parse a PCAP/PCAPNG capture into aggregated conversations."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Capture must be uploaded as binary data")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("Capture exceeds the 64 MB import limit")
    data = bytes(data)
    if len(data) < 8:
        raise ValueError("Capture file is empty or truncated")

    if struct.unpack("<I", data[:4])[0] == PCAPNG_MAGIC:
        packets = _iter_pcapng(data)
        capture_format = "pcapng"
    else:
        packets = _iter_classic_pcap(data)
        capture_format = "pcap"

    flows = {}
    domains = {}
    total_packets = 0
    first_seen = None
    last_seen = None

    for linktype, timestamp, packet in packets:
        total_packets += 1
        ethertype, payload = _strip_link_layer(linktype, packet)
        parsed = _parse_ip_packet(ethertype, payload) if ethertype else None
        if not parsed:
            continue
        if timestamp:
            first_seen = timestamp if first_seen is None else min(first_seen, timestamp)
            last_seen = timestamp if last_seen is None else max(last_seen, timestamp)
        for name in parsed["dns_names"]:
            entry = domains.setdefault(name, {"domain": name, "queries": 0, "clients": set()})
            entry["queries"] += 1
            entry["clients"].add(parsed["src_ip"])
        key = (parsed["src_ip"], parsed["dst_ip"], parsed["dst_port"], parsed["protocol"])
        flow = flows.get(key)
        if flow is None:
            if len(flows) >= MAX_OBSERVATIONS:
                continue
            flow = {
                "src_ip": parsed["src_ip"],
                "dst_ip": parsed["dst_ip"],
                "dst_port": parsed["dst_port"],
                "src_port": parsed["src_port"],
                "protocol": parsed["protocol"],
                "packets": 0,
                "bytes": 0,
            }
            flows[key] = flow
        flow["packets"] += 1
        flow["bytes"] += parsed["bytes"]

    def iso(value):
        if not value:
            return None
        return datetime.fromtimestamp(value, timezone.utc).isoformat()

    flow_list = sorted(flows.values(), key=lambda item: item["bytes"], reverse=True)
    for flow in flow_list:
        service = OT_SERVICE_PORTS.get(flow["dst_port"])
        if service:
            flow["ot_protocol"] = service
        flow["external"] = _is_routable(flow["dst_ip"]) or _is_routable(flow["src_ip"])

    domain_list = sorted(
        ({"domain": item["domain"], "queries": item["queries"], "clients": sorted(item["clients"])[:10]}
         for item in domains.values()),
        key=lambda item: item["queries"],
        reverse=True,
    )[:MAX_OBSERVATIONS]

    return {
        "tool": "wireshark",
        "format": capture_format,
        "packets_parsed": total_packets,
        "flows": flow_list,
        "dns_queries": domain_list,
        "ot_flows": [flow for flow in flow_list if flow.get("ot_protocol")],
        "first_seen": iso(first_seen),
        "last_seen": iso(last_seen),
        "source": "local-pcap-parser",
    }


# --------------------------------------------------------------------------
# Nmap
# --------------------------------------------------------------------------

def parse_nmap_xml(text):
    """Parse an Nmap XML report into hosts, ports and detected services."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    if not str(text or "").strip():
        raise ValueError("Nmap report is empty")
    if len(text) > MAX_ARTIFACT_BYTES:
        raise ValueError("Nmap report exceeds the 64 MB import limit")
    try:
        # resolve_entities defaults to off for ElementTree; it does not expand external entities.
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        raise ValueError(f"Nmap XML could not be parsed: {error}") from error
    if root.tag != "nmaprun":
        raise ValueError("File is not an Nmap XML report (expected <nmaprun>)")

    hosts = []
    for host in root.findall("host")[:MAX_OBSERVATIONS]:
        state = (host.find("status").get("state") if host.find("status") is not None else "") or ""
        addresses = {}
        for address in host.findall("address"):
            addresses[address.get("addrtype") or "ipv4"] = address.get("addr")
        hostnames = [name.get("name") for name in host.findall("hostnames/hostname") if name.get("name")]
        ports = []
        for port in host.findall("ports/port"):
            port_state = port.find("state")
            service = port.find("service")
            if port_state is not None and port_state.get("state") != "open":
                continue
            try:
                port_number = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            entry = {
                "port": port_number,
                "protocol": _safe_text(port.get("protocol"), 16),
                "service": _safe_text(service.get("name") if service is not None else "", 64),
                "product": _safe_text(service.get("product") if service is not None else "", 128),
                "version": _safe_text(service.get("version") if service is not None else "", 64),
            }
            if port_number in OT_SERVICE_PORTS:
                entry["ot_protocol"] = OT_SERVICE_PORTS[port_number]
            ports.append(entry)
        os_match = host.find("os/osmatch")
        scripts = [
            {"id": _safe_text(script.get("id"), 64), "output": _safe_text(script.get("output"), 2000)}
            for script in host.findall("hostscript/script")
        ]
        cves = sorted({
            match.upper()
            for script in host.iter("script")
            for match in re.findall(r"CVE-\d{4}-\d{4,7}", script.get("output") or "", re.IGNORECASE)
        })
        address = addresses.get("ipv4") or addresses.get("ipv6") or ""
        if not address:
            continue
        hosts.append({
            "ip": address,
            "mac": addresses.get("mac"),
            "state": state,
            "hostnames": hostnames[:10],
            "ports": ports,
            "os": _safe_text(os_match.get("name") if os_match is not None else "", 128),
            "scripts": scripts[:20],
            "cves": cves,
            "external": _is_routable(address),
        })

    args = _safe_text(root.get("args"), 1000)
    return {
        "tool": "nmap",
        "scanner_version": _safe_text(root.get("version"), 32),
        "arguments": args,
        "started_at": _safe_text(root.get("startstr"), 64),
        "hosts": hosts,
        "host_count": len(hosts),
        "open_port_count": sum(len(host["ports"]) for host in hosts),
        "source": "local-nmap-parser",
    }


# --------------------------------------------------------------------------
# Atomic Red Team
# --------------------------------------------------------------------------

_ATOMIC_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _parse_atomic_yaml(text):
    """Minimal reader for the Atomic Red Team YAML shape (no third-party deps)."""
    technique = ""
    display_name = ""
    tests = []
    current = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        stripped = line.strip()
        if stripped.startswith("attack_technique:"):
            technique = stripped.split(":", 1)[1].strip().strip("'\"")
        elif stripped.startswith("display_name:") and not display_name:
            display_name = stripped.split(":", 1)[1].strip().strip("'\"")
        elif stripped.startswith("- name:"):
            if current:
                tests.append(current)
            current = {"name": stripped.split(":", 1)[1].strip().strip("'\""), "platforms": [], "executor": ""}
        elif current is not None:
            if stripped.startswith("supported_platforms:"):
                inline = stripped.split(":", 1)[1].strip()
                if inline.startswith("["):
                    current["platforms"] = [p.strip().strip("'\"") for p in inline.strip("[]").split(",") if p.strip()]
            elif stripped.startswith("- ") and ":" not in stripped and current.get("platforms") is not None:
                value = stripped[2:].strip().strip("'\"")
                if value and value.casefold() in {"windows", "linux", "macos", "containers", "iaas", "office-365", "azure-ad", "google-workspace"}:
                    current["platforms"].append(value)
            elif stripped.startswith("name:") and current.get("executor") == "":
                pass
            elif stripped.startswith("auto_generated_guid:"):
                current["guid"] = stripped.split(":", 1)[1].strip().strip("'\"")
            elif stripped.startswith("description:"):
                current["description"] = stripped.split(":", 1)[1].strip().strip("'\"")[:500]
    if current:
        tests.append(current)
    return technique, display_name, tests


def parse_atomic_tests(text):
    """Parse Atomic Red Team definitions or execution results (JSON or YAML)."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    if not str(text or "").strip():
        raise ValueError("Atomic Red Team artifact is empty")
    if len(text) > MAX_ARTIFACT_BYTES:
        raise ValueError("Atomic artifact exceeds the 64 MB import limit")

    tests = []
    technique_display = ""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None

    if payload is not None:
        records = payload if isinstance(payload, list) else payload.get("atomic_tests") or payload.get("results") or []
        technique_display = payload.get("display_name", "") if isinstance(payload, dict) else ""
        parent_technique = payload.get("attack_technique", "") if isinstance(payload, dict) else ""
        if not isinstance(records, list):
            raise ValueError("Atomic JSON must contain a list of tests under 'atomic_tests' or 'results'")
        for record in records[:MAX_OBSERVATIONS]:
            if not isinstance(record, dict):
                continue
            technique = _safe_text(
                record.get("attack_technique") or record.get("technique") or record.get("Technique") or parent_technique, 32
            )
            tests.append({
                "technique": technique.upper(),
                "name": _safe_text(record.get("name") or record.get("Name") or record.get("test_name"), 256),
                "guid": _safe_text(record.get("auto_generated_guid") or record.get("GUID") or record.get("test_guid"), 64),
                "platforms": [
                    _safe_text(item, 32) for item in (record.get("supported_platforms") or []) if isinstance(item, str)
                ][:10],
                "status": _safe_text(record.get("status") or record.get("Status") or record.get("outcome"), 32).casefold(),
                "executed_at": _safe_text(record.get("executed_at") or record.get("ExecutedTimeUtc") or record.get("timestamp"), 64),
                "hostname": _safe_text(record.get("hostname") or record.get("Hostname"), 128),
                "description": _safe_text(record.get("description"), 500),
            })
    else:
        technique, technique_display, raw_tests = _parse_atomic_yaml(text)
        for record in raw_tests[:MAX_OBSERVATIONS]:
            tests.append({
                "technique": (technique or "").upper(),
                "name": _safe_text(record.get("name"), 256),
                "guid": _safe_text(record.get("guid"), 64),
                "platforms": record.get("platforms") or [],
                "status": "",
                "executed_at": "",
                "hostname": "",
                "description": _safe_text(record.get("description"), 500),
            })

    for test in tests:
        if not _ATOMIC_TECHNIQUE.fullmatch(test["technique"] or ""):
            found = _ATOMIC_TECHNIQUE.search(f"{test['technique']} {test['name']} {test['description']}")
            test["technique"] = found.group(0).upper() if found else ""

    if not tests:
        raise ValueError("No Atomic Red Team tests were found in the artifact")

    techniques = sorted({test["technique"] for test in tests if test["technique"]})
    executed = [test for test in tests if test["status"]]
    return {
        "tool": "atomic-red-team",
        "display_name": _safe_text(technique_display, 128),
        "tests": tests,
        "test_count": len(tests),
        "techniques": techniques,
        "technique_count": len(techniques),
        "executed_count": len(executed),
        "detected_count": sum(1 for test in executed if test["status"] in {"detected", "prevented", "blocked"}),
        "missed_count": sum(1 for test in executed if test["status"] in {"missed", "undetected", "not detected"}),
        "source": "local-atomic-parser",
    }


# --------------------------------------------------------------------------
# Normalization into integration events
# --------------------------------------------------------------------------

def _event(system, event_type, event_id, details, indicators=None, severity="informational", **extra):
    event = {
        "event_id": event_id,
        "event_type": event_type,
        "event_time": _utc_now(),
        "severity": severity,
        "source": {"system": system, "vendor": "local-import"},
        "details": details,
    }
    if indicators:
        event["indicators"] = indicators
    event.update(extra)
    return event


def pcap_to_events(parsed, capture_name="capture"):
    """Turn capture flows and DNS lookups into correlatable events."""
    events = []
    name = _safe_text(capture_name, 128) or "capture"
    for index, flow in enumerate(parsed.get("flows", [])):
        # Only externally-routable conversations can match an IP feed.
        if not flow.get("external") and not flow.get("ot_protocol"):
            continue
        details = {
            "srcIp": flow["src_ip"],
            "dstIp": flow["dst_ip"],
            "dstPort": flow.get("dst_port"),
            "protocol": flow.get("protocol"),
            "packets": flow.get("packets"),
            "bytes": flow.get("bytes"),
            "capture": name,
        }
        if flow.get("ot_protocol"):
            details["otProtocol"] = flow["ot_protocol"]
        events.append(_event(
            "wireshark",
            "network.flow.observed",
            f"pcap:{name}:flow:{index}",
            details,
            network={"protocol": flow.get("protocol"), "destination_port": flow.get("dst_port")},
        ))
    for index, query in enumerate(parsed.get("dns_queries", [])):
        events.append(_event(
            "wireshark",
            "network.dns.query",
            f"pcap:{name}:dns:{index}",
            {"domain": query["domain"], "queries": query["queries"], "capture": name},
        ))
    return events


def nmap_to_events(parsed, scan_name="nmap-scan"):
    """Turn scanned hosts, open ports and script CVEs into events."""
    events = []
    name = _safe_text(scan_name, 128) or "nmap-scan"
    for host in parsed.get("hosts", []):
        open_ports = [port["port"] for port in host.get("ports", [])]
        details = {
            "ip": host["ip"],
            "hostname": (host.get("hostnames") or [""])[0],
            "openPorts": open_ports,
            "os": host.get("os"),
            "scan": name,
        }
        ot_services = [port["ot_protocol"] for port in host.get("ports", []) if port.get("ot_protocol")]
        if ot_services:
            details["otProtocols"] = sorted(set(ot_services))
        events.append(_event(
            "nmap",
            "asset.scan.host",
            f"nmap:{name}:{host['ip']}",
            details,
            device={"ip": host["ip"], "hostname": (host.get("hostnames") or [""])[0], "os": host.get("os")},
        ))
        for cve in host.get("cves", []):
            events.append(_event(
                "nmap",
                "vulnerability.finding",
                f"nmap:{name}:{host['ip']}:{cve}",
                {"ip": host["ip"], "cve": cve, "scan": name, "summary": f"{cve} reported by Nmap script scan on {host['ip']}"},
                severity="medium",
                device={"ip": host["ip"]},
            ))
    return events


def atomic_to_events(parsed, run_name="atomic-run"):
    """Turn Atomic Red Team tests into detection-validation events."""
    events = []
    name = _safe_text(run_name, 128) or "atomic-run"
    for index, test in enumerate(parsed.get("tests", [])):
        status = test.get("status") or "imported"
        missed = status in {"missed", "undetected", "not detected"}
        details = {
            "technique": test.get("technique"),
            "testName": test.get("name"),
            "status": status,
            "platforms": test.get("platforms"),
            "run": name,
        }
        if test.get("hostname"):
            details["hostname"] = test["hostname"]
        events.append(_event(
            "atomic-red-team",
            "detection.validation.test",
            f"atomic:{name}:{test.get('guid') or index}",
            details,
            severity="high" if missed else "informational",
        ))
    return events
