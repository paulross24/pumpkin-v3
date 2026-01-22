"""Observation sources."""

from __future__ import annotations

import base64
import os
import shutil
import socket
import subprocess
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import ha_client
from . import settings

def _read_meminfo() -> Dict[str, int]:
    data: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                value = parts[1].strip().split()[0]
                if value.isdigit():
                    data[key] = int(value)
    except FileNotFoundError:
        pass
    return data


def system_snapshot() -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    load1, load5, load15 = os.getloadavg()
    disk = shutil.disk_usage("/")
    disk_used_percent = disk.used / disk.total if disk.total else 0.0
    meminfo = _read_meminfo()

    payload = {
        "loadavg": {"1m": load1, "5m": load5, "15m": load15},
        "disk": {
            "path": "/",
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
            "used_percent": round(disk_used_percent, 4),
        },
        "meminfo_kb": {
            "MemTotal": meminfo.get("MemTotal"),
            "MemAvailable": meminfo.get("MemAvailable"),
        },
    }

    severity = "warn" if disk_used_percent >= 0.9 else "info"
    events.append(
        {
            "source": "system",
            "type": "system.snapshot",
            "payload": payload,
            "severity": severity,
        }
    )

    return events


def _detect_local_ip() -> Optional[str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except Exception:
        return None


def _read_arp_table() -> List[Dict[str, str]]:
    entries: Dict[str, Dict[str, str]] = {}
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                ip, _, _, mac, _, device = parts[:6]
                if mac == "00:00:00:00:00:00":
                    continue
                entries[ip] = {"ip": ip, "mac": mac.lower(), "device": device}
    except FileNotFoundError:
        pass
    for entry in _read_ip_neigh():
        ip = entry.get("ip")
        if not ip:
            continue
        current = entries.get(ip, {"ip": ip})
        if entry.get("mac"):
            current["mac"] = entry["mac"]
        if entry.get("device"):
            current["device"] = entry["device"]
        entries[ip] = current
    return list(entries.values())


def _read_ip_neigh() -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"], capture_output=True, text=True, check=False
        )
    except Exception:
        return entries
    if result.returncode != 0 or not result.stdout:
        return entries
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = None
        device = None
        for idx, part in enumerate(parts):
            if part == "dev" and idx + 1 < len(parts):
                device = parts[idx + 1]
            if part == "lladdr" and idx + 1 < len(parts):
                mac = parts[idx + 1].lower()
        if mac and mac != "00:00:00:00:00:00":
            entries.append({"ip": ip, "mac": mac, "device": device or ""})
    return entries


def _mdns_discover(timeout: float, max_responses: int) -> List[Dict[str, str]]:
    responders: Dict[str, Dict[str, str]] = {}
    query = b"".join(
        [
            b"\x00\x00",  # Transaction ID
            b"\x00\x00",  # Flags
            b"\x00\x01",  # Questions
            b"\x00\x00",  # Answer RRs
            b"\x00\x00",  # Authority RRs
            b"\x00\x00",  # Additional RRs
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00",
            b"\x00\x0c",  # PTR
            b"\x00\x01",  # IN
        ]
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", 5353))
        except OSError:
            sock.bind(("", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        try:
            mreq = socket.inet_aton("224.0.0.251") + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            pass
        sock.settimeout(timeout)
        sock.sendto(query, ("224.0.0.251", 5353))
        while len(responders) < max_responses:
            try:
                _data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            ip = addr[0]
            if ip and ip not in responders:
                responders[ip] = {"ip": ip}
    except Exception:
        return []
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return list(responders.values())


def _probe_port(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _read_tcp_banner(ip: str, port: int, timeout: float, max_bytes: int) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(max_bytes)
            if not data:
                return None
            return data.decode(errors="ignore").strip()
    except Exception:
        return None


def _probe_ssh(ip: str, port: int, timeout: float, max_bytes: int) -> Optional[Dict[str, Any]]:
    banner = _read_tcp_banner(ip, port, timeout, max_bytes)
    if not banner:
        return None
    return {"type": "ssh", "port": port, "banner": banner}


DEFAULT_RTSP_PATHS = [
    "/",
    "/stream1",
    "/stream2",
    "/live",
    "/live/ch0",
    "/h264",
    "/h264/ch1/main/av_stream",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/onvif1",
    "/onvif2",
    "/profile1",
    "/profile2",
]


def basic_auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _probe_rtsp(ip: str, port: int, timeout: float, max_bytes: int) -> Optional[Dict[str, Any]]:
    payload = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Pumpkin\r\n\r\n"
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            data = sock.recv(max_bytes)
        if not data:
            return None
        text = data.decode(errors="ignore")
        status_line = text.splitlines()[0] if text else ""
        return {"type": "rtsp", "port": port, "status": status_line.strip()}
    except Exception:
        return None


def _rtsp_describe(
    ip: str,
    port: int,
    path: str,
    timeout: float,
    max_bytes: int,
    auth_header: Optional[str] = None,
) -> Optional[str]:
    url = f"rtsp://{ip}:{port}{path}"
    headers = (
        f"DESCRIBE {url} RTSP/1.0\r\n"
        "CSeq: 2\r\n"
        "User-Agent: Pumpkin\r\n"
        "Accept: application/sdp\r\n"
    )
    if auth_header:
        headers += f"Authorization: {auth_header}\r\n"
    payload = (headers + "\r\n").encode("ascii")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            data = sock.recv(max_bytes)
        if not data:
            return None
        text = data.decode(errors="ignore")
        status_line = text.splitlines()[0] if text else ""
        return status_line.strip()
    except Exception:
        return None


def _rtsp_probe_paths(
    ip: str,
    port: int,
    timeout: float,
    max_bytes: int,
    auth_header: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    for path in DEFAULT_RTSP_PATHS:
        status = _rtsp_describe(ip, port, path, timeout, max_bytes, auth_header=auth_header)
        if not status:
            continue
        status_lower = status.lower()
        auth_required = "401" in status_lower or "403" in status_lower
        return {
            "type": "rtsp",
            "port": port,
            "status": status,
            "url": f"rtsp://{ip}:{port}{path}",
            "auth_required": auth_required,
        }
    return None


def rtsp_probe_paths(
    ip: str,
    port: int,
    paths: Iterable[str],
    timeout: float,
    max_bytes: int,
    auth_header: Optional[str] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for raw in paths:
        path = str(raw).strip()
        if not path:
            continue
        if not path.startswith("/"):
            path = f"/{path}"
        status = _rtsp_describe(ip, port, path, timeout, max_bytes, auth_header=auth_header)
        if not status:
            results.append({"path": path, "status": "no response"})
            continue
        status_lower = status.lower()
        results.append(
            {
                "path": path,
                "status": status,
                "auth_required": "401" in status_lower or "403" in status_lower,
            }
        )
    return results


def _onvif_probe(ip: str, port: int, timeout: float, max_bytes: int) -> Optional[Dict[str, Any]]:
    body = (
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
        "<s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>"
    ).encode("utf-8")
    request = (
        f"POST /onvif/device_service HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        "Content-Type: application/soap+xml; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            data = sock.recv(max_bytes)
        if not data:
            return None
        text = data.decode(errors="ignore")
        status_line = text.splitlines()[0] if text else ""
        status_lower = status_line.lower()
        if "getdeviceinformationresponse" not in text.lower():
            if "401" in status_lower or "403" in status_lower:
                return {
                    "type": "onvif",
                    "port": port,
                    "status": status_line.strip(),
                    "auth_required": True,
                }
            return None
        def _extract(tag: str) -> Optional[str]:
            start = text.find(f"<tds:{tag}>")
            end = text.find(f"</tds:{tag}>")
            if start == -1 or end == -1 or end <= start:
                return None
            start += len(f"<tds:{tag}>")
            return text[start:end].strip() or None
        return {
            "type": "onvif",
            "port": port,
            "status": status_line.strip(),
            "manufacturer": _extract("Manufacturer"),
            "model": _extract("Model"),
            "firmware_version": _extract("FirmwareVersion"),
            "serial_number": _extract("SerialNumber"),
            "hardware_id": _extract("HardwareId"),
        }
    except Exception:
        return None


def _probe_http(
    ip: str,
    port: int,
    timeout: float,
    max_bytes: int,
    use_tls: bool,
) -> Optional[Dict[str, Any]]:
    request = (
        f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Pumpkin\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if use_tls:
                import ssl

                context = ssl._create_unverified_context()
                with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                    tls_sock.sendall(request)
                    data = tls_sock.recv(max_bytes)
            else:
                sock.sendall(request)
                data = sock.recv(max_bytes)
        if not data:
            return None
        text = data.decode(errors="ignore")
        lines = text.splitlines()
        status_line = lines[0] if lines else ""
        server = ""
        title = ""
        for line in lines[1:]:
            if not line.strip():
                break
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
        if "<title>" in text.lower():
            lower = text.lower()
            start = lower.find("<title>")
            end = lower.find("</title>", start + 7)
            if start != -1 and end != -1:
                title = text[start + 7 : end].strip()
        return {
            "type": "https" if use_tls else "http",
            "port": port,
            "status": status_line.strip(),
            "server": server,
            "title": title,
        }
    except Exception:
        return None


def _ssdp_discover(timeout: float, max_responses: int) -> List[Dict[str, str]]:
    responses: List[Dict[str, str]] = []
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT: Pumpkin\r\n\r\n"
    ).encode("ascii")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(message, ("239.255.255.250", 1900))
        while len(responses) < max_responses:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            text = data.decode(errors="ignore")
            headers: Dict[str, str] = {"_raw": text}
            for line in text.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
            headers["ip"] = addr[0]
            responses.append(headers)
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return responses


def _classify_services(open_ports: List[int], services: List[Dict[str, Any]]) -> List[str]:
    hints: List[str] = []
    if 8123 in open_ports:
        hints.append("homeassistant")
    if 554 in open_ports or 8554 in open_ports:
        hints.append("rtsp_camera")
    if 8008 in open_ports or 8009 in open_ports:
        hints.append("chromecast")
    if 1400 in open_ports:
        hints.append("sonos")
    if 62078 in open_ports:
        hints.append("airplay")
    if 9100 in open_ports:
        hints.append("printer")
    if 22 in open_ports:
        hints.append("ssh")
    for service in services:
        if service.get("type") in {"http", "https"} and service.get("title"):
            hints.append(f"http:{service['title']}")
    return sorted(set(hints))


def network_discovery(
    subnet: Optional[str],
    tcp_ports: Iterable[int],
    timeout_seconds: float,
    max_hosts: int,
    max_scan_seconds: Optional[float] = None,
    fast_ports: Optional[Iterable[int]] = None,
    fast_timeout_seconds: Optional[float] = None,
    active: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    start_time = time.monotonic()
    local_ip = _detect_local_ip()
    network = None
    if isinstance(subnet, str) and subnet.strip() and subnet.strip().lower() != "auto":
        try:
            network = ipaddress.ip_network(subnet.strip(), strict=False)
        except ValueError:
            network = None
    if network is None and local_ip:
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    arp_entries = _read_arp_table()
    devices: List[Dict[str, Any]] = []
    ports = [int(p) for p in tcp_ports if isinstance(p, int) or str(p).isdigit()]
    fast_ports_list = [int(p) for p in (fast_ports or []) if isinstance(p, int) or str(p).isdigit()]
    fast_timeout = None
    if fast_timeout_seconds is not None:
        try:
            fast_timeout = float(fast_timeout_seconds)
        except (TypeError, ValueError):
            fast_timeout = None
    active_cfg = active if isinstance(active, dict) else {}
    active_enabled = bool(active_cfg.get("enabled", False))
    scan_subnet = bool(active_cfg.get("scan_subnet", False))
    ssdp_enabled = bool(active_cfg.get("ssdp", False))
    mdns_enabled = bool(active_cfg.get("mdns", False))
    http_enabled = bool(active_cfg.get("http", False))
    rtsp_enabled = bool(active_cfg.get("rtsp", False))
    ssh_enabled = bool(active_cfg.get("ssh", False))
    max_banner_bytes = int(active_cfg.get("max_banner_bytes", 256))
    max_http_bytes = int(active_cfg.get("max_http_bytes", 2048))
    max_ssdp_responses = int(active_cfg.get("max_ssdp_responses", 32))

    ssdp_services = _ssdp_discover(timeout_seconds, max_ssdp_responses) if active_enabled and ssdp_enabled else []
    mdns_services = _mdns_discover(timeout_seconds, max_ssdp_responses) if active_enabled and mdns_enabled else []

    seen_ips: set[str] = set()
    candidates: List[Tuple[str, Optional[Dict[str, str]]]] = []
    for entry in arp_entries:
        ip = entry.get("ip")
        if not ip:
            continue
        if network:
            try:
                if ipaddress.ip_address(ip) not in network:
                    continue
            except ValueError:
                continue
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        candidates.append((ip, entry))

    for entry in mdns_services:
        ip = entry.get("ip")
        if not ip or ip in seen_ips:
            continue
        if network:
            try:
                if ipaddress.ip_address(ip) not in network:
                    continue
            except ValueError:
                continue
        seen_ips.add(ip)
        candidates.append((ip, {"ip": ip, "device": "mdns"}))

    if scan_subnet and network:
        for host in network.hosts():
            if max_scan_seconds is not None and (time.monotonic() - start_time) >= max_scan_seconds:
                break
            ip = str(host)
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            candidates.append((ip, None))
            if len(candidates) >= max_hosts * 2:
                break

    for ip, entry in candidates:
        if max_scan_seconds is not None and (time.monotonic() - start_time) >= max_scan_seconds:
            break
        open_ports: List[int] = []
        port_list = ports
        port_timeout = timeout_seconds
        if entry is None and fast_ports_list:
            port_list = fast_ports_list
        if entry is None and fast_timeout is not None:
            port_timeout = fast_timeout
        for port in port_list:
            if max_scan_seconds is not None and (time.monotonic() - start_time) >= max_scan_seconds:
                break
            if _probe_port(ip, port, port_timeout):
                open_ports.append(port)

        if entry is None and not open_ports:
            continue

        services: List[Dict[str, Any]] = []
        if active_enabled and open_ports:
            for port in open_ports:
                if http_enabled and port in {80, 443, 8000, 8080, 8081, 8123, 8443, 9000, 9443}:
                    service = _probe_http(ip, port, timeout_seconds, max_http_bytes, port in {443, 8443, 9443})
                    if service:
                        services.append(service)
                if rtsp_enabled and port in {554, 8554}:
                    service = _probe_rtsp(ip, port, timeout_seconds, max_banner_bytes)
                    if service:
                        services.append(service)
                if ssh_enabled and port == 22:
                    service = _probe_ssh(ip, port, timeout_seconds, max_banner_bytes)
                    if service:
                        services.append(service)

        device_payload = {
            "ip": ip,
            "mac": entry.get("mac") if entry else None,
            "device": entry.get("device") if entry else None,
            "open_ports": open_ports,
            "services": services,
        }
        device_payload["hints"] = _classify_services(open_ports, services)
        devices.append(device_payload)
        if len(devices) >= max_hosts:
            break

    return {
        "local_ip": local_ip,
        "subnet": str(network) if network else None,
        "device_count": len(devices),
        "devices": devices,
        "ssdp": ssdp_services,
        "mdns": mdns_services,
    }


def deep_scan_host(
    ip: str,
    ports: Iterable[int],
    timeout_seconds: float,
    max_workers: int,
    active: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ports_list = [int(p) for p in ports if isinstance(p, int) or str(p).isdigit()]
    max_workers = max(1, min(int(max_workers), len(ports_list))) if ports_list else 1
    open_ports: List[int] = []

    if ports_list:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_probe_port, ip, port, timeout_seconds): port for port in ports_list}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    continue

    open_ports.sort()
    active_cfg = active if isinstance(active, dict) else {}
    http_enabled = bool(active_cfg.get("http", True))
    rtsp_enabled = bool(active_cfg.get("rtsp", True))
    ssh_enabled = bool(active_cfg.get("ssh", True))
    max_banner_bytes = int(active_cfg.get("max_banner_bytes", 256))
    max_http_bytes = int(active_cfg.get("max_http_bytes", 2048))

    services: List[Dict[str, Any]] = []
    for port in open_ports:
        if http_enabled and port in {80, 81, 443, 8000, 8080, 8081, 8123, 8443, 9000, 9443}:
            service = _probe_http(ip, port, timeout_seconds, max_http_bytes, port in {443, 8443, 9443})
            if service:
                services.append(service)
            if port in {80, 8000, 8080, 8081, 8899}:
                onvif = _onvif_probe(ip, port, timeout_seconds, max_http_bytes)
                if onvif:
                    services.append(onvif)
        if rtsp_enabled and port in {554, 8554}:
            service = _probe_rtsp(ip, port, timeout_seconds, max_banner_bytes)
            if service:
                services.append(service)
            enriched = _rtsp_probe_paths(ip, port, timeout_seconds, max_banner_bytes)
            if enriched:
                services.append(enriched)
        if ssh_enabled and port == 22:
            service = _probe_ssh(ip, port, timeout_seconds, max_banner_bytes)
            if service:
                services.append(service)

    return {
        "ip": ip,
        "open_ports": open_ports,
        "services": services,
        "hints": _classify_services(open_ports, services),
    }


_DEFAULT_ATTR_ALLOWLIST = [
    "friendly_name",
    "device_class",
    "unit_of_measurement",
    "icon",
    "battery_level",
    "latitude",
    "longitude",
    "radius",
    "passive",
    "temperature",
    "current_temperature",
    "humidity",
    "brightness",
    "hvac_mode",
    "hvac_action",
    "preset_mode",
]


def _normalize_attributes(attributes: Dict[str, Any], allowlist: Iterable[str]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key in allowlist:
        if key in attributes:
            normalized[key] = attributes[key]
    return normalized


def _filter_entity(
    entity_id: str,
    include_domains: Optional[Iterable[str]],
    include_entities: Optional[Iterable[str]],
    exclude_domains: Optional[Iterable[str]],
    exclude_entities: Optional[Iterable[str]],
) -> bool:
    domain = entity_id.split(".", 1)[0] if "." in entity_id else ""
    if exclude_entities and entity_id in exclude_entities:
        return False
    if exclude_domains and domain in exclude_domains:
        return False
    if include_entities and entity_id in include_entities:
        return True
    if include_domains:
        if "*" in include_domains:
            return True
        return domain in include_domains
    return True


def _summarize_states(states: Dict[str, Dict[str, Any]], areas: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    home_people: List[str] = []
    people: List[Dict[str, Any]] = []
    zones: List[Dict[str, Any]] = []
    entity_areas: Dict[str, str] = {}
    upstairs = set()
    downstairs = set()
    upstairs_tokens = (
        "upstairs",
        "first floor",
        "1st floor",
        "floor one",
        "upper",
        "bedroom",
        "bathroom",
        "ensuite",
        "loft",
        "office",
        "study",
    )
    downstairs_tokens = (
        "downstairs",
        "ground floor",
        "groundfloor",
        "ground level",
        "lower",
        "kitchen",
        "living",
        "lounge",
        "hall",
        "toilet",
        "wc",
        "dining",
    )
    for entity_id, payload in states.items():
        domain = entity_id.split(".", 1)[0] if "." in entity_id else ""
        counts[domain] = counts.get(domain, 0) + 1
        area = payload.get("area_id")
        if area:
            entity_areas[entity_id] = area
            name = areas.get(area, {}).get("name", area)
            lowered = name.lower()
            if any(token in lowered for token in upstairs_tokens):
                upstairs.add(entity_id)
            if any(token in lowered for token in downstairs_tokens):
                downstairs.add(entity_id)
        if domain == "person":
            name = payload.get("attributes", {}).get("friendly_name") or entity_id
            if payload.get("state") == "home":
                home_people.append(str(name))
            people.append(
                {
                    "entity_id": entity_id,
                    "name": str(name),
                    "state": payload.get("state"),
                }
            )
        if domain == "zone":
            attributes = payload.get("attributes", {}) or {}
            name = attributes.get("friendly_name") or entity_id
            zones.append(
                {
                    "entity_id": entity_id,
                    "name": str(name),
                    "latitude": attributes.get("latitude"),
                    "longitude": attributes.get("longitude"),
                    "radius": attributes.get("radius"),
                    "passive": attributes.get("passive"),
                    "icon": attributes.get("icon"),
                }
            )
    return {
        "entity_count": len(states),
        "counts_by_domain": counts,
        "people_home": sorted(home_people),
        "people": sorted(people, key=lambda item: item.get("name", "")),
        "zones": sorted(zones, key=lambda item: item.get("name", "")),
        "entity_areas": entity_areas,
        "upstairs_entities": sorted(upstairs),
        "downstairs_entities": sorted(downstairs),
    }


def _parse_datetime(value: str) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _event_start(event: Dict[str, Any]) -> Optional[datetime]:
    start = event.get("start") or {}
    if isinstance(start, dict):
        value = start.get("dateTime") or start.get("date")
        return _parse_datetime(value) if value else None
    if isinstance(start, str):
        return _parse_datetime(start)
    return None


def homeassistant_snapshot(
    base_url: str,
    token: str,
    previous: Optional[Dict[str, Dict[str, Any]]] = None,
    previous_summary: Optional[Dict[str, Any]] = None,
    include_domains: Optional[Iterable[str]] = None,
    include_entities: Optional[Iterable[str]] = None,
    exclude_domains: Optional[Iterable[str]] = None,
    exclude_entities: Optional[Iterable[str]] = None,
    attribute_allowlist: Optional[Iterable[str]] = None,
    calendar_enabled: bool = False,
    calendar_days_ahead: int = 7,
    calendar_limit: int = 10,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    areas_map: Dict[str, Dict[str, Any]] = {}
    previous_summary = previous_summary or {}
    details: Dict[str, Any] = {"areas": None, "entity_registry": None, "device_registry": None}
    result = ha_client.fetch_status(
        base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
    )
    if result.get("ok"):
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.status",
                "payload": {"status": result.get("status")},
                "severity": "info",
            }
        )
    else:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.request_failed",
                "payload": {"error": result.get("error")},
                "severity": "warn",
            }
        )
        return events, previous or {}, {}, details

    states_result = ha_client.fetch_states(
        base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
    )
    if not states_result.get("ok"):
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.states_failed",
                "payload": {"error": states_result.get("error")},
                "severity": "warn",
            }
        )
        return events, previous or {}, {}, details

    areas_result = ha_client.fetch_areas(
        base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
    )
    if areas_result.get("ok"):
        details["areas"] = areas_result.get("areas", [])
        for area in areas_result.get("areas", []):
            if not isinstance(area, dict):
                continue
            area_id = area.get("area_id")
            if area_id:
                areas_map[area_id] = area
    else:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.areas_failed",
                "payload": {"error": areas_result.get("error")},
                "severity": "warn",
            }
        )

    registry_result = ha_client.fetch_entity_registry(
        base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
    )
    if not registry_result.get("ok"):
        registry_result = ha_client.fetch_entity_registry(
            base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
        )
    entity_area_map: Dict[str, str] = {}
    device_area_map: Dict[str, str] = {}
    if registry_result.get("ok"):
        details["entity_registry"] = registry_result.get("entities", [])
        for entry in registry_result.get("entities", []):
            if not isinstance(entry, dict):
                continue
            eid = entry.get("entity_id")
            aid = entry.get("area_id")
            did = entry.get("device_id")
            if eid and aid:
                entity_area_map[eid] = aid
            if eid and did:
                device_area_map[eid] = did
    else:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.entity_registry_failed",
                "payload": {"error": registry_result.get("error")},
                "severity": "warn",
            }
        )
        entity_area_map = previous_summary.get("entity_areas", {}) or {}

    device_registry = ha_client.fetch_device_registry(
        base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
    )
    device_area_lookup: Dict[str, str] = {}
    if device_registry.get("ok"):
        details["device_registry"] = device_registry.get("devices", [])
        for dev in device_registry.get("devices", []):
            if not isinstance(dev, dict):
                continue
            did = dev.get("id")
            aid = dev.get("area_id")
            if did and aid:
                device_area_lookup[did] = aid
    else:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.device_registry_failed",
                "payload": {"error": device_registry.get("error")},
                "severity": "warn",
            }
        )
        device_area_lookup = previous_summary.get("device_area_lookup", {}) or {}

    allowlist = list(attribute_allowlist or _DEFAULT_ATTR_ALLOWLIST)
    current: Dict[str, Dict[str, Any]] = {}
    for entity in states_result.get("states", []):
        entity_id = entity.get("entity_id")
        if not entity_id:
            continue
        if not _filter_entity(
            entity_id,
            include_domains=include_domains,
            include_entities=include_entities,
            exclude_domains=exclude_domains,
            exclude_entities=exclude_entities,
        ):
            continue
        attributes = entity.get("attributes", {}) or {}
        area_id = entity.get("area_id") or entity_area_map.get(entity_id)
        if not area_id:
            device_id = device_area_map.get(entity_id)
            if device_id:
                area_id = device_area_lookup.get(device_id)
        current[entity_id] = {
            "state": entity.get("state"),
            "attributes": _normalize_attributes(attributes, allowlist),
            "area_id": area_id,
        }

    summary = _summarize_states(current, areas_map)
    summary["areas"] = [
        {"area_id": aid, "name": area.get("name")} for aid, area in areas_map.items() if isinstance(area, dict)
    ]
    if not summary.get("entity_areas") and previous_summary.get("entity_areas"):
        summary["entity_areas"] = previous_summary.get("entity_areas")
    if not summary.get("upstairs_entities") and previous_summary.get("upstairs_entities"):
        summary["upstairs_entities"] = previous_summary.get("upstairs_entities")
    if not summary.get("downstairs_entities") and previous_summary.get("downstairs_entities"):
        summary["downstairs_entities"] = previous_summary.get("downstairs_entities")
    previous = previous or {}
    if not previous:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.state_snapshot",
                "payload": {
                    "entity_count": summary.get("entity_count", 0),
                    "counts_by_domain": summary.get("counts_by_domain", {}),
                    "people_home": summary.get("people_home", []),
                },
                "severity": "info",
            }
        )
        return events, current, summary, details

    changes: List[Dict[str, Any]] = []
    for entity_id, payload in current.items():
        previous_payload = previous.get(entity_id)
        if previous_payload == payload:
            continue
        changes.append(
            {
                "entity_id": entity_id,
                "domain": entity_id.split(".", 1)[0],
                "old": previous_payload,
                "new": payload,
            }
        )
    if changes:
        events.append(
            {
                "source": "homeassistant",
                "type": "homeassistant.entity_changed",
                "payload": {"changes": changes[:200]},
                "severity": "info",
            }
        )
    if calendar_enabled:
        summary["calendars"] = []
        summary["upcoming_events"] = []
        summary["calendar_events"] = {}
        calendars_result = ha_client.fetch_calendars(
            base_url=base_url, token=token, timeout=settings.ha_request_timeout_seconds()
        )
        if calendars_result.get("ok"):
            calendars = []
            for item in calendars_result.get("calendars", []):
                if not isinstance(item, dict):
                    continue
                entity_id = item.get("entity_id")
                name = item.get("name") or entity_id
                if entity_id:
                    calendars.append({"entity_id": entity_id, "name": name})
            summary["calendars"] = calendars
            now = datetime.now(timezone.utc)
            end = now + timedelta(days=max(1, calendar_days_ahead))
            upcoming = []
            for cal in calendars:
                entity_id = cal.get("entity_id")
                if not entity_id:
                    continue
                per_calendar = []
                result = ha_client.fetch_calendar_events(
                    base_url=base_url,
                    token=token,
                    entity_id=entity_id,
                    start=now.isoformat(),
                    end=end.isoformat(),
                    timeout=settings.ha_request_timeout_seconds(),
                )
                if not result.get("ok"):
                    continue
                for event in result.get("events", []):
                    if not isinstance(event, dict):
                        continue
                    entry = {
                        "calendar": cal.get("name"),
                        "entity_id": entity_id,
                        "summary": event.get("summary"),
                        "start": event.get("start"),
                        "end": event.get("end"),
                        "location": event.get("location"),
                    }
                    per_calendar.append(entry)
                    upcoming.append(
                        {
                            **entry,
                        }
                    )
                summary["calendar_events"][entity_id] = per_calendar
            upcoming.sort(key=lambda item: _event_start(item) or datetime.max)
            summary["upcoming_events"] = upcoming[: max(1, calendar_limit)]
        else:
            summary["calendar_error"] = calendars_result.get("error")
            events.append(
                {
                    "source": "homeassistant",
                    "type": "homeassistant.calendar_failed",
                    "payload": {"error": calendars_result.get("error")},
                    "severity": "warn",
                }
            )
    return events, current, summary, details
