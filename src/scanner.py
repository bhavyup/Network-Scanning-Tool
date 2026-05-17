from scapy.all import IP, ICMP, TCP, UDP, ARP, Ether, sr1, srp, send  # type: ignore[attr-defined]
import ipaddress
from typing import Any, List, Dict, Optional
import time
import logging
import socket
import ssl
import os
import subprocess
import errno

logger = logging.getLogger("network_scanner")


def _os_name() -> str:
    return os.name

class NetworkScanner:
    def __init__(self, timeout: int = 2, delay: float = 0.0, max_ports: int = 1024, udp_ambiguity: str = "open", unprivileged: bool = False):
        
        self.timeout = timeout
        self.delay = float(delay)
        self.max_ports = int(max_ports)
        self.unprivileged = bool(unprivileged)
        # Number of retries for UDP probes when no response is received.
        # Increasing this will reduce false "closed" results at the cost of time.
        self.udp_retries = 2
        # How to classify ambiguous UDP results (no ICMP unreachable and no UDP response)
        # Allowed values: 'open' or 'closed'
        self.udp_ambiguity = str(udp_ambiguity).lower()
        if self.udp_ambiguity not in ("open", "closed"):
            raise ValueError("udp_ambiguity must be 'open' or 'closed'")

    def _icmp_scan_unprivileged(self, target: str) -> bool:
        """ICMP fallback using system ping (works without raw sockets)."""
        timeout_ms = max(100, int(self.timeout * 1000))
        timeout_s = max(1, int(self.timeout))

        if _os_name() == "nt":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), target]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), target]

        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode == 0

    def _tcp_scan_unprivileged(self, target: str, ports: List[int]) -> Dict[int, str]:
        """TCP connect scan fallback that does not require raw socket privileges."""
        results: Dict[int, str] = {}
        timeout_codes = {errno.ETIMEDOUT, 10060}
        refused_codes = {errno.ECONNREFUSED, 10061}

        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                status = sock.connect_ex((target, port))
                if status == 0:
                    results[port] = "open"
                elif status in refused_codes:
                    results[port] = "closed"
                elif status in timeout_codes:
                    results[port] = "filtered"
                else:
                    results[port] = "filtered"
            except socket.timeout:
                results[port] = "filtered"
            except Exception:
                logger.exception("Error in unprivileged TCP scan for port %s on %s", port, target)
                results[port] = "error"
            finally:
                sock.close()

            if self.delay and port != ports[-1]:
                time.sleep(self.delay)

        return results

    def _udp_scan_unprivileged(self, target: str, ports: List[int]) -> Dict[int, str]:
        """Best-effort UDP probe fallback without raw sockets."""
        results: Dict[int, str] = {}

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                try:
                    sock.connect((target, port))
                    sock.send(b"\x00")

                    try:
                        sock.recv(1024)
                        results[port] = "open"
                    except socket.timeout:
                        results[port] = "open" if self.udp_ambiguity == "open" else "closed"
                    except ConnectionResetError:
                        # Windows often reports ICMP port unreachable like this.
                        results[port] = "closed"
                    except OSError as e:
                        if getattr(e, "winerror", None) in (10054, 10061):
                            results[port] = "closed"
                        else:
                            logger.exception("Error in unprivileged UDP recv for port %s on %s", port, target)
                            results[port] = "error"
                finally:
                    sock.close()
            except Exception:
                logger.exception("Error in unprivileged UDP scan for port %s on %s", port, target)
                results[port] = "error"

            if self.delay and port != ports[-1]:
                time.sleep(self.delay)

        return results

    def icmp_scan(self, target: str) -> bool:
        """
        Perform ICMP echo request (ping) scan on a target IP
        Returns True if host is up, False otherwise
        """
        if self.unprivileged:
            return self._icmp_scan_unprivileged(target)

        try:
            # Create ICMP packet
            packet = IP(dst=target)/ICMP()
            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=0)
            return response is not None
        except Exception as e:
            raise RuntimeError(f"ICMP scan failed: {str(e)}") from e

    def tcp_scan(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        Perform TCP SYN scan on specified ports
        Returns dictionary of port:status
        """
        results: Dict[int, str] = {}
        if len(ports) > self.max_ports:
            raise ValueError(f"Requested {len(ports)} ports exceeds max_ports={self.max_ports}")

        if self.unprivileged:
            return self._tcp_scan_unprivileged(target, ports)

        for port in ports:
            try:
                # Create TCP SYN packet
                packet = IP(dst=target)/TCP(dport=port, flags="S")
                # Send packet and wait for response
                response = sr1(packet, timeout=self.timeout, verbose=0)
                
                if response is None:
                    results[port] = "filtered"
                elif response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer is None:
                        results[port] = "filtered"
                    elif tcp_layer.flags == 0x12:  # SYN-ACK
                        results[port] = "open"
                        # Send RST to close connection
                        rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
                        send(rst_packet, verbose=0)
                    elif tcp_layer.flags == 0x14:  # RST-ACK
                        results[port] = "closed"
                    else:
                        results[port] = "filtered"
                else:
                    results[port] = "filtered"
            except Exception as e:
                logger.exception("Error scanning port %s on %s", port, target)
                results[port] = "error"

            # Rate limit to be polite and avoid DoS
            if self.delay and port != ports[-1]:
                time.sleep(self.delay)
        return results

    def udp_scan(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        Perform UDP scan on specified ports
        Returns dictionary of port:status
        UDP scanning is less reliable than TCP; open|filtered indicates port may be open
        """
        results: Dict[int, str] = {}
        if len(ports) > self.max_ports:
            raise ValueError(f"Requested {len(ports)} ports exceeds max_ports={self.max_ports}")

        if self.unprivileged:
            return self._udp_scan_unprivileged(target, ports)

        for port in ports:
            try:
                # Try multiple attempts to reduce ambiguous "open|filtered" results.
                is_closed = False
                got_udp_response = False
                for attempt in range(max(1, self.udp_retries)):
                    packet = IP(dst=target)/UDP(dport=port)
                    response = sr1(packet, timeout=self.timeout, verbose=0)

                    if response is None:
                        # No response this attempt; retry (if any left)
                        pass
                    elif response.haslayer(ICMP):
                        icmp_layer = response.getlayer(ICMP)
                        if icmp_layer is None:
                            is_closed = True
                            break
                        icmp_type = icmp_layer.type
                        icmp_code = icmp_layer.code

                        # ICMP type 3 = Destination Unreachable
                        if icmp_type == 3 and icmp_code == 3:
                            is_closed = True
                            break
                        else:
                            # Other ICMP unreachable messages usually indicate closed/filtered
                            is_closed = True
                            break
                    elif response.haslayer(UDP):
                        # Got UDP response = port is open
                        got_udp_response = True
                        break
                    else:
                        # Any other response treat as open
                        got_udp_response = True
                        break

                    # Rate limit between retry attempts
                    if self.delay and attempt != self.udp_retries - 1:
                        time.sleep(self.delay)

                # Final classification: only 'open' or 'closed' (no 'filtered')
                if is_closed:
                    results[port] = "closed"
                elif got_udp_response:
                    results[port] = "open"
                else:
                    # If after retries we saw no definitive response, follow configured policy
                    results[port] = "open" if self.udp_ambiguity == "open" else "closed"
            except Exception as e:
                logger.exception("Error scanning UDP port %s on %s", port, target)
                results[port] = "error"

            # Rate limit to be polite and avoid DoS
            if self.delay and port != ports[-1]:
                time.sleep(self.delay)
        return results

    def tcp_service_detect(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        Best-effort TCP service detection/banner grabbing for open ports.
        Returns dictionary of port:banner/info.
        """
        services: Dict[int, str] = {}
        for port in ports:
            try:
                with socket.create_connection((target, port), timeout=self.timeout) as sock:
                    sock.settimeout(max(0.8, min(2.0, float(self.timeout))))

                    # Optional protocol hints for common ports
                    if port in (80, 8080, 8000, 8008, 8888):
                        host = target.encode(errors="ignore")
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host + b"\r\n\r\n")

                    if port == 443:
                        try:
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            with ctx.wrap_socket(sock, server_hostname=target) as tls_sock:
                                cert = tls_sock.getpeercert()
                                if cert:
                                    services[port] = "TLS service (certificate presented)"
                                else:
                                    services[port] = "TLS service"
                                continue
                        except Exception:
                            services[port] = "TLS/HTTPS likely (handshake probe failed)"
                            continue

                    try:
                        data = sock.recv(256)
                        if data:
                            banner = data.decode(errors="ignore").replace("\r", " ").replace("\n", " ").strip()
                            services[port] = banner[:120] if banner else "open (no banner)"
                        else:
                            services[port] = "open (no banner)"
                    except socket.timeout:
                        services[port] = "open (no banner)"
            except Exception as e:
                services[port] = f"probe-error: {e}"

            if self.delay and port != ports[-1]:
                time.sleep(self.delay)

        return services

    def udp_service_detect(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        Best-effort UDP service detection for open/ambiguous ports.
        Returns dictionary of port:info.
        """
        services: Dict[int, str] = {}

        dns_probe = (
            b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x01\x00\x01"
        )
        ntp_probe = b"\x1b" + (47 * b"\x00")

        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(max(0.8, min(2.0, float(self.timeout))))
                    sock.connect((target, port))

                    if port == 53:
                        payload = dns_probe
                    elif port == 123:
                        payload = ntp_probe
                    else:
                        payload = b"\x00"

                    sock.send(payload)

                    try:
                        data = sock.recv(512)
                        if data:
                            services[port] = f"udp-response ({len(data)} bytes)"
                        else:
                            services[port] = "open|unknown"
                    except socket.timeout:
                        services[port] = "open|unknown"
                    except ConnectionResetError:
                        services[port] = "closed/unreachable"
                    except OSError as e:
                        if getattr(e, "winerror", None) in (10054, 10061):
                            services[port] = "closed/unreachable"
                        else:
                            services[port] = f"probe-error: {e}"
            except Exception as e:
                services[port] = f"probe-error: {e}"

            if self.delay and port != ports[-1]:
                time.sleep(self.delay)

        return services

    def arp_scan(self, network: str) -> List[Dict[str, str]]:
        """
        Perform ARP scan on a network
        Returns list of dictionaries containing IP and MAC addresses
        """
        if self.unprivileged:
            raise RuntimeError("ARP scan requires administrator/root privileges and is unavailable in unprivileged mode")

        try:
            # Validate network format
            if "/" not in network:
                network = f"{network}/24"  # Default to /24 subnet
            
            # Create ARP request packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and get responses
            result = srp(packet, timeout=self.timeout, verbose=0)[0]
            
            clients = []
            for sent, received in result:
                clients.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
            return clients
        except Exception as e:
            raise RuntimeError(f"ARP scan failed: {str(e)}") from e

    def validate_ip(self, ip: str) -> bool:
        """
        Validate IP address format
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def validate_network(self, network: str) -> bool:
        """
        Validate network format (IP with subnet)
        """
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False

    def scan_network(
        self, target: str, scan_type: str = "all", ports: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive network scan
        scan_type: "all", "icmp", "tcp", "udp", or "arp"
        """
        results: Dict[str, Any] = {
            "icmp": None,
            "tcp": None,
            "udp": None,
            "arp": None,
            "_errors": []
        }

        try:
            # Validate target format
            if not (self.validate_ip(target) or self.validate_network(target)):
                raise ValueError(f"Invalid IP address or network format: {target}")
            
            if scan_type in ["all", "icmp"]:
                try:
                    results["icmp"] = self.icmp_scan(target)
                except Exception as e:
                    logger.error("ICMP scan failed for %s: %s", target, e)
                    results["_errors"].append(str(e))
            
            if scan_type in ["all", "tcp"]:
                if ports is None:
                    print("Warning: No ports specified for TCP scan")
                else:
                    results["tcp"] = self.tcp_scan(target, ports)
                    tcp_errors = [p for p, status in results["tcp"].items() if status == "error"]
                    if tcp_errors:
                        preview = ",".join(map(str, tcp_errors[:10]))
                        suffix = "..." if len(tcp_errors) > 10 else ""
                        results["_errors"].append(
                            f"TCP scan had {len(tcp_errors)} port probe error(s): {preview}{suffix}"
                        )
            
            if scan_type in ["all", "udp"]:
                if ports is None:
                    print("Warning: No ports specified for UDP scan")
                else:
                    results["udp"] = self.udp_scan(target, ports)
                    udp_errors = [p for p, status in results["udp"].items() if status == "error"]
                    if udp_errors:
                        preview = ",".join(map(str, udp_errors[:10]))
                        suffix = "..." if len(udp_errors) > 10 else ""
                        results["_errors"].append(
                            f"UDP scan had {len(udp_errors)} port probe error(s): {preview}{suffix}"
                        )
            
            if scan_type in ["all", "arp"]:
                try:
                    results["arp"] = self.arp_scan(target)
                except Exception as e:
                    logger.error("ARP scan failed for %s: %s", target, e)
                    results["_errors"].append(str(e))
            
            return results
        except ValueError as e:
            msg = f"Error: {str(e)}"
            logger.error(msg)
            results["_errors"].append(str(e))
            return results
        except Exception as e:
            logger.exception("Error during network scan")
            results["_errors"].append(f"Error during network scan: {str(e)}")
            return results 