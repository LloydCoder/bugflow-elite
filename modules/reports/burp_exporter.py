"""
BugFlow Elite v6 — Burp Suite Exporter
Generates Burp Suite importable files from BugFlow's discovered endpoints.
Formats: Burp XML (importable), JSON target sitemap, plain URL list.
Includes AI-suggested attack chains per finding for manual testing.
Tinlance Limited | LloydCoder
"""

import json
import logging
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional
from db.models import get_conn

logger = logging.getLogger(__name__)


class BurpExporter:
    """
    Exports BugFlow's discovered assets and findings into
    formats that Burp Suite can import directly.

    Burp XML format: Burp Suite → Project → Import → Burp XML
    JSON sitemap: Burp Suite REST API import
    URL list: Burp Suite → Target → Add to scope from file
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get(
            "db_path", "./db/bugflow.db"
        )
        self.output_dir = Path("./output/burp")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(
        self, domain: str, include_findings: bool = True
    ) -> dict:
        """
        Full export for a domain.
        Returns paths to generated files.
        """
        logger.info(f"[BurpExport] Exporting {domain}")

        endpoints = self._load_endpoints(domain)
        findings = self._load_findings(domain) if include_findings else []
        assets = self._load_assets(domain)

        # Generate all export formats
        xml_path = self._export_burp_xml(
            domain, endpoints, findings, assets
        )
        json_path = self._export_json_sitemap(
            domain, endpoints, findings
        )
        url_path = self._export_url_list(domain, endpoints, assets)
        chains_path = self._export_attack_chains(domain, findings)

        result = {
            "domain": domain,
            "burp_xml": str(xml_path),
            "json_sitemap": str(json_path),
            "url_list": str(url_path),
            "attack_chains": str(chains_path),
            "stats": {
                "endpoints": len(endpoints),
                "findings": len(findings),
                "assets": len(assets),
            },
            "exported_at": datetime.utcnow().isoformat(),
        }

        logger.info(
            f"[BurpExport] Exported: {len(endpoints)} endpoints, "
            f"{len(findings)} findings for {domain}"
        )
        return result

    def _export_burp_xml(
        self,
        domain: str,
        endpoints: list,
        findings: list,
        assets: list,
    ) -> Path:
        """
        Generate Burp Suite XML import file.
        Format: Burp Suite → Proxy → HTTP history import
        """
        root = ET.Element("items", burpVersion="2023.10", exportTime=datetime.utcnow().isoformat())

        # Add endpoints as HTTP request items
        for ep in endpoints:
            url = ep.get("url", "")
            if not url:
                continue

            item = ET.SubElement(root, "item")

            ET.SubElement(item, "time").text = ep.get("last_seen", datetime.utcnow().isoformat())
            ET.SubElement(item, "url").text = url

            # Determine host and port
            host_elem = ET.SubElement(item, "host")
            host_elem.set("ip", "")
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host_elem.text = parsed.netloc.split(":")[0]
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                ET.SubElement(item, "port").text = str(port)
                ET.SubElement(item, "protocol").text = parsed.scheme
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                ET.SubElement(item, "path").text = path
            except Exception:
                host_elem.text = domain
                ET.SubElement(item, "port").text = "443"
                ET.SubElement(item, "protocol").text = "https"
                ET.SubElement(item, "path").text = "/"

            ET.SubElement(item, "extension").text = ""
            ET.SubElement(item, "method").text = ep.get("method", "GET")
            ET.SubElement(item, "statusCode").text = str(
                ep.get("status_code", "")
            )

            # Build HTTP request
            http_req = f"GET {url} HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: BugFlow-Elite/6\r\n\r\n"
            req_b64 = base64.b64encode(http_req.encode()).decode()
            req_elem = ET.SubElement(item, "request")
            req_elem.set("base64", "true")
            req_elem.text = req_b64

            ET.SubElement(item, "comment").text = (
                f"BugFlow Elite v6 — Source: {ep.get('source', 'discovery')}"
            )
            ET.SubElement(item, "highlight").text = ""

        path = self.output_dir / f"{domain.replace('.', '_')}_burp.xml"
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(str(path), encoding="utf-8", xml_declaration=True)
        return path

    def _export_json_sitemap(
        self, domain: str, endpoints: list, findings: list
    ) -> Path:
        """
        Generate JSON sitemap with attack chain suggestions.
        Used with Burp Suite's REST API or manual import.
        """
        sitemap = {
            "domain": domain,
            "exported_at": datetime.utcnow().isoformat(),
            "generator": "BugFlow Elite v6",
            "endpoints": [],
            "findings": [],
            "attack_suggestions": [],
        }

        for ep in endpoints:
            sitemap["endpoints"].append({
                "url": ep.get("url", ""),
                "method": ep.get("method", "GET"),
                "params": ep.get("params", []),
                "status": ep.get("status_code"),
                "source": ep.get("source", ""),
                "is_interesting": ep.get("is_interesting", False),
            })

        for f in findings:
            sitemap["findings"].append({
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "vuln_type": f.get("vuln_type", ""),
                "target": f.get("target", ""),
                "ai_score": f.get("ai_score", 0),
                "reproduction_steps": f.get("reproduction_steps", ""),
                "suggested_burp_tests": self._suggest_burp_tests(f),
            })

        # Generate attack chain suggestions
        sitemap["attack_suggestions"] = self._generate_attack_suggestions(
            findings, endpoints
        )

        path = self.output_dir / f"{domain.replace('.', '_')}_sitemap.json"
        path.write_text(json.dumps(sitemap, indent=2))
        return path

    def _export_url_list(
        self, domain: str, endpoints: list, assets: list
    ) -> Path:
        """Plain URL list for Burp Suite target scope import."""
        urls = set()

        for ep in endpoints:
            url = ep.get("url", "")
            if url:
                urls.add(url)

        for asset in assets:
            sub = asset.get("subdomain", "")
            if sub:
                urls.add(f"https://{sub}/")
                urls.add(f"http://{sub}/")

        path = self.output_dir / f"{domain.replace('.', '_')}_urls.txt"
        path.write_text("\n".join(sorted(urls)))
        return path

    def _export_attack_chains(
        self, domain: str, findings: list
    ) -> Path:
        """Export AI-suggested attack chains for manual testing in Burp."""
        chains = {
            "domain": domain,
            "exported_at": datetime.utcnow().isoformat(),
            "manual_testing_guide": [],
        }

        for f in findings:
            vuln_type = f.get("vuln_type", "")
            target = f.get("target", "")
            title = f.get("title", "")

            guide = {
                "finding": title,
                "target": target,
                "severity": f.get("severity", ""),
                "burp_extensions_recommended": self._get_burp_extensions(vuln_type),
                "manual_steps": self._get_manual_steps(vuln_type, target),
                "chain_with": self._get_chain_opportunities(vuln_type, findings),
            }
            chains["manual_testing_guide"].append(guide)

        path = self.output_dir / f"{domain.replace('.', '_')}_chains.json"
        path.write_text(json.dumps(chains, indent=2))
        return path

    def _suggest_burp_tests(self, finding: dict) -> list:
        """Suggest specific Burp Suite tests for a finding."""
        vuln_type = finding.get("vuln_type", "")
        suggestions = {
            "xss": [
                "Use Burp Intruder with XSS payload list",
                "Enable DOM Invader in Burp browser",
                "Check Reflected + Stored variants",
                "Test in all parameters with Burp Scanner active",
            ],
            "sqli": [
                "Send to Burp Intruder, use SQL injection payloads",
                "Right-click → Scan → Active scan this insertion point",
                "Use SQLmap extension in Burp",
                "Check time-based blind SQLi with delay payloads",
            ],
            "ssrf": [
                "Use Burp Collaborator for SSRF callback",
                "Test all URL parameters with Collaborator payload",
                "Try protocol smuggling: dict://, gopher://",
                "Check for blind SSRF via DNS lookup in Collaborator",
            ],
            "idor": [
                "Use Burp Autorize extension",
                "Create two accounts, swap IDs in Repeater",
                "Check all numeric IDs, UUIDs, and hash values",
                "Test horizontal + vertical privilege escalation",
            ],
            "takeover": [
                "Confirm CNAME in Burp DNS resolver",
                "Test claiming the endpoint via its provider",
                "Document full request/response chain in Repeater",
            ],
        }
        return suggestions.get(
            vuln_type,
            ["Send to Burp Repeater and manually verify finding"]
        )

    def _get_burp_extensions(self, vuln_type: str) -> list:
        """Get recommended Burp extensions for each vuln type."""
        extensions = {
            "xss": ["DOM Invader", "XSS Validator", "Reflected Parameters"],
            "sqli": ["SQLiPy", "Active Scan++", "Backslash Powered Scanner"],
            "ssrf": ["Collaborator Everywhere", "SSRF Finder"],
            "idor": ["Autorize", "Authz", "Paramalyzer"],
            "cors": ["CORS*", "Param Miner"],
            "ssti": ["Backslash Powered Scanner", "Active Scan++"],
        }
        return extensions.get(vuln_type, ["Active Scan++", "Param Miner"])

    def _get_manual_steps(self, vuln_type: str, target: str) -> list:
        """Get manual testing steps in Burp for each vuln type."""
        return [
            f"1. Open {target} in Burp Browser",
            f"2. Intercept request in Proxy",
            f"3. Send to Repeater (Ctrl+R)",
            f"4. Apply {vuln_type.upper()} test payloads",
            f"5. Document evidence in Burp Notes",
            f"6. Export request/response for H1 report",
        ]

    def _get_chain_opportunities(
        self, vuln_type: str, all_findings: list
    ) -> list:
        """Identify findings that could be chained with this one."""
        chain_map = {
            "ssrf": ["cloud_misconfiguration", "secret", "idor"],
            "xss": ["csrf", "cors", "open_redirect"],
            "idor": ["sqli", "secret"],
            "takeover": ["xss", "phishing"],
        }
        target_types = chain_map.get(vuln_type, [])
        chains = []
        for f in all_findings:
            if f.get("vuln_type") in target_types:
                chains.append(
                    f"{f.get('vuln_type')} at {f.get('target', '')[:60]}"
                )
        return chains[:3]

    def _generate_attack_suggestions(
        self, findings: list, endpoints: list
    ) -> list:
        """Generate top-level attack chain suggestions."""
        suggestions = []
        vuln_types = {f.get("vuln_type") for f in findings}

        if "ssrf" in vuln_types and "cloud_misconfiguration" in vuln_types:
            suggestions.append({
                "chain": "SSRF → Cloud Metadata",
                "priority": "CRITICAL",
                "steps": [
                    "Use SSRF to reach 169.254.169.254",
                    "Retrieve IAM credentials from metadata",
                    "Use credentials to access cloud resources",
                ],
            })
        if "xss" in vuln_types and "csrf" in vuln_types:
            suggestions.append({
                "chain": "XSS → CSRF → Account Takeover",
                "priority": "HIGH",
                "steps": [
                    "Use XSS to bypass SameSite cookies",
                    "Chain with CSRF to perform state-changing actions",
                    "Demonstrate account takeover in PoC",
                ],
            })
        if "takeover" in vuln_types:
            suggestions.append({
                "chain": "Subdomain Takeover → Credential Harvest",
                "priority": "HIGH",
                "steps": [
                    "Claim the subdomain via its provider",
                    "Host a convincing phishing page",
                    "Show how users could be tricked",
                ],
            })
        return suggestions

    def _load_endpoints(self, domain: str) -> list:
        conn = get_conn(self.db_path)
        try:
            rows = conn.execute(
                "SELECT url, method, status_code, source, params, "
                "is_interesting, last_seen "
                "FROM endpoints WHERE url LIKE ? LIMIT 2000",
                (f"%{domain}%",)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
        finally:
            conn.close()

    def _load_findings(self, domain: str) -> list:
        conn = get_conn(self.db_path)
        try:
            rows = conn.execute(
                "SELECT title, severity, vuln_type, description, "
                "reproduction_steps, proof_of_concept, ai_score "
                "FROM findings WHERE program=? AND is_duplicate=0 "
                "ORDER BY ai_score DESC LIMIT 100",
                (domain,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
        finally:
            conn.close()

    def _load_assets(self, domain: str) -> list:
        conn = get_conn(self.db_path)
        try:
            rows = conn.execute(
                "SELECT subdomain, ip, status_code, tech_stack "
                "FROM assets WHERE domain=? AND is_alive=1 LIMIT 1000",
                (domain,)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
        finally:
            conn.close()
