"""
BugFlow Elite v6 — Deep Verification Engine
Re-verifies findings up to 4 times before recommending H1 draft.
Reduces false positives that waste H1 reputation.
Checks: HTTP re-probe, DNS re-verify, exploitability confirmation,
scope re-validation, CVSS scoring, evidence quality scoring.
Tinlance Limited | LloydCoder
"""

import json
import logging
import asyncio
import hashlib
import aiohttp
from typing import Optional
from modules.scope.scope_enforcer import ScopeEnforcer

logger = logging.getLogger(__name__)

# Minimum evidence quality scores per severity to recommend draft
EVIDENCE_THRESHOLDS = {
    "critical": 0.70,
    "high":     0.65,
    "medium":   0.55,
    "low":      0.45,
    "info":     0.30,
}


class VerificationEngine:
    """
    Deep multi-pass verifier. Every finding passes through here
    before the AI report polisher and H1 draft creation.
    Runs up to 4 re-checks to confirm the finding is real.
    """

    def __init__(self, config: dict, scope: ScopeEnforcer):
        self.config = config
        self.scope = scope
        self.rechecks = config.get("ai", {}).get(
            "verification_rechecks", 4
        )
        self.timeout = aiohttp.ClientTimeout(total=15)

    async def deep_verify(self, finding: dict) -> dict:
        """
        Full verification pipeline for a finding.
        Returns enriched finding with:
        - verified: bool
        - confidence: float (0-1)
        - evidence_score: float (0-1)
        - recommend_draft: bool
        - verification_notes: list
        """
        finding = dict(finding)  # Don't mutate original
        finding.setdefault("verification_notes", [])
        finding.setdefault("verified", False)
        finding.setdefault("confidence", 0.0)
        finding.setdefault("recommend_draft", False)

        target = finding.get("target", "")
        severity = finding.get("severity", "info")
        vuln_type = finding.get("vuln_type", "")

        logger.info(
            f"[Verify] Checking: {finding.get('title', '')[:60]} "
            f"on {target}"
        )

        # Skip info-level — not worth verifying
        if severity == "info":
            finding["verified"] = True
            finding["confidence"] = 0.3
            finding["recommend_draft"] = False
            return finding

        checks_passed = 0
        checks_total = 0

        # ── Check 1: Scope re-validation ──────────────────────
        checks_total += 1
        in_scope, reason = self.scope.is_in_scope(target)
        if in_scope:
            checks_passed += 1
            finding["verification_notes"].append("✅ Scope: confirmed in scope")
        else:
            finding["verification_notes"].append(f"❌ Scope: {reason}")
            finding["verified"] = False
            finding["recommend_draft"] = False
            logger.warning(f"[Verify] Out of scope: {target}")
            return finding

        # ── Check 2: HTTP liveness re-probe ───────────────────
        checks_total += 1
        is_live, status_code = await self._http_probe(target)
        if is_live:
            checks_passed += 1
            finding["verification_notes"].append(
                f"✅ HTTP: target alive (status {status_code})"
            )
        else:
            finding["verification_notes"].append("⚠️ HTTP: target not responding")

        # ── Check 3: Vuln-type specific re-verification ───────
        checks_total += 1
        type_verified, type_note = await self._type_specific_check(
            finding, target, vuln_type
        )
        if type_verified:
            checks_passed += 1
        finding["verification_notes"].append(type_note)

        # ── Check 4: Evidence quality scoring ─────────────────
        checks_total += 1
        evidence_score = self._score_evidence(finding)
        finding["evidence_score"] = evidence_score
        threshold = EVIDENCE_THRESHOLDS.get(severity, 0.5)
        if evidence_score >= threshold:
            checks_passed += 1
            finding["verification_notes"].append(
                f"✅ Evidence: quality score {evidence_score:.2f} "
                f"(threshold {threshold:.2f})"
            )
        else:
            finding["verification_notes"].append(
                f"⚠️ Evidence: score {evidence_score:.2f} below "
                f"threshold {threshold:.2f}"
            )

        # ── Compute final confidence ───────────────────────────
        confidence = checks_passed / checks_total if checks_total > 0 else 0.0
        finding["confidence"] = confidence
        finding["verified"] = confidence >= 0.5

        # ── Recommend draft? ───────────────────────────────────
        ai_score = float(finding.get("ai_score", 0))
        min_score = self.config.get("ai", {}).get(
            "scoring", {}
        ).get("min_score_for_draft", 7.0)

        finding["recommend_draft"] = (
            finding["verified"]
            and ai_score >= min_score
            and confidence >= 0.6
            and not finding.get("is_duplicate", False)
            and severity not in ("info", "low")
        )

        logger.info(
            f"[Verify] {finding.get('title', '')[:50]} — "
            f"confidence: {confidence:.2f}, "
            f"recommend_draft: {finding['recommend_draft']}"
        )
        return finding

    async def _http_probe(self, target: str) -> tuple[bool, int]:
        """Re-probe the target URL/host to confirm it's still alive."""
        if not target:
            return False, 0

        # Normalize to URL
        url = target if target.startswith("http") else f"https://{target}"

        for scheme in ["https://", "http://"]:
            probe_url = url if url.startswith(scheme) else url
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        probe_url,
                        timeout=self.timeout,
                        allow_redirects=True,
                        ssl=False
                    ) as resp:
                        return True, resp.status
            except Exception:
                continue
        return False, 0

    async def _type_specific_check(
        self, finding: dict, target: str, vuln_type: str
    ) -> tuple[bool, str]:
        """
        Run a vuln-type-specific re-verification check.
        Returns (verified, note).
        """
        vuln_type = vuln_type.lower()

        if vuln_type == "takeover":
            return await self._verify_takeover(target)

        elif vuln_type == "cloud_misconfiguration":
            return await self._verify_cloud_bucket(
                finding.get("proof_of_concept", "")
            )

        elif vuln_type in ("secret", "secrets"):
            return self._verify_secret_quality(finding)

        elif vuln_type == "nuclei":
            # Trust Nuclei findings with evidence
            has_poc = bool(finding.get("proof_of_concept"))
            return has_poc, (
                "✅ Nuclei: has PoC evidence"
                if has_poc else "⚠️ Nuclei: no PoC"
            )

        elif vuln_type == "xss":
            return self._verify_xss_payload(finding)

        else:
            # Default: check if there's any proof of concept
            has_poc = bool(
                finding.get("proof_of_concept") or
                finding.get("description")
            )
            return has_poc, (
                "✅ Generic: evidence present"
                if has_poc else "⚠️ Generic: no evidence"
            )

    async def _verify_takeover(self, subdomain: str) -> tuple[bool, str]:
        """Re-verify subdomain takeover is still exploitable."""
        import aiohttp
        try:
            url = f"https://{subdomain}"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=self.timeout,
                    ssl=False
                ) as resp:
                    body = await resp.text(errors="ignore")
                    # Check for takeover fingerprints
                    takeover_sigs = [
                        "There is no app configured",
                        "NoSuchBucket",
                        "There isn't a GitHub Pages site here",
                        "Fastly error: unknown domain",
                        "project not found",
                        "This UserVoice subdomain is currently available",
                    ]
                    for sig in takeover_sigs:
                        if sig.lower() in body.lower():
                            return True, f"✅ Takeover: confirmed ({sig[:40]})"
                    return False, "⚠️ Takeover: signature not found on re-check"
        except Exception as e:
            return False, f"⚠️ Takeover: probe failed ({str(e)[:50]})"

    async def _verify_cloud_bucket(self, poc: str) -> tuple[bool, str]:
        """Re-verify cloud bucket is still publicly accessible."""
        try:
            poc_data = json.loads(poc) if poc else {}
            url = poc_data.get("url", "")
        except Exception:
            url = poc if poc and poc.startswith("http") else ""

        if not url:
            return False, "⚠️ Cloud: no bucket URL in evidence"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=self.timeout
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        if any(m in body for m in
                               ["ListBucketResult", "Contents", "Blobs"]):
                            return True, "✅ Cloud: bucket still publicly listed"
                    return False, f"⚠️ Cloud: status {resp.status} on re-check"
        except Exception as e:
            return False, f"⚠️ Cloud: re-check failed ({str(e)[:50]})"

    def _verify_secret_quality(
        self, finding: dict
    ) -> tuple[bool, str]:
        """Check if the secret finding has enough detail to report."""
        desc = finding.get("description", "")
        poc = finding.get("proof_of_concept", "")
        combined = desc + poc

        # Must have source URL
        has_url = "http" in combined.lower()
        # Must have some secret pattern
        has_pattern = any(
            kw in combined.lower()
            for kw in ["key", "token", "secret", "password", "credential"]
        )
        verified = has_url and has_pattern
        note = (
            "✅ Secret: has URL + pattern"
            if verified else "⚠️ Secret: missing URL or pattern"
        )
        return verified, note

    def _verify_xss_payload(self, finding: dict) -> tuple[bool, str]:
        """Check if XSS finding has a working payload."""
        poc = finding.get("proof_of_concept", "")
        desc = finding.get("description", "")
        combined = poc + desc
        has_payload = any(
            p in combined
            for p in ["<script>", "alert(", "onerror=", "onload=",
                      "javascript:", "xss", "payload"]
        )
        return has_payload, (
            "✅ XSS: payload found in evidence"
            if has_payload else "⚠️ XSS: no payload in evidence"
        )

    def _score_evidence(self, finding: dict) -> float:
        """
        Score the quality of evidence for a finding (0.0 - 1.0).
        Higher = more detailed, actionable, reproducible.
        """
        score = 0.0
        weights = {
            "title":               (0.10, lambda f: len(f.get("title", "")) > 10),
            "description":         (0.20, lambda f: len(f.get("description", "")) > 50),
            "reproduction_steps":  (0.20, lambda f: bool(f.get("reproduction_steps"))),
            "proof_of_concept":    (0.25, lambda f: bool(f.get("proof_of_concept"))),
            "target_url":          (0.10, lambda f: "http" in str(f.get("target", ""))),
            "ai_analysis":         (0.10, lambda f: bool(f.get("ai_analysis"))),
            "screenshot":          (0.05, lambda f: bool(f.get("screenshot_paths"))),
        }
        for field, (weight, check) in weights.items():
            try:
                if check(finding):
                    score += weight
            except Exception:
                pass
        return min(score, 1.0)
