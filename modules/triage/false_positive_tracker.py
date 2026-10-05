"""
BugFlow Elite v6 — False Positive Tracker
Learns from researcher feedback (Telegram reject buttons, manual marks).
Builds a program-specific false positive pattern library.
Feeds back into AI triage to prevent same mistakes.
Tinlance Limited | LloydCoder
"""

import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from db.models import get_conn

logger = logging.getLogger(__name__)


class FalsePositiveTracker:
    """
    Tracks false positives per program and vuln type.
    When you reject a finding via Telegram, the pattern is
    learned and future similar findings are auto-downgraded.
    """

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get("general", {}).get("db_path", "./db/bugflow.db")
        self.patterns_file = Path("./output/fp_patterns.json")
        self.patterns_file.parent.mkdir(parents=True, exist_ok=True)
        self._patterns = self._load_patterns()

    def record_rejection(
        self,
        finding_id: int,
        reason: str = "researcher_rejected"
    ):
        """
        Record a finding as false positive.
        Called when researcher hits Reject button in Telegram.
        """
        conn = get_conn(self.db_path)
        try:
            # Mark in DB
            conn.execute("""
                UPDATE findings
                SET is_duplicate = 1,
                    ai_score = 1.0,
                    h1_status = 'rejected'
                WHERE id = ?
            """, (finding_id,))
            conn.commit()

            # Get finding details for pattern learning
            row = conn.execute(
                "SELECT vuln_type, program, title, description, template_id "
                "FROM findings WHERE id = ?",
                (finding_id,)
            ).fetchone()

            if row:
                self._learn_pattern(dict(row), reason)
                logger.info(
                    f"[FPTracker] Recorded rejection: "
                    f"{row['vuln_type']} on {row['program']}"
                )
        except Exception as e:
            logger.error(f"[FPTracker] Record error: {e}")
        finally:
            conn.close()

    def _learn_pattern(self, finding: dict, reason: str):
        """Extract and store the FP pattern from a rejected finding."""
        program = finding.get("program", "unknown")
        vuln_type = finding.get("vuln_type", "unknown")
        template_id = finding.get("template_id", "")
        title = finding.get("title", "")

        # Build pattern key
        key = f"{program}:{vuln_type}"
        if key not in self._patterns:
            self._patterns[key] = {
                "program": program,
                "vuln_type": vuln_type,
                "rejection_count": 0,
                "template_ids": [],
                "title_keywords": [],
                "last_updated": "",
            }

        pattern = self._patterns[key]
        pattern["rejection_count"] += 1
        pattern["last_updated"] = datetime.utcnow().isoformat()

        # Track template IDs that produce FPs
        if template_id and template_id not in pattern["template_ids"]:
            pattern["template_ids"].append(template_id)

        # Extract keywords from title
        words = [w.lower() for w in title.split() if len(w) > 4]
        for word in words:
            if word not in pattern["title_keywords"]:
                pattern["title_keywords"].append(word)

        self._save_patterns()

    def is_likely_false_positive(self, finding: dict) -> tuple[bool, float]:
        """
        Check if a finding matches known FP patterns.
        Returns (is_fp, confidence).
        """
        program = finding.get("program", "")
        vuln_type = finding.get("vuln_type", "")
        template_id = finding.get("template_id", "")
        title = finding.get("title", "").lower()

        key = f"{program}:{vuln_type}"
        pattern = self._patterns.get(key)

        if not pattern:
            return False, 0.0

        rejection_count = pattern.get("rejection_count", 0)

        # If we've rejected this template ID before — high confidence FP
        if template_id and template_id in pattern.get("template_ids", []):
            confidence = min(0.9, 0.5 + (rejection_count * 0.1))
            return True, confidence

        # Check title keyword overlap
        keywords = pattern.get("title_keywords", [])
        if keywords:
            overlap = sum(1 for kw in keywords if kw in title)
            if overlap >= 3:
                confidence = min(0.8, overlap * 0.15)
                return True, confidence

        # High rejection count for this vuln type on this program
        if rejection_count >= 5:
            return True, 0.6

        return False, 0.0

    def adjust_score(self, finding: dict) -> dict:
        """
        Adjust AI score down if finding matches FP patterns.
        Returns modified finding.
        """
        is_fp, confidence = self.is_likely_false_positive(finding)
        if is_fp and confidence >= 0.5:
            original_score = float(finding.get("ai_score", 5.0))
            penalty = confidence * 3.0
            finding["ai_score"] = max(1.0, original_score - penalty)
            finding["fp_warning"] = True
            finding["fp_confidence"] = confidence
            logger.info(
                f"[FPTracker] Score adjusted: {original_score:.1f} → "
                f"{finding['ai_score']:.1f} "
                f"(FP confidence: {confidence:.2f})"
            )
        return finding

    def get_stats(self) -> dict:
        """Return FP tracking statistics."""
        total_patterns = len(self._patterns)
        total_rejections = sum(
            p.get("rejection_count", 0)
            for p in self._patterns.values()
        )
        top_fp_programs = sorted(
            self._patterns.values(),
            key=lambda p: p.get("rejection_count", 0),
            reverse=True
        )[:5]

        return {
            "total_patterns": total_patterns,
            "total_rejections": total_rejections,
            "top_fp_patterns": [
                {
                    "program": p["program"],
                    "vuln_type": p["vuln_type"],
                    "rejections": p["rejection_count"],
                }
                for p in top_fp_programs
            ],
        }

    def _load_patterns(self) -> dict:
        if not self.patterns_file.exists():
            return {}
        try:
            return json.loads(self.patterns_file.read_text())
        except Exception:
            return {}

    def _save_patterns(self):
        try:
            self.patterns_file.write_text(
                json.dumps(self._patterns, indent=2)
            )
        except Exception as e:
            logger.error(f"[FPTracker] Save error: {e}")
