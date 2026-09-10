from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/gemini-pr-review.yml"


class GeminiReviewWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_block_findings_are_bounded_and_nonempty(self) -> None:
        self.assertIn('(.findings | type == "array" and length <= 20)', self.workflow)
        self.assertIn('((.verdict == "PASS") or (.findings | length >= 1))', self.workflow)

    def test_validated_exact_sha_response_is_logged_before_block_exit(self) -> None:
        identity_guard = 'if [[ "${head_sha}" != "${EXPECTED_HEAD_SHA}" || "${base_sha}" != "${EXPECTED_BASE_SHA}" ]]'
        compact_log = "validated_response=\"$(jq -c '{verdict,head_sha,base_sha,findings}' <<<\"${response}\")\""
        log_line = "printf 'Gemini validated exact-SHA review: %s\\n' \"${validated_response}\""
        block_exit = 'if [[ "${verdict}" != "PASS" ]]; then'

        guard_pos = self.workflow.index(identity_guard)
        compact_pos = self.workflow.index(compact_log)
        log_pos = self.workflow.index(log_line)
        block_pos = self.workflow.index(block_exit)

        self.assertLess(guard_pos, compact_pos)
        self.assertLess(compact_pos, log_pos)
        self.assertLess(log_pos, block_pos)

    def test_raw_provider_wrapper_is_not_dumped(self) -> None:
        self.assertNotIn('cat "${stdout_file}"', self.workflow)
        self.assertNotIn('cat ${stdout_file}', self.workflow)


if __name__ == "__main__":
    unittest.main()
