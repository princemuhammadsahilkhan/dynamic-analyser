"""Unit tests for the command-line interface entry point."""

import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.cli import build_parser, main
from dynamic_analysis.job import AnalysisJob, JobState
from dynamic_analysis.runner import AnalysisRunResult


class TestCLI(unittest.TestCase):
    """Unit test suite for CLI argument parsing and main entry point execution."""

    def test_build_parser_defaults(self) -> None:
        """Verify default CLI arguments parsed correctly."""
        parser = build_parser()
        args = parser.parse_args([])
        self.assertIsNone(args.apk)
        self.assertEqual(args.avd, "analysis_baseline_api33")
        self.assertIsNone(args.output_dir)
        self.assertFalse(args.no_launch)
        self.assertEqual(args.boot_timeout, 90.0)

    def test_build_parser_custom_args(self) -> None:
        """Verify custom CLI arguments parsed correctly."""
        parser = build_parser()
        args = parser.parse_args([
            "--apk", "/path/to/target.apk",
            "--avd", "custom_avd",
            "--output-dir", "/tmp/evidence_out",
            "--no-launch",
            "--boot-timeout", "120.0",
        ])
        self.assertEqual(args.apk, "/path/to/target.apk")
        self.assertEqual(args.avd, "custom_avd")
        self.assertEqual(args.output_dir, "/tmp/evidence_out")
        self.assertTrue(args.no_launch)
        self.assertEqual(args.boot_timeout, 120.0)

    @patch("dynamic_analysis.cli.AnalysisRunner")
    def test_main_successful_execution(self, mock_runner_cls) -> None:
        """Verify main returns exit code 0 on successful workflow execution."""
        mock_runner = MagicMock()
        mock_job = AnalysisJob(apk_path="")
        mock_job.state = JobState.COMPLETED
        mock_result = AnalysisRunResult(
            job=mock_job,
            success=True,
            evidence_items=[],
            evidence_file_path="/tmp/out/evidence.json",
        )
        mock_runner.run.return_value = mock_result
        mock_runner_cls.return_value = mock_runner

        exit_code = main(["--output-dir", "/tmp/out"])
        self.assertEqual(exit_code, 0)
        mock_runner.run.assert_called_once()

    @patch("dynamic_analysis.cli.AnalysisRunner")
    def test_main_failure_execution(self, mock_runner_cls) -> None:
        """Verify main returns exit code 1 on failed workflow execution."""
        mock_runner = MagicMock()
        mock_job = AnalysisJob(apk_path="")
        mock_job.state = JobState.FAILED
        mock_result = AnalysisRunResult(
            job=mock_job,
            success=False,
            error_message="Emulator failed to launch",
        )
        mock_runner.run.return_value = mock_result
        mock_runner_cls.return_value = mock_runner

        exit_code = main([])
        self.assertEqual(exit_code, 1)
        mock_runner.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
