"""Command-line interface entry point for the Dynamic Analysis platform."""

import argparse
import sys
from typing import Optional, Sequence

from dynamic_analysis.config import AndroidRuntimeConfig, AppConfig
from dynamic_analysis.job import AnalysisJob
from dynamic_analysis.runner import AnalysisRunResult, AnalysisRunner
from dynamic_analysis.runtime import AndroidRuntimeOrchestrator


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Automated Android APK Dynamic Analysis Platform"
    )
    parser.add_argument(
        "--apk",
        "-a",
        type=str,
        default=None,
        help="Path to the target Android APK file to analyze",
    )
    parser.add_argument(
        "--avd",
        type=str,
        default="analysis_baseline_api33",
        help="Target AVD name (default: analysis_baseline_api33)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default=None,
        help="Directory path to save captured evidence JSON artifacts",
    )
    parser.add_argument(
        "--no-launch",
        action="store_true",
        help="Disable automatic application launch after installation",
    )
    parser.add_argument(
        "--boot-timeout",
        type=float,
        default=90.0,
        help="Maximum seconds to wait for guest boot completion (default: 90.0)",
    )
    return parser


def main(args: Optional[Sequence[str]] = None) -> int:
    """Execute dynamic analysis workflow from command-line arguments."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    env_config = AppConfig.from_env()
    apk_path = parsed_args.apk or env_config.target_apk or ""

    runtime_config = AndroidRuntimeConfig(
        avd_name=parsed_args.avd or env_config.runtime.avd_name,
        sdk_root=env_config.runtime.sdk_root,
        adb_binary=env_config.runtime.adb_binary,
    )

    orchestrator = AndroidRuntimeOrchestrator(runtime_config)
    runner = AnalysisRunner(orchestrator=orchestrator)
    job = AnalysisJob(apk_path=apk_path)

    result = runner.run(
        job=job,
        apk_path=apk_path if apk_path else None,
        output_dir=parsed_args.output_dir,
        launch_app=not parsed_args.no_launch,
        boot_timeout=parsed_args.boot_timeout,
    )

    if result.success:
        print(f"Analysis completed successfully (Job State: {job.state.name})")
        print(f"Evidence captured: {len(result.evidence_items)} items")
        if result.evidence_file_path:
            print(f"Evidence file saved: {result.evidence_file_path}")
        return 0
    else:
        print(f"Analysis failed (Job State: {job.state.name}): {result.error_message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
