"""Unit tests for the analysis job domain model."""

import unittest
from dynamic_analysis.job import AnalysisJob, JobState


class TestAnalysisJob(unittest.TestCase):
    """Test suite for AnalysisJob domain model behavior."""

    def test_job_initialization_defaults_to_submitted(self):
        """Verify AnalysisJob initializes with SUBMITTED state."""
        job = AnalysisJob(apk_path="/path/to/sample.apk")
        self.assertEqual(job.apk_path, "/path/to/sample.apk")
        self.assertEqual(job.state, JobState.SUBMITTED)

    def test_job_state_transition(self):
        """Verify job state can transition through supported lifecycle states."""
        job = AnalysisJob(apk_path="/path/to/sample.apk")
        job.transition_to(JobState.EXECUTING)
        self.assertEqual(job.state, JobState.EXECUTING)

        job.transition_to(JobState.COLLECTING_EVIDENCE)
        self.assertEqual(job.state, JobState.COLLECTING_EVIDENCE)

        job.transition_to(JobState.REPORTING)
        self.assertEqual(job.state, JobState.REPORTING)

        job.transition_to(JobState.COMPLETED)
        self.assertEqual(job.state, JobState.COMPLETED)

    def test_job_failure_state_transition(self):
        """Verify job state can transition to FAILED state."""
        job = AnalysisJob(apk_path="/path/to/sample.apk")
        job.transition_to(JobState.FAILED)
        self.assertEqual(job.state, JobState.FAILED)


if __name__ == "__main__":
    unittest.main()
