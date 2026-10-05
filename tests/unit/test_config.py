"""Unit tests for the configuration boundary module."""

import unittest
from dynamic_analysis.config import AppConfig


class TestAppConfig(unittest.TestCase):
    """Test suite for AppConfig boundary behavior."""

    def test_app_config_instantiation(self):
        """Verify AppConfig can be instantiated with default minimal schema."""
        config = AppConfig()
        self.assertIsInstance(config, AppConfig)

    def test_app_config_from_env_default(self):
        """Verify AppConfig.from_env loads using default environment."""
        config = AppConfig.from_env()
        self.assertIsInstance(config, AppConfig)

    def test_app_config_from_env_custom_mapping(self):
        """Verify AppConfig.from_env accepts a custom environment mapping."""
        custom_env = {"TARGET_APK": "/path/to/target.apk"}
        config = AppConfig.from_env(env=custom_env)
        self.assertIsInstance(config, AppConfig)
        self.assertEqual(config.target_apk, "/path/to/target.apk")


if __name__ == "__main__":
    unittest.main()
