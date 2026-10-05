"""Android runtime orchestration interface for managing emulator child processes."""

import os
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from dynamic_analysis.config import AndroidRuntimeConfig


class AndroidRuntimeError(Exception):
    """Base exception for Android runtime orchestration errors."""

    pass


class EmulatorStartError(AndroidRuntimeError):
    """Raised when the emulator child process fails to launch or exits unexpectedly."""

    pass


class ADBError(AndroidRuntimeError):
    """Raised when ADB communication or device discovery fails."""

    pass


class BootTimeoutError(AndroidRuntimeError):
    """Raised when guest OS boot completion times out."""

    pass


class ShellCommandError(AndroidRuntimeError):
    """Raised when an ADB shell command fails or times out."""

    pass


class ShutdownError(AndroidRuntimeError):
    """Raised when clean emulator process shutdown fails."""

    pass


@dataclass(frozen=True)
class ShellResult:
    """Encapsulates execution output from an ADB shell command."""

    exit_code: int
    stdout: str
    stderr: str


class AndroidRuntimeOrchestrator:
    """Automated orchestrator for launching and controlling an Android emulator child process."""

    def __init__(self, config: Optional[AndroidRuntimeConfig] = None) -> None:
        self.config: AndroidRuntimeConfig = config or AndroidRuntimeConfig()
        self._process: Optional[subprocess.Popen] = None

    def is_running(self) -> bool:
        """Return True if the tracked emulator child process is actively running."""
        return self._process is not None and self._process.poll() is None

    def start(self) -> None:
        """Start the configured AVD as a tracked child process."""
        if self.is_running():
            raise EmulatorStartError("Emulator process is already running")

        emulator_bin = self.config.resolved_emulator_binary
        if not os.path.exists(emulator_bin):
            raise EmulatorStartError(f"Emulator binary not found at: {emulator_bin}")

        cmd = [
            emulator_bin,
            "-avd",
            self.config.avd_name,
            "-port",
            str(self.config.port),
        ]

        if self.config.headless:
            cmd.append("-no-window")
        if self.config.no_audio:
            cmd.append("-no-audio")
        if self.config.read_only:
            cmd.append("-read-only")
        if self.config.no_snapshot_save:
            cmd.append("-no-snapshot-save")
        if self.config.no_snapshot_load:
            cmd.append("-no-snapshot-load")
        if self.config.wipe_data:
            cmd.append("-wipe-data")

        if self.config.extra_flags:
            cmd.extend(self.config.extra_flags)

        env = {
            **os.environ,
            "ANDROID_SDK_ROOT": self.config.sdk_root,
            "ANDROID_HOME": self.config.sdk_root,
        }

        try:
            self._process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as exc:
            raise EmulatorStartError(f"Failed to spawn emulator process: {exc}") from exc

        time.sleep(0.5)
        exit_code = self._process.poll()
        if exit_code is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            self._process = None
            raise EmulatorStartError(
                f"Emulator process exited immediately with code {exit_code}: {stderr.strip()}"
            )

    def wait_for_adb(self, timeout: Optional[float] = None) -> bool:
        """Wait for the target ADB device serial to become reachable and reported as 'device'."""
        max_time = timeout if timeout is not None else self.config.adb_timeout
        start_time = time.time()
        serial = self.config.serial
        adb_bin = self.config.adb_binary

        while time.time() - start_time < max_time:
            if not self.is_running():
                stderr = self._process.stderr.read() if (self._process and self._process.stderr) else ""
                raise EmulatorStartError(f"Emulator process terminated unexpectedly while waiting for ADB: {stderr.strip()}")

            try:
                res = subprocess.run(
                    [adb_bin, "-s", serial, "get-state"],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )
                if res.returncode == 0 and res.stdout.strip() == "device":
                    return True
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

            time.sleep(1.0)

        raise ADBError(
            f"ADB device '{serial}' remained unavailable/offline after {max_time}s"
        )

    def wait_for_boot(self, timeout: Optional[float] = None) -> bool:
        """Wait for guest OS sys.boot_completed property to equal '1'."""
        self.wait_for_adb(timeout=timeout)

        max_time = timeout if timeout is not None else self.config.boot_timeout
        start_time = time.time()
        serial = self.config.serial
        adb_bin = self.config.adb_binary

        while time.time() - start_time < max_time:
            if not self.is_running():
                stderr = self._process.stderr.read() if (self._process and self._process.stderr) else ""
                raise EmulatorStartError(f"Emulator process terminated unexpectedly while waiting for boot: {stderr.strip()}")

            try:
                res = subprocess.run(
                    [adb_bin, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                )
                if res.returncode == 0 and res.stdout.strip() == "1":
                    return True
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

            time.sleep(1.0)

        raise BootTimeoutError(
            f"Guest OS boot completion timed out after {max_time}s on '{serial}'"
        )

    def shell(self, command: str, timeout: Optional[float] = None) -> ShellResult:
        """Execute a shell command against the running target emulator via ADB."""
        if not self.is_running():
            raise AndroidRuntimeError("Emulator process is not running")

        serial = self.config.serial
        adb_bin = self.config.adb_binary
        max_time = timeout if timeout is not None else self.config.command_timeout

        try:
            res = subprocess.run(
                [adb_bin, "-s", serial, "shell", command],
                capture_output=True,
                text=True,
                timeout=max_time,
            )
            return ShellResult(
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            raise ShellCommandError(
                f"Command '{command}' timed out after {max_time}s on '{serial}'"
            ) from exc
        except FileNotFoundError as exc:
            raise ADBError(f"ADB binary not found at: {adb_bin}") from exc
        except Exception as exc:
            raise ShellCommandError(
                f"Failed to execute command '{command}' on '{serial}': {exc}"
            ) from exc

    def install_apk(
        self,
        apk_path: str,
        options: Tuple[str, ...] = ("-r", "-g"),
        timeout: Optional[float] = 60.0,
    ) -> ShellResult:
        """Install an APK file onto the target emulator via ADB install."""
        if not self.is_running():
            raise AndroidRuntimeError("Emulator process is not running")

        serial = self.config.serial
        adb_bin = self.config.adb_binary
        cmd = [adb_bin, "-s", serial, "install"] + list(options) + [apk_path]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return ShellResult(
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            raise ShellCommandError(
                f"ADB install timed out after {timeout}s on '{serial}'"
            ) from exc
        except FileNotFoundError as exc:
            raise ADBError(f"ADB binary not found at: {adb_bin}") from exc

    def shutdown(self, timeout: Optional[float] = None) -> None:
        """Perform a clean shutdown of the tracked child emulator process."""
        proc = self._process
        if proc is None or proc.poll() is not None:
            self._process = None
            return

        serial = self.config.serial
        adb_bin = self.config.adb_binary
        max_time = timeout if timeout is not None else self.config.shutdown_timeout

        try:
            subprocess.run(
                [adb_bin, "-s", serial, "emu", "kill"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
        except Exception:
            pass

        try:
            proc.wait(timeout=max_time)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=5.0)
            except Exception as exc:
                raise ShutdownError(f"Failed to force-terminate tracked process {proc.pid}: {exc}") from exc
        finally:
            self._process = None

    def cleanup(self) -> None:
        """Emergency cleanup handler to terminate the tracked child process if active."""
        if self.is_running():
            try:
                self.shutdown(timeout=5.0)
            except Exception:
                if self._process and self._process.poll() is None:
                    try:
                        self._process.kill()
                    except Exception:
                        pass
                    self._process = None

    def start_and_wait_for_boot(self) -> None:
        """Convenience method to start emulator and wait for boot completion with cleanup on error."""
        self.start()
        try:
            self.wait_for_boot()
        except Exception:
            self.cleanup()
            raise
