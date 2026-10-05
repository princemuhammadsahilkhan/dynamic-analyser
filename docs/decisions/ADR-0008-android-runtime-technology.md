# ADR-0008: Android Runtime Technology Selection

## Status
Accepted

## Context
Requirements DA-005 (Android Runtime Infrastructure), DA-006 (Android Device Communication & APK Execution), DA-014 (Security & Isolation), and DA-015 (Reproducibility & Observability) mandate that the dynamic analysis platform execute target APKs in an isolated, automated, observable, and reproducible Android runtime environment.

Section 18 of `REQUIREMENTS.md` explicitly marked `emulator/runtime technology` as an unresolved design decision. A primary Android runtime technology approach must be evaluated and selected prior to implementing runtime management code (Section 21).

## Requirements Driving the Decision
- **DA-005**: Provide an isolated Android runtime infrastructure to host and run the target application.
- **DA-006**: Establish communication channels for automated APK installation, launch, and execution management.
- **DA-014**: Ensure strict sandboxing and isolation between the host system and target application to prevent host compromise or cross-job contamination.
- **DA-015**: Ensure dynamic analysis execution produces observable logs and deterministic, reproducible outputs.
- **Section 19 (Definition of Done)**: Requires valid execution in an isolated Android runtime environment.

## Options Evaluated

### 1. Official Android SDK Emulator (KVM-accelerated AVD)
- **Description**: Official AOSP QEMU/KVM-based Android Virtual Device (AVD) managed via `emulator`, `sdkmanager`, and `avdmanager`.
- **Verified Capabilities**:
  - Native headless execution (`-no-window`, `-no-audio`).
  - Full hardware VM isolation via KVM (`/dev/kvm`), protecting the host kernel from untrusted APK execution.
  - Native instant snapshot restoration (`-snapshot`, `adb emu snapshot load`) ensuring deterministic execution state before every run.
  - Native ADB interface over TCP (`5555`) / local pipe.
  - Broad support for x86_64 system images across Android API levels.
  - Full compatibility with Frida, network proxies (mitmproxy), and runtime instrumentation.
- **Limitations**: Higher RAM/CPU overhead per instance compared to OS containers; anti-emulation detection in obfuscated samples.

### 2. Physical Android Hardware Devices
- **Description**: Real Android hardware devices connected via USB or Wi-Fi ADB.
- **Verified Capabilities**: Native hardware execution, true hardware behavior.
- **Limitations**: Inability to perform fast memory/disk snapshot restoration (requires lengthy factory resets); physical cabling, power management, and hardware wear bottlenecks; poor suitability for automated, reproducible open-core server execution.

### 3. Containerized Android Runtimes (e.g., ReDroid / Anbox)
- **Description**: Android OS running inside LXC/Docker containers sharing the host Linux kernel.
- **Verified Capabilities**: Fast container creation, low RAM overhead, native ADB over TCP.
- **Limitations**: Weak isolation for untrusted/malicious code (shares host Linux kernel, violating DA-014); requires specialized host kernel modules (`binder_linux`, `ashmem`) not present by default on standard Linux kernels.

### 4. AOSP Cuttlefish (Cloud Virtual Device Platform)
- **Description**: Google's official AOSP virtualization platform using KVM and crosvm.
- **Verified Capabilities**: Strong VM isolation, headless cloud operation.
- **Limitations**: Significantly higher operational and build complexity (requires custom AOSP build pipelines and Debian host packages) compared to standard SDK AVDs.

## Decision
Select the **Official Android SDK Emulator (KVM-accelerated AVD)** as the primary Android runtime technology for automated APK dynamic execution.

## Rationale
1. **Security & Isolation (DA-014)**: Uses hardware-level VM isolation via KVM (`/dev/kvm`), isolating untrusted application code from the host kernel.
2. **Reproducibility (DA-015)**: Provides instant QEMU snapshot restoration, ensuring every analysis job starts from a clean, deterministic state.
3. **Automated Control (DA-006)**: Native ADB integration over TCP enables programmatic APK installation, execution launch, log collection, and device control.
4. **Host Environment Compatibility**: Host environment is an `x86_64` Linux platform with active KVM hardware virtualization (`/dev/kvm`, Intel `VT-x` enabled) and existing Android SDK CLI tools (`sdkmanager`, `adb`, `aapt`, `apksigner`).
5. **Open-Core & Tooling Neutrality**: Uses standard PyPA/AOSP tooling and open-source emulator components (QEMU/AOSP), avoiding vendor lock-in or specialized host kernel dependencies.

## Scope
This decision applies exclusively to selecting the primary virtualization technology approach for running target Android applications during dynamic analysis.

## Not Decided / Deferred
The following runtime implementation details remain explicitly deferred:
- Specific Android OS versions and API levels (e.g. API 30, 33, 34)
- System image variants (Google APIs vs. Automated Test Device / ATD images)
- Snapshot creation, naming, and restoration lifecycle policy
- Concurrency, instance pooling, and worker resource allocation
- Headless emulator CLI flags (`-no-window`, `-gpu`, etc.)
- ADB communication client library implementation

## Consequences
- Future runtime management code will interact with KVM-accelerated Android SDK AVD instances.
- Development host environments must support KVM hardware acceleration (`/dev/kvm`).
- Subsystem designs will incorporate snapshot restoration into the job execution flow to guarantee reproducible state.

## Sources & References Used for Fact-Checking
- Android Developers Documentation: *Run the Android Emulator from the command line* (`developer.android.com/studio/run/emulator`)
- Android Developers Documentation: *Configure hardware acceleration for the Android Emulator* (`developer.android.com/studio/run/emulator-acceleration`)
- Android Developers Documentation: *Automated Test Device (ATD) system images* (`developer.android.com/studio/test/atd`)
- AOSP / Cuttlefish Documentation: *Cuttlefish Architecture* (`source.android.com/docs/setup/create/cuttlefish`)
- ReDroid Project Documentation: *Remote Android in Docker* (`github.com/remote-android/redroid`)
