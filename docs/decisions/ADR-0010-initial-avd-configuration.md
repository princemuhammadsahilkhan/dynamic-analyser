# ADR-0010: Initial AVD Configuration Baseline

## Status
Accepted

## Context
Requirements DA-005 (Android Runtime Infrastructure), DA-006 (Android Device Communication & APK Execution), DA-014 (Security & Isolation), and DA-015 (Reproducibility & Observability) mandate that the dynamic analysis platform execute target APKs in an isolated, automated, observable, and reproducible Android runtime environment.

ADR-0008 selected the Official Android SDK Emulator with KVM acceleration as the primary virtualization technology. ADR-0009 selected `system-images;android-33;default;x86_64` as the initial baseline system image, which was installed into the user-writable SDK root at `/home/kali/.local/share/android-sdk` in Step 26.

Section 18 of `REQUIREMENTS.md` lists `resource limits`, `runtime provisioning`, and `AVD configuration` as unresolved implementation decisions. Before executing `avdmanager create avd`, the minimal defensible hardware parameters and runtime defaults for the initial AVD baseline instance must be audited, classified, and established.

## Requirements Driving the Decision
- **DA-005**: Provide an isolated Android runtime infrastructure to host and run the target application.
- **DA-006**: Establish communication channels for automated APK installation, launch, and execution management via ADB.
- **DA-014**: Ensure strict VM sandboxing and isolation between the host system and target application via KVM (`/dev/kvm`).
- **DA-015**: Ensure dynamic analysis execution produces observable logs and deterministic, reproducible outputs.
- **Section 19 (Definition of Done)**: Requires valid execution in an isolated Android runtime environment.

## Audited Configuration Items & Classification

Each configuration item and runtime parameter has been audited and classified into one of four categories:
- **Category A**: Explicitly required by project requirements
- **Category B**: Technically required to create an AVD definition
- **Category C**: Provisional development baseline choice (NOT a product requirement)
- **Category D**: Must remain unresolved (Deferred implementation mechanism / CLI flag)

| Configuration Item / Option | Audited Specification | Classification Category | Classification Description & Rationale |
|---|---|---|---|
| **1. AVD Name** | `analysis_baseline_api33` | **C** (Provisional Development Baseline Choice) | Required argument for `avdmanager create avd -n`. Descriptive provisional name. |
| **2. System Image Package** | `system-images;android-33;default;x86_64` | **A** (Explicitly Required) | Mandated by accepted decision ADR-0009. |
| **3. Hardware Profile Template** | `pixel_6` (ID 47) | **C** (Provisional Development Baseline Choice) | Standard 1080p phone screen geometry available in `avdmanager list device`. |
| **4. Guest RAM Allocation** | `2048 MB` (2 GiB) | **C** (Provisional Development Baseline Choice) | Ensures stable OS execution on host while leaving >80% host RAM free. |
| **5. Internal Storage (`/data`)** | `4096 MB` (4 GiB) | **C** (Provisional Development Baseline Choice) | Adequate capacity for target APKs, app data, and evidence collection logs. |
| **6. SD-Card Storage** | Disabled (0 MB) | **C** (Provisional Development Baseline Choice) | Minimizes disk overhead and avoids unneeded external storage state. |
| **7. Virtual CPU Cores** | `2` vCPUs | **C** (Provisional Development Baseline Choice) | Enables multi-threaded guest execution while preserving 6 host CPU cores. |
| **8. Graphics Rendering** | `swiftshader_indirect` / Software | **C** (Provisional Development Baseline Choice) | Guarantees reliable software rendering without relying on host display servers. |
| **9. Hardware Keyboard Input** | Enabled (`hw.keyboard = yes`) | **C** (Provisional Development Baseline Choice) | Permits direct ADB text injection (`adb shell input text`) into UI text fields. |
| **10. Camera & Audio Hardware** | Disabled / `fake` | **C** (Provisional Development Baseline Choice) | Prevents emulator crashes caused by missing physical host media devices. |
| **11. Initial Boot Procedure** | Initial Cold Boot (for OS Init) | **D** (Deferred Execution Detail) | Procedural step to initialize OS state; not a product requirement or AVD setting. |
| **12. Clean State Reset Mechanism** | Snapshot vs Ephemeral Overlay | **D** (Deferred Implementation Mechanism) | Requirements DA-014/015 mandate isolation; exact reset mechanism remains deferred. |
| **13. Emulator Invocation Flags** | `-no-window -no-audio` | **D** (Deferred Runtime Invocation Flags) | Emulator CLI invocation flags, not AVD creation parameters (Section 18). |
| **14. Snapshot Lifecycle Policy** | Deferred | **D** (Must Remain Unresolved) | Snapshot naming, save triggers, and reset mechanisms remain explicitly deferred. |
| **15. Network Stack & Proxy** | Default QEMU NAT (`10.0.2.15`) | **D** (Must Remain Unresolved) | Network proxy technology and certificate injection remain deferred (Section 18). |

## Separation of Requirements, Verified Facts, Provisional Choices, and Deferred Decisions

### Verified Technical Facts
1. The host environment possesses 15 GiB total RAM (11 GiB available), 8 logical `x86_64` CPU cores, and ~165 GiB available disk space.
2. `avdmanager` supports `pixel_6` (ID 47) as an existing device hardware definition template.
3. `system-images;android-33;default;x86_64` is installed at `/home/kali/.local/share/android-sdk/system-images/android-33/default/x86_64`.
4. Command line flags such as `-no-window` and `-no-audio` are emulator runtime invocation arguments, separate from AVD device definition properties.

### Provisional Development Baseline Choices
The following parameters are established strictly as provisional development choices for initial local testing. They are **NOT** product requirements:
- AVD Name: `analysis_baseline_api33`
- Hardware Profile: `pixel_6`
- Guest RAM: `2048 MB`
- Internal Storage: `4096 MB`
- Virtual CPUs: `2` vCPUs
- Graphics Mode: `swiftshader_indirect` / Software
- Keyboard/Camera/Audio: `hw.keyboard = yes`, `camera = none`, `audio = fake`

### Deferred Production & Implementation Decisions
The following implementation items remain explicitly unresolved:
- Production worker pool concurrency and per-job resource quota enforcement (Section 18)
- Automated state reset mechanism (snapshots vs. ephemeral overlays vs. AVD re-creation)
- Emulator CLI invocation flags (`-no-window`, `-gpu`, `-writable-system`, etc.)
- Network proxy integration, CA certificate generation, and trust store injection (Section 18)
- Dynamic instrumentation framework (Frida hooking engine, agent scripts) (Section 18)
- Application UI exercise and interaction strategy (Section 18)

## Decision
Establish the initial AVD baseline configuration named `analysis_baseline_api33` using `system-images;android-33;default;x86_64`, `pixel_6` hardware profile, 2 vCPUs, 2048 MB RAM, 4096 MB internal storage, software graphics, and disabled physical media hardware.

## Rationale
1. **Host Safety & Stability**: Consumes only 2 vCPUs and 2 GiB RAM, ensuring the development host remains responsive and unconstrained.
2. **Execution Reliability**: Software graphics (`swiftshader_indirect`) and disabled physical camera/audio devices eliminate driver crashes in headless Linux server environments.
3. **Requirement Alignment**: Fulfills DA-005, DA-006, DA-014, and DA-015 by providing an isolated, observable, and reproducible Android 13 runtime environment.

## Scope
This decision establishes **one initial baseline AVD configuration** (`analysis_baseline_api33`) for early development and testing. It does not define production worker pool sizing, multi-device hardware matrices, or final resource quota enforcement.

## Sources & References Used
- Android Developers Documentation: *Create and manage virtual devices with avdmanager* (`developer.android.com/studio/command-line/avdmanager`)
- Android Developers Documentation: *Start the Android Emulator from the command line* (`developer.android.com/studio/run/emulator`)
- Installed Tooling Output: `/home/kali/.local/share/android-sdk/cmdline-tools/latest/bin/avdmanager list device`
