# ADR-0009: Initial Android System Image Baseline Selection

## Status
Accepted

## Context
Requirements DA-005 (Android Runtime Infrastructure), DA-006 (Android Device Communication & APK Execution), DA-014 (Security & Isolation), and DA-015 (Reproducibility & Observability) mandate that the dynamic analysis platform execute target APKs in an isolated, automated, observable, and reproducible Android runtime environment.

ADR-0008 selected the Official Android SDK Emulator with KVM acceleration as the primary virtualization technology. In Step 24, `emulator` (v29.3.4.0) and `cmdline-tools;latest` (`avdmanager`) were installed into the user-writable SDK root at `/home/kali/.local/share/android-sdk`.

Section 18 of `REQUIREMENTS.md` explicitly listed `Android images/API levels` as an unresolved design decision. Prior to provisioning AVD instances or implementing runtime management code, a specific initial Android system image and API-level baseline must be evaluated and selected.

## Requirements Driving the Decision
- **DA-005**: Provide an isolated Android runtime infrastructure to host and run the target application.
- **DA-006**: Establish communication channels for automated APK installation, launch, and execution management via ADB.
- **DA-014**: Ensure hardware-level VM isolation between host and untrusted APK execution via KVM.
- **DA-015**: Ensure dynamic analysis execution produces observable logs and deterministic, reproducible outputs.
- **Section 19 (Definition of Done)**: Requires valid execution in an isolated Android runtime environment.

## Candidates Evaluated

### 1. `system-images;android-33;default;x86_64` (Android 13, API Level 33, AOSP Default x86_64)
- **Verified Capabilities**:
  - Available in host `sdkmanager` package repository.
  - Native `x86_64` architecture, leveraging host KVM acceleration (`/dev/kvm`).
  - Pure AOSP (`default`) build providing documented `adb root` capability (switching `adbd` daemon to root privileges).
  - Modern API level capable of executing target applications declaring a `minSdkVersion` up to 33.
- **Partition Write Considerations**: Modifying system partition files (such as adding custom CA certificates to `/system/etc/security/cacerts`) is not automatic; it requires explicit runtime options (such as the `-writable-system` emulator flag) and `adb remount` or overlayfs operations.

### 2. `system-images;android-30;default;x86_64` (Android 11, API Level 30, AOSP Default x86_64)
- **Verified Capabilities**: Available in `sdkmanager`; stable AOSP `x86_64` build with native `adb root` capability.
- **Limitations**: Older API target level (Android 11); an application declaring a `minSdkVersion` greater than 30 cannot execute on this system image.

### 3. `system-images;android-34;default;x86_64` (Android 14, API Level 34, AOSP Default x86_64)
- **Verified Capabilities**: Available in `sdkmanager`; represents a newer Android OS release.

### 4. Google APIs & Automated Test Device (ATD) Images
- **Host Repository State**: Executing `sdkmanager --list` on the host verified that `google_apis` and `atd` system images for modern API levels are not indexed in the current host repository feed. Default AOSP (`default`) images are available and provide `adb root` capabilities.
- **ATD Overview**: Official Android documentation defines Automated Test Device (ATD) system images as stripped-down AOSP images optimized for headless CI/CD automated testing. While ATD images exist in official Google SDK channels, their absence in the current host repository feed precludes selecting them as the initial host baseline.

## Verified Facts vs. Engineering Inferences

### Verified Facts
1. `system-images;android-33;default;x86_64` is verified available via `sdkmanager --list` in the host repository.
2. Android OS rules dictate that an application cannot be installed or executed if its declared `minSdkVersion` exceeds the API level of the runtime system image.
3. Android Network Security Configuration (starting in Android 7.0 / API 24) by default trusts only system-installed CA certificates, not user-added CA certificates.
4. AOSP (`default`) emulator images include `adb root` capability in `adbd`, whereas production Google Play images restrict `adbd` from running as root.
5. AOSP `default` images do not grant arbitrary writable `/system` access by default; modifying system partition files requires explicit runtime invocation flags (e.g. `-writable-system`) and `adb remount` operations.
6. `sdkmanager --list` on this host currently indexes `default` AOSP images but does not contain `atd` images for modern API levels.

### Engineering Inferences
1. Selecting API Level 33 (Android 13) provides a balanced initial baseline capable of executing modern target applications while utilizing `x86_64` KVM hardware acceleration.
2. Relying on an AOSP (`default`) image provides documented `adb root` access needed for future system-level observation and administrative control.

## Decision
Select **`system-images;android-33;default;x86_64`** (Android 13, API Level 33, AOSP Default x86_64) as the initial reproducible Android runtime baseline system image.

## Rationale
1. **Hardware Virtualization Performance**: Native `x86_64` image matches the host CPU architecture and leverages KVM hardware acceleration (`/dev/kvm`) for fast execution and deterministic QEMU snapshot restoration (DA-005, DA-015).
2. **Elevated Privilege Capability for Observability & Control**: Pure AOSP (`default`) image supports `adb root`, enabling root-level process inspection, log collection, and administrative control necessary for runtime evidence gathering (DA-006, DA-010).
3. **Repository Availability**: Verified immediately available in the host's `sdkmanager` CLI package index without requiring extra repository configuration.
4. **Initial Fixed Baseline**: Establishes a single, reproducible initial baseline for developing automated runtime orchestration before expanding to multi-API execution matrices.

## Scope
This decision establishes **one initial baseline system image** (`system-images;android-33;default;x86_64`) for early runtime environment implementation. It does not restrict future support for additional API levels or multi-API matrix execution.

## Explicitly Deferred Decisions
The following items remain explicitly deferred:
- Multi-API matrix execution strategy and downloading additional system images
- AVD definition, instance naming, and hardware profiles
- Emulator CLI invocation flags (e.g., `-writable-system`, `-no-window`, `-gpu`)
- QEMU snapshot lifecycle management
- Network proxy architecture and certificate generation code
- Instrumentation frameworks (Frida server deployment, scripts, hooking)

## Sources & References Used for Fact-Checking
- Android Developers Documentation: *Run the Android Emulator from the command line* (`developer.android.com/studio/run/emulator`)
- Android Developers Documentation: *Network Security Configuration* (`developer.android.com/training/articles/security-config`)
- Android Developers Documentation: *Automated Test Device (ATD) system images* (`developer.android.com/studio/test/atd`)
- Android Developers Documentation: *uses-sdk Element & minSdkVersion Specification* (`developer.android.com/guide/topics/manifest/uses-sdk-element`)
- Host Repository Verification Command: `ANDROID_HOME=/home/kali/.local/share/android-sdk sdkmanager --sdk_root=/home/kali/.local/share/android-sdk --list`
