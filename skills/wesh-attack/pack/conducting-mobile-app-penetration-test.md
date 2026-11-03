---
name: conducting-mobile-app-penetration-test
description: Conducts penetration testing of iOS and Android mobile applications following the OWASP Mobile Application Security Testing Guide (MASTG) to identify vulnerabilities in data storage, network communication, authentication, cryptography, and platform-specific security controls.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1426
- T1409
- T1521.003
- T1633
- T1417
- T1422
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: conducting-mobile-app-penetration-test@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

Not for: mobile applications without written authorization from the application owner, for distributing modified or repackaged applications, or for testing apps on the public app stores without a separate test build.

## Prerequisites

- Target application IPA (iOS) and APK (Android) files or access to download from private distribution channel
- Rooted Android device or emulator (Genymotion, Android Studio AVD) with Frida, Objection, and Magisk installed
- Jailbroken iOS device or Corellium virtual device with Frida, Objection, and SSL Kill Switch installed
- Static analysis tools: jadx (Android decompilation), Hopper/Ghidra (iOS binary analysis), MobSF (automated scanning)
- Burp Suite Professional configured as proxy for intercepting mobile app traffic with CA certificate installed on test device

## Workflow

### Step 1: Static Analysis

Analyze application binary without executing it:

**Android Static Analysis:**
- Decompile APK: `jadx -d output/ target.apk` to obtain Java/Kotlin source code
- Review `AndroidManifest.xml` for exported components (activities, services, receivers, content providers), permissions, and debuggable flag
- Search for hardcoded secrets: `grep -rn "api_key\|password\|secret\|token\|aws_" output/`
- Identify insecure data storage patterns: SharedPreferences with sensitive data, SQLite databases without encryption, files in external storage
- Check for WebView vulnerabilities: `setJavaScriptEnabled(true)`, `addJavascriptInterface()`, and loading untrusted content
- Run MobSF automated scan: `python manage.py runserver` and upload APK for automated static analysis

**iOS Static Analysis:**
- Extract IPA and locate Mach-O binary
- Use `otool -L <binary>` to list linked frameworks and identify third-party libraries
- Analyze with Ghidra or Hopper for hardcoded URLs, API endpoints, and embedded credentials
- Check Info.plist for App Transport Security (ATS) exceptions that allow insecure HTTP connections
- Review embedded entitlements for excessive capabilities

### Step 2: Network Security Testing

Intercept and analyze all network communications:

- Configure Burp Suite as proxy on test device and install Burp CA certificate
- Exercise all application functionality while Burp captures API traffic
- **SSL/TLS validation**: Verify app validates server certificates properly. If app fails to connect through proxy, it may implement certificate pinning.
- **Certificate pinning bypass**:
  - Android: Use Frida script: `frida -U -f com.target.app -l ssl-pinning-bypass.js --no-pause`
  - iOS: Use SSL Kill Switch or Objection: `objection -g "Target App" explore --startup-command "ios sslpinning disable"`
- **API traffic analysis**: Review all API calls for:
  - Sensitive data transmitted without encryption
  - Authentication tokens in URL parameters (visible in logs)
  - Excessive data in API responses beyond what UI displays
  - Missing or weak authentication on API endpoints
- **WebSocket and custom protocols**: Check for non-HTTP communication channels that may bypass standard proxy interception

### Step 3: Data Storage Analysis

Test for insecure local data storage:

**Android Data Storage:**
- Access app data directory: `/data/data/com.target.app/`
- Check SharedPreferences XML files for stored credentials, tokens, and PII
- Examine SQLite databases: `sqlite3 /data/data/com.target.app/databases/*.db ".dump"`
- Check for sensitive data in application logs: `logcat -d | grep -i "password\|token\|key"`
- Verify that application data is excluded from backups: `android:allowBackup="false"` in AndroidManifest.xml
- Check clipboard for sensitive data leakage

**iOS Data Storage:**
- Examine Keychain for stored credentials: `objection -g "Target App" explore` then `ios keychain dump`
- Check NSUserDefaults/plist files: `find /var/mobile/Containers/Data/Application/ -name "*.plist" -exec plutil -p {} \;`
- Inspect SQLite databases and Core Data stores for unencrypted sensitive data
- Check for data leaking through screenshots (iOS captures screenshots during app backgrounding)
- Verify data protection class: sensitive files should use NSFileProtectionComplete

### Step 4: Authentication and Session Management

Test mobile-specific authentication controls:

- **Biometric bypass**: Test if biometric authentication can be bypassed by hooking authentication callback with Frida to always return success
- **Token storage**: Verify that authentication tokens are stored in Keychain (iOS) or Android Keystore, not in SharedPreferences or files
- **Session timeout**: Verify that sessions expire after reasonable idle timeout and that tokens are invalidated server-side on logout
- **Root/jailbreak detection bypass**: Test if app detects rooted/jailbroken devices and if detection can be bypassed with Frida or Magisk Hide
- **Deep link abuse**: Test if custom URL schemes or universal links can be used to bypass authentication or access restricted functionality

### Step 5: Runtime Manipulation

Test application's resistance to runtime attacks:

- **Frida hooking**: Use Frida to hook and modify application functions at runtime:
  - Bypass root detection: hook detection function to return false
  - Modify return values of authentication checks
  - Intercept encryption functions to capture plaintext data before encryption
  - Bypass certificate pinning by hooking SSL verification
- **Method swizzling** (iOS): Use Frida to replace Objective-C method implementations
- **Intent manipulation** (Android): Send crafted intents to exported components: `adb shell am start -n com.target.app/.InternalActivity -e "user_id" "admin"`
- **Tampering detection**: Modify APK/IPA (add code, change resources), re-sign, and install. Verify whether app detects tampering.

## Key Concepts

| Term | Definition |
|------|------------|
| **OWASP MASTG** | Mobile Application Security Testing Guide; comprehensive manual for mobile app security testing covering both iOS and Android platforms |
| **Certificate Pinning** | Mobile security control that restricts which TLS certificates app trusts, preventing man-in-the-middle attacks through proxy interception |
| **Frida** | Dynamic instrumentation toolkit that allows injection of JavaScript into running processes to hook functions, modify behavior, and bypass security controls |
| **Root/Jailbreak Detection** | Application-level checks to detect if device has been modified to grant root access, typically blocking app usage on compromised devices |
| **Android Keystore** | Hardware-backed credential storage on Android that protects cryptographic keys and secrets from extraction even on rooted devices |
| **App Transport Security (ATS)** | iOS security feature that enforces HTTPS connections by default; ATS exceptions may indicate insecure network communication |
| **Deep Links** | URL schemes that open specific screens within mobile application, which may bypass normal navigation and authentication flows if not properly validated |

## Tools & Systems

- **Frida / Objection**: Dynamic instrumentation tools for hooking functions, bypassing security controls, and manipulating application behavior at runtime
- **MobSF (Mobile Security Framework)**: Automated static and dynamic analysis platform for Android and iOS applications
- **jadx**: Android decompiler that converts APK bytecode to readable Java source code for manual code review
- **Burp Suite Professional**: HTTP proxy for intercepting and modifying mobile app API traffic after bypassing certificate pinning

### Scenario: Mobile Banking Application Security Assessment

**Context**: Bank is launching new mobile banking app for iOS and Android. App handles account viewing, fund transfers, bill payment, and check deposit. OWASP MASVS L2 compliance is required due to financial data handled.

**Approach**:
1. Static analysis of Android APK reveals API endpoints, hardcoded staging server URL, and AWS API key in configuration file
2. Certificate pinning is implemented but bypassed with Frida SSL pinning bypass script
3. API traffic analysis reveals that balance check endpoint returns all account numbers associated with user, not just requested account
4. Local data storage analysis finds that app caches last 10 transactions in unencrypted SQLite database
5. Biometric authentication bypass: Frida hook on biometric callback always returns success, granting access without fingerprint
6. Root detection is present but bypassed with Magisk Hide module, allowing app to run on rooted device with full data access

**Pitfalls**:
- Testing only on emulator and missing hardware-specific security features (Android Keystore hardware backing, iOS Secure Enclave)
- Not testing both iOS and Android versions, as they may have different implementations and different vulnerabilities
- Ignoring backend API security because it was "tested separately" when mobile app may call API endpoints differently than web app
- Failing to test certificate pinning bypass, resulting in incomplete network analysis

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-mobile-app-penetration-test
