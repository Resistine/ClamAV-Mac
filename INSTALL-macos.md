# Installing ClamAV on macOS with On-Access Scanning

ClamAV 0.106+ includes experimental support for On-Access Scanning on macOS using Apple's Endpoint Security Framework (ESF). This replaces `fanotify` used on Linux.

## Requirements

1.  **macOS 10.15 (Catalina) or newer**.
2.  **Xcode Command Line Tools**: `xcode-select --install`
3.  **CMake**: `brew install cmake`
4.  **Apple Developer Account**: Required for code-signing the application to run with Endpoint Security entitlements.

## Building from Source

Standard CMake build instructions apply, but the ESF module will be automatically enabled if compiling on macOS.

```bash
mkdir build
cd build
cmake .. \
    -D CMAKE_BUILD_TYPE=RelWithDebInfo \
    -D CMAKE_INSTALL_PREFIX=/usr/local/clamav
make
make install
```

## Code Signing (CRITICAL)

The Endpoint Security Framework requires the `clamonacc` binary to be code-signed with the `com.apple.developer.endpoint-security.client` entitlement. **The application will fail to start without this.**

1.  Create an `entitlements.plist` file:
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>com.apple.developer.endpoint-security.client</key>
        <true/>
    </dict>
    </plist>
    ```

2.  Sign the `clamonacc` binary using your Developer ID certificate:
    ```bash
    codesign --entitlements entitlements.plist --force -s "Developer ID Application: Your Name (TEAMID)" /usr/local/clamav/sbin/clamonacc
    ```

    *Note: For local testing, you may try ad-hoc signing (`-s -`), but ESF often requires a valid Apple-issued certificate trusted by the system layer, and SIP (System Integrity Protection) often blocks unsigned ESF clients. Disabling SIP allows ad-hoc signatures but is not recommended for production.*

## Running

1.  **Full Disk Access**: The terminal or service running `clamonacc` must have Full Disk Access granted in `System Settings > Privacy & Security > Full Disk Access`.
2.  **Root Privileges**: `clamonacc` must be run as root to interact with the system ESF subsystem.

```bash
sudo /usr/local/clamav/sbin/clamonacc --config-file=/usr/local/clamav/etc/clamd.conf
```
