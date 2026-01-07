# Anycubic Kobra 3 Series - Protocol Reverse Engineering

**Project:** Open-source documentation of Anycubic Kobra 3 series printer communication protocols  
**Last Updated:** 2026-01-07  
**Tested Slicer:** AnycubicSlicerNext 1.3.7.3 (macOS)  
**Tested Printer:** Anycubic Kobra 3 Max (Firmware 2.4.6)  

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [LAN Communication (Working)](#3-lan-communication-working)
4. [HTTP Endpoints](#4-http-endpoints)
5. [MQTT Protocol](#5-mqtt-protocol)
6. [SSDP Discovery](#6-ssdp-discovery)
7. [Cloud Signature Algorithm](#7-cloud-signature-algorithm)
8. [LAN Pairing - Unsolved](#8-lan-pairing---unsolved)
9. [Binary Analysis (Ghidra)](#9-binary-analysis-ghidra)
10. [Tools and Scripts](#10-tools-and-scripts)
11. [Contributing](#11-contributing)

**Appendices:**
- [Appendix A: Video Streaming](#appendix-a-video-streaming)
- [Appendix B: Complete MQTT Message Examples](#appendix-b-complete-mqtt-message-examples)
- [Appendix C: Troubleshooting](#appendix-c-troubleshooting)

---

## 1. Overview

This document contains reverse engineering findings for the Anycubic Kobra 3 series printers communication protocols. The goal is to enable third-party software to control these printers without relying on Anycubic's proprietary slicer or cloud services.

### Current Status

| Feature | Status | Notes |
|---------|--------|-------|
| LAN MQTT Connection | **Working** | Using credentials from official slicer config |
| LAN MQTT Commands | **Working** | Full printer control via MQTT |
| LAN HTTP /info | **Working** | Printer info without authentication |
| LAN HTTP /ctrl (pairing) | **Not Working** | Signature algorithm unknown |
| SSDP Discovery | **Working** | Auto-discover printers on network |
| Cloud API | **Working** | Full signature algorithm documented |
| Video Stream | **Working** | FLV stream on port 18088 |

### Supported Models

| machine_type | Model | LAN | Cloud | Rinkhals |
|--------------|-------|-----|-------|----------|
| 20021 | Kobra 2 Pro | Yes | Yes | Yes |
| 20023 | Kobra 2 Plus | Yes | Yes | Yes |
| 20024 | Kobra 2 Max | Yes | Yes | Yes |
| 20025 | Kobra 3 | Yes | Yes | Yes |
| 20026 | Kobra 3 Max | Yes | Yes | No |
| 20030 | Kobra S1 | Yes | Yes | No |
| 20031 | Kobra S1 Combo | Yes | Yes | No |

---

## 2. Architecture

```
                     ┌─────────────────────────────────────────┐
                     │           CLOUD SERVERS                 │
                     │  cloud-universe.anycubic.com:443        │
                     │  mqtt-universe.anycubic.com:8883        │
                     └──────────────────┬──────────────────────┘
                                        │
            ┌───────────────────────────┼───────────────────────────┐
            │                           │                           │
            ▼                           ▼                           ▼
     ┌─────────────┐            ┌─────────────┐            ┌─────────────┐
     │   Slicer    │            │   Printer   │            │ Third-party │
     │  (Official) │            │  (Kobra 3)  │            │   Client    │
     └──────┬──────┘            └──────┬──────┘            └──────┬──────┘
            │                          │                          │
            │         LAN Network      │                          │
            └──────────────────────────┼──────────────────────────┘
                                       │
                        ┌──────────────┼──────────────┐
                        ▼              ▼              ▼
                   Port 9883     Port 18910     Port 18088
                   (MQTTS)       (HTTP API)    (Video FLV)
```

### Ports Used

| Port | Protocol | Purpose |
|------|----------|---------|
| 9883 | MQTTS (TLS) | MQTT communication with printer |
| 18910 | HTTP | /info and /ctrl endpoints |
| 18088 | HTTP | Video stream (FLV format) |
| 1900 | UDP | SSDP discovery |

---

## 3. LAN Communication (Working)

### Requirements

To connect to the printer via LAN MQTT, you need credentials that are generated during the **initial pairing** process. These credentials are stored in the slicer's config file.

### Config File Location

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/AnycubicSlicerNext/AnycubicSlicerNext.conf` |
| Windows | `%APPDATA%\AnycubicSlicerNext\AnycubicSlicerNext.conf` |
| Linux | `~/.config/AnycubicSlicerNext/AnycubicSlicerNext.conf` |

### Extracting Credentials

The config file is JSON. Look for the `machine_list_of_LAN` key.

**Important:** In newer versions of the slicer (1.3.7+), this field may be **encrypted** as `machine_lan_list`. See below for decryption.

#### Unencrypted Format (older versions)

```json
{
  "machine_list_of_LAN": [
    {
      "did": "4333d2cb625a1ec7099b521ec69e10c6",
      "lanIp": "192.168.0.171",
      "user": "user3HtOknyU",
      "pw": "uoyASSNmUViUlnK",
      "port": 9883,
      "modeId": 20026,
      "name": "Kobra3 Max"
    }
  ]
}
```

#### Encrypted Format (newer versions)

In newer slicer versions, the LAN credentials are stored encrypted:

```json
{
  "machine_lan_list": "U2FsdGVkX1+ABC123...base64_encrypted_data..."
}
```

### Decrypting machine_lan_list

The encryption uses **AES-256-CBC** with OpenSSL-compatible format.

#### Encryption Details

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-CBC |
| Key Derivation | OpenSSL EVP_BytesToKey (MD5-based) |
| Password | `anycubic_slicer_next_encrypt` |
| Format | OpenSSL `Salted__` prefix + salt + ciphertext |

#### Decryption Script (Node.js)

```javascript
const crypto = require('crypto');

function decryptMachineLanList(encryptedBase64) {
  const password = 'anycubic_slicer_next_encrypt';
  const data = Buffer.from(encryptedBase64, 'base64');

  // Check for OpenSSL "Salted__" header
  if (data.slice(0, 8).toString() !== 'Salted__') {
    throw new Error('Invalid OpenSSL format');
  }

  // Extract salt (bytes 8-15) and ciphertext (bytes 16+)
  const salt = data.slice(8, 16);
  const ciphertext = data.slice(16);

  // Derive key and IV using OpenSSL EVP_BytesToKey (MD5)
  const keyLen = 32; // AES-256
  const ivLen = 16;
  let derived = Buffer.alloc(0);
  let block = Buffer.alloc(0);

  while (derived.length < keyLen + ivLen) {
    block = crypto.createHash('md5')
      .update(Buffer.concat([block, Buffer.from(password), salt]))
      .digest();
    derived = Buffer.concat([derived, block]);
  }

  const key = derived.slice(0, keyLen);
  const iv = derived.slice(keyLen, keyLen + ivLen);

  // Decrypt
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(ciphertext);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return JSON.parse(decrypted.toString('utf8'));
}

// Usage
const encrypted = "U2FsdGVkX1+..."; // from config file
const credentials = decryptMachineLanList(encrypted);
console.log(credentials);
// Output: [{ did: "...", user: "...", pw: "...", ... }]
```

#### Decryption Script (Python)

```python
import base64
import hashlib
from Crypto.Cipher import AES

def decrypt_machine_lan_list(encrypted_base64):
    password = b'anycubic_slicer_next_encrypt'
    data = base64.b64decode(encrypted_base64)

    # Check OpenSSL header
    assert data[:8] == b'Salted__', 'Invalid format'

    salt = data[8:16]
    ciphertext = data[16:]

    # EVP_BytesToKey derivation
    key_iv = b''
    block = b''
    while len(key_iv) < 48:  # 32 key + 16 iv
        block = hashlib.md5(block + password + salt).digest()
        key_iv += block

    key = key_iv[:32]
    iv = key_iv[32:48]

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    # Remove PKCS7 padding
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    return json.loads(decrypted.decode('utf-8'))
```

#### Command Line (OpenSSL)

```bash
# Extract the base64 value from the config file
# Then decode and decrypt:
echo "U2FsdGVkX1+..." | base64 -d | \
  openssl enc -aes-256-cbc -d -pass pass:anycubic_slicer_next_encrypt -md md5
```

### Credential Fields

| Field | Description | Example |
|-------|-------------|---------|
| `did` | Device ID (MD5 hash, 32 chars) | `4333d2cb625a1ec7099b521ec69e10c6` |
| `lanIp` | Printer's LAN IP address | `192.168.0.171` |
| `user` | MQTT username (`user` + 8 random chars) | `user3HtOknyU` |
| `pw` | MQTT password (15 alphanumeric chars) | `uoyASSNmUViUlnK` |
| `port` | MQTT TLS port | `9883` |
| `modeId` | Printer model code | `20026` |
| `name` | Printer display name | `Kobra3 Max` |

### Important Notes

- Credentials are **generated by the printer** during pairing
- Each pairing generates **new credentials**
- The printer accepts **only one active session** at a time
- TLS certificate validation must be disabled (self-signed cert)

---

## 4. HTTP Endpoints

The printer exposes HTTP endpoints on port 18910.

### GET /info (No Authentication)

Returns printer status in JSON format.

```bash
curl http://192.168.0.171:18910/info
```

Response:
```json
{
  "msg": "success",
  "code": 0,
  "data": {
    "ip": "192.168.0.171",
    "model": "Kobra3 Max",
    "machine_type": "20026",
    "did": "4333d2cb625a1ec7099b521ec69e10c6",
    "mac": "C0:F4:09:xx:xx:xx",
    "alias": "My Printer"
  }
}
```

### POST /ctrl (Authentication Required - UNSOLVED)

This endpoint requires a `sign` parameter that we have not been able to reverse engineer.

```bash
curl -X POST http://192.168.0.171:18910/ctrl \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "action=pairing&timestamp=1736300000000&sign=UNKNOWN"
```

The signature algorithm is different from the Cloud API signature. See [Section 8](#8-lan-pairing---unsolved) for details.

---

## 5. MQTT Protocol

### Connection Parameters

```javascript
const mqttOptions = {
  host: '192.168.0.171',
  port: 9883,
  protocol: 'mqtts',
  username: 'user3HtOknyU',
  password: 'uoyASSNmUViUlnK',
  rejectUnauthorized: false, // Self-signed certificate
  clientId: 'slicer-' + Date.now()
};
```

### Topics Structure

**Publish commands to printer:**
```
anycubic/anycubicCloud/v1/slicer/printer/{modeId}/{deviceId}/{action}
```

**Subscribe to printer responses:**
```
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/response
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/info/report
```

### Example Topics (Kobra 3 Max)

```javascript
const modeId = '20026';
const deviceId = '4333d2cb625a1ec7099b521ec69e10c6';

// Topics to subscribe
const topics = [
  `anycubic/anycubicCloud/v1/printer/public/${modeId}/${deviceId}/response`,
  `anycubic/anycubicCloud/v1/printer/public/${modeId}/${deviceId}/info/report`
];

// Topics to publish
const publishTopic = `anycubic/anycubicCloud/v1/slicer/printer/${modeId}/${deviceId}/`;
```

### Message Format

All MQTT messages use JSON format:

```json
{
  "type": "command_type",
  "action": "action_name",
  "timestamp": 1736300000,
  "msgid": "unique-message-id"
}
```

### Common Commands

#### Get Printer Status
```json
{
  "type": "getStatus",
  "action": "getStatus",
  "timestamp": 1736300000,
  "msgid": "status-001"
}
```

#### Pause Print
```json
{
  "type": "print",
  "action": "pause",
  "timestamp": 1736300000,
  "msgid": "pause-001"
}
```

#### Resume Print
```json
{
  "type": "print",
  "action": "resume",
  "timestamp": 1736300000,
  "msgid": "resume-001"
}
```

#### Cancel Print
```json
{
  "type": "print",
  "action": "cancel",
  "timestamp": 1736300000,
  "msgid": "cancel-001"
}
```

---

## 6. SSDP Discovery

Printers advertise themselves via SSDP (Simple Service Discovery Protocol).

### Discovery Request

```bash
# Send multicast UDP to 239.255.255.250:1900
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 3
ST: urn:schemas-anycubic-com:device:3dprinter:1
```

### Discovery Response

```
HTTP/1.1 200 OK
CACHE-CONTROL: max-age=1800
LOCATION: http://192.168.0.171:18910/info
ST: urn:schemas-anycubic-com:device:3dprinter:1
USN: uuid:kobra3max-xxxx::urn:schemas-anycubic-com:device:3dprinter:1
```

### Node.js Implementation

```javascript
const dgram = require('dgram');

function discoverPrinters() {
  const socket = dgram.createSocket('udp4');
  const SSDP_ADDRESS = '239.255.255.250';
  const SSDP_PORT = 1900;

  const searchMessage = Buffer.from([
    'M-SEARCH * HTTP/1.1',
    'HOST: 239.255.255.250:1900',
    'MAN: "ssdp:discover"',
    'MX: 3',
    'ST: urn:schemas-anycubic-com:device:3dprinter:1',
    '', ''
  ].join('\r\n'));

  socket.on('message', (msg, rinfo) => {
    console.log(`Found printer at ${rinfo.address}`);
  });

  socket.send(searchMessage, SSDP_PORT, SSDP_ADDRESS);
}
```

---

## 7. Cloud Signature Algorithm

The Cloud API uses a custom signature algorithm that has been fully reverse engineered.

### Algorithm (HMAC-SHA256)

```javascript
const crypto = require('crypto');

function generateCloudSignature(params, appSecret) {
  // 1. Sort parameters alphabetically
  const sortedKeys = Object.keys(params).sort();

  // 2. Build query string
  const queryString = sortedKeys
    .map(key => `${key}=${params[key]}`)
    .join('&');

  // 3. Generate HMAC-SHA256
  const hmac = crypto.createHmac('sha256', appSecret);
  hmac.update(queryString);
  return hmac.digest('hex').toUpperCase();
}

// Usage
const params = {
  app_key: 'anycubic_slicer_next',
  timestamp: Date.now().toString(),
  nonce: crypto.randomBytes(16).toString('hex')
};

const APP_SECRET = 'your_app_secret_here';
const signature = generateCloudSignature(params, APP_SECRET);
```

### Cloud API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `api/v2/app/user/login` | POST | User authentication |
| `api/v2/printerController/getPrinterBrief` | GET | Get printer list |
| `api/v2/printerController/getPrinterInfo` | GET | Get printer details |
| `api/v2/printerController/sendPrinterOrder` | POST | Send command to printer |

---

## 8. LAN Pairing - UNSOLVED

The LAN pairing process uses a signature algorithm that is **different from the Cloud API** and has not been fully reverse engineered.

### What We Know

1. The `/ctrl` endpoint requires a `sign` parameter
2. The signature is generated by the slicer binary (not JavaScript)
3. The algorithm uses **MD5** (based on Frida analysis)
4. The input includes timestamp and possibly machine-specific data

### Frida Analysis Results

Using Frida to intercept the slicer, we found:

```javascript
// MD5 hash is called during signature generation
// The input appears to be a combination of:
// - Timestamp (milliseconds)
// - Device ID
// - Action type
// - Unknown salt/key
```

### Failed Attempts

We tried multiple signature formulas including:

```javascript
// Attempt 1: Simple MD5
MD5(timestamp + action + deviceId)

// Attempt 2: With salt
MD5(salt + timestamp + action)

// Attempt 3: Cloud-style
MD5(action=pairing&timestamp=xxx&key=xxx)

// All returned 403 Forbidden from the printer
```

### Binary Analysis (Ghidra)

The signature generation appears to be in the `libAnycubicSlicer.dylib` library. Key functions identified:

- `_ZN12AnycubicLAN*` - LAN-related functions
- `getSignature` - Signature generation (obfuscated)
- `MD5_Init`, `MD5_Update`, `MD5_Final` - OpenSSL MD5 functions

### Help Wanted

If you can help reverse engineer the LAN signature algorithm, please:

1. Analyze the binary with IDA Pro or Ghidra
2. Use Frida to trace the exact inputs to MD5
3. Compare multiple signature requests to find patterns

---

## 9. Binary Analysis (Ghidra)

### Target Binary

| OS | Path |
|----|------|
| macOS | `/Applications/AnycubicSlicerNext.app/Contents/Frameworks/libAnycubicSlicer.dylib` |
| Windows | `C:\Program Files\AnycubicSlicerNext\anycubic_slicer.dll` |

### Key Functions Found

```c
// LAN Control function (decompiled pseudocode)
void AnycubicLAN::sendCtrlRequest(timestamp, action, callback) {
    char signature[64];
    generateLANSignature(timestamp, action, signature);

    // Build HTTP request
    sprintf(url, "http://%s:18910/ctrl", printer_ip);
    sprintf(body, "action=%s&timestamp=%lld&sign=%s", action, timestamp, signature);

    httpPost(url, body, callback);
}

// Signature function (heavily obfuscated)
void generateLANSignature(timestamp, action, output) {
    MD5_CTX ctx;
    MD5_Init(&ctx);

    // Unknown data added here
    MD5_Update(&ctx, ???, ???);
    MD5_Update(&ctx, timestamp_str, timestamp_len);
    MD5_Update(&ctx, ???, ???);

    unsigned char digest[16];
    MD5_Final(digest, &ctx);

    // Convert to hex string
    for (int i = 0; i < 16; i++) {
        sprintf(output + i*2, "%02x", digest[i]);
    }
}
```

### Ghidra Script

A Ghidra script is available in `scripts/ghidra_find_sign.py` to help locate signature-related functions.

---

## 10. Tools and Scripts

This repository includes several tools for analysis:

### Frida Scripts

| Script | Purpose |
|--------|---------|
| `frida_ctrl_intercept.js` | Intercept /ctrl HTTP requests |
| `frida_md5_intercept.js` | Trace MD5 function calls |
| `frida_lan_traffic.js` | Monitor all LAN traffic |
| `frida_evp_sign.js` | Trace OpenSSL signing functions |

### Test Scripts

| Script | Purpose |
|--------|---------|
| `test-anycubic-mqtt-lan.js` | Test MQTT LAN connection |
| `test-anycubic-ssdp.js` | Test SSDP discovery |
| `test-lan-sign-formulas.js` | Test signature formulas |

### Usage Example (Frida)

```bash
# Attach to running slicer and trace MD5
frida -n AnycubicSlicerNext -l scripts/frida_md5_intercept.js

# Then trigger a pairing action in the slicer to see the trace
```

---

## 11. Contributing

### How to Help

1. **Reverse engineer the LAN signature** - This is the main blocker
2. **Test with other printer models** - Verify compatibility
3. **Document additional MQTT commands** - Expand command coverage
4. **Create alternative pairing methods** - Explore other approaches

### Alternative Approaches

If the signature cannot be cracked, consider:

1. **Rinkhals firmware** - Custom firmware with Moonraker API (https://github.com/jokubasver/Rinkhals)
2. **Cloud API only** - Use cloud authentication (requires internet)
3. **Extract credentials** - Parse official slicer config files

### Related Projects

| Project | Description |
|---------|-------------|
| [hass-anycubic_cloud](https://github.com/WaresWichall/hass-anycubic_cloud) | Home Assistant integration via Cloud |
| [Rinkhals](https://github.com/jokubasver/Rinkhals) | Custom firmware with Moonraker |
| [ac2mqtt](https://github.com/lkonga/ac2mqtt) | Anycubic to MQTT bridge |

---

## Appendix A: Video Streaming

### Stream URL Format

```
http://{printer_ip}:18088/flv
```

### FFmpeg Commands

```bash
# View stream
ffplay http://192.168.0.171:18088/flv

# Save snapshot
ffmpeg -i http://192.168.0.171:18088/flv -vframes 1 -q:v 2 snapshot.jpg

# Record stream
ffmpeg -i http://192.168.0.171:18088/flv -c copy recording.flv
```

### Integration with go2rtc

```yaml
# go2rtc.yaml
streams:
  kobra3:
    - ffmpeg:http://192.168.0.171:18088/flv#video=copy
```

---

## Appendix B: Complete MQTT Message Examples

### Printer Status Report (from printer)

```json
{
  "type": "status",
  "data": {
    "state": "printing",
    "progress": 45.5,
    "temp_hotend": 215.0,
    "temp_bed": 60.0,
    "temp_chamber": 35.0,
    "fan_speed": 100,
    "print_speed": 100,
    "layer_current": 125,
    "layer_total": 500,
    "time_remaining": 7200,
    "filename": "model.gcode"
  },
  "timestamp": 1736300000
}
```

### ACE Unit Status (Kobra 3 Combo)

```json
{
  "type": "ace_status",
  "data": {
    "slots": [
      {"id": 0, "color": "#FF0000", "material": "PLA", "loaded": true},
      {"id": 1, "color": "#00FF00", "material": "PLA", "loaded": true},
      {"id": 2, "color": "#0000FF", "material": "PETG", "loaded": false},
      {"id": 3, "color": "#FFFF00", "material": "PLA", "loaded": true}
    ],
    "current_slot": 0,
    "drying": false
  }
}
```

---

## Appendix C: Troubleshooting

### MQTT Connection Fails

1. **Check credentials** - Verify user/password from config file
2. **Check IP address** - Printer may have changed IP (use SSDP to discover)
3. **Check TLS** - Make sure `rejectUnauthorized: false` is set
4. **Check session** - Close official slicer (only one session allowed)

### /ctrl Returns 403

The signature algorithm is not yet reverse engineered. Use one of:
- Extract credentials from existing slicer config
- Use Cloud API instead
- Install Rinkhals firmware (if supported)

### Encrypted Config

If `machine_lan_list` is encrypted (starts with `U2FsdGVkX1`), use the decryption script in Section 3.

---

## Changelog

- **2026-01-07**: Initial public release
- Added complete decryption documentation for machine_lan_list
- Documented all known MQTT commands
- Added Frida and Ghidra analysis findings
- Marked LAN pairing signature as unsolved

---

## License

This documentation is provided for educational and interoperability purposes. All trademarks belong to their respective owners.

## Acknowledgments

- [hass-anycubic_cloud](https://github.com/WaresWichall/hass-anycubic_cloud) for initial Cloud API research
- [Rinkhals](https://github.com/jokubasver/Rinkhals) for alternative firmware approach
- The 3D printing community for testing and feedback
