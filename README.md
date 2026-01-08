# Anycubic Kobra 3 Series - Reverse Engineering Guide

This document describes the reverse engineering process for the Anycubic Kobra 3 series (Kobra 3, Kobra 3 Max, Kobra 3 Combo, etc.) LAN communication protocol.

**Purpose**: Help developers integrate with Anycubic printers via local network without depending on cloud services.

**Tested with**: Anycubic Kobra 3 Max, Firmware 2.4.6

---

## Table of Contents

1. [Overview](#overview)
2. [The Authentication Problem](#the-authentication-problem)
3. [Solution: Extract Credentials](#solution-extract-credentials-from-anycubicsslicernext)
4. [Complete Credential Extractor Script](#complete-credential-extractor-script)
5. [LAN Communication Examples](#lan-mode-communication-examples)
6. [SSDP Discovery](#ssdp-discovery)
7. [Complete Working Example](#complete-working-example)
8. [Known Model IDs](#known-model-ids)
9. [Future Work](#future-work)

---

## Overview

The Anycubic Kobra 3 series uses:
- **SSDP** for printer discovery on the local network (UDP port 1900)
- **MQTT over TLS** (port 9883) for bidirectional communication
- **HTTP** (port 8888) for file uploads
- **Dynamic credentials** generated during printer pairing

---

## The Authentication Problem

### What We Tried

We attempted to reverse engineer the complete authentication flow to generate credentials programmatically, similar to how BambuLab X1 works with a simple access code. Our efforts included:

1. **Analyzing the AnycubicSlicerNext binary** - Extracted strings and analyzed the MQTT connection logic
2. **Reverse engineering native libraries**:
   - `libmach_mqtt.dylib` - Found MQTT topic structures and commands
   - `libMachMQTT.dylib` - MQTT protocol implementation
   - `libssdplib.dylib` - SSDP discovery parameters
   - `libmqtt_client.dylib` - MQTT client wrapper
3. **Network traffic capture** - Captured MQTT handshakes during pairing
4. **Attempting mTLS with extracted certificates** - The slicer stores certificates but they are not used for auth

### Why We Couldn't Recreate It

The authentication system uses **dynamic credentials** (username/password) that are generated during the pairing process between the printer and the AnycubicSlicerNext application. This pairing likely involves:

- A challenge-response mechanism during initial handshake
- Server-side validation through Anycubic cloud during pairing
- Credentials that are unique per client and cannot be regenerated

Unlike BambuLab which uses a static "access code" printed on the printer, Anycubic generates random credentials like:
- Username: `user3HtOknyU`
- Password: `uoyASSNmUViUlnK`

**We could not find a way to generate these credentials without going through the official pairing flow.**

---

## Solution: Extract Credentials from AnycubicSlicerNext

Since we cannot recreate the pairing, we extract the already-paired credentials from the AnycubicSlicerNext configuration file.

### Step 1: Pair your printer with AnycubicSlicerNext

1. Download and install [AnycubicSlicerNext](https://www.anycubic.com/pages/anycubic-slicer)
2. Open the slicer and go to printer settings
3. Add your printer via LAN mode (scan or enter IP)
4. Complete the pairing process (QR code or manual entry)

### Step 2: Locate the configuration file

| Platform | Path |
|----------|------|
| macOS    | `~/Library/Application Support/AnycubicSlicerNext/AnycubicSlicerNext.conf` |
| Windows  | `%APPDATA%\AnycubicSlicerNext\AnycubicSlicerNext.conf` |
| Linux    | `~/.config/AnycubicSlicerNext/AnycubicSlicerNext.conf` |

### Step 3: Understand the encryption

The printer data is stored in the `machine_list_of_LAN` key, **encrypted** with a custom encoding algorithm we reverse engineered.

**Decoding Algorithm**:
1. Base64 decode the string
2. Subtract 5 from each byte (mod 256)
3. Add Base64 padding (`=`) if needed
4. Repeat steps 1-2
5. Result is JSON plaintext

### Step 4: Decoded data structure

After decoding, you get a JSON array with printer data:

```json
[
  {
    "deviceType": "fdm",
    "broker": "mqtts://192.168.0.171:9883",
    "deviceId": "4333d2cb625a1ec7099b521ec69e10c6",
    "username": "user3HtOknyU",
    "password": "uoyASSNmUViUlnK",
    "modeId": "20026",
    "modelName": "Anycubic Kobra 3 Max",
    "ip": "192.168.0.171",
    "name": "MyPrinter",
    "uuid": "uuid:fdm:70-68-71-F1-B3-C6"
  }
]
```

**Required fields for MQTT connection:**
| Field | Description | Example |
|-------|-------------|---------|
| `ip` | Printer IP address | `192.168.0.171` |
| `username` | MQTT username | `user3HtOknyU` |
| `password` | MQTT password | `uoyASSNmUViUlnK` |
| `deviceId` | 32-char device hash | `4333d2cb625a1ec7099b521ec69e10c6` |
| `modeId` | Model ID | `20026` |

---

## Complete Credential Extractor Script

Save this as `anycubic-extract-credentials.js` and run with Node.js:

```javascript
#!/usr/bin/env node
/**
 * Anycubic Credential Extractor
 * Extracts MQTT credentials from AnycubicSlicerNext configuration file
 *
 * Usage:
 *   node anycubic-extract-credentials.js
 *   node anycubic-extract-credentials.js --ip 192.168.0.171
 *   node anycubic-extract-credentials.js --json
 *
 * Requirements: Node.js 18+
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Get config file path based on platform
function getConfigPath() {
    const homeDir = os.homedir();
    const platform = os.platform();

    if (platform === 'darwin') {
        return path.join(homeDir, 'Library', 'Application Support', 'AnycubicSlicerNext', 'AnycubicSlicerNext.conf');
    } else if (platform === 'win32') {
        return path.join(homeDir, 'AppData', 'Roaming', 'AnycubicSlicerNext', 'AnycubicSlicerNext.conf');
    } else {
        return path.join(homeDir, '.config', 'AnycubicSlicerNext', 'AnycubicSlicerNext.conf');
    }
}

// Decode encrypted data from config
function anycubicDecode(encryptedData) {
    function decodeStep(data) {
        const decoded = Buffer.from(data, 'base64');
        return Buffer.from([...decoded].map(b => (b - 5 + 256) % 256));
    }

    // First pass
    let result = decodeStep(encryptedData);

    // Convert to string and add padding if needed
    let resultStr = result.toString('ascii');
    const missingPadding = resultStr.length % 4;
    if (missingPadding) {
        resultStr = resultStr + '='.repeat(4 - missingPadding);
    }

    // Second pass
    result = decodeStep(resultStr);

    return JSON.parse(result.toString('utf-8'));
}

// Read and parse credentials
function readCredentials() {
    const configPath = getConfigPath();

    if (!fs.existsSync(configPath)) {
        console.error(`Config file not found: ${configPath}`);
        console.error('Make sure AnycubicSlicerNext is installed and you have paired a printer.');
        process.exit(1);
    }

    const content = fs.readFileSync(configPath, 'utf-8');
    let rawValue = null;

    // Try JSON format first
    try {
        const jsonConfig = JSON.parse(content);
        rawValue = jsonConfig.anycubic_remote_printing?.machine_list_of_LAN
                || jsonConfig.machine_list_of_LAN;
    } catch {
        // Try INI format
        const lines = content.split('\n');
        for (const line of lines) {
            if (line.startsWith('machine_list_of_LAN')) {
                const eqIndex = line.indexOf('=');
                if (eqIndex !== -1) {
                    rawValue = line.substring(eqIndex + 1).trim();
                    break;
                }
            }
        }
    }

    if (!rawValue) {
        console.error('No printer data found in config file.');
        console.error('Make sure you have paired a printer in LAN mode.');
        process.exit(1);
    }

    // Decode if encrypted
    if (rawValue.startsWith('[')) {
        return JSON.parse(rawValue);
    } else {
        return anycubicDecode(rawValue);
    }
}

// Main
const args = process.argv.slice(2);
const filterIp = args.includes('--ip') ? args[args.indexOf('--ip') + 1] : null;
const jsonOutput = args.includes('--json');

const printers = readCredentials().map(m => ({
    name: m.name,
    ip: m.ip,
    modelName: m.modelName,
    modeId: m.modeId,
    deviceId: m.deviceId,
    username: m.username,
    password: m.password,
}));

const filtered = filterIp ? printers.filter(p => p.ip === filterIp) : printers;

if (jsonOutput) {
    console.log(JSON.stringify(filtered, null, 2));
} else {
    console.log(`\nFound ${filtered.length} printer(s):\n`);
    for (const p of filtered) {
        console.log(`  Name:     ${p.name}`);
        console.log(`  Model:    ${p.modelName}`);
        console.log(`  IP:       ${p.ip}`);
        console.log(`  Mode ID:  ${p.modeId}`);
        console.log(`  Device:   ${p.deviceId}`);
        console.log(`  Username: ${p.username}`);
        console.log(`  Password: ${p.password}`);
        console.log('');
    }
}
```

Run it:
```bash
node anycubic-extract-credentials.js
```

Output:
```
Found 1 printer(s):

  Name:     Zeta
  Model:    Anycubic Kobra 3 Max
  IP:       192.168.0.171
  Mode ID:  20026
  Device:   4333d2cb625a1ec7099b521ec69e10c6
  Username: user3HtOknyU
  Password: uoyASSNmUViUlnK
```

---

## LAN Mode Communication Examples

### MQTT Topics Structure

**Publish (Client -> Printer):**
```
anycubic/anycubicCloud/v1/slicer/printer/{modeId}/{deviceId}/{action}
```

**Subscribe (Printer -> Client):**
```
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/response
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/info/report
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/print/report
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/fan/report
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/multiColorBox/report
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/peripherie/report
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/light/report
anycubic/anycubicCloud/v1/printer/public/{modeId}/{deviceId}/file/report
```

### Message Format

All messages use this JSON structure:

```json
{
    "type": "info",
    "action": "query",
    "msgid": "unique-uuid-here",
    "timestamp": 1704672000000,
    "data": {}
}
```

### Available Commands

| Command | Topic Suffix | Description |
|---------|-------------|-------------|
| `info` | `/info` | Query printer information |
| `print` | `/print` | Start print job |
| `pause` | `/pause` | Pause current print |
| `resume` | `/resume` | Resume paused print |
| `stop` | `/stop` | Stop current print |
| `cancel` | `/cancel` | Cancel current print |
| `tempature` | `/tempature` | Set temperature (note: typo in protocol) |
| `preheating` | `/preheating` | Preheat nozzle and bed |
| `listLocal` | `/listLocal` | List local files |
| `listUdisk` | `/listUdisk` | List USB files |
| `deleteLocal` | `/deleteLocal` | Delete local file |
| `deleteUdisk` | `/deleteUdisk` | Delete USB file |
| `multiColorBox` | `/multiColorBox` | Query ACE status |
| `light` | `/light` | Control LED light |
| `axis` | `/axis` | Home axes |
| `move` | `/move` | Move axis |
| `levelling` | `/levelling` | Auto-leveling |
| `fan` | `/fan` | Control fans |

---

## SSDP Discovery

Discover printers on the network without credentials. Save as `anycubic-discover.js`:

```javascript
#!/usr/bin/env node
/**
 * Anycubic Printer Discovery via SSDP
 * Finds all Anycubic printers on the local network
 *
 * Usage: node anycubic-discover.js
 * Requirements: Node.js 18+
 */

const dgram = require('dgram');

const SSDP_MULTICAST_IP = '239.255.255.250';
const SSDP_PORT = 1900;
const TIMEOUT_MS = 5000;

const message = [
    'M-SEARCH * HTTP/1.1',
    `Host: ${SSDP_MULTICAST_IP}:${SSDP_PORT}`,
    'ST: ac:3dprinter',
    'Man: "ssdp:discover"',
    'MX: 5',
    '',
    ''
].join('\r\n');

function parseSsdpResponse(response, ip) {
    const info = { ip };
    const lines = response.split('\r\n');

    for (const line of lines) {
        const colonIndex = line.indexOf(':');
        if (colonIndex > 0) {
            const key = line.substring(0, colonIndex).trim().toLowerCase();
            const value = line.substring(colonIndex + 1).trim();
            info[key] = value;
        }
    }

    // Extract query params from ST header
    if (info.st && info.st.includes('?')) {
        const queryStart = info.st.indexOf('?');
        const params = new URLSearchParams(info.st.substring(queryStart));
        info.modelId = params.get('modelId');
        info.cn = params.get('cn'); // Access code if available
    }

    return info;
}

console.log('Searching for Anycubic printers...\n');

const printers = [];
const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

socket.on('message', (msg, rinfo) => {
    const response = msg.toString();
    if (response.includes('ac:3dprinter')) {
        const printer = parseSsdpResponse(response, rinfo.address);
        printers.push(printer);
        console.log(`Found: ${printer.ip}`);
        if (printer.modelId) console.log(`  Model ID: ${printer.modelId}`);
        if (printer.usn) console.log(`  USN: ${printer.usn}`);
        console.log('');
    }
});

socket.on('error', (err) => {
    console.error('Socket error:', err.message);
});

socket.bind(() => {
    socket.setBroadcast(true);
    socket.setMulticastTTL(4);
    socket.send(message, 0, message.length, SSDP_PORT, SSDP_MULTICAST_IP);
});

setTimeout(() => {
    socket.close();
    console.log(`\nDiscovery complete. Found ${printers.length} printer(s).`);
    if (printers.length === 0) {
        console.log('Make sure your printer is on and connected to the same network.');
    }
}, TIMEOUT_MS);
```

---

## Complete Working Example

Save this as `anycubic-client.js`. This is a complete, standalone script:

```javascript
#!/usr/bin/env node
/**
 * Anycubic Kobra 3 LAN Client - Complete Example
 *
 * Usage:
 *   node anycubic-client.js --ip 192.168.0.171 --username user3HtOknyU --password uoyASSNmUViUlnK --deviceId 4333d2cb625a1ec7099b521ec69e10c6 --modeId 20026
 *
 * Or use with extracted credentials from config:
 *   node anycubic-client.js --from-config
 *
 * Requirements:
 *   npm install mqtt
 */

const mqtt = require('mqtt');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ============ CREDENTIAL EXTRACTION ============

function getConfigPath() {
    const homeDir = os.homedir();
    const platform = os.platform();
    if (platform === 'darwin') {
        return path.join(homeDir, 'Library', 'Application Support', 'AnycubicSlicerNext', 'AnycubicSlicerNext.conf');
    } else if (platform === 'win32') {
        return path.join(homeDir, 'AppData', 'Roaming', 'AnycubicSlicerNext', 'AnycubicSlicerNext.conf');
    }
    return path.join(homeDir, '.config', 'AnycubicSlicerNext', 'AnycubicSlicerNext.conf');
}

function anycubicDecode(encryptedData) {
    function decodeStep(data) {
        const decoded = Buffer.from(data, 'base64');
        return Buffer.from([...decoded].map(b => (b - 5 + 256) % 256));
    }
    let result = decodeStep(encryptedData);
    let resultStr = result.toString('ascii');
    const missingPadding = resultStr.length % 4;
    if (missingPadding) resultStr += '='.repeat(4 - missingPadding);
    result = decodeStep(resultStr);
    return JSON.parse(result.toString('utf-8'));
}

function readCredentialsFromConfig() {
    const configPath = getConfigPath();
    if (!fs.existsSync(configPath)) {
        throw new Error(`Config not found: ${configPath}`);
    }
    const content = fs.readFileSync(configPath, 'utf-8');
    let rawValue = null;
    try {
        const json = JSON.parse(content);
        rawValue = json.anycubic_remote_printing?.machine_list_of_LAN || json.machine_list_of_LAN;
    } catch {
        for (const line of content.split('\n')) {
            if (line.startsWith('machine_list_of_LAN')) {
                rawValue = line.substring(line.indexOf('=') + 1).trim();
                break;
            }
        }
    }
    if (!rawValue) throw new Error('No printer data in config');
    const machines = rawValue.startsWith('[') ? JSON.parse(rawValue) : anycubicDecode(rawValue);
    return machines[0]; // Return first printer
}

// ============ MQTT CLIENT ============

function createClient(config) {
    const { ip, username, password, deviceId, modeId } = config;
    const port = 9883;

    const publishBase = `anycubic/anycubicCloud/v1/slicer/printer/${modeId}/${deviceId}`;
    const subscribeBase = `anycubic/anycubicCloud/v1/printer/public/${modeId}/${deviceId}`;

    console.log(`Connecting to ${ip}:${port}...`);
    console.log(`  Device ID: ${deviceId}`);
    console.log(`  Mode ID: ${modeId}`);
    console.log('');

    const client = mqtt.connect(`mqtts://${ip}:${port}`, {
        username,
        password,
        rejectUnauthorized: false,
        reconnectPeriod: 5000,
        keepalive: 60,
    });

    client.on('connect', () => {
        console.log('Connected!\n');

        // Subscribe to all printer topics
        client.subscribe(`${subscribeBase}/#`, (err) => {
            if (err) {
                console.error('Subscribe error:', err.message);
                return;
            }
            console.log('Subscribed to printer topics.\n');

            // Query printer info
            console.log('Querying printer info...\n');
            const msg = {
                type: 'info',
                action: 'query',
                msgid: crypto.randomUUID(),
                timestamp: Date.now(),
            };
            client.publish(`${publishBase}/info`, JSON.stringify(msg));
        });
    });

    client.on('message', (topic, message) => {
        try {
            const data = JSON.parse(message.toString());
            const shortTopic = topic.replace(subscribeBase + '/', '');

            console.log(`[${shortTopic}]`);
            console.log(JSON.stringify(data, null, 2));
            console.log('');

            // Show useful info from info/report
            if (data.type === 'info' && data.data) {
                const info = data.data;
                console.log('=== Printer Status ===');
                console.log(`  Name:        ${info.printerName}`);
                console.log(`  Model:       ${info.model}`);
                console.log(`  Firmware:    ${info.version}`);
                console.log(`  State:       ${info.state}`);
                console.log(`  Nozzle:      ${info.temp?.curr_nozzle_temp}C / ${info.temp?.target_nozzle_temp}C`);
                console.log(`  Bed:         ${info.temp?.curr_hotbed_temp}C / ${info.temp?.target_hotbed_temp}C`);
                if (info.project?.filename) {
                    console.log(`  Printing:    ${info.project.filename}`);
                    console.log(`  Progress:    ${info.project.progress}%`);
                    console.log(`  Layer:       ${info.project.curr_layer}/${info.project.total_layers}`);
                }
                console.log('');
            }
        } catch (e) {
            console.log(`[RAW] ${topic}: ${message.toString()}`);
        }
    });

    client.on('error', (err) => {
        console.error('MQTT Error:', err.message);
    });

    client.on('close', () => {
        console.log('Connection closed.');
    });

    // Helper functions
    return {
        client,

        sendCommand(action, data = {}) {
            const msg = {
                action,
                msgid: crypto.randomUUID(),
                timestamp: Math.floor(Date.now() / 1000),
                data,
            };
            client.publish(`${publishBase}/${action}`, JSON.stringify(msg));
            console.log(`Sent: ${action}`);
        },

        queryInfo() {
            const msg = {
                type: 'info',
                action: 'query',
                msgid: crypto.randomUUID(),
                timestamp: Date.now(),
            };
            client.publish(`${publishBase}/info`, JSON.stringify(msg));
        },

        pause() { this.sendCommand('pause'); },
        resume() { this.sendCommand('resume'); },
        stop() { this.sendCommand('stop'); },

        setNozzleTemp(temp) {
            this.sendCommand('tempature', { target: 'nozzle', temp });
        },

        setBedTemp(temp) {
            this.sendCommand('tempature', { target: 'bed', temp });
        },

        listFiles() { this.sendCommand('listLocal'); },

        setLight(on) {
            this.sendCommand('light', { status: on ? 1 : 0, brightness: on ? 100 : 0 });
        },

        disconnect() { client.end(); },
    };
}

// ============ MAIN ============

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Anycubic Kobra 3 LAN Client

Usage:
  node anycubic-client.js --from-config
  node anycubic-client.js --ip <IP> --username <USER> --password <PASS> --deviceId <ID> --modeId <MODE>

Options:
  --from-config    Read credentials from AnycubicSlicerNext config file
  --ip             Printer IP address
  --username       MQTT username
  --password       MQTT password
  --deviceId       Device ID (32-char hash)
  --modeId         Mode ID (e.g., 20026 for Kobra 3 Max)
`);
    process.exit(0);
}

let config;

if (args.includes('--from-config')) {
    try {
        const creds = readCredentialsFromConfig();
        config = {
            ip: creds.ip,
            username: creds.username,
            password: creds.password,
            deviceId: creds.deviceId,
            modeId: creds.modeId,
        };
        console.log(`Using credentials for: ${creds.name || creds.ip}\n`);
    } catch (e) {
        console.error('Error reading config:', e.message);
        process.exit(1);
    }
} else {
    const getArg = (name) => {
        const idx = args.indexOf(`--${name}`);
        return idx !== -1 ? args[idx + 1] : null;
    };

    config = {
        ip: getArg('ip'),
        username: getArg('username'),
        password: getArg('password'),
        deviceId: getArg('deviceId'),
        modeId: getArg('modeId'),
    };

    if (!config.ip || !config.username || !config.password || !config.deviceId || !config.modeId) {
        console.error('Missing required arguments. Use --help for usage.');
        process.exit(1);
    }
}

const printer = createClient(config);

// Keep running and handle Ctrl+C
process.on('SIGINT', () => {
    console.log('\nDisconnecting...');
    printer.disconnect();
    process.exit(0);
});
```

Install dependency and run:
```bash
npm install mqtt
node anycubic-client.js --from-config
```

---

## Response Examples

### info/report Response

```json
{
  "type": "info",
  "action": "report",
  "timestamp": 1767808006302,
  "msgid": "unique-uuid",
  "state": "done",
  "code": 200,
  "msg": "done",
  "data": {
    "printerName": "Zeta",
    "model": "Anycubic Kobra 3 Max",
    "ip": "192.168.0.171",
    "version": "2.4.6",
    "state": "idle",
    "temp": {
      "curr_hotbed_temp": 25,
      "curr_nozzle_temp": 28,
      "target_hotbed_temp": 0,
      "target_nozzle_temp": 0
    },
    "project": {
      "remain_time": 0,
      "curr_layer": 0,
      "total_layers": 0,
      "progress": 0,
      "print_status": 0,
      "filename": ""
    },
    "urls": {
      "fileUploadurl": "http://192.168.0.171:18910/gcode_upload?s=TOKEN",
      "rtspUrl": "http://192.168.0.171:18088/flv"
    },
    "print_speed_mode": 2,
    "fan_speed_pct": 0,
    "features": {
      "auto_leveling_support": true,
      "vibration_compensation_support": true,
      "flow_calibration_support": true,
      "camera_timelapse_support": true
    }
  }
}
```

### multiColorBox/report (ACE) Response

```json
{
  "type": "multiColorBox",
  "action": "getInfo",
  "code": 200,
  "data": {
    "multi_color_box": [
      {
        "id": 0,
        "status": 1,
        "auto_feed": 1,
        "loaded_slot": 0,
        "temp": 37,
        "drying_status": {
          "status": 0,
          "target_temp": 0,
          "remain_time": 0
        },
        "slots": [
          {
            "index": 0,
            "type": "PETG",
            "color": [255, 255, 255],
            "status": 5
          },
          {
            "index": 1,
            "type": "PLA",
            "color": [0, 0, 0],
            "status": 5
          },
          {
            "index": 2,
            "type": "PLA",
            "color": [255, 0, 0],
            "status": 4
          },
          {
            "index": 3,
            "type": "PLA",
            "color": [0, 255, 0],
            "status": 4
          }
        ]
      }
    ]
  }
}
```

**Slot status values:**
- `4` = Empty
- `5` = Filament loaded

### print/report Response (during printing)

```json
{
  "type": "print",
  "action": "start",
  "state": "printing",
  "code": 200,
  "data": {
    "curr_layer": 16,
    "total_layers": 155,
    "filename": "MyModel.gcode",
    "print_time": 130,
    "progress": 16,
    "remain_time": 257,
    "supplies_usage": 19821,
    "taskid": "613940378"
  }
}
```

---

## File Upload via HTTP

Files can be uploaded via HTTP POST to port 8888. Save as `anycubic-upload.js`:

```javascript
#!/usr/bin/env node
/**
 * Upload GCode file to Anycubic Kobra 3
 *
 * Usage: node anycubic-upload.js --ip 192.168.0.171 --file model.gcode
 *
 * Requirements:
 *   npm install axios form-data
 */

const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const getArg = (name) => {
    const idx = args.indexOf(`--${name}`);
    return idx !== -1 ? args[idx + 1] : null;
};

const ip = getArg('ip');
const filePath = getArg('file');

if (!ip || !filePath) {
    console.log('Usage: node anycubic-upload.js --ip <IP> --file <path>');
    process.exit(1);
}

if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(1);
}

const filename = path.basename(filePath);
const fileStream = fs.createReadStream(filePath);
const fileSize = fs.statSync(filePath).size;

const form = new FormData();
form.append('file', fileStream, {
    filename,
    contentType: 'application/octet-stream',
});

console.log(`Uploading ${filename} (${(fileSize / 1024 / 1024).toFixed(2)} MB) to ${ip}...`);

axios.post(`http://${ip}:8888/uploadGcode`, form, {
    headers: form.getHeaders(),
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    timeout: 600000, // 10 minutes
    onUploadProgress: (progress) => {
        if (progress.total) {
            const pct = Math.round((progress.loaded * 100) / progress.total);
            process.stdout.write(`\rProgress: ${pct}%`);
        }
    },
})
.then((response) => {
    console.log('\nUpload complete!');
    console.log('Response:', response.data);
})
.catch((error) => {
    console.error('\nUpload failed:', error.message);
    process.exit(1);
});
```

---

## Known Model IDs

| Model | modeId |
|-------|--------|
| Kobra 3 Max | 20026 |
| Kobra 3 | 20025 |
| Kobra 3 V2 | 20027 |
| Kobra S1 | 20028 |
| Kobra 2 Pro | 20015 |
| Kobra 2 Plus | 20014 |
| Kobra 2 Max | 20013 |

---

## References

- [hass-anycubic_cloud](https://github.com/WaresWichall/hass-anycubic_cloud) - Home Assistant integration (cloud mode only)
- AnycubicSlicerNext binaries analyzed (macOS):
  - `libssdplib.dylib` - SSDP discovery protocol
  - `libmach_mqtt.dylib` - MQTT local client
  - `libMachMQTT.dylib` - MQTT protocol implementation
  - `libmqtt_client.dylib` - MQTT client wrapper

---

## Future Work

Areas that need more reverse engineering:

1. **Pairing protocol** - How to generate credentials without the official app. The printer and slicer exchange credentials during initial pairing, likely using a challenge-response mechanism.

2. **Access code retrieval** - The protocol has a `get_access_code` system command, but it requires existing authentication to use.

3. **Camera streaming** - The `rtspUrl` provided is actually FLV over HTTP (port 18088), not RTSP. Parsing requires FLV demuxing.

4. **Cloud API authentication** - The cloud API uses `XX-Token` header, but the token generation/login flow hasn't been documented.

5. **Print from cloud** - Starting a print from cloud-stored files requires additional API calls.

---

## Contributing

If you discover more about the protocol, please share:
- New commands or message formats
- The pairing/authentication flow
- Cloud API endpoints
- Camera stream parsing

---

**License**: This documentation is provided for educational purposes. Use at your own risk.

*Last updated: 2026-01-08*
*Tested with: Anycubic Kobra 3 Max, Firmware 2.4.6*

