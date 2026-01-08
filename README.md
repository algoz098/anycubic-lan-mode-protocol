# Anycubic Kobra 3 Series - Reverse Engineering Guide

This document describes the reverse engineering process for the Anycubic Kobra 3 series (Kobra 3, Kobra 3 Max, Kobra 3 Combo, etc.) LAN communication protocol.

**Purpose**: Help other developers continue the reverse engineering work and integrate with Anycubic printers.

## Overview

The Anycubic Kobra 3 series uses:
- **SSDP** for printer discovery on the local network
- **MQTT over TLS** (port 9883) for bidirectional communication
- **Dynamic credentials** generated during printer pairing

## Authentication Problem

### What We Tried

We attempted to reverse engineer the complete authentication flow to generate credentials programmatically, similar to how BambuLab X1 works with a simple access code. Our efforts included:

1. **Analyzing the AnycubicSlicerNext binary** - Extracted strings and analyzed the MQTT connection logic
2. **Reverse engineering libmach_mqtt.dylib and libMachMQTT.dylib** - Found MQTT topic structures and commands
3. **Analyzing libssdplib.dylib** - Found SSDP discovery parameters
4. **Network traffic capture** - Captured MQTT handshakes during pairing
5. **Attempting mTLS with extracted certificates** - The slicer stores certificates but they are not used for auth

### Why We Couldn't Recreate It

The authentication system uses **dynamic credentials** (username/password) that are generated during the pairing process between the printer and the AnycubicSlicerNext application. This pairing likely involves:

- A challenge-response mechanism during initial handshake
- Server-side validation through Anycubic cloud during pairing
- Credentials that are unique per client and cannot be regenerated

Unlike BambuLab which uses a static "access code" printed on the printer, Anycubic generates random credentials like:
- Username: `user3HtOknyU`
- Password: `uoyASSNmUViUlnK`

**We could not find a way to generate these credentials without going through the official pairing flow.**

## Solution: Extract Credentials from AnycubicSlicerNext

Since we cannot recreate the pairing, we extract the already-paired credentials from the AnycubicSlicerNext configuration file.

### Step 1: Pair your printer with AnycubicSlicerNext

1. Download and install [AnycubicSlicerNext](https://www.anycubic.com/pages/anycubic-slicer)
2. Connect to your printer via LAN mode
3. Complete the pairing process (QR code or manual)

### Step 2: Locate the configuration file

| Platform | Path |
|----------|------|
| macOS    | `~/Library/Application Support/AnycubicSlicerNext/AnycubicSlicerNext.conf` |
| Windows  | `%APPDATA%\AnycubicSlicerNext\AnycubicSlicerNext.conf` |
| Linux    | `~/.config/AnycubicSlicerNext/AnycubicSlicerNext.conf` |

### Step 3: Decode the credentials

The printer data is stored in the `machine_list_of_LAN` key, **encrypted** with a custom encoding.

**Decoding Algorithm** (discovered via reverse engineering):

```javascript
function anycubicDecode(encryptedData) {
    function decodeStep(data) {
        // 1. Decode base64
        const decoded = Buffer.from(data, 'base64')
        // 2. Subtract 5 from each byte (mod 256)
        return Buffer.from([...decoded].map(b => (b - 5 + 256) % 256))
    }

    // First pass
    let result = decodeStep(encryptedData)

    // Convert to string and add padding if needed
    let resultStr = result.toString('ascii')
    const missingPadding = resultStr.length % 4
    if (missingPadding) {
        resultStr = resultStr + '='.repeat(4 - missingPadding)
    }

    // Second pass
    result = decodeStep(resultStr)

    // Parse JSON
    return JSON.parse(result.toString('utf-8'))
}
```

The algorithm:
1. Base64 decode
2. Subtract 5 from each byte (mod 256)
3. Add padding if needed
4. Repeat steps 1-2
5. Result is JSON plaintext

### Step 4: Extract required fields

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
    "name": "MyPrinter"
  }
]
```

Required fields for connection:
- `ip` - Printer IP address
- `username` - MQTT username
- `password` - MQTT password
- `deviceId` - 32-char device hash
- `modeId` - Model ID (e.g., "20026" for Kobra 3 Max)

## LAN Mode Communication Examples

### MQTT Connection

```javascript
import mqtt from 'mqtt'

const ip = '192.168.0.171'
const port = 9883
const username = 'user3HtOknyU'      // From extracted credentials
const password = 'uoyASSNmUViUlnK'   // From extracted credentials
const deviceId = '4333d2cb625a1ec7099b521ec69e10c6'
const modeId = '20026'

const client = mqtt.connect(`mqtts://${ip}:${port}`, {
    username,
    password,
    rejectUnauthorized: false,  // Self-signed cert
    reconnectPeriod: 5000,
    keepalive: 60,
})

// Subscribe to printer responses
const subscribeTopic = `anycubic/anycubicCloud/v1/printer/public/${modeId}/${deviceId}/#`
client.subscribe(subscribeTopic)

client.on('message', (topic, message) => {
    const data = JSON.parse(message.toString())
    console.log('Received:', topic, data)
})
```

### MQTT Topics

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
```

### Query Printer Info

```javascript
const publishTopic = `anycubic/anycubicCloud/v1/slicer/printer/${modeId}/${deviceId}/info`

const message = {
    type: 'info',
    action: 'query',
    msgid: crypto.randomUUID(),
    timestamp: Date.now(),
}

client.publish(publishTopic, JSON.stringify(message))
```

Response on `{base}/info/report`:
```json
{
  "type": "info",
  "action": "report",
  "code": 200,
  "data": {
    "printerName": "MyPrinter",
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
      "progress": 0,
      "print_status": 0,
      "filename": ""
    },
    "urls": {
      "fileUploadurl": "http://192.168.0.171:18910/gcode_upload?s=TOKEN",
      "rtspUrl": "http://192.168.0.171:18088/flv"
    }
  }
}
```

### Control Print Job

```javascript
// Pause print
client.publish(
    `anycubic/anycubicCloud/v1/slicer/printer/${modeId}/${deviceId}/pause`,
    JSON.stringify({
        action: 'pause',
        msgid: crypto.randomUUID(),
        timestamp: Math.floor(Date.now() / 1000),
        data: {}
    })
)

// Resume print
client.publish(
    `anycubic/anycubicCloud/v1/slicer/printer/${modeId}/${deviceId}/resume`,
    JSON.stringify({
        action: 'resume',
        msgid: crypto.randomUUID(),
        timestamp: Math.floor(Date.now() / 1000),
        data: {}
    })
)

// Stop print
client.publish(
    `anycubic/anycubicCloud/v1/slicer/printer/${modeId}/${deviceId}/stop`,
    JSON.stringify({
        action: 'stop',
        msgid: crypto.randomUUID(),
        timestamp: Math.floor(Date.now() / 1000),
        data: {}
    })
)
```

### Set Temperature

```javascript
// Note: The protocol has a typo - it uses "tempature" not "temperature"
client.publish(
    `anycubic/anycubicCloud/v1/slicer/printer/${modeId}/${deviceId}/tempature`,
    JSON.stringify({
        action: 'tempature',
        msgid: crypto.randomUUID(),
        timestamp: Math.floor(Date.now() / 1000),
        data: {
            target: 'nozzle',  // or 'bed'
            temp: 200
        }
    })
)
```

### Query ACE (Multi Color Box)

```javascript
client.publish(
    `anycubic/anycubicCloud/v1/slicer/printer/${modeId}/${deviceId}/multiColorBox`,
    JSON.stringify({
        action: 'multiColorBox',
        msgid: crypto.randomUUID(),
        timestamp: Math.floor(Date.now() / 1000),
        data: {}
    })
)
```

### Upload GCode File

Files can be uploaded via HTTP to port 8888:

```javascript
import FormData from 'form-data'
import axios from 'axios'
import fs from 'fs'

const form = new FormData()
form.append('file', fs.createReadStream('/path/to/file.gcode'), {
    filename: 'myprint.gcode',
    contentType: 'application/octet-stream',
})

await axios.post(`http://${ip}:8888/uploadGcode`, form, {
    headers: form.getHeaders(),
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
})
```

## SSDP Discovery

You can discover printers on the network without credentials:

```javascript
import dgram from 'dgram'

const SSDP_MULTICAST_IP = '239.255.255.250'
const SSDP_PORT = 1900

const message = [
    'M-SEARCH * HTTP/1.1',
    `Host: ${SSDP_MULTICAST_IP}:${SSDP_PORT}`,
    'ST: ac:3dprinter',
    'Man: "ssdp:discover"',
    'MX: 5',
    '',
    ''
].join('\r\n')

const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })

socket.on('message', (msg, rinfo) => {
    console.log(`Printer found at ${rinfo.address}:`)
    console.log(msg.toString())
})

socket.bind(() => {
    socket.setBroadcast(true)
    socket.setMulticastTTL(4)
    socket.send(message, 0, message.length, SSDP_PORT, SSDP_MULTICAST_IP)
})

setTimeout(() => socket.close(), 5000)
```

## Known Model IDs

| Model             | modeId |
|-------------------|--------|
| Kobra 3 Max       | 20026  |
| Kobra 3           | 20025  |
| Kobra 3 V2        | 20027  |
| Kobra S1          | 20028  |
| Kobra 2 Pro       | 20015  |

## CLI Tool

We provide a CLI tool to extract credentials:

```bash
# List all paired printers
node src/cli/anycubic-config.js

# Filter by IP
node src/cli/anycubic-config.js --ip 192.168.0.171

# Export as JSON
node src/cli/anycubic-config.js --json

# Decode encrypted string directly
node src/cli/anycubic-config.js --decode "Xk5Gc2ZcdTxn..."
```

## References

- [hass-anycubic_cloud](https://github.com/WaresWichall/hass-anycubic_cloud) - Home Assistant integration (cloud mode)
- AnycubicSlicerNext binaries analyzed:
  - `libssdplib.dylib` - SSDP discovery
  - `libmach_mqtt.dylib` - MQTT local client
  - `libMachMQTT.dylib` - MQTT protocol
  - `libmqtt_client.dylib` - MQTT client wrapper

## Future Work

Areas that need more reverse engineering:

1. **Pairing protocol** - How to generate credentials without the official app
2. **Access code retrieval** - The protocol has a `get_access_code` command but it requires existing auth
3. **Camera streaming** - The `rtspUrl` is FLV over HTTP, not actual RTSP
4. **Cloud API authentication** - Uses XX-Token header but token generation is unknown

---

*Last updated: 2026-01-08*
*Tested with: Anycubic Kobra 3 Max, Firmware 2.4.6*

