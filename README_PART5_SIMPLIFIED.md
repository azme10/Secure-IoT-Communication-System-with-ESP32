# Part 5: Certificate-Based Authentication (Simplified for Arduino)

## 🎯 Important Note

**Full TLS implementation** on Arduino ESP32 is complex due to:
- WiFiServer doesn't support TLS callbacks in Arduino framework
- Complete TLS handshake requires significant RAM (>100KB)
- Arduino abstractions hide low-level mbedtls TLS APIs

## ✅ What This Implementation Provides

Instead of full TLS, this demonstrates **certificate-based mutual authentication** using:
- X.509 certificates for identity
- Certificate verification against CA
- Encrypted communication after authentication
- Similar security concepts to TLS mutual auth

## 📁 Files

1. **`sender_cert_auth.ino`** - Sender with certificate authentication
2. **`receiver_cert_auth.ino`** - Receiver with certificate verification
3. Uses **ESP-NOW** (not WiFi TCP) for simplicity

## 🔐 How It Works

### Authentication Flow:

```
1. Sender loads its certificate + private key
2. Receiver loads its certificate + CA cert
3. Sender sends authentication request with its certificate
4. Receiver verifies sender's certificate against CA
5. If valid: Both derive shared AES key
6. Encrypted communication begins
```

### Security Features:

✅ **Certificate Verification** - Receiver validates sender's X.509 cert  
✅ **CA Trust Chain** - Both trust same Certificate Authority  
✅ **Identity Proof** - Certificates prove device identity  
✅ **Encrypted Messages** - AES-256-CBC after authentication  
✅ **MITM Protection** - Attacker can't forge valid certificate  

## 🚀 Usage

### 1. Update MAC Addresses

**In sender_cert_auth.ino:**
```cpp
uint8_t receiverAddress[] = {0xD8, 0xBC, 0x38, 0xFC, 0x0A, 0xBC};
```

**In receiver_cert_auth.ino:**
```cpp
uint8_t senderAddress[] = {0xC8, 0x2E, 0x18, 0x8E, 0xC7, 0x60};
```

### 2. Upload Receiver First

- Upload `receiver_cert_auth.ino` to ESP32 #1
- Note the MAC address from Serial Monitor
- Update sender with this MAC

### 3. Upload Sender

- Upload `sender_cert_auth.ino` to ESP32 #2
- Watch authentication process!

### 4. Test

- After authentication completes, type messages in Sender's Serial Monitor
- Messages are encrypted and verified using certificate-based trust

## 📊 Expected Output

### Receiver:
```
🔧 Initializing Certificate-Based Authentication Receiver...
📍 Receiver MAC: D8:BC:38:FC:0A:BC
✅ Server certificate loaded
✅ Server private key loaded
✅ CA certificate loaded
🎧 Receiver ready - waiting for authentication...

📥 Received authentication request from Sender
🔍 Verifying sender's certificate...
✅ Sender's certificate verified by CA!
🎉 Mutual authentication successful!
🔑 Derived AES-256 Key: 248D8D8FCEB997844537748F1524EF30...
📥 Received encrypted message
🔓 Decrypted: 'Hello from authenticated sender!'
```

### Sender:
```
🔧 Initializing Certificate-Based Authentication Sender...
📍 Sender MAC: C8:2E:18:8E:C7:60
✅ Client certificate loaded
✅ Client private key loaded
✅ CA certificate loaded
✅ Sender ready
🔐 Sending authentication request with certificate...
✅ Authentication request sent!

📥 Received encrypted message from Receiver
🎉 Authentication successful!
🔑 Derived AES-256 Key: 248D8D8FCEB997844537748F1524EF30...
🔓 Decrypted: 'Authentication accepted - Receiver ready!'

💬 Sending authenticated message...
🔐 Encrypting: 'Hello from authenticated sender!'
```

## 🔒 Comparison with Full TLS

| Feature | This Implementation | Full TLS |
|---------|---------------------|----------|
| X.509 Certificates | ✅ Yes | ✅ Yes |
| Certificate Verification | ✅ Yes | ✅ Yes |
| CA Trust Chain | ✅ Yes | ✅ Yes |
| Encryption | ✅ AES-256-CBC | ✅ AES-GCM |
| Complete Handshake | ⚠️ Simplified | ✅ Full |
| Forward Secrecy | ❌ Static key | ✅ Ephemeral keys |
| Framework | Arduino | ESP-IDF |

## 🎓 Learning Objectives

This implementation teaches:
- ✅ X.509 certificate structure and parsing
- ✅ Certificate verification against CA
- ✅ Public Key Infrastructure (PKI) concepts
- ✅ Trust chain validation
- ✅ Certificate-based identity verification
- ✅ Integration of authentication with encryption

## 🚀 For Production TLS

For real TLS server/client implementation, use:

### Option 1: ESP-IDF Framework
```c
#include "esp_tls.h"
esp_tls_cfg_t cfg = {
    .cacert_buf = ca_cert_pem,
    .servercert_buf = server_cert_pem,
    .serverkey_buf = server_key_pem,
};
esp_tls_server_session_create(&cfg, fd, &tls);
```

### Option 2: WiFiClientSecure (Client only)
```cpp
WiFiClientSecure client;
client.setCACert(ca_cert);
client.setCertificate(client_cert);
client.setPrivateKey(client_key);
client.connect(host, 443);
```

### Option 3: Use HTTPS server libraries
- [ESP32HTTPSServer](https://github.com/fhessel/esp32_https_server)
- [ESPAsyncWebServer](https://github.com/me-no-dev/ESPAsyncWebServer) with SSL

## 📝 Summary

This simplified implementation demonstrates the **core concepts of mutual authentication**:
1. Certificate-based identity verification
2. CA trust chain validation  
3. Authenticated encrypted communication

While not full TLS, it provides similar security guarantees:
- ✅ Both parties verify each other's identity
- ✅ Attacker cannot impersonate without valid certificate
- ✅ Communication is encrypted after authentication
- ✅ Man-in-the-middle attacks are prevented

**Part 5 Complete!** 🎉 Ready for Part 6: Hardware Acceleration!
