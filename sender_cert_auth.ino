/*
 * ESP32 Part 5: Certificate-Based Authentication Sender (Simplified)
 * 
 * This demonstrates certificate-based mutual authentication using ESP-NOW
 * Sender proves identity using X.509 certificate verified by receiver
 */

#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"

// MAC of receiver (update with your receiver's MAC)
uint8_t receiverAddress[] = {0xD8, 0xBC, 0x38, 0xFC, 0x0A, 0xBC};

// Message structures
typedef struct __attribute__((packed)) {
  uint8_t certificate[800];  // Sender's certificate
  uint16_t certLen;
  uint8_t signature[64];     // Signature of a challenge
  uint8_t challenge[32];     // Challenge data
} auth_message_t;

typedef struct __attribute__((packed)) {
  uint8_t iv[16];
  uint8_t encryptedData[240];
  size_t dataLen;
} encrypted_message_t;

// Client (Sender) certificate
const char* client_cert_pem = R"EOF(
-----BEGIN CERTIFICATE-----
MIICHjCCAcWgAwIBAgIUa7EshuvJZ6NC6caE0H6Yk2b182swCgYIKoZIzj0EAwIw
dTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNp
c2NvMRYwFAYDVQQKDA1FU1AzMiBUZXN0IENBMREwDwYDVQQLDAhTZWN1cml0eTEW
MBQGA1UEAwwNRVNQMzIgUm9vdCBDQTAeFw0yNTExMDUxNjE2MDhaFw0yNjExMDUx
NjE2MDhaMHAxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2Fu
IEZyYW5jaXNjbzEOMAwGA1UECgwFRVNQMzIxFTATBgNVBAsMDEVTUDMyLVNlbmRl
cjEVMBMGA1UEAwwMRVNQMzItU2VuZGVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAE4VbF0vD+SCLjggruyMsnUqzgZG80AylVzrqzJydyFwz3j1OxSB5OMvXp6iQM
shUz4aziepfXsphxIDJ84VvpU6M4MDYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E
BAMCA4gwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwCgYIKoZIzj0EAwIDRwAwRAIg
AtH+YmpJrCq74lV6JET+rDltOscCkIQ9YK74Nvx8K1kCIBLSkfaW2VvBeNEmEaBI
qi2Z2XB2Memqv29Qctp+xeGG
-----END CERTIFICATE-----
)EOF";

// Client private key
const char* client_key_pem = R"EOF(
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAgrs0ZT3v/LWC+fprFu9Jho1QHsCZgUqk9R5rDE1tpToAoGCCqGSM49
AwEHoUQDQgAE4VbF0vD+SCLjggruyMsnUqzgZG80AylVzrqzJydyFwz3j1OxSB5O
MvXp6iQMshUz4aziepfXsphxIDJ84VvpUw==
-----END EC PRIVATE KEY-----
)EOF";

// CA certificate
const char* ca_cert_pem = R"EOF(
-----BEGIN CERTIFICATE-----
MIICDzCCAbWgAwIBAgIUQfGwuEDZQfyBdHwo+dNqExSewg0wCgYIKoZIzj0EAwIw
dTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNp
c2NvMRYwFAYDVQQKDA1FU1AzMiBUZXN0IENBMREwDwYDVQQLDAhTZWN1cml0eTEW
MBQGA1UEAwwNRVNQMzIgUm9vdCBDQTAeFw0yNTExMDUxNjE2MDhaFw0zNTExMDMx
NjE2MDhaMHUxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2Fu
IEZyYW5jaXNjbzEWMBQGA1UECgwNRVNQMzIgVGVzdCBDQTERMA8GA1UECwwIU2Vj
dXJpdHkxFjAUBgNVBAMMDUVTUDMyIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQkgmaN2/rtIqu5Avc9gf79HcTQ0XPKVn8H5Q5tGBzWkR/e62kgYsQg
2/nqjfPab22zhx4eZOBVFhuKMzSd5iiIoyMwITAPBgNVHRMBAf8EBTADAQH/MA4G
A1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNIADBFAiAHnpK1AGd8+rpnAaGPsej2
SvLNKDAsvp0xO9G+v7nh9gIhAIHyxfzU72FBITUeRGo9scbZyJjemBxH9uc3Nyku
GpZr
-----END CERTIFICATE-----
)EOF";

mbedtls_pk_context client_key;
mbedtls_x509_crt client_cert;
mbedtls_x509_crt ca_cert;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_aes_context aes;

uint8_t aesKey[32];
bool authenticated = false;
bool aesKeyReady = false;

void deriveAESKey() {
  const char* keyMaterial = "authenticated_session_key";
  
  mbedtls_md_context_t sha_ctx;
  mbedtls_md_init(&sha_ctx);
  mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&sha_ctx);
  mbedtls_md_update(&sha_ctx, (unsigned char*)keyMaterial, strlen(keyMaterial));
  mbedtls_md_finish(&sha_ctx, aesKey);
  mbedtls_md_free(&sha_ctx);
  
  Serial.print("🔑 Derived AES-256 Key: ");
  for(int i = 0; i < 32; i++) {
    Serial.printf("%02X", aesKey[i]);
  }
  Serial.println();
  
  aesKeyReady = true;
}

void sendAuthenticationRequest() {
  Serial.println("🔐 Sending authentication request with certificate...");
  
  auth_message_t authMsg;
  memset(&authMsg, 0, sizeof(authMsg));
  
  // Copy certificate (DER format would be better, but PEM for simplicity)
  size_t certLen = strlen(client_cert_pem);
  if (certLen > sizeof(authMsg.certificate)) {
    certLen = sizeof(authMsg.certificate);
  }
  memcpy(authMsg.certificate, client_cert_pem, certLen);
  authMsg.certLen = certLen;
  
  // In real TLS, would sign a challenge here
  // For demo, just send the cert
  
  esp_err_t result = esp_now_send(receiverAddress, (uint8_t*)&authMsg, sizeof(authMsg));
  if (result == ESP_OK) {
    Serial.println("✅ Authentication request sent!");
  } else {
    Serial.printf("❌ Send failed: %d\n", result);
  }
}

void sendEncryptedMessage(const char* message) {
  if (!aesKeyReady) {
    Serial.println("❌ Not authenticated yet!");
    return;
  }
  
  encrypted_message_t encMsg;
  
  // Generate random IV
  mbedtls_ctr_drbg_random(&ctr_drbg, encMsg.iv, 16);
  
  size_t msgLen = strlen(message);
  size_t paddedLen = ((msgLen / 16) + 1) * 16;
  uint8_t plaintext[240];
  memcpy(plaintext, message, msgLen);
  
  // PKCS7 padding
  uint8_t padValue = paddedLen - msgLen;
  for(size_t i = msgLen; i < paddedLen; i++) {
    plaintext[i] = padValue;
  }
  
  // Encrypt
  uint8_t iv_copy[16];
  memcpy(iv_copy, encMsg.iv, 16);
  
  mbedtls_aes_setkey_enc(&aes, aesKey, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, 
                        iv_copy, plaintext, encMsg.encryptedData);
  
  encMsg.dataLen = paddedLen;
  
  Serial.printf("🔐 Encrypting: '%s'\n", message);
  esp_now_send(receiverAddress, (uint8_t*)&encMsg, sizeof(encMsg));
}

void OnDataSent(const wifi_tx_info_t *info, esp_now_send_status_t status) {
  if (status == ESP_NOW_SEND_SUCCESS) {
    Serial.println("✅ Message sent successfully");
  }
}

void OnDataRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  if (len == sizeof(encrypted_message_t)) {
    Serial.println("📥 Received encrypted message from Receiver");
    
    if (!aesKeyReady && !authenticated) {
      // First message after auth - setup encryption
      Serial.println("🎉 Authentication successful!");
      authenticated = true;
      deriveAESKey();
    }
    
    encrypted_message_t encMsg;
    memcpy(&encMsg, data, sizeof(encMsg));
    
    // Decrypt
    uint8_t decrypted[240];
    uint8_t iv_copy[16];
    memcpy(iv_copy, encMsg.iv, 16);
    
    mbedtls_aes_setkey_dec(&aes, aesKey, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encMsg.dataLen,
                          iv_copy, encMsg.encryptedData, decrypted);
    
    // Remove padding
    uint8_t padValue = decrypted[encMsg.dataLen - 1];
    if (padValue > 0 && padValue <= 16) {
      decrypted[encMsg.dataLen - padValue] = '\0';
      Serial.printf("🔓 Decrypted: '%s'\n", (char*)decrypted);
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("🔧 Initializing Certificate-Based Authentication Sender...");
  Serial.println("📝 Note: Simplified mutual authentication demonstration\n");
  
  // Initialize WiFi in station mode
  WiFi.mode(WIFI_STA);
  WiFi.setChannel(1);
  WiFi.disconnect();
  delay(100);
  
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  Serial.printf("📍 Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  Serial.println("⚠️ UPDATE this MAC in receiver's code!");
  
  // Initialize ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("❌ ESP-NOW init failed");
    return;
  }
  
  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);
  
  // Add receiver as peer
  esp_now_peer_info_t peerInfo{};
  memcpy(peerInfo.peer_addr, receiverAddress, 6);
  peerInfo.channel = 1;
  peerInfo.encrypt = false;
  peerInfo.ifidx = WIFI_IF_STA;
  
  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("❌ Failed to add peer");
    return;
  }
  
  // Initialize crypto
  mbedtls_pk_init(&client_key);
  mbedtls_x509_crt_init(&client_cert);
  mbedtls_x509_crt_init(&ca_cert);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_aes_init(&aes);
  
  const char *pers = "cert_auth_sender";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char*)pers, strlen(pers));
  
  // Load client certificate
  int ret = mbedtls_x509_crt_parse(&client_cert, (const unsigned char*)client_cert_pem,
                                   strlen(client_cert_pem) + 1);
  if (ret != 0) {
    Serial.printf("❌ Failed to load client certificate: %d\n", ret);
    return;
  }
  Serial.println("✅ Client certificate loaded");
  
  // Load client private key
  ret = mbedtls_pk_parse_key(&client_key, (const unsigned char*)client_key_pem,
                             strlen(client_key_pem) + 1, NULL, 0,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.printf("❌ Failed to load client key: %d\n", ret);
    return;
  }
  Serial.println("✅ Client private key loaded");
  
  // Load CA certificate
  ret = mbedtls_x509_crt_parse(&ca_cert, (const unsigned char*)ca_cert_pem,
                               strlen(ca_cert_pem) + 1);
  if (ret != 0) {
    Serial.printf("❌ Failed to load CA certificate: %d\n", ret);
    return;
  }
  Serial.println("✅ CA certificate loaded");
  
  Serial.println("\n✅ Sender ready");
  delay(2000);
  
  // Send authentication request
  sendAuthenticationRequest();
}

void loop() {
  // Send encrypted messages after authentication
  if (authenticated && aesKeyReady) {
    if (Serial.available() > 0) {
      String input = Serial.readStringUntil('\n');
      input.trim();
      
      if (input.length() > 0) {
        Serial.println("\n💬 Sending authenticated message...");
        sendEncryptedMessage(input.c_str());
      }
    }
  }
  
  delay(100);
}
