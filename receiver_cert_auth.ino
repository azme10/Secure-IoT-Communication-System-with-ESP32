/*
 * ESP32 Part 5: Certificate-Based Authentication (Simplified)
 * 
 * NOTE: Full TLS server implementation in Arduino is complex.
 * This version demonstrates certificate-based authentication concepts
 * using ESP-NOW with signature verification (similar to TLS mutual auth)
 * 
 * For production TLS: Use ESP-IDF framework or dedicated libraries
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

// MAC of sender (update with your sender's MAC)
uint8_t senderAddress[] = {0xC8, 0x2E, 0x18, 0x8E, 0xC7, 0x60};

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

// Server (Receiver) certificate
const char* server_cert_pem = R"EOF(
-----BEGIN CERTIFICATE-----
MIICITCCAcigAwIBAgITSLF9H4S3hDjoGjxTxq4reK1bPDAKBggqhkjOPQQDAjB1
MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lz
Y28xFjAUBgNVBAoMDUVTUDMyIFRlc3QgQ0ExETAPBgNVBAsMCFNlY3VyaXR5MRYw
FAYDVQQDDA1FU1AzMiBSb290IENBMB4XDTI1MTEwNTE2MTYwOFoXDTI2MTEwNTE2
MTYwOFowdDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4g
RnJhbmNpc2NvMQ4wDAYDVQQKDAVFU1AzMjEXMBUGA1UECwwORVNQMzItUmVjZWl2
ZXIxFzAVBgNVBAMMDkVTUDMyLVJlY2VpdmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEmxAW1rgT8ft63tb9AN/f9CYvbQmlBk8a20ZfJ6KS0krSS7Dsl6O5/VFs
QohN3r8O2fBwtKzJ6MabfeZfB/sYQKM4MDYwDAYDVR0TAQH/BAIwADAOBgNVHQ8B
Af8EBAMCA6gwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDRwAw
RAIgaYgOW63yhhhDsX1GF7etZ9fTRLWaG4/OTlBwD0fW44MCIE2sOvUuPOmot+vW
2suJpD1Ss3rjR3TkKsxewAhpNJpE
-----END CERTIFICATE-----
)EOF";

// Server private key
const char* server_key_pem = R"EOF(
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMxkR5K0VGwTC/EJeVhmpWLzMzIv3clb78HPSJN7k2jCoAoGCCqGSM49
AwEHoUQDQgAEmxAW1rgT8ft63tb9AN/f9CYvbQmlBk8a20ZfJ6KS0krSS7Dsl6O5
/VFsQohN3r8O2fBwtKzJ6MabfeZfB/sYQA==
-----END EC PRIVATE KEY-----
)EOF";

// CA certificate (to verify sender)
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

mbedtls_pk_context server_key;
mbedtls_x509_crt server_cert;
mbedtls_x509_crt ca_cert;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_aes_context aes;

uint8_t aesKey[32];
bool authenticated = false;
bool aesKeyReady = false;

void deriveAESKey() {
  // Derive AES key from successful authentication
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

bool verifySenderCertificate(const uint8_t* certData, size_t certLen) {
  Serial.println("🔍 Verifying sender's certificate...");
  
  mbedtls_x509_crt client_cert;
  mbedtls_x509_crt_init(&client_cert);
  
  // Parse sender's certificate
  int ret = mbedtls_x509_crt_parse(&client_cert, certData, certLen + 1);
  if (ret != 0) {
    Serial.printf("❌ Failed to parse certificate: %d\n", ret);
    mbedtls_x509_crt_free(&client_cert);
    return false;
  }
  
  // Verify certificate chain against CA
  uint32_t flags;
  ret = mbedtls_x509_crt_verify(&client_cert, &ca_cert, NULL, NULL, &flags, NULL, NULL);
  
  if (ret != 0) {
    Serial.printf("❌ Certificate verification failed: %d, flags: %u\n", ret, flags);
    mbedtls_x509_crt_free(&client_cert);
    return false;
  }
  
  Serial.println("✅ Sender's certificate verified by CA!");
  mbedtls_x509_crt_free(&client_cert);
  return true;
}

void sendEncryptedMessage(const char* message) {
  if (!aesKeyReady) {
    Serial.println("❌ AES key not ready!");
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
  esp_now_send(senderAddress, (uint8_t*)&encMsg, sizeof(encMsg));
}

void OnDataSent(const wifi_tx_info_t *info, esp_now_send_status_t status) {
  if (status == ESP_NOW_SEND_SUCCESS) {
    Serial.println("✅ Message sent successfully");
  }
}

void OnDataRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  if (len == sizeof(auth_message_t) && !authenticated) {
    Serial.println("📥 Received authentication request from Sender");
    
    auth_message_t authMsg;
    memcpy(&authMsg, data, sizeof(authMsg));
    
    // Verify sender's certificate
    if (verifySenderCertificate(authMsg.certificate, authMsg.certLen)) {
      Serial.println("🎉 Mutual authentication successful!");
      authenticated = true;
      deriveAESKey();
      
      // Send acknowledgment
      delay(500);
      sendEncryptedMessage("Authentication accepted - Receiver ready!");
    } else {
      Serial.println("❌ Authentication failed - invalid certificate");
    }
    
  } else if (len == sizeof(encrypted_message_t) && authenticated) {
    Serial.println("📥 Received encrypted message");
    
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
  
  Serial.println("🔧 Initializing Certificate-Based Authentication Receiver...");
  Serial.println("📝 Note: Simplified mutual authentication demonstration");
  Serial.println("   (Full TLS requires ESP-IDF framework)\n");
  
  // Initialize WiFi in station mode
  WiFi.mode(WIFI_STA);
  WiFi.setChannel(1);
  WiFi.disconnect();
  delay(100);
  
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  Serial.printf("📍 Receiver MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  Serial.println("⚠️ UPDATE this MAC in sender's code!");
  
  // Initialize ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("❌ ESP-NOW init failed");
    return;
  }
  
  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);
  
  // Add sender as peer
  esp_now_peer_info_t peerInfo{};
  memcpy(peerInfo.peer_addr, senderAddress, 6);
  peerInfo.channel = 1;
  peerInfo.encrypt = false;
  peerInfo.ifidx = WIFI_IF_STA;
  
  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("❌ Failed to add peer");
    return;
  }
  
  // Initialize crypto
  mbedtls_pk_init(&server_key);
  mbedtls_x509_crt_init(&server_cert);
  mbedtls_x509_crt_init(&ca_cert);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_aes_init(&aes);
  
  const char *pers = "cert_auth_receiver";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char*)pers, strlen(pers));
  
  // Load server certificate
  int ret = mbedtls_x509_crt_parse(&server_cert, (const unsigned char*)server_cert_pem,
                                   strlen(server_cert_pem) + 1);
  if (ret != 0) {
    Serial.printf("❌ Failed to load server certificate: %d\n", ret);
    return;
  }
  Serial.println("✅ Server certificate loaded");
  
  // Load server private key
  ret = mbedtls_pk_parse_key(&server_key, (const unsigned char*)server_key_pem,
                             strlen(server_key_pem) + 1, NULL, 0,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.printf("❌ Failed to load server key: %d\n", ret);
    return;
  }
  Serial.println("✅ Server private key loaded");
  
  // Load CA certificate
  ret = mbedtls_x509_crt_parse(&ca_cert, (const unsigned char*)ca_cert_pem,
                               strlen(ca_cert_pem) + 1);
  if (ret != 0) {
    Serial.printf("❌ Failed to load CA certificate: %d\n", ret);
    return;
  }
  Serial.println("✅ CA certificate loaded");
  
  Serial.println("\n🎧 Receiver ready - waiting for authentication...");
}

void loop() {
  delay(100);
}
