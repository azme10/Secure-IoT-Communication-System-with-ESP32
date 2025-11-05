#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"

// MAC of receiver (update with your receiver's MAC)
uint8_t receiverAddress[] = {0xD8, 0xBC, 0x38, 0xFC, 0x0A, 0xBC};

typedef struct __attribute__((packed)) {
  uint8_t publicKey[65]; // Uncompressed EC point (1 + 32 + 32 bytes)
} ecdh_message_t;

typedef struct __attribute__((packed)) {
  uint8_t iv[16];
  uint8_t encryptedData[240];
  size_t dataLen;
} encrypted_message_t;

mbedtls_ecdh_context ecdh_ctx;
mbedtls_ecp_group grp;
mbedtls_mpi our_private;
mbedtls_ecp_point our_public;
mbedtls_ecp_point peer_public;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_aes_context aes;

uint8_t aesKey[32];
bool keyExchangeComplete = false;
bool aesKeyReady = false;

void deriveAESKey(const uint8_t* sharedSecret, size_t secretLen) {
  // Use SHA-256 to derive a 256-bit AES key from shared secret
  mbedtls_md_context_t sha_ctx;
  mbedtls_md_init(&sha_ctx);
  mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&sha_ctx);
  mbedtls_md_update(&sha_ctx, sharedSecret, secretLen);
  mbedtls_md_finish(&sha_ctx, aesKey);
  mbedtls_md_free(&sha_ctx);
  
  Serial.print("🔑 Derived AES-256 Key: ");
  for(int i = 0; i < 32; i++) {
    Serial.printf("%02X", aesKey[i]);
  }
  Serial.println();
  
  aesKeyReady = true;
}

void sendEncryptedMessage(const char* message) {
  if (!aesKeyReady) {
    Serial.println("❌ AES key not ready yet!");
    return;
  }
  
  encrypted_message_t encMsg;
  
  // Generate random IV
  mbedtls_ctr_drbg_random(&ctr_drbg, encMsg.iv, 16);
  
  // Prepare plaintext with padding
  size_t msgLen = strlen(message);
  size_t paddedLen = ((msgLen / 16) + 1) * 16;
  uint8_t plaintext[240];
  memcpy(plaintext, message, msgLen);
  
  // PKCS7 padding
  uint8_t padValue = paddedLen - msgLen;
  for(size_t i = msgLen; i < paddedLen; i++) {
    plaintext[i] = padValue;
  }
  
  // Encrypt with AES-256-CBC
  // Copy IV since it gets modified during encryption
  uint8_t iv_copy[16];
  memcpy(iv_copy, encMsg.iv, 16);
  
  mbedtls_aes_setkey_enc(&aes, aesKey, 256);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, 
                        iv_copy, plaintext, encMsg.encryptedData);
  
  encMsg.dataLen = paddedLen;
  
  Serial.printf("🔐 Encrypting: '%s'\n", message);
  Serial.print("📤 Sending encrypted message (");
  Serial.print(paddedLen);
  Serial.println(" bytes)...");
  
  esp_err_t result = esp_now_send(receiverAddress, (uint8_t*)&encMsg, sizeof(encMsg));
  if (result == ESP_OK) {
    Serial.println("✅ Encrypted message sent!");
  } else {
    Serial.printf("❌ Send failed: %d\n", result);
  }
}

void OnDataSent(const wifi_tx_info_t *info, esp_now_send_status_t status) {
  if (status == ESP_NOW_SEND_SUCCESS) {
    Serial.println("✅ Data sent successfully");
  } else {
    Serial.println("❌ Send failed");
  }
}

void OnDataRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  // Check if it's ECDH public key or encrypted message
  if (len == sizeof(ecdh_message_t)) {
    Serial.println("📥 Received ECDH public key from Receiver");
    
    ecdh_message_t received;
    memcpy(&received, data, sizeof(received));
    
    // Read peer's public key
    int ret = mbedtls_ecp_point_read_binary(&grp, &peer_public,
                                            received.publicKey, 65);
    if (ret != 0) {
      Serial.printf("❌ Failed to read peer public key: %d\n", ret);
      return;
    }
    
    Serial.print("🔑 Peer's public key received (");
    Serial.print(65);
    Serial.println(" bytes)");
    
    // Compute shared secret: z = d * Q_peer
    mbedtls_mpi shared_secret_mpi;
    mbedtls_mpi_init(&shared_secret_mpi);
    
    ret = mbedtls_ecdh_compute_shared(&grp, &shared_secret_mpi,
                                      &peer_public, &our_private,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
      Serial.printf("❌ Failed to compute shared secret: %d\n", ret);
      mbedtls_mpi_free(&shared_secret_mpi);
      return;
    }
    
    // Extract x-coordinate as shared secret
    uint8_t sharedSecret[32];
    size_t olen = mbedtls_mpi_size(&shared_secret_mpi);
    mbedtls_mpi_write_binary(&shared_secret_mpi, sharedSecret, 32);
    mbedtls_mpi_free(&shared_secret_mpi);
    
    Serial.print("🔑 ECDH Shared Secret (");
    Serial.print(32);
    Serial.print(" bytes): ");
    for(size_t i = 0; i < 32; i++) {
      Serial.printf("%02X", sharedSecret[i]);
    }
    Serial.println();
    
    deriveAESKey(sharedSecret, 32);
    keyExchangeComplete = true;
    Serial.println("🎉 Key exchange complete! Ready for encrypted communication.");
    
  } else if (len == sizeof(encrypted_message_t)) {
    Serial.println("📥 Received encrypted message from Receiver");
    
    if (!aesKeyReady) {
      Serial.println("❌ AES key not ready, cannot decrypt!");
      return;
    }
    
    encrypted_message_t encMsg;
    memcpy(&encMsg, data, sizeof(encMsg));
    
    Serial.printf("📦 Encrypted data length: %d bytes\n", encMsg.dataLen);
    Serial.print("🔢 IV: ");
    for(int i = 0; i < 16; i++) {
      Serial.printf("%02X", encMsg.iv[i]);
    }
    Serial.println();
    
    // Decrypt with AES-256-CBC
    uint8_t decrypted[240];
    uint8_t iv_copy[16];
    memcpy(iv_copy, encMsg.iv, 16);  // Copy IV since it gets modified
    
    mbedtls_aes_setkey_dec(&aes, aesKey, 256);
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encMsg.dataLen,
                                    iv_copy, encMsg.encryptedData, decrypted);
    
    if (ret != 0) {
      Serial.printf("❌ Decryption failed: %d\n", ret);
      return;
    }
    
    // Remove PKCS7 padding
    uint8_t padValue = decrypted[encMsg.dataLen - 1];
    if (padValue > 0 && padValue <= 16) {
      size_t actualLen = encMsg.dataLen - padValue;
      decrypted[actualLen] = '\0';
      Serial.printf("🔓 Decrypted message: '%s'\n", (char*)decrypted);
    } else {
      Serial.println("❌ Invalid padding");
    }
  } else {
    Serial.printf("⚠️ Received unknown message type (len=%d)\n", len);
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("🔧 Initializing ECDH-AES Sender...");
  
  // Initialize WiFi in station mode
  WiFi.mode(WIFI_STA);
  WiFi.setChannel(1);
  WiFi.disconnect();
  delay(100);
  
  // Get and print MAC address
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
  
  // Initialize crypto libraries
  mbedtls_ecdh_init(&ecdh_ctx);
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&our_private);
  mbedtls_ecp_point_init(&our_public);
  mbedtls_ecp_point_init(&peer_public);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_aes_init(&aes);
  
  // Seed random number generator
  const char *pers = "ecdh_aes_sender";
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char*)pers, strlen(pers));
  if (ret != 0) {
    Serial.printf("❌ RNG seed failed: %d\n", ret);
    return;
  }
  
  // Setup ECDH using secp256r1 (P-256) curve
  ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret != 0) {
    Serial.printf("❌ Failed to load EC group: %d\n", ret);
    return;
  }
  
  // Generate sender's key pair
  ret = mbedtls_ecdh_gen_public(&grp, &our_private, &our_public,
                                mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) {
    Serial.printf("❌ Failed to generate ECDH keys: %d\n", ret);
    return;
  }
  
  Serial.println("✅ Sender ECDH key pair generated");
  
  delay(2000);
  
  // Export and send public key
  ecdh_message_t ecdh_msg;
  size_t olen;
  ret = mbedtls_ecp_point_write_binary(&grp, &our_public,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, ecdh_msg.publicKey, 65);
  if (ret != 0) {
    Serial.printf("❌ Failed to export public key: %d\n", ret);
    return;
  }
  
  Serial.print("📤 Sending ECDH public key (");
  Serial.print(olen);
  Serial.println(" bytes)...");
  esp_now_send(receiverAddress, (uint8_t*)&ecdh_msg, sizeof(ecdh_msg));
  
  Serial.println("✅ Sender ready, waiting for Receiver's public key...");
}

void loop() {
  // After key exchange, allow interactive message sending
  if (keyExchangeComplete && aesKeyReady) {
    if (Serial.available() > 0) {
      String input = Serial.readStringUntil('\n');
      input.trim();
      
      if (input.length() > 0) {
        Serial.println("\n💬 Sending your message...");
        sendEncryptedMessage(input.c_str());
      }
    }
  }
  
  delay(100);
}
