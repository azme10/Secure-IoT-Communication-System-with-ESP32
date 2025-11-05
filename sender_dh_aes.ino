#include <Arduino.h>
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"

// MAC of receiver (update with your receiver's MAC)
uint8_t receiverAddress[] = {0xD8, 0xBC, 0x38, 0xFC, 0x0A, 0xBC};

typedef struct {
  char publicKey[256];
} dh_message_t;

typedef struct {
  uint8_t iv[16];
  uint8_t encryptedData[240];
  size_t dataLen;
} encrypted_message_t;

mbedtls_mpi p, g, privateKey, publicKey, peerPublicKey, sharedKey;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_aes_context aes;

uint8_t aesKey[32];
bool keyExchangeComplete = false;
bool aesKeyReady = false;

void deriveAESKey() {
  char sharedKeyStr[256];
  size_t olen;
  mbedtls_mpi_write_string(&sharedKey, 16, sharedKeyStr, sizeof(sharedKeyStr), &olen);
  
  // Use SHA-256 to derive a 256-bit AES key from shared secret
  mbedtls_md_context_t sha_ctx;
  mbedtls_md_init(&sha_ctx);
  mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&sha_ctx);
  mbedtls_md_update(&sha_ctx, (unsigned char*)sharedKeyStr, strlen(sharedKeyStr));
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
  // Check if it's DH public key or encrypted message
  if (len == sizeof(dh_message_t)) {
    Serial.println("📥 Received public key from Receiver");
    
    dh_message_t received;
    memcpy(&received, data, sizeof(received));
    
    int ret = mbedtls_mpi_read_string(&peerPublicKey, 16, received.publicKey);
    if (ret != 0) {
      Serial.printf("❌ Failed to read peer public key: %d\n", ret);
      return;
    }
    
    ret = mbedtls_mpi_exp_mod(&sharedKey, &peerPublicKey, &privateKey, &p, NULL);
    if (ret != 0) {
      Serial.printf("❌ Failed to compute shared key: %d\n", ret);
      return;
    }
    
    char sharedKeyStr[256];
    size_t olen;
    mbedtls_mpi_write_string(&sharedKey, 16, sharedKeyStr, sizeof(sharedKeyStr), &olen);
    Serial.print("🔑 DH Shared key (hex): ");
    Serial.println(sharedKeyStr);
    
    // Print peer's public key for debugging
    char peerPubStr[256];
    mbedtls_mpi_write_string(&peerPublicKey, 16, peerPubStr, sizeof(peerPubStr), &olen);
    Serial.print("🔑 Peer's public key: ");
    Serial.println(peerPubStr);
    
    deriveAESKey();
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
  
  Serial.println("🔧 Initializing DH-AES Sender...");
  
  WiFi.mode(WIFI_STA);
  WiFi.setChannel(1);
  WiFi.disconnect();
  delay(100);
  
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_STA, mac);
  Serial.printf("📍 Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  Serial.println("⚠️ UPDATE this MAC in receiver's code!");
  
  if (esp_now_init() != ESP_OK) {
    Serial.println("❌ ESP-NOW init failed");
    return;
  }
  
  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);
  
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
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&g);
  mbedtls_mpi_init(&privateKey);
  mbedtls_mpi_init(&publicKey);
  mbedtls_mpi_init(&peerPublicKey);
  mbedtls_mpi_init(&sharedKey);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_aes_init(&aes);
  
  const char *pers = "dh_aes_sender";
  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char*)pers, strlen(pers));
  
  // DH parameters (must match receiver)
  mbedtls_mpi_read_string(&p, 16, "F7E75FDC469067FFDC4E847C51F452DF");
  mbedtls_mpi_read_string(&g, 16, "02");
  
  // Generate sender's private key
  mbedtls_mpi_fill_random(&privateKey, 16, mbedtls_ctr_drbg_random, &ctr_drbg);
  
  // Compute sender's public key: publicKey = g^privateKey mod p
  mbedtls_mpi_exp_mod(&publicKey, &g, &privateKey, &p, NULL);
  
  char pubKeyStr[256];
  size_t olen;
  mbedtls_mpi_write_string(&publicKey, 16, pubKeyStr, sizeof(pubKeyStr), &olen);
  Serial.print("🔑 Sender's public key: ");
  Serial.println(pubKeyStr);
  
  Serial.println("✅ Sender ready");
  delay(2000);
  
  // Send public key to initiate DH key exchange
  dh_message_t dh_msg;
  memset(&dh_msg, 0, sizeof(dh_msg));
  mbedtls_mpi_write_string(&publicKey, 16, dh_msg.publicKey, sizeof(dh_msg.publicKey), &olen);
  
  Serial.println("📤 Sending DH public key...");
  esp_now_send(receiverAddress, (uint8_t*)&dh_msg, sizeof(dh_msg));
}

void loop() {
  // Display ready message once after key exchange
  static bool readyMessageShown = false;
  if (keyExchangeComplete && aesKeyReady && !readyMessageShown) {
    Serial.println("\n✅ Ready to send encrypted messages!");
    Serial.println("💬 Type your message and press Enter:");
    readyMessageShown = true;
  }
  
  // Check for user input from Serial Monitor
  if (aesKeyReady && Serial.available() > 0) {
    String userMessage = Serial.readStringUntil('\n');
    userMessage.trim();  // Remove whitespace
    
    if (userMessage.length() > 0) {
      Serial.print("📝 You typed: ");
      Serial.println(userMessage);
      sendEncryptedMessage(userMessage.c_str());
      Serial.println("💬 Type next message:");
    }
  }
  
  delay(10);
}
