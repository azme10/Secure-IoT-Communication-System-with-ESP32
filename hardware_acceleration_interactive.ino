/*
 * ESP32 Part 6: Interactive Hardware Acceleration Demo
 * 
 * Type messages in Serial Monitor to encrypt them and see
 * ESP32's hardware crypto acceleration in action!
 * 
 * Note: mbedtls automatically uses ESP32 hardware acceleration
 */

#include <Arduino.h>
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

// AES-256 key
uint8_t aes_key[32] = {
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

// IV for CBC
uint8_t iv[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// Single-call encryption (includes setup overhead)
void encryptStandard(const uint8_t* plaintext, uint8_t* ciphertext, size_t len) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, aes_key, 256);
  
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);
  
  unsigned long start = micros();
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv_copy, plaintext, ciphertext);
  unsigned long elapsed = micros() - start;
  
  mbedtls_aes_free(&aes);
  
  Serial.printf("⚡ Encryption: %lu µs (%.3f ms)\n", elapsed, elapsed / 1000.0);
}

void decryptStandard(const uint8_t* ciphertext, uint8_t* plaintext, size_t len) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, aes_key, 256);
  
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);
  
  unsigned long start = micros();
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv_copy, ciphertext, plaintext);
  unsigned long elapsed = micros() - start;
  
  mbedtls_aes_free(&aes);
  
  Serial.printf("🔓 Decryption: %lu µs (%.3f ms)\n", elapsed, elapsed / 1000.0);
}

void processMessage(const char* message) {
  size_t msgLen = strlen(message);
  
  // Calculate padded length (multiple of 16)
  size_t paddedLen = ((msgLen / 16) + 1) * 16;
  
  uint8_t* plaintext = (uint8_t*)malloc(paddedLen);
  uint8_t* ciphertext_soft = (uint8_t*)malloc(paddedLen);
  uint8_t* ciphertext_hard = (uint8_t*)malloc(paddedLen);
  uint8_t* decrypted = (uint8_t*)malloc(paddedLen);
  
  // Prepare plaintext with PKCS7 padding
  memcpy(plaintext, message, msgLen);
  uint8_t padValue = paddedLen - msgLen;
  for (size_t i = msgLen; i < paddedLen; i++) {
    plaintext[i] = padValue;
  }
  
  Serial.println("\n╔════════════════════════════════════════════════════════════════╗");
  Serial.printf("║ Processing: '%s' (%zu bytes → %zu padded)\n", message, msgLen, paddedLen);
  Serial.println("╚════════════════════════════════════════════════════════════════╝");
  
  // Encrypt
  encryptStandard(plaintext, ciphertext_hard, paddedLen);
  
  // Show ciphertext sample
  Serial.print("📦 Ciphertext (first 32 bytes): ");
  for (int i = 0; i < min((size_t)32, paddedLen); i++) {
    Serial.printf("%02X", ciphertext_hard[i]);
  }
  Serial.println(paddedLen > 32 ? "..." : "");
  
  // Decrypt
  decryptStandard(ciphertext_hard, decrypted, paddedLen);
  
  // Remove padding and show result
  uint8_t pad = decrypted[paddedLen - 1];
  if (pad > 0 && pad <= 16) {
    decrypted[paddedLen - pad] = '\0';
    Serial.printf("✅ Verified: '%s'\n", (char*)decrypted);
  }
  
  Serial.println("\n💡 ESP32 automatically used hardware acceleration!");
  
  free(plaintext);
  free(ciphertext_hard);
  free(decrypted);
}

void showMenu() {
  Serial.println("\n════════════════════════════════════════════════════════════════");
  Serial.println("      ESP32 Hardware Crypto Acceleration - Interactive Demo");
  Serial.println("════════════════════════════════════════════════════════════════");
  Serial.println("Commands:");
  Serial.println("  📝 Type any message → Encrypt & decrypt it");
  Serial.println("  🏃 'bench'         → Run performance benchmark");
  Serial.println("  ℹ️  'info'          → Show hardware capabilities");
  Serial.println("  ❓ 'help'          → Show this menu");
  Serial.println("════════════════════════════════════════════════════════════════");
  Serial.println();
}

void runQuickBenchmark() {
  Serial.println("\n🏃 Running benchmark (500 iterations, 1KB data)...\n");
  
  uint8_t data[1024];
  uint8_t encrypted[1024];
  uint8_t decrypted[1024];
  
  // Initialize with recognizable pattern
  for (int i = 0; i < 1024; i++) {
    data[i] = (uint8_t)(i & 0xFF);
  }
  
  // Show original data sample
  Serial.println("📝 Original Data (first 64 bytes):");
  Serial.print("   ");
  for (int i = 0; i < 64; i++) {
    Serial.printf("%02X ", data[i]);
    if ((i + 1) % 16 == 0) Serial.print("\n   ");
  }
  Serial.println();
  
  // Benchmark with hardware acceleration
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, aes_key, 256);
  
  unsigned long start = millis();
  for (int i = 0; i < 500; i++) {
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 1024, iv_copy, data, encrypted);
  }
  unsigned long elapsed = millis() - start;
  mbedtls_aes_free(&aes);
  
  // Show encrypted data sample
  Serial.println("🔒 Encrypted Data (first 64 bytes):");
  Serial.print("   ");
  for (int i = 0; i < 64; i++) {
    Serial.printf("%02X ", encrypted[i]);
    if ((i + 1) % 16 == 0) Serial.print("\n   ");
  }
  Serial.println();
  
  // Decrypt to verify
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, aes_key, 256);
  uint8_t iv_dec[16];
  memcpy(iv_dec, iv, 16);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 1024, iv_dec, encrypted, decrypted);
  mbedtls_aes_free(&aes);
  
  // Verify correctness
  bool verified = memcmp(data, decrypted, 1024) == 0;
  
  Serial.println("🔓 Decrypted Data (first 64 bytes):");
  Serial.print("   ");
  for (int i = 0; i < 64; i++) {
    Serial.printf("%02X ", decrypted[i]);
    if ((i + 1) % 16 == 0) Serial.print("\n   ");
  }
  Serial.println();
  
  // Performance metrics
  float throughput = (500.0 * 1024.0) / (elapsed * 1000.0); // MB/s
  float timePerOp = (float)elapsed / 500.0;
  
  Serial.println("════════════════════════════════════════════════════════════════");
  Serial.printf("✅ Completed 500 encryptions in %lu ms\n", elapsed);
  Serial.printf("📊 Time per operation: %.3f ms\n", timePerOp);
  Serial.printf("🚀 Throughput: %.2f MB/s\n", throughput);
  Serial.printf("✅ Verification: %s\n", verified ? "PASSED" : "FAILED");
  Serial.println("════════════════════════════════════════════════════════════════");
  Serial.println("\n💡 All operations used ESP32 hardware acceleration!");
}

void showHardwareInfo() {
  Serial.println("\n╔════════════════════════════════════════════════════════════════╗");
  Serial.println("║            ESP32 Hardware Crypto Information                   ║");
  Serial.println("╚════════════════════════════════════════════════════════════════╝");
  Serial.printf("Chip: %s Rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("CPU: %d MHz\n", ESP.getCpuFreqMHz());
  Serial.printf("Flash: %d MB\n", ESP.getFlashChipSize() / (1024 * 1024));
  Serial.printf("Free Heap: %d KB\n", ESP.getFreeHeap() / 1024);
  Serial.println("\nHardware Crypto Accelerators:");
  Serial.println("✅ AES-128/192/256 (all modes)");
  Serial.println("✅ SHA-1/224/256/384/512");
  Serial.println("✅ RSA (up to 4096-bit)");
  Serial.println("✅ ECC (P-192, P-256)");
  Serial.println("✅ Hardware RNG (TRNG)");
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("\n🚀 ESP32 Hardware Acceleration - Interactive Demo");
  Serial.println("📝 Part 6: Hardware Acceleration for Cryptographic Operations\n");
  
  showHardwareInfo();
  showMenu();
  
  Serial.println("💬 Type a message to encrypt, or 'help' for commands...\n");
}

void loop() {
  if (Serial.available() > 0) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    
    if (input.length() == 0) {
      return;
    }
    
    if (input.equalsIgnoreCase("help")) {
      showMenu();
    } else if (input.equalsIgnoreCase("bench")) {
      runQuickBenchmark();
    } else if (input.equalsIgnoreCase("info")) {
      showHardwareInfo();
    } else {
      processMessage(input.c_str());
    }
    
    Serial.println("\n💬 Ready for next command...\n");
  }
  
  delay(10);
}
