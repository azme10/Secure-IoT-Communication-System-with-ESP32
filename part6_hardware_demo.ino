/*
 * ESP32 Part 6: Hardware Acceleration Demo
 * 
 * This demo shows ESP32's hardware crypto acceleration in action.
 * The mbedtls library automatically uses hardware when available!
 */

#include <Arduino.h>
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

// Test data sizes
#define TEST_16B    16
#define TEST_1KB    1024
#define TEST_4KB    4096

// AES-256 key
uint8_t aes_key[32] = {
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

uint8_t iv[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

void benchmarkAES(size_t dataSize, int iterations) {
  uint8_t* plaintext = (uint8_t*)malloc(dataSize);
  uint8_t* ciphertext = (uint8_t*)malloc(dataSize);
  
  // Initialize test data
  for (size_t i = 0; i < dataSize; i++) {
    plaintext[i] = (uint8_t)(i & 0xFF);
  }
  
  // Setup AES context (hardware accelerated automatically on ESP32)
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, aes_key, 256);
  
  // Benchmark encryption
  unsigned long startTime = millis();
  for (int i = 0; i < iterations; i++) {
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, dataSize, iv_copy, plaintext, ciphertext);
  }
  unsigned long elapsed = millis() - startTime;
  
  mbedtls_aes_free(&aes);
  
  // Calculate metrics
  float throughput = (float)(dataSize * iterations) / (elapsed * 1000.0); // MB/s
  float timePerOp = (float)elapsed / iterations;
  
  // Display results
  Serial.println("────────────────────────────────────────────────────────");
  Serial.printf("📊 Data Size: %d bytes\n", dataSize);
  Serial.printf("🔄 Iterations: %d\n", iterations);
  Serial.printf("⏱️  Total Time: %lu ms\n", elapsed);
  Serial.printf("⚡ Time/Operation: %.3f ms\n", timePerOp);
  Serial.printf("🚀 Throughput: %.2f MB/s\n", throughput);
  Serial.println("────────────────────────────────────────────────────────\n");
  
  free(plaintext);
  free(ciphertext);
}

void benchmarkSHA256(int iterations) {
  uint8_t data[1024];
  uint8_t hash[32];
  
  memset(data, 0xAA, sizeof(data));
  
  unsigned long startTime = millis();
  
  for (int i = 0; i < iterations; i++) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 = SHA-256
    mbedtls_sha256_update(&ctx, data, sizeof(data));
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
  }
  
  unsigned long elapsed = millis() - startTime;
  
  Serial.println("────────────────────────────────────────────────────────");
  Serial.println("📊 SHA-256 Benchmark");
  Serial.printf("🔄 Iterations: %d (1KB each)\n", iterations);
  Serial.printf("⏱️  Total Time: %lu ms\n", elapsed);
  Serial.printf("⚡ Time/Hash: %.3f ms\n", (float)elapsed / iterations);
  Serial.printf("🚀 Hashes/sec: %.0f\n", (float)iterations / (elapsed / 1000.0));
  Serial.print("📋 Sample Hash: ");
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02X", hash[i]);
  }
  Serial.println("...\n");
}

void demonstrateEncryption() {
  Serial.println("════════════════════════════════════════════════════════════════");
  Serial.println("              🔐 AES-256 Encryption Demonstration");
  Serial.println("════════════════════════════════════════════════════════════════\n");
  
  const char* message = "Hello ESP32! Hardware acceleration rocks!";
  size_t msgLen = strlen(message);
  size_t paddedLen = ((msgLen / 16) + 1) * 16;
  
  uint8_t* plaintext = (uint8_t*)malloc(paddedLen);
  uint8_t* ciphertext = (uint8_t*)malloc(paddedLen);
  uint8_t* decrypted = (uint8_t*)malloc(paddedLen);
  
  // Prepare plaintext with PKCS7 padding
  memcpy(plaintext, message, msgLen);
  uint8_t padValue = paddedLen - msgLen;
  for (size_t i = msgLen; i < paddedLen; i++) {
    plaintext[i] = padValue;
  }
  
  Serial.printf("📝 Original Message: '%s'\n", message);
  Serial.printf("📏 Length: %zu bytes (padded to %zu)\n\n", msgLen, paddedLen);
  
  // Encrypt
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, aes_key, 256);
  
  uint8_t iv_enc[16];
  memcpy(iv_enc, iv, 16);
  
  unsigned long encStart = micros();
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, iv_enc, plaintext, ciphertext);
  unsigned long encTime = micros() - encStart;
  
  Serial.printf("🔒 Encrypted in %lu µs (%.3f ms)\n", encTime, encTime / 1000.0);
  Serial.print("📦 Ciphertext: ");
  for (size_t i = 0; i < min((size_t)32, paddedLen); i++) {
    Serial.printf("%02X", ciphertext[i]);
  }
  Serial.println(paddedLen > 32 ? "..." : "");
  
  // Decrypt
  mbedtls_aes_free(&aes);
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, aes_key, 256);
  
  uint8_t iv_dec[16];
  memcpy(iv_dec, iv, 16);
  
  unsigned long decStart = micros();
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, paddedLen, iv_dec, ciphertext, decrypted);
  unsigned long decTime = micros() - decStart;
  
  mbedtls_aes_free(&aes);
  
  // Remove padding
  uint8_t pad = decrypted[paddedLen - 1];
  if (pad > 0 && pad <= 16) {
    decrypted[paddedLen - pad] = '\0';
  }
  
  Serial.printf("\n🔓 Decrypted in %lu µs (%.3f ms)\n", decTime, decTime / 1000.0);
  Serial.printf("✅ Result: '%s'\n\n", (char*)decrypted);
  
  bool success = strcmp((char*)decrypted, message) == 0;
  Serial.println(success ? "✅ Verification: SUCCESS!" : "❌ Verification: FAILED!");
  Serial.println("\n💡 All operations used ESP32 hardware acceleration!\n");
  
  free(plaintext);
  free(ciphertext);
  free(decrypted);
}

void showHardwareInfo() {
  Serial.println("\n╔════════════════════════════════════════════════════════════════╗");
  Serial.println("║          ESP32 Hardware Crypto Acceleration Features          ║");
  Serial.println("╚════════════════════════════════════════════════════════════════╝\n");
  
  Serial.printf("🔧 Chip: %s Rev %d\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("⚡ CPU Frequency: %d MHz\n", ESP.getCpuFreqMHz());
  Serial.printf("💾 Flash Size: %d MB\n", ESP.getFlashChipSize() / (1024 * 1024));
  Serial.printf("🧠 Free Heap: %d KB\n\n", ESP.getFreeHeap() / 1024);
  
  Serial.println("🔐 Hardware Crypto Accelerators:");
  Serial.println("   ✅ AES (128/192/256-bit)");
  Serial.println("      • ECB, CBC, CTR, GCM modes");
  Serial.println("      • DMA support for large data");
  Serial.println("   ✅ SHA (1/224/256/384/512)");
  Serial.println("      • Hardware hash engine");
  Serial.println("   ✅ RSA (up to 4096-bit)");
  Serial.println("      • Modular exponentiation");
  Serial.println("   ✅ ECC (secp192r1, secp256r1)");
  Serial.println("      • Point multiplication");
  Serial.println("   ✅ Hardware RNG (TRNG)");
  Serial.println("      • True random number generator\n");
  
  Serial.println("📊 Performance Benefits:");
  Serial.println("   🚀 2-10x faster than software implementation");
  Serial.println("   ⚡ Lower power consumption");
  Serial.println("   🔓 Frees CPU for other tasks");
  Serial.println("   🛡️  Constant-time operations (timing attack resistant)\n");
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("\n\n");
  Serial.println("╔════════════════════════════════════════════════════════════════╗");
  Serial.println("║        ESP32 Hardware Acceleration Benchmark - Part 6         ║");
  Serial.println("╚════════════════════════════════════════════════════════════════╝");
  
  showHardwareInfo();
  
  delay(2000);
  
  // Demonstration
  demonstrateEncryption();
  
  delay(1000);
  
  // Benchmarks
  Serial.println("════════════════════════════════════════════════════════════════");
  Serial.println("                🏃 Performance Benchmarks");
  Serial.println("════════════════════════════════════════════════════════════════\n");
  
  Serial.println("📊 Benchmark 1: Small Messages (16 bytes, 1000 iterations)");
  benchmarkAES(TEST_16B, 1000);
  delay(500);
  
  Serial.println("📊 Benchmark 2: Medium Messages (1 KB, 1000 iterations)");
  benchmarkAES(TEST_1KB, 1000);
  delay(500);
  
  Serial.println("📊 Benchmark 3: Large Messages (4 KB, 500 iterations)");
  benchmarkAES(TEST_4KB, 500);
  delay(500);
  
  Serial.println("📊 Benchmark 4: SHA-256 Hashing");
  benchmarkSHA256(1000);
  
  // Final summary
  Serial.println("════════════════════════════════════════════════════════════════");
  Serial.println("                    ✅ Benchmarks Complete!");
  Serial.println("════════════════════════════════════════════════════════════════");
  Serial.println("\n🎯 Key Takeaways:");
  Serial.println("   • ESP32 automatically uses hardware crypto acceleration");
  Serial.println("   • mbedtls is compiled with hardware support (MBEDTLS_*_ALT)");
  Serial.println("   • No special code needed - it just works!");
  Serial.println("   • Hardware acceleration is transparent to your application");
  Serial.println("   • Significant performance gains for crypto operations");
  Serial.println("\n💡 For IoT security, ESP32's crypto hardware provides:");
  Serial.println("   → Fast encryption for real-time communication");
  Serial.println("   → Energy-efficient operation for battery-powered devices");
  Serial.println("   → Secure key storage and cryptographic operations");
  Serial.println("   → Protection against timing attacks\n");
  
  Serial.println("✅ Part 6 Complete! 🎉\n");
}

void loop() {
  // All tests complete
  delay(10000);
}
