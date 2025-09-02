# ChaCha20

Usage:

```C
// Initialize context
struct chacha20_context ctx;

// Define your KEY (32-Byte)
static const uint8_t CHACHA20_KEY[32] = { };

// Define your Nonce (12-Byte)
static const uint8_t CHACHA20_NONCE[12] = { };

// Define counter (should be 0)
 static const uint64_t CHACHA20_COUNTER = 0;

// After those intializations, you can encrypt / decrypt your buffer using the same function
chacha20_init_context(&ctx, CHACHA20_KEY, CHACHA20_NONCE, CHACHA20_COUNTER);
chacha20_xor(&ctx, pBuffer, dwSize); // Encrypt or Decrypt
SecureZeroMemory(&ctx, sizeof(ctx)); // Optional

```
