# ChaCha20

Usage:

```C
// Initialize context
struct chacha20_context ctx;

// Define your KEY (32-Byte)
unsigned char CHACHA20_KEY[32] = { };

// Define your Nonce (12-Byte)
unsigned char CHACHA20_NONCE[12] = { };

// After those intializations, you can encrypt / decrypt your buffer using the same function
chacha20_init_context(&ctx, CHACHA20_KEY, CHACHA20_NONCE, 0);
chacha20_xor(&ctx, pBuffer, dwSize); // Encrypt or Decrypt
SecureZeroMemory(&ctx, sizeof(ctx)); // Optional

```
