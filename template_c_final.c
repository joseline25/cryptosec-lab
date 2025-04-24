// Athenaa Protocol (Phase I, II, III) - Version C compatible WebAssembly
// ⚠️ Ceci est une version de base minimaliste. Pas encore sécurisé ni complet.
// Compilation avec emcc :
// emcc -O3 -s WASM=1 -s EXPORTED_FUNCTIONS="['_main', '_encrypt_sender']" -o encrypt.js

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// === Simulacre de SHA-256 ===
// ⚠️ Remplacer par une vraie implémentation SHA-256 (ou SHA-lib wasm compatible)
//intégrer une lib SHA256 réelle compatible WebAssembly (par exemple [SHA256 from mbedTLS ou BearSSL])
void hash_data(const uint8_t* input, size_t len, uint8_t* output) {
    // Simulacre : juste copier les 32 premiers octets, ou remplir avec 0xAA
    for (int i = 0; i < 32; i++) {
        output[i] = (i < len) ? input[i] : 0xAA;
    }
}

// === AES-CTR simulé ===
// ⚠️ À remplacer par tiny-AES + AES_ctr_encrypt si requis (via AES_set_encrypt_key)
void encrypt_aes_ctr(const uint8_t* key, const uint8_t* nonce, const uint8_t* input, size_t len, uint8_t* output) {
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ key[i % 32] ^ nonce[i % 8];  // Simulation simple XOR
    }
}

// === Normalisation ASCII ===
void normalize(char* word) {
    for (size_t i = 0; word[i]; i++) {
        if (word[i] >= 'A' && word[i] <= 'Z') {
            word[i] = word[i] + ('a' - 'A');
        }
    }
}
// === encrypt_sender ===
void encrypt_sender(const char** words, int num_words, const uint8_t* key, const uint8_t* nonce, uint8_t* out_buffer) {
    size_t out_idx = 0;
    for (int w = 0; w < num_words; w++) {
        char word[64];
        strncpy(word, words[w], 63);
        word[63] = '\0';
        normalize(word);

        uint8_t hashed[32];
        hash_data((uint8_t*)word, strlen(word), hashed);

        uint8_t encrypted[32];
        encrypt_aes_ctr(key, nonce, hashed, 32, encrypted);

        memcpy(&out_buffer[out_idx], encrypted, 32);
        out_idx += 32;
    }
}

// === encrypt_receiver ===
void encrypt_receiver(const uint8_t* input_buffer, int num_elements, const uint8_t* key, const uint8_t* nonce, uint8_t* out_buffer) {
    for (int i = 0; i < num_elements; i++) {
        const uint8_t* current_block = &input_buffer[i * 32];
        uint8_t* output_block = &out_buffer[i * 32];
        encrypt_aes_ctr(key, nonce, current_block, 32, output_block);
    }
}

// === Test complet ===
int main() {
    const char* inputs[3] = {"Abc", "dEF", "GHi"};
    uint8_t key1[32], nonce1[8];
    uint8_t key2[32], nonce2[8];
    for (int i = 0; i < 32; i++) {
        key1[i] = i;
        key2[i] = 32 - i;
    }
    for (int i = 0; i < 8; i++) {
        nonce1[i] = i;
        nonce2[i] = 8 - i;
    }

    uint8_t step1_output[3 * 32];
    encrypt_sender(inputs, 3, key1, nonce1, step1_output);

    uint8_t step2_output[3 * 32];
    encrypt_receiver(step1_output, 3, key2, nonce2, step2_output);

    printf("Step2 (double encrypted):\n");
    for (int i = 0; i < 3 * 32; i++) {
        printf("%02x", step2_output[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }

    return 0;
}