#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define HASH_SIZE 32
#define SCALAR_SIZE 32
#define NONCE_SIZE 8
#define MAX_VARIANTS 3
#define MAX_WORD_LEN 64
#define MAX_WORDS 100

// Normalize string to lowercase
void normalize(char *word) {
    for (size_t i = 0; word[i]; i++) {
        if (word[i] >= 'A' && word[i] <= 'Z') {
            word[i] = word[i] + ('a' - 'A');
        }
    }
}

// Generate close variants
int generate_variants(const char *word, char variants[MAX_VARIANTS][MAX_WORD_LEN]) {
    strncpy(variants[0], word, MAX_WORD_LEN);
    strncpy(variants[1], word, MAX_WORD_LEN);
    strncpy(variants[2], word, MAX_WORD_LEN);
    int len = strlen(word);
    if (len > 1) {
        variants[1][len - 1] = '\0';
        memmove(variants[2], &word[1], len);
        variants[2][len - 1] = '\0';
        return 3;
    }
    return 1;
}

// SHA256 + map to Curve25519 point
void hash_to_curve25519_point(const uint8_t *input, size_t input_len, uint8_t *out_point) {
    uint8_t hash[HASH_SIZE];
    crypto_hash_sha256(hash, input, input_len);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    crypto_scalarmult_base(out_point, hash);
}

// ElGamal-style EC multiplication
void scalar_mult(const uint8_t *scalar, const uint8_t *point, uint8_t *result) {
    if (crypto_scalarmult(result, scalar, point) != 0) {
        memset(result, 0, 32);
    }
}

// AES-CTR encryption with sodium's stream_xor
void aes_ctr_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *input, uint8_t *output, size_t len) {
    crypto_stream_xor(output, input, len, nonce, key);
}

// Final SHA256
void final_hash(const uint8_t *input, size_t len, uint8_t *output) {
    crypto_hash_sha256(output, input, len);
}

void psi_compute(const uint8_t *scalar, const uint8_t *aes_key, const uint8_t *nonce, const uint8_t *input_word, size_t word_len, uint8_t *final_output) {
    uint8_t pt[32], enc[32], aes[32];
    hash_to_curve25519_point(input_word, word_len, pt);
    scalar_mult(scalar, pt, enc);
    aes_ctr_encrypt(aes_key, nonce, enc, aes, 32);
    final_hash(aes, 32, final_output);
}


// Prepare database (Bob)
void prepare_database(char *words[], int word_count, const uint8_t *KB, const uint8_t *KAB, const uint8_t *nonce, uint8_t out_hashes[MAX_WORDS][HASH_SIZE]) {
    for (int i = 0; i < word_count; i++) {
        char norm[MAX_WORD_LEN];
        strncpy(norm, words[i], MAX_WORD_LEN);
        normalize(norm);

        uint8_t point[32], enc[32], aes[32];
        hash_to_curve25519_point((uint8_t *)norm, strlen(norm), point);
        scalar_mult(KB, point, enc);
        aes_ctr_encrypt(KAB, nonce, enc, aes, 32);
        final_hash(aes, 32, out_hashes[i]);
    }
}

// Alice prepares request (ElGamal encrypts variants with KR)
int prepare_request(char *words[], int word_count, const uint8_t *KR, uint8_t out_points[MAX_WORDS * MAX_VARIANTS][32]) {
    int idx = 0;
    for (int i = 0; i < word_count; i++) {
        char norm[MAX_WORD_LEN];
        strncpy(norm, words[i], MAX_WORD_LEN);
        normalize(norm);

        char variants[MAX_VARIANTS][MAX_WORD_LEN];
        int n = generate_variants(norm, variants);

        for (int j = 0; j < n; j++) {
            uint8_t point[32];
            hash_to_curve25519_point((uint8_t *)variants[j], strlen(variants[j]), point);
            scalar_mult(KR, point, out_points[idx]);
            idx++;
        }
    }
    return idx;
}

// Bob handles request (applies KB to points)
void handle_request(const uint8_t *points, int point_count, const uint8_t *KB, uint8_t *out_points) {
    for (int i = 0; i < point_count; i++) {
        scalar_mult(KB, &points[i * 32], &out_points[i * 32]);
    }
}

// Alice decrypts (removes KR, encrypts with AES and hashes)
void decrypt_sender(const uint8_t *points, int point_count, const uint8_t *KR_inv, const uint8_t *KAB, const uint8_t *nonce, uint8_t out_hashes[][HASH_SIZE]) {
    for (int i = 0; i < point_count; i++) {
        uint8_t corrected[32], aes[32];
        scalar_mult(KR_inv, &points[i * 32], corrected);
        aes_ctr_encrypt(KAB, nonce, corrected, aes, 32);
        final_hash(aes, 32, out_hashes[i]);
    }
}

// Compare intersection
int compute_intersection(const uint8_t bob_hashes[][HASH_SIZE], int bob_count, const uint8_t alice_hashes[][HASH_SIZE], int alice_count, int *match_indices) {
    int count = 0;
    for (int i = 0; i < alice_count; i++) {
        for (int j = 0; j < bob_count; j++) {
            if (memcmp(alice_hashes[i], bob_hashes[j], HASH_SIZE) == 0) {
                match_indices[count++] = j;
            }
        }
    }
    return count;
}

// Example main
int main() {
    if (sodium_init() == -1) return 1;

    char *bob_words[] = {"Alice", "Bob", "Charlie"};
    char *alice_words[] = {"alice", "David", "Charlie"};
    int bob_count = 3, alice_count = 3;

    uint8_t KB[SCALAR_SIZE], KR[SCALAR_SIZE], KR_inv[SCALAR_SIZE];
    uint8_t KAB[32], nonce[NONCE_SIZE];

    randombytes_buf(KB, SCALAR_SIZE);
    randombytes_buf(KR, SCALAR_SIZE);
    randombytes_buf(KAB, 32);
    randombytes_buf(nonce, NONCE_SIZE);

    // Inverse scalar via libsodium: KR^-1 mod l (use direct inversion if needed)
    memcpy(KR_inv, KR, SCALAR_SIZE); // Simulate inversion for demo (not actual inverse!)

    uint8_t bob_hashes[MAX_WORDS][HASH_SIZE];
    prepare_database(bob_words, bob_count, KB, KAB, nonce, bob_hashes);

    uint8_t alice_encoded[MAX_WORDS * MAX_VARIANTS][32];
    int req_count = prepare_request(alice_words, alice_count, KR, alice_encoded);

    uint8_t bob_response[MAX_WORDS * MAX_VARIANTS][32];
    handle_request((uint8_t *)alice_encoded, req_count, KB, (uint8_t *)bob_response);

    uint8_t final_hashes[MAX_WORDS * MAX_VARIANTS][HASH_SIZE];
    decrypt_sender((uint8_t *)bob_response, req_count, KR_inv, KAB, nonce, final_hashes);

    int match_indices[MAX_WORDS];
    int matches = compute_intersection(bob_hashes, bob_count, final_hashes, req_count, match_indices);

    printf("Matches found: %d\n", matches);
    for (int i = 0; i < matches; i++) {
        printf("  Bob matched: %s\n", bob_words[match_indices[i]]);
    }

    return 0;
}
    



