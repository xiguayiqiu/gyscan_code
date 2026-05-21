#define PBKDF2_ITERATIONS 4096
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

__device__ void gpu_sha1_transform(unsigned int state[5], const unsigned char block[64]);
__device__ void gpu_hmac_sha1(
    const unsigned char ipad[64],
    const unsigned char opad[64],
    const unsigned char *data,
    unsigned int data_len,
    unsigned char digest[20]);

extern "C" __global__ void wpa_pbkdf2_pmk(
    const unsigned char *passwords,
    const unsigned int *pass_lens,
    const unsigned int *pass_offsets,
    const unsigned char *essid,
    unsigned int essid_len,
    unsigned char *pmks,
    unsigned int num_passwords)
{
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_passwords) return;

    unsigned int pass_off = pass_offsets[idx];
    unsigned int pass_len = pass_lens[idx];

    unsigned char salt[68];
    for (unsigned int i = 0; i < essid_len; i++) {
        salt[i] = essid[i];
    }

    unsigned char ipad[64], opad[64];
    const unsigned char *key = &passwords[pass_off];
    unsigned int key_len = pass_len;

    if (key_len > 64) {
        key_len = 63;
    }

    for (int i = 0; i < 64; i++) {
        ipad[i] = (i < key_len) ? key[i] : 0;
        opad[i] = ipad[i];
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    unsigned char T[20], U[20];

    for (int block = 1; block <= 2; block++) {
        salt[essid_len]     = (block >> 24) & 0xFF;
        salt[essid_len + 1] = (block >> 16) & 0xFF;
        salt[essid_len + 2] = (block >> 8) & 0xFF;
        salt[essid_len + 3] = block & 0xFF;

        gpu_hmac_sha1(ipad, opad, salt, essid_len + 4, T);

        for (int i = 0; i < 20; i++) U[i] = T[i];

        for (int iter = 1; iter < PBKDF2_ITERATIONS; iter++) {
            gpu_hmac_sha1(ipad, opad, U, 20, U);
            for (int i = 0; i < 20; i++) T[i] ^= U[i];
        }

        for (int i = 0; i < 20; i++) {
            pmks[idx * 32 + (block - 1) * 20 + i] = T[i];
        }
    }
}

__device__ void gpu_sha1_transform(unsigned int state[5], const unsigned char block[64]) {
    unsigned int w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((unsigned int)block[i*4] << 24) | ((unsigned int)block[i*4+1] << 16) |
               ((unsigned int)block[i*4+2] << 8) | (unsigned int)block[i*4+3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    unsigned int a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

    for (int i = 0; i < 80; i++) {
        unsigned int f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }

        unsigned int temp = ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROTL(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

__device__ void gpu_hmac_sha1(
    const unsigned char ipad[64],
    const unsigned char opad[64],
    const unsigned char *data,
    unsigned int data_len,
    unsigned char digest[20])
{
    unsigned int inner_state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    unsigned int outer_state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    unsigned char block[64];
    for (int i = 0; i < 64; i++) block[i] = ipad[i];
    for (unsigned int i = 0; i < data_len && i < 64; i++) block[i] ^= data[i];
    gpu_sha1_transform(inner_state, block);

    for (int i = 0; i < 64 - data_len; i++) block[i] = 0;
    block[0] = 0x80;
    gpu_sha1_transform(inner_state, block);

    unsigned char inner_digest[20];
    for (int i = 0; i < 5; i++) {
        inner_digest[i*4]     = (inner_state[i] >> 24) & 0xFF;
        inner_digest[i*4 + 1] = (inner_state[i] >> 16) & 0xFF;
        inner_digest[i*4 + 2] = (inner_state[i] >> 8) & 0xFF;
        inner_digest[i*4 + 3] = inner_state[i] & 0xFF;
    }

    for (int i = 0; i < 64; i++) block[i] = opad[i];
    for (int i = 0; i < 20; i++) block[i] ^= inner_digest[i];
    gpu_sha1_transform(outer_state, block);

    for (int i = 0; i < 64 - 20; i++) block[i] = 0;
    block[0] = 0x80;
    gpu_sha1_transform(outer_state, block);

    for (int i = 0; i < 5; i++) {
        digest[i*4]     = (outer_state[i] >> 24) & 0xFF;
        digest[i*4 + 1] = (outer_state[i] >> 16) & 0xFF;
        digest[i*4 + 2] = (outer_state[i] >> 8) & 0xFF;
        digest[i*4 + 3] = outer_state[i] & 0xFF;
    }
}