#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <omp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <chrono>
#include <atomic>

// Base58 alphabet
const std::string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Base58 encoding function
std::string base58Encode(const std::vector<unsigned char>& input) {
    std::string result;
    std::vector<unsigned char> digits;

    for (auto byte : input) {
        unsigned int carry = byte;
        for (auto& digit : digits) {
            carry += digit << 8;
            digit = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }

    for (auto byte : input) {
        if (byte == 0x00) {
            result += BASE58_ALPHABET[0];
        } else {
            break;
        }
    }

    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        result += BASE58_ALPHABET[*it];
    }

    return result;
}

// Generate compact public key from private key
std::vector<unsigned char> generatePublicKeyCompact(const std::string& privateKeyHex) {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ecKey) throw std::runtime_error("Failed to create EC key");

    BIGNUM* privKeyBN = BN_new();
    BN_hex2bn(&privKeyBN, privateKeyHex.c_str());
    EC_KEY_set_private_key(ecKey, privKeyBN);

    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* pubKey = EC_POINT_new(group);
    EC_POINT_mul(group, pubKey, privKeyBN, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(ecKey, pubKey);

    std::vector<unsigned char> publicKey;
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    EC_POINT_get_affine_coordinates_GFp(group, pubKey, x, y, ctx);
    publicKey.push_back(BN_is_bit_set(y, 0) ? 0x03 : 0x02); // 0x02 if Y is even, 0x03 if odd
    unsigned char* xBuffer = (unsigned char*)OPENSSL_malloc(BN_num_bytes(x));
    BN_bn2bin(x, xBuffer);
    publicKey.insert(publicKey.end(), xBuffer, xBuffer + BN_num_bytes(x));

    OPENSSL_free(xBuffer);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
    EC_POINT_free(pubKey);
    BN_free(privKeyBN);
    EC_KEY_free(ecKey);

    return publicKey;
}

// Generate Bitcoin address from private key
std::string generateBitcoinAddress(const std::string& privateKeyHex) {
    std::vector<unsigned char> publicKey = generatePublicKeyCompact(privateKeyHex);

    unsigned char sha256Hash[SHA256_DIGEST_LENGTH];
    SHA256(publicKey.data(), publicKey.size(), sha256Hash);

    unsigned char ripemd160Hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256Hash, SHA256_DIGEST_LENGTH, ripemd160Hash);

    std::vector<unsigned char> extendedRipemd160Hash;
    extendedRipemd160Hash.push_back(0x00);
    extendedRipemd160Hash.insert(extendedRipemd160Hash.end(), ripemd160Hash, ripemd160Hash + RIPEMD160_DIGEST_LENGTH);

    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256(extendedRipemd160Hash.data(), extendedRipemd160Hash.size(), checksum);
    SHA256(checksum, SHA256_DIGEST_LENGTH, checksum);

    extendedRipemd160Hash.insert(extendedRipemd160Hash.end(), checksum, checksum + 4);

    return base58Encode(extendedRipemd160Hash);
}

// Brute force optimized with error prevention
void bruteForceKeyOptimized(const std::string& knownPrivateKey, const std::string& targetAddress, int maxThreads) {
    auto startTime = std::chrono::high_resolution_clock::now();

    std::atomic<bool> found(false);
    std::string resultKey;
    std::atomic<int64_t> keysTested(0);
    int privateKeyLength = knownPrivateKey.size();

    for (int depth = 1; depth <= privateKeyLength; ++depth) {
        std::string privateKey = knownPrivateKey;
        auto depthStartTime = std::chrono::high_resolution_clock::now();

        int64_t totalCombinations = 1;
        for (int i = 0; i < depth; ++i) {
            totalCombinations *= 16;
        }

        if (totalCombinations < 100) { // Evita divisões por zero em progress updates
            totalCombinations = 100;
        }

        int64_t blockSize = totalCombinations / (5 * maxThreads);
        if (blockSize < 1) blockSize = 1;

        std::cout << "\nStarting depth " << depth << ": " << totalCombinations << " combinations.\n";

        #pragma omp parallel for schedule(dynamic) num_threads(maxThreads)
        for (int64_t blockStart = 0; blockStart < totalCombinations; blockStart += blockSize) {
            if (found.load()) continue;

            for (int64_t i = blockStart; i < blockStart + blockSize && i < totalCombinations; ++i) {
                if (found.load()) break;

                std::string testKey = privateKey;
                int64_t temp = i;

                for (int d = 1; d <= depth; ++d) {
                    int hexValue = temp % 16;
                    testKey[testKey.size() - d] = (hexValue < 10 ? '0' + hexValue : 'a' + hexValue - 10);
                    temp /= 16;
                }

                try {
                    std::string generatedAddress = generateBitcoinAddress(testKey);
                    keysTested++;

                    if (generatedAddress == targetAddress) {
                        found.store(true);
                        resultKey = testKey;
                    }
                } catch (...) {}
            }

            if (blockStart % (totalCombinations / 100) == 0) {
                auto now = std::chrono::high_resolution_clock::now();
                double elapsed = std::chrono::duration<double>(now - startTime).count();
                double keysPerSecond = keysTested / elapsed;
                int progress = (100 * blockStart) / totalCombinations;
                std::cout << "\rDepth: " << depth
                          << " | Progress: " << progress << "%"
                          << " | Keys Tested: " << keysTested
                          << " | Speed: " << keysPerSecond << " keys/s"
                          << "        "
                          << std::flush;
            }
        }

        if (found.load()) break;

        auto depthEndTime = std::chrono::high_resolution_clock::now();
        double depthDuration = std::chrono::duration<double>(depthEndTime - depthStartTime).count();
        std::cout << "\nDepth " << depth << " completed in " << depthDuration << " seconds.\n";
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    double totalDuration = std::chrono::duration<double>(endTime - startTime).count();

    if (found.load()) {
        std::cout << "\nMatch found! Private Key: " << resultKey << "\n";
    } else {
        std::cout << "\nNo match found.\n";
    }

    std::cout << "Total time elapsed: " << totalDuration << " seconds.\n";
}

int main() {
    std::string knownPrivateKey;
    std::string targetAddress;
    int maxThreads;

    std::cout << "Enter the known private key: ";
    std::cin >> knownPrivateKey;

    std::cout << "Enter the target Bitcoin address: ";
    std::cin >> targetAddress;

    std::cout << "Enter the maximum number of threads to use: ";
    std::cin >> maxThreads;

    if (maxThreads < 1) {
        std::cerr << "Invalid number of threads. Using 1 thread by default.\n";
        maxThreads = 1;
    }

    bruteForceKeyOptimized(knownPrivateKey, targetAddress, maxThreads);

    return 0;
}
