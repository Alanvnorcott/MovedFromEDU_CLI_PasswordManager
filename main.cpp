#include <iostream>
#include <fstream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <cstring>

const int AES_KEY_LENGTH = 256;
const char *PASSWORD_FILE = "passwords.enc";

void encrypt(const std::string &data, std::vector<unsigned char> &encrypted, unsigned char *key) {
    AES_KEY encryptKey;
    AES_set_encrypt_key(key, AES_KEY_LENGTH, &encryptKey);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    
    encrypted.insert(encrypted.end(), iv, iv + AES_BLOCK_SIZE);
    int numBlocks = data.size() / AES_BLOCK_SIZE + 1;
    std::vector<unsigned char> paddedData(numBlocks * AES_BLOCK_SIZE);
    memcpy(paddedData.data(), data.c_str(), data.size());

    for (int i = 0; i < numBlocks; ++i) {
        AES_encrypt(paddedData.data() + i * AES_BLOCK_SIZE, encrypted.data() + AES_BLOCK_SIZE + i * AES_BLOCK_SIZE, &encryptKey);
    }
}

void savePassword(const std::string &site, const std::string &password, unsigned char *key) {
    std::ofstream file(PASSWORD_FILE, std::ios::binary | std::ios::app);
    std::string entry = site + " " + password + "\n";
    std::vector<unsigned char> encrypted(entry.size() + AES_BLOCK_SIZE);
    encrypt(entry, encrypted, key);
    file.write(reinterpret_cast<char *>(encrypted.data()), encrypted.size());
    file.close();
}

int main() {
    unsigned char key[32] = "thisisaverysecurekey123456789"; 
    std::string site, password;

    std::cout << "Enter site: ";
    std::cin >> site;
    std::cout << "Enter password: ";
    std::cin >> password;

    savePassword(site, password, key);
    std::cout << "Password saved securely.\n";

    return 0;
}
