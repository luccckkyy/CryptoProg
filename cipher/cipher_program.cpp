#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h> 
#include <cryptopp/files.h> 

using namespace std;
using namespace CryptoPP;

CryptoPP::byte* generateKey(const string& password, size_t& keySize) {
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.Update((const CryptoPP::byte*)password.data(), password.size());
    hash.Final(digest);
    keySize = CryptoPP::SHA256::DIGESTSIZE;
    return new CryptoPP::byte[keySize];
}

void encryptFile(const string& inputFileName, const string& outputFileName, const string& password) {
    size_t keySize;
    CryptoPP::byte* key = generateKey(password, keySize);

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::OS_GenerateRandomBlock(false, iv, CryptoPP::AES::BLOCKSIZE);

    ifstream inputFile(inputFileName, ios::binary);
    ofstream outputFile(outputFileName, ios::binary);

    if (!inputFile.is_open() || !outputFile.is_open()) {
        cerr << "Failed to open file." << endl;
        return;
    }

    CryptoPP::AES::Encryption aesEncryption(key, keySize);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    outputFile.write((char*)iv, CryptoPP::AES::BLOCKSIZE);

    CryptoPP::FileSource(inputFile, true,
               new CryptoPP::StreamTransformationFilter(cbcEncryption,
                                            new CryptoPP::FileSink(outputFile)));

    delete[] key;
}

void decryptFile(const string& inputFileName, const string& outputFileName, const string& password) {
    size_t keySize;
    CryptoPP::byte* key = generateKey(password, keySize);

    ifstream inputFile(inputFileName, ios::binary);
    ofstream outputFile(outputFileName, ios::binary);

    if (!inputFile.is_open() || !outputFile.is_open()) {
        cerr << "Failed to open file." << endl;
        return;
    }

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    inputFile.read((char*)iv, CryptoPP::AES::BLOCKSIZE);

    CryptoPP::AES::Decryption aesDecryption(key, keySize);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    CryptoPP::FileSource(inputFile, true,
               new CryptoPP::StreamTransformationFilter(cbcDecryption,
                                            new CryptoPP::FileSink(outputFile)));

    delete[] key;
}

int main() {
    string mode, inputFileName, outputFileName, password;

    cout << "Choose the mode (encrypt/decrypt): ";
    cin >> mode;

    cout << "Enter the input file name: ";
    cin >> inputFileName;

    cout << "Enter the output file name: ";
    cin >> outputFileName;

    cout << "Enter the password: ";
    cin >> password;

    if (mode == "encrypt") {
        encryptFile(inputFileName, outputFileName, password);
    } else if (mode == "decrypt") {
        decryptFile(inputFileName, outputFileName, password);
    } else {
        cerr << "Invalid mode. Use 'encrypt' or 'decrypt'." << endl;
        return 1;
    }

    return 0;
}


