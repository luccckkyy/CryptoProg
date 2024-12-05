#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h> 

using CryptoPP::byte;
using CryptoPP::SHA256;
using CryptoPP::HexEncoder;
using CryptoPP::StringSource;
using CryptoPP::StringSink;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv << " <filename>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << argv[1] << std::endl;
        return 1;
    }

    std::size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    byte* buffer = new byte[fileSize];
    file.read((char*)buffer, fileSize);

    SHA256 hash;
    byte digest[SHA256::DIGESTSIZE];
    hash.Update(buffer, fileSize);
    hash.Final(digest);

    delete[] buffer; 

    std::string encoded;
    HexEncoder encoder(new StringSink(encoded));
    encoder.Put(digest, SHA256::DIGESTSIZE);
    encoder.MessageEnd();

    std::cout << encoded << std::endl;

    return 0;
}


