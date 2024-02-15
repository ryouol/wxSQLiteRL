#ifndef CRYPTO_H
#define CRYPTO_H

#include <cryptopp/sha.h>
#include <cryptopp/twofish.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

#include <vector>

std::vector<unsigned char> Encrypt(std::vector<unsigned char>& data);

std::vector<unsigned char> Decrypt(std::vector<unsigned char>& data);

#endif