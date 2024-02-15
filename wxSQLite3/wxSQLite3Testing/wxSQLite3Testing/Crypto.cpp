#include "../pch.h"
#include "Crypto.h"

std::vector<unsigned char> Encrypt(std::vector<unsigned char>& data) {
	int dataSize = data.size();
	int it = 0;

	const size_t BLOCK_SIZE = 16;
	const size_t KEY_SIZE = 32;
	const std::string kPassphrase = "AesCEInsight012";

	std::vector<unsigned char> salt(8);

	// generate salt
	CryptoPP::AutoSeededRandomPool rnd1;
	rnd1.GenerateBlock(salt.data(), salt.size());
	CryptoPP::SHA512 hash;
	unsigned char digest[CryptoPP::SHA512::DIGESTSIZE];
	hash.Update(salt.data(), salt.size());
	hash.Update(reinterpret_cast<const unsigned char*>(kPassphrase.data()), kPassphrase.size());
	hash.Final(digest);

	// generate iv
	std::vector<unsigned char> iv(CryptoPP::Twofish::BLOCKSIZE);
	CryptoPP::AutoSeededRandomPool rnd2;
	rnd2.GenerateBlock(iv.data(), iv.size());

	std::vector<unsigned char> outputBuffer(dataSize + 24);
	std::copy(salt.begin(), salt.end(), outputBuffer.begin());
	it += 8;
	std::copy(iv.begin(), iv.end(), outputBuffer.begin() + it);
	it += 16;

	CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption encryptor;

	encryptor.SetKeyWithIV(digest, KEY_SIZE, iv.data());

	size_t lastBlockSize = dataSize % BLOCK_SIZE;

	if (lastBlockSize != 0)
	{
		dataSize -= lastBlockSize;

		CryptoPP::ArraySource as(data.data(), dataSize, true,
			new CryptoPP::StreamTransformationFilter(encryptor,
				new CryptoPP::ArraySink(outputBuffer.data() + it, dataSize),
				CryptoPP::BlockPaddingSchemeDef::NO_PADDING));

		unsigned char* lastBlock = data.data() + dataSize;
		unsigned char* lastOutput = outputBuffer.data() + it + dataSize;
		
		CryptoPP::Twofish::Encryption encryption;
		encryption.SetKey(digest, KEY_SIZE);
		unsigned char encryptedBlock[BLOCK_SIZE];
		encryption.ProcessBlock(lastOutput - BLOCK_SIZE, encryptedBlock);

		for (size_t i = 0; i < lastBlockSize; ++i) {
			lastBlock[i] ^= encryptedBlock[i]; 
			lastOutput[i] = lastBlock[i]; 
		}
	}
	else {
		CryptoPP::ArraySource as(data.data(), dataSize, true,
			new CryptoPP::StreamTransformationFilter(encryptor,
				new CryptoPP::ArraySink(outputBuffer.data() + it, dataSize),
				CryptoPP::BlockPaddingSchemeDef::NO_PADDING));
	}

	return outputBuffer;
}

std::vector<unsigned char> Decrypt(std::vector<unsigned char>& data){
	const size_t BLOCK_SIZE = 16; // Block size for Twofish
	const size_t KEY_SIZE = 32; // Size of key in bytes for Twofish
	const std::string kPassphrase = "AesCEInsight012";

	int it = 0;
	// get 8 byte salt
	std::vector<unsigned char> salt(8);
	std::copy(data.begin(), data.begin() + 8, salt.begin());
	it += 8;
	// create 64 byte hash digest using pass phrase
	CryptoPP::SHA512 hash;
	unsigned char digest[CryptoPP::SHA512::DIGESTSIZE];
	hash.Update(salt.data(), salt.size());
	hash.Update(reinterpret_cast<const unsigned char*>(kPassphrase.data()), kPassphrase.size());
	hash.Final(digest);

	// get 16 byte IV
	std::vector<unsigned char> iv(CryptoPP::Twofish::BLOCKSIZE);
	std::copy(data.begin() + it, data.begin() + it + 16, iv.begin());
	it += 16;

	// set cipher
	CryptoPP::CBC_Mode<CryptoPP::Twofish>::Decryption decryptor;
	//decryptor.SetBlockSize(BLOCK_SIZE);
	decryptor.SetKeyWithIV(digest, KEY_SIZE, iv.data());

	// get data buffer
	int dataSize = data.size() - it;

	// Calculate the size of the last block
	size_t lastBlockSize = dataSize % BLOCK_SIZE;

	std::vector<unsigned char> outputBuffer(dataSize);
	// DcPCryptV2 compatibility; procedure TDCP_blockcipher128.DecryptCBC()
	// Basically, for the last final block that is not of size = BLOCK_SIZE
	if (lastBlockSize != 0)
	{
		dataSize -= lastBlockSize;

		// Decrypt full blocks
		CryptoPP::ArraySource as(data.data() + it, dataSize, true,
			new CryptoPP::StreamTransformationFilter(decryptor,
				new CryptoPP::ArraySink(outputBuffer.data(), outputBuffer.size()),
				CryptoPP::BlockPaddingSchemeDef::NO_PADDING));


		// Get a pointer to the start of the last block in buffer
		unsigned char* lastBlock = data.data() + it + dataSize;
		unsigned char* lastOutput = outputBuffer.data() + dataSize;

		// Create a new cipher object for encrypting the last full block of ciphertext
		CryptoPP::Twofish::Encryption encryption;
		encryption.SetKey(digest, KEY_SIZE);

		// Encrypt the last full block of ciphertext
		unsigned char encryptedBlock[BLOCK_SIZE];
		encryption.ProcessBlock(lastBlock - BLOCK_SIZE, encryptedBlock);

		for (size_t i = 0; i < lastBlockSize; ++i) {
			lastBlock[i] ^= encryptedBlock[i]; // XOR the remaining bytes with the encrypted block
			lastOutput[i] = lastBlock[i]; // place the bytes into the output buffer
		}

	} // decypt as normal
	else CryptoPP::ArraySource as(data.data() + it, dataSize, true,
		new CryptoPP::StreamTransformationFilter(decryptor,
			new CryptoPP::ArraySink(outputBuffer.data(), outputBuffer.size()),
			CryptoPP::BlockPaddingSchemeDef::NO_PADDING));

	return outputBuffer;
}
