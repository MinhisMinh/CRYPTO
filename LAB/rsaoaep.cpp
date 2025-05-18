#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

// UTF-8 Vietnamese languages
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>

#include "include/cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "include/cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "include/cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "include/cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "include/cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include "include/cryptopp/integer.h"
using CryptoPP::Integer;

#include "include/cryptopp/nbtheory.h"
using CryptoPP::ModularSquareRoot;

#include "include/cryptopp/modarith.h"
using CryptoPP::ModularArithmetic;

#include <cstdlib>
#include <locale>
#include <cctype>

#include <fstream>
#include <sstream>
using std::ofstream;
using std::ifstream;
using std::getline;
using std::istringstream;

#ifndef DLL_EXPORT
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif
#endif

// Add these constants at the top of your file
const string RSA_PRIV_HEADER = "-----BEGIN RSA PRIVATE KEY-----\n";
const string RSA_PRIV_FOOTER = "-----END RSA PRIVATE KEY-----\n";
const string RSA_PUB_HEADER = "-----BEGIN PUBLIC KEY-----\n";
const string RSA_PUB_FOOTER = "-----END PUBLIC KEY-----\n";

// Save (BER-BIN) key to file
void Save(const string &filename, const BufferedTransformation &bt);
void SavePrivateKey(const string &filename, const PrivateKey &key);
void SavePublicKey(const string &filename, const PublicKey &key);

// Save (BER-BASE64) key to file
// void SaveBase64(const string &filename, const BufferedTransformation &bt);
// void SaveBase64PrivateKey(const string &filename, const PrivateKey &key);
// void SaveBase64PublicKey(const string &filename, const PublicKey &key);

// Load (BER-BIN) key to buffer
void Load(const string &filename, BufferedTransformation &bt);
void LoadPrivateKey(const string &filename, PrivateKey &key);
void LoadPublicKey(const string &filename, PublicKey &key);

// Loat (BER-BASE64) key to buffer
// void LoadBase64(const string &filename, BufferedTransformation &bt);
// void LoadBase64PrivateKey(const string &filename, RSA::PrivateKey &key);
// void LoadBase64PublicKey(const string &filename, RSA::PublicKey &key);

void SavePEMKey(const string &filename, const BufferedTransformation &bt, 
                const string &header, const string &footer);
void SavePEMPrivateKey(const string &filename, const PrivateKey &key);
void SavePEMPublicKey(const string &filename, const PublicKey &key);
void LoadPEMKey(const string &filename, BufferedTransformation &bt);
void LoadPEMPrivateKey(const string &filename, RSA::PrivateKey &key);
void LoadPEMPublicKey(const string &filename, RSA::PublicKey &key);

// extern "C"
// {
// 	DLL_EXPORT void GenerateAndSaveRSAKeys(int keySize, const char *format, const char *privateKeyFile, const char *publicKeyFile);
// 	DLL_EXPORT void RSAencrypt(const char *format, const char *publicKeyFile, const char *PlaintextFile, const char *CiphertFile);
// 	DLL_EXPORT void RSAdecrypt(const char *format, const char *privateKeyFile, const char *ciphertextFile, const char *PlaintextFile);
// }

void GenerateAndSaveRSAKeys(int keySize, const char *format, const char *privateKeyFile, const char *publicKeyFile)
{
	// convert commandline char to string
	string strFormat(format);
	string strPrivateKey(privateKeyFile);
	string strPublicKey(publicKeyFile);

	AutoSeededRandomPool rnd;
	// Generate Private key
	RSA::PrivateKey rsaPrivate;
	rsaPrivate.GenerateRandomWithKeySize(rnd, keySize);
	// Generate public key
	RSA::PublicKey rsaPublic(rsaPrivate);

	if (strFormat == "DER")
	{
		// Save keys to file (bin)
		SavePrivateKey(strPrivateKey, rsaPrivate);
		SavePublicKey(strPublicKey, rsaPublic);
	}
	else if (strFormat == "PEM")
	{
		// Save keys to file (PEM)
		SavePEMPrivateKey(strPrivateKey, rsaPrivate);
		SavePEMPublicKey(strPublicKey, rsaPublic);
	}
	else
	{
		cout << "Unsupported format. Please choose 'DER' or 'PEM'." << endl;
		exit(1);
	}

	Integer modul1 = rsaPrivate.GetModulus();	  // modul n (from private)
	Integer prime1 = rsaPrivate.GetPrime1();	  // prime p
	Integer prime2 = rsaPrivate.GetPrime2();	  // prime p
	Integer SK = rsaPrivate.GetPrivateExponent(); // secret exponent d
	Integer PK = rsaPublic.GetPublicExponent();
	Integer modul2 = rsaPublic.GetModulus(); // modul n (from public)
	cout << " Modulo (private) n = " << modul1 << endl;
	cout << " Modulo (public) n = " << modul2 << endl;
	cout << " Prime number (private) p = " << std::hex << prime1 << endl;
	cout << " Prime number (public) q = " << prime2 << std::dec << endl;
	cout << " Secret exponent d =  " << SK << endl;
	cout << " Public exponent e = " << PK << endl; // 17?

	cout << "Successfully generated and saved RSA keys" << endl;
}

// Encryption
string RSAencrypt(const string format, const char *publicKeyFile, const char *PlaintextFile, const char *CipherFile)
{
    // Load public key
    RSA::PublicKey rsaPublic;
    if (format == "DER") {
        LoadPublicKey(publicKeyFile, rsaPublic);
    } else if (format == "PEM") {
        LoadPEMPublicKey(publicKeyFile, rsaPublic);
    } else {
        cout << "Unsupported format" << endl;
        return "";
    }

    // Get maximum message length for RSA-OAEP
    RSAES_OAEP_SHA_Encryptor e(rsaPublic);
    size_t maxMsgLength = e.FixedMaxPlaintextLength();
    
    // Read input file in chunks
    string plain, cipher, hex_cipher;
    FileSource(PlaintextFile, true, new StringSink(plain));
    
    // Process file in chunks
    AutoSeededRandomPool rng;
    for(size_t pos = 0; pos < plain.length(); pos += maxMsgLength) {
        // Get chunk of appropriate size
        string chunk = plain.substr(pos, maxMsgLength);
        
        // Encrypt chunk
        string encrypted_chunk;
        StringSource(chunk, true,
            new PK_EncryptorFilter(rng, e,
                new StringSink(encrypted_chunk))
        );
        
        // Add chunk length and encrypted chunk to output
        cipher += encrypted_chunk;
    }

    // Save complete ciphertext
    StringSource(cipher, true, new FileSink(CipherFile));

    // Convert to hex for display
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(hex_cipher)
        )
    );

    return hex_cipher;
}

// Decryption
string RSAdecrypt(const string format, const char *secretKeyFile, const char *CipherFile, const char *PlaintextFile)
{
    // Load private key
    RSA::PrivateKey rsaPrivate;
    if (format == "DER")
        LoadPrivateKey(secretKeyFile, rsaPrivate);
    else if (format == "PEM")
        LoadPEMPrivateKey(secretKeyFile, rsaPrivate);
    else {
        cout << "Unsupported format" << endl;
        return "";
    }

    // Get RSA parameters
    RSAES_OAEP_SHA_Decryptor d(rsaPrivate);
    size_t cipherBlockSize = d.FixedCiphertextLength();  // Block size for RSA-OAEP

    // Read encrypted data
    string cipher;
    FileSource(CipherFile, true, new StringSink(cipher));

    // Verify total length is multiple of block size
    if (cipher.length() % cipherBlockSize != 0) {
        throw runtime_error("Invalid ciphertext length");
    }

    string recovered;
    AutoSeededRandomPool rng;

    // Process each block
    for (size_t pos = 0; pos < cipher.length(); pos += cipherBlockSize) {
        string block = cipher.substr(pos, cipherBlockSize);
        
        // Decrypt block
        string decrypted_block;
        StringSource(block, true,
            new PK_DecryptorFilter(rng, d,
                new StringSink(decrypted_block))
        );
        
        recovered += decrypted_block;
    }

    // Save decrypted result
    StringSource(recovered, true, new FileSink(PlaintextFile));

    return recovered;
}

int main(int argc, char **argv)
{
#ifdef _WIN32
	// Set console code page to UTF-8 on Windows C.utf8, CP_UTF8
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);
#endif
	if (argc < 2)
	{
		cerr << "Usage: \n"
			 << argv[0] << " gen <keysize> <format> <privateKeyFile> <publicKeyFile>\n"
			 << argv[0] << " enc <format> <publicKeyFile> <plainFile> <cipherFile>\n"
			 << argv[0] << " dec <format> <privateKeyFile> <plainFile> <cipherFile>\n";
		return -1;
	}

	string mode = argv[1];

	if (mode == "gen" && argc == 6)
	{
		int keySize = std::stoi(argv[2]);
		GenerateAndSaveRSAKeys(keySize, argv[3], argv[4], argv[5]);
	}
	else if (mode == "enc" && argc == 6)
	{
		string cipher = RSAencrypt(argv[2], argv[3], argv[4], argv[5]);
		//cout << "Cipher text: " << cipher << endl;
		cout << "Do you want to encrypt 10000 times? (y/n) ";
		char c;
		std::cin >> c;
		if (c == 'y')
		{
			auto start = std::chrono::high_resolution_clock::now();
			for (int i = 0; i < 10000; i++)
			{
				string cipher = RSAencrypt(argv[2], argv[3], argv[4], argv[5]);
				// cout << "Round: " << i << endl;
			}
			auto end = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
			double averageTime = static_cast<double>(duration) / 10000.0;
			std::cout << "Total time for over 10000 rounds: " << static_cast<double>(duration) << " ms" << std::endl;
			std::cout << "Average time for over 10000 rounds: " << averageTime << " ms" << std::endl;
		}
		else if (c == 'n')
		{
			cout << "Goodbye!" << endl;
		}
		else
		{
			cout << "Invalid input" << endl;
		}
	}
	else if (mode == "dec")
	{
		const string format = argv[2];
		const char *private_key = argv[3];
		const char *cipher = argv[5];
		const char *plain = argv[4];
		string plaintext = RSAdecrypt(format, private_key, cipher, plain);
		//cout << "Plaintext: " << plaintext << endl;
		cout << "Do you want to decrypt 10000 times? (y/n) ";
		char c;
		std::cin >> c;
		if (c == 'y')
		{
			auto start = std::chrono::high_resolution_clock::now();
			for (int i = 0; i < 10000; i++)
			{
				string palin = RSAdecrypt(format, private_key, cipher, plain);
				// cout << "Round: " << i << endl;
			}
			auto end = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
			double averageTime = static_cast<double>(duration) / 10000.0;
			std::cout << "Total time for over 10000 rounds: " << static_cast<double>(duration) << " ms" << std::endl;
			std::cout << "Average time for over 10000 rounds: " << averageTime << " ms" << std::endl;
		}
		else if (c == 'n')
		{
			cout << "Goodbye!" << endl;
		}
		else
		{
			cout << "Invalid input" << endl;
		}
	}
	else
	{
		cerr << "Invalid arguments. Please check the usage instructions.\n";
		return -1;
	}

	return 0;
}

// Def functions
/* ############################### */
void SavePrivateKey(const string &filename, const PrivateKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string &filename, const PublicKey &key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string &filename, const BufferedTransformation &bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SavePEMKey(const string &filename, const BufferedTransformation &bt, 
                const string &header, const string &footer)
{
    // Open file and write header
    ofstream file(filename);
    file << header;

    // Set up Base64 encoder with linebreaks every 64 characters
    string encoded;
    Base64Encoder encoder(new StringSink(encoded), true, 64);  // true enables line breaks
    bt.CopyTo(encoder);
    encoder.MessageEnd();

    // Format the encoded data with proper line spacing
    istringstream iss(encoded);
    string line;
    while (getline(iss, line)) {
        if (!line.empty()) {
            file << line << "\n";  // Add newline after each 64-char line
        }
    }

    // Write footer on a new line
    file << footer;
    file.close();
}

void SavePEMPrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    SavePEMKey(filename, queue, RSA_PRIV_HEADER, RSA_PRIV_FOOTER);
}

void SavePEMPublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    SavePEMKey(filename, queue, RSA_PUB_HEADER, RSA_PUB_FOOTER);
}

void LoadPEMKey(const string &filename, BufferedTransformation &bt)
{
    string line, content;
    ifstream file(filename);
    bool isFirst = true;
    
    // Read all lines
    while (getline(file, line)) {
        // Skip header (first line)
        if (isFirst) {
            isFirst = false;
            continue;
        }
        
        // Stop at footer
        if (line.find("-----END") != string::npos) {
            break;
        }
        
        // Add content line
        content += line;
    }
    
    // Decode only the content (without header/footer)
    StringSource source(content, true, new Base64Decoder);
    source.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPEMPrivateKey(const string &filename, RSA::PrivateKey &key)
{
    ByteQueue queue;
    LoadPEMKey(filename, queue);
    key.Load(queue);
    
    // Validate the loaded key
    AutoSeededRandomPool prng;
    if (!key.Validate(prng, 3))
        throw runtime_error("Loaded private key is invalid");
}

void LoadPEMPublicKey(const string &filename, RSA::PublicKey &key)
{
    ByteQueue queue;
    LoadPEMKey(filename, queue);
    key.Load(queue);
    
    // Validate the loaded key
    AutoSeededRandomPool prng;
    if (!key.Validate(prng, 3))
        throw runtime_error("Loaded public key is invalid");
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true);
    file.TransferTo(bt);
    bt.MessageEnd();
}