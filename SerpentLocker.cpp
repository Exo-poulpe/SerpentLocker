// CryptoFiles.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include <string>
#include <fstream>
#include <algorithm>
#include <ctime>

#include "args.hxx"
#include "dirent.h"

#include "CryptoPP/base64.h"
#include "CryptoPP/hex.h"
#include "CryptoPP/osrng.h"
#include "CryptoPP/serpent.h"
#include "CryptoPP/aes.h"
#include "CryptoPP/sha.h"
#include "CryptoPP/modes.h"
#include "CryptoPP/filters.h"


using namespace std;
using namespace CryptoPP;


bool verbose = false;
clock_t timerStarted, timerEnded;

string base64_decode(string& input);
string base64_encode(string& input);
//void aes_ecb_encrypt(string& text, unsigned char key[AES::MAX_KEYLENGTH]);
//void aes_ecb_decrypt(string& cipher, unsigned char key[AES::MAX_KEYLENGTH]);
//void srp_cbc_encrypt(string& input, unsigned char pass[Serpent::MAX_KEYLENGTH]);
//void srp_cbc_decrypt(string& input, unsigned char pass[Serpent::MAX_KEYLENGTH]);
void srp_cfb_encrypt(string& input, unsigned char key[AES::DEFAULT_KEYLENGTH]);
void srp_cfb_decrypt(string& input, unsigned char key[AES::DEFAULT_KEYLENGTH]);
void srp_encrypt_file(string path, string pass, string outputname);
void srp_decrypt_file(string path, string pass, string outputname);
vector<string> list_files_in_folder(string path);
void StartTimer();
void StopTimer();
string CalcElapsedTime();










int main(int argc, char** argv)
{
	args::ArgumentParser parser("This program crypt data of file with advanced encrypt algorithm", "Author Exo-poulpe");
	args::Group group(parser, "This group is all exclusive:", args::Group::Validators::DontCare);
	args::Flag fVerbose(group, "verbose", "Verbosity of program", { 'v',"verbose" });
	args::Flag fTime(group, "time", "print time elapsed", { "time" });
	args::Flag fVersion(group, "version", "Version of program", { "version" });
	args::Flag fEncrypt(group, "encrypt", "Encrypt file", { 'e', "encrypt" });
	args::Flag fDecrypt(group, "decrypt", "Decrypt file", { 'd', "decrypt" });
	args::ValueFlag<string> fFile(group, "file", "The file to encrypt", { 'f', "file" });
	args::ValueFlag<string> fFolder(group, "folder", "The folder to encrypt all file", { 'F', "folder" });
	args::ValueFlag<string> fText(group, "text", "The text to encrypt", { 't', "text" });
	args::ValueFlag<string> fPass(group, "pass", "The pass to use for encryption", { 'p',"password" });
	args::ValueFlag<string> fOutFile(group, "outputfile", "The output data file", { 'o',"output" });
	args::HelpFlag help(parser, "help", "Display this help menu", { 'h', "help" });
	try
	{
		parser.ParseCLI(argc, argv);
	}
	catch (args::Help)
	{
		std::cout << parser;
		return 0;
	}
	catch (args::ParseError e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		return 1;
	}
	catch (args::ValidationError e)
	{
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		return 1;
	}
	if (fVersion)
	{
		const char* vers = "Author \t\t: \@Exo-poulpe\n"
			"Version \t: 0.1.0.1\n"

			"This tool is for educational purpose only, usage of PerlForing for attacking targets without prior mutual consent is illegal.\n"
			"Developers assume no liabilityand are not responsible for any misuse or damage cause by this program.";
		cout << vers << endl;
	}

	if (fVerbose)
	{
		verbose = true;
	}

	// If text is selected + password + (options encrypt or decrypt)
	if (fText && fPass && (fEncrypt || fDecrypt))
	{
		try
		{
			unsigned char* key = (unsigned char*)args::get(fPass).c_str();
			string message = args::get(fText);
			if (fEncrypt)
			{
				srp_cfb_encrypt(message, key);
			}
			else if (fDecrypt)
			{
				srp_cfb_decrypt(message, key);
			}
		}
		catch (CryptoPP::Exception ex)
		{
			cout << ex.what() << endl;
		}

		return 0;

	}
	else if (fFile && fPass && (fEncrypt || fDecrypt)) // If file is selected + password + (options encrpyt or decrypt)
	{

		try
		{
			if (fEncrypt)
			{
				StartTimer();
				srp_encrypt_file(args::get(fFile), args::get(fPass), args::get(fOutFile));
				StopTimer();
				if (fTime)
				{
					cout << "Time elapsed : " << CalcElapsedTime() << " seconds " << endl;
				}
			}
			else if (fDecrypt)
			{
				StartTimer();
				srp_decrypt_file(args::get(fFile), args::get(fPass), args::get(fOutFile));
				StopTimer();
				if (fTime)
				{
					cout << "Time elapsed : " << CalcElapsedTime() << " seconds " << endl;
				}
			}
		}
		catch (Exception ex)
		{
			cout << "Error : " << ex.what() << endl;
		}
	}
	else if (fFolder && fPass && (fEncrypt || fDecrypt))
	{
		vector<string> filesList = list_files_in_folder(args::get(fFolder));

		if (fEncrypt)
		{
			StartTimer();
			for (auto i = filesList.begin(); i != filesList.end(); ++i)
			{
				string tmp = string(*i);
				srp_encrypt_file(tmp, args::get(fPass), tmp + ".srp");

				remove(tmp.c_str());
			}
			StopTimer();
			if (fTime)
			{
				cout << "Time elapsed : " << CalcElapsedTime() << " seconds " << endl;
			}
		}
		else if (fDecrypt)
		{
			StartTimer();
			for (auto i = filesList.begin(); i != filesList.end(); ++i)
			{
				string tmp = string(*i);
				srp_decrypt_file(tmp, args::get(fPass), tmp.substr(0, tmp.length() - 4));

				remove(string(tmp).c_str());
			}
			StopTimer();
			if (fTime)
			{
				cout << "Time elapsed : " << CalcElapsedTime() << " seconds " << endl;
			}
		}

	}

	if (argc == 1)
	{

		cout << parser;
		return 1;
	}

	return 0;
}


vector<string> list_files_in_folder(string path)
{
	struct dirent** files;
	vector<string> result = vector<string>();
	DIR* dir = opendir(path.c_str());

	if (dir == NULL) {
		exit(1);
	}
	int num = scandir(path.c_str(), &files, NULL, alphasort);

	for (int i = 2; i < num; i++)
	{
		struct dirent* entryListed = files[i];
		if (entryListed->d_type == DT_DIR)
		{
			vector<string> resultAux = list_files_in_folder(path + entryListed->d_name);
			result.insert(result.end(), resultAux.begin(), resultAux.end());
		}
		else
		{
			if (path.substr(path.length() - 1, 1) == "\\" || path.substr(path.length() - 1, 1) == "/")
			{
				result.push_back(path + entryListed->d_name);
			}
			else
			{
				result.push_back(path + "/" + entryListed->d_name);
			}
		}
	}

	closedir(dir);

	return result;
}

void srp_encrypt_file(string path, string pass, string outputname)
{
	try
	{
		char outFile[1];
		string data = string(), line = string(), result = string();
		ifstream infile(path, ios::in | ios::binary);
		infile.seekg(0, infile.end);
		int FileSize = infile.tellg();

		if (verbose)
		{
			cout << "File size : " << FileSize << endl;
		}

		infile.seekg(0);


		for (int i = 0; i < FileSize; i += 1)
		{
			infile.seekg(i);
			infile.read(outFile, 1);
			data += outFile[0];
		}

		infile.close();

		srp_cfb_encrypt(data, (unsigned char*)pass.c_str());

		if (verbose)
		{
			cout << "data length : " << data.length() << endl;
		}

		if (outputname.length() > 0)
		{
			ofstream outfile;
			outfile.open(outputname, ios::out | ios::binary);
			outfile.seekp(0);
			outfile.write(data.c_str(), data.length());
			outfile.close();
		}
		else
		{
			exit(1);
		}

	}
	catch (Exception ex)
	{
		cout << "Error : " << ex.what() << endl;
	}
}

void srp_decrypt_file(string path, string pass, string outputname)
{
	try
	{
		char outFile[1];
		string data = string(), line = string(), result = string();
		ifstream infile(path, ios::in | ios::binary);
		infile.seekg(0, infile.end);
		int FileSize = infile.tellg();

		if (verbose)
		{
			cout << "File size : " << FileSize << endl;
		}

		infile.seekg(0);


		for (int i = 0; i < FileSize; i += 1)
		{
			infile.seekg(i);
			infile.read(outFile, 1);
			data += outFile[0];
		}

		infile.close();

		srp_cfb_decrypt(data, (unsigned char*)pass.c_str());

		if (verbose)
		{
			cout << "data length : " << data.length() << endl;
		}

		if (outputname.length() > 0)
		{
			ofstream outfile;
			outfile.open(outputname, ios::out | ios::binary);
			outfile.seekp(0);
			outfile.write(data.c_str(), data.length());
			outfile.close();
		}
		else
		{
			exit(1);
		}

	}
	catch (Exception ex)
	{
		cout << "Error : " << ex.what() << endl;
	}
}

/// Hash password => SHA1 + Encrypt data
void srp_cfb_encrypt(string& input, unsigned char key[Serpent::MAX_KEYLENGTH])
{
	try
	{
		string digest, finalH;
		string cipher = string();
		string pass((char*)key);


		SHA1 hash;
		hash.Update((const byte*)pass.data(), pass.size());
		digest.resize(hash.DigestSize());
		hash.Final((byte*)&digest[0]);

		StringSource(digest, true, new HexEncoder(new StringSink(finalH)));

		byte iv[Serpent::BLOCKSIZE];
		for (int i = 0; i < Serpent::BLOCKSIZE; i++)
		{
			iv[i] = key[i];
		}

		CryptoPP::CFB_Mode< CryptoPP::Serpent >::Encryption Encryptor;
		Encryptor.SetKeyWithIV((byte*)finalH.data(), 32, iv, 16);

		// Encryption

		CryptoPP::StringSource(input, true,
			new CryptoPP::StreamTransformationFilter(
				Encryptor,
				new CryptoPP::StringSink(cipher)
			) // StreamTransformationFilter

		); // StringSource
		//cout << "Data : " << cipher << endl;
		input = cipher;
	}
	catch (Exception ex)
	{
		cout << "Error : " << ex.GetWhat() << endl;
		exit(1);
	}


}

void srp_cfb_decrypt(string& input, unsigned char key[Serpent::MAX_KEYLENGTH])
{
	try
	{
		string digest, finalH;
		string plainText = string();
		string pass((char*)key);


		SHA1 hash;
		hash.Update((const byte*)pass.data(), pass.size());
		digest.resize(hash.DigestSize());
		hash.Final((byte*)&digest[0]);

		StringSource(digest, true, new HexEncoder(new StringSink(finalH)));

		byte iv[Serpent::BLOCKSIZE];
		for (int i = 0; i < Serpent::BLOCKSIZE; i++)
		{
			iv[i] = key[i];
		}

		CryptoPP::CFB_Mode< CryptoPP::Serpent >::Decryption Decryptor;
		Decryptor.SetKeyWithIV((byte*)finalH.data(), 32, iv, 16);

		// Encryption

		CryptoPP::StringSource(input, true,
			new CryptoPP::StreamTransformationFilter(
				Decryptor,
				new CryptoPP::StringSink(plainText)
			) // StreamTransformationFilter

		); // StringSource
		input = plainText;
	}
	catch (Exception ex)
	{
		cout << "Error : " << ex.GetWhat() << endl;
		exit(1);
	}

}

void StartTimer()
{
	timerStarted = clock();
}

void StopTimer()
{
	timerEnded = clock();
}

string CalcElapsedTime()
{
	double elapsed_sec = double(timerEnded - timerStarted) / CLOCKS_PER_SEC;
	return to_string(elapsed_sec);
}



string base64_encode(string& input) {
	std::string result;
	CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(result)));
	return result;
}

string base64_decode(string& input) {
	std::string result;
	CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(result)));
	std::cout << (input.size() % 16 == 0) << std::endl;
	return result;
}