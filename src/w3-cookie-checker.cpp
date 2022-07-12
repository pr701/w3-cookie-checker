/*
*	w3 cookie checker
*	pr, 2022
*/

#include <cstdint>
#include <iostream>
#include <filesystem>
#include <fstream>

#include <cxxopts.hpp>

#undef min
#undef max

#pragma comment(lib, "botan.lib")

#ifdef _DEBUG
#pragma comment(lib, "libprotobuf-lited.lib")
#else
#pragma comment(lib, "libprotobuf-lite.lib")
#endif

#include "proto/authentication_utils.h"
#include "client/client_hwid.h"

using namespace classic::protocol::v1::authentication;
using namespace client;

#if defined(WIN32) && defined(UNICODE)
#define file_path(x)	get_file_path(x)	
#else
#define file_path(x)	x
#endif

#if defined(WIN32) && defined(UNICODE)
std::filesystem::path get_file_path(const std::string& filepath)
{
	std::wstring unicode;
	int count = MultiByteToWideChar(CP_UTF8, 0, filepath.c_str(), filepath.length(), nullptr, 0);
	if (count)
	{
		unicode.resize(count + 1);
		count = MultiByteToWideChar(CP_UTF8, 0, filepath.c_str(), filepath.length(), unicode.data(), count);
		if (count) unicode.resize(count);
	}
	return std::filesystem::path(unicode);
}
#endif

void print_AuthSessionResponse(const AuthSessionResponse& auth)
{
	int ent_count = auth.entitlements_size();
	if (ent_count > 0)
	{
		std::cout << "Entitlements = [";
		for (int i = 0; i < ent_count; ++i)
		{
			std::cout << auth.entitlements(i);
			if (i != ent_count - 1) std::cout << ",";
		}
		std::cout << "]" << std::endl;
	}
	std::cout << "Game ID = " << auth.game_id() << std::endl;
	std::cout << "Account ID = " << auth.account_id() << std::endl;
	std::cout << "ID = " << auth.id() << std::endl;
	std::cout << "Locale = " << auth.locale() << std::endl;
	std::cout << "Expiration Timestamp = " << auth.not_valid_after() << std::endl;
}

void print_cookie(const std::filesystem::path& cookiefile, const std::string& hwid_key)
{
	OfflineCookies cookies;

	std::ifstream file(cookiefile, std::ios::binary);
	if (file)
	{
		if (cookies.ParseFromIstream(&file))
		{
			std::cout << "Reading Cookies..." << std::endl;

			for (int i = 0; i < cookies.cookie_size(); ++i)
			{
				const auto cookie = cookies.cookie(i);

				std::cout << "[#" << i << "]" << std::endl;

				std::cout << "Game ID = " << cookie.game_id() << " (" << app_id_to_name(cookie.game_id()) << ")" << std::endl;
				std::cout << "Verified signature = " << (verify_cookie(cookie) ? "true" : "false") << std::endl;

				AuthSessionResponse response;
				auto decrypt_result = decrypt_cookie(cookie, hwid_key, response);
				if (decrypt_error::success_decrypt == decrypt_result)
				{
					int ent_count = response.entitlements_size();
					if (ent_count > 0)
					{
						std::cout << "Entitlements = [";
						for (int i = 0; i < ent_count; ++i)
						{
							std::cout << response.entitlements(i);
							if (i != ent_count - 1) std::cout << ",";
						}
						std::cout << "]" << std::endl;
					}

					std::cout << "Game ID = " << response.game_id() << std::endl;
					std::cout << "Account ID = " << response.account_id() << std::endl;
					std::cout << "ID = " << response.id() << std::endl;
					std::cout << "Locale = " << response.locale() << std::endl;
					std::cout << "Expiration Timestamp = " << response.not_valid_after() << std::endl;
				}
				else
				{
					std::cout << "Cookie #" << i << " payload error: ";
					switch (decrypt_result)
					{
					case decrypt_error::mismatched_protobuf_types:
						std::cout << "mismatched protobuf types" << std::endl;
						break;
					case decrypt_error::invalid_decryption_key:
						std::cout << "incorrect decryption key" << std::endl;
						break;
					case decrypt_error::parse_protobuf_error:
						std::cout << "protobuf parsing ended with an error" << std::endl;
						break;
					default:
						std::cout << "unknown error" << std::endl;
						break;
					}
				}
			}
		}
		file.close();
	}
}

std::string generate_hwid(const std::string& input)
{
	return HWID_Create(input);
}

#ifdef UNICODE
int _tmain(int argc, TCHAR* argv[])
#else
int main(int argc, char* argv[])
#endif
{
	std::string desc = "Offline cookie checker v1.0";

	cxxopts::Options options("w3-cookie-checker", desc);

	std::string key;
	std::string drive;
	std::string cookie;

	options.add_options()
		("k,key", "set HWID (if this parameter is not set, the HWID will be generated)", cxxopts::value<std::string>(key))
		("d,drive", "set logical drive to generate HWID (format: X:\\)", cxxopts::value<std::string>(drive))
		("c,cookie", "cookie filename", cxxopts::value<std::string>(cookie))
		("h,help", "print help");

	cxxopts::ParseResult result;
	try
	{
		result = options.parse(argc, argv);
	}
	catch (cxxopts::OptionParseException e)
	{
		std::cout << options.help() << std::endl;
		return 1;
	}

	if (!result.arguments().size() || result.count("help"))
	{
		std::cout << options.help() << std::endl;
		return 1;
	}

	std::cout << desc << std::endl << std::endl;

	if (result.count("drive"))
	{
		if (drive.length() < 3 || drive[1] != ':' || drive[2] != '\\')
		{
			std::cout << "Invalid drive param, input example X:\\" << std::endl;
			return 1;
		}
		if (drive[0] < 'A' || drive[0] > 'Z')
		{
			std::cout << "Invalid the drive letter" << std::endl;
			return 1;
		}
	}

	if (result.count("key"))
	{
		if (!key.empty())
		{
			try
			{
				auto hwid = Botan::base64_decode(key);
				if (hwid.size() != 20)
				{
					std::cout << "Invalid HWID param: SHA-1 is required" << std::endl;
					return 1;
				}
			}
			catch (const std::exception&)
			{
				std::cout << "Invalid HWID param: Base64(SHA-1) is required" << std::endl;
				return 1;
			}
		}
	}

	if (key.empty())
	{
		std::cout << "Generate HWID (drive: " << (drive.empty() ? "default" : drive) << ")..." << std::endl;
		key = generate_hwid(drive);
	}
	std::cout << "HWID = " << key << std::endl;

	if (result.count("cookie"))
	{
		std::filesystem::path cookie_file(file_path(cookie));

		if (!std::filesystem::exists(cookie_file))
		{
			std::cout << "File not found: " << cookie_file << std::endl;
			return 1;
		}

		print_cookie(cookie_file, key);
		return 0;
	}
	return 1;
}
