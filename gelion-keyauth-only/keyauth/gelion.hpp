#include <windows.h>
#include <iostream>
#include "../scanner/scanner.h"
#include "../minhook/MinHook.h"
#include <fstream>
#include "json.hpp"
#include <regex>
#include <chrono>
#include <sstream>
#include <filesystem>
class function_storage
{
public:
	using request_function = std::string(*)(std::string, std::string);
	using error_function = void(*)(std::string);
	using integrity_check_function = auto(*)(const char*, bool) -> bool;

	request_function keyauth_request_address_original = nullptr;
	error_function keyauth_error_address_original = nullptr;
	integrity_check_function keyauth_integrity_check_original = nullptr;
	
	static std::string hexDecode(const std::string& hex)
	{
		int len = hex.length();
		std::string newString;
		for (int i = 0; i < len; i += 2)
		{
			std::string byte = hex.substr(i, 2);
			char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
			newString.push_back(chr);
		}
		return newString;
	}
	int GetInstructionLength(DWORD_PTR address) {

		const int bufferSize = 15;
		unsigned char buffer[bufferSize];

		if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), buffer, bufferSize, nullptr)) {
			return -1;
		}

		int length = 0;
		while (length < bufferSize && buffer[length] != 0xC3) {
			length++;
		}

		return length;
	}
	bool nop_memory(DWORD_PTR address)
	{
		DWORD oldProtect;

		size_t size = GetInstructionLength(address);

		if (size <= 0) {
			MessageBoxA(NULL, "Invalid instruction length", "gelion", MB_ICONERROR | MB_OK);
			return false;
		}

		if (VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			memset(reinterpret_cast<void*>(address), 0x90, size);
			VirtualProtect(reinterpret_cast<void*>(address), size, oldProtect, &oldProtect);
			return true;
		}
		else {
			int error = GetLastError();
			printf("Failed to NOP memory at 0x%lX. Error code: %i", address, error);
			return false;
		}
	}

	void remove_global_check(uintptr_t start_address) {
		size_t size = GetInstructionLength(start_address);
		DWORD oldProtect;
		VirtualProtect(reinterpret_cast<LPVOID>(start_address), size, PAGE_EXECUTE_READWRITE, &oldProtect);

		memset(reinterpret_cast<LPVOID>(start_address), 0x90, size);

		VirtualProtect(reinterpret_cast<LPVOID>(start_address), size, oldProtect, &oldProtect);
	}

	void patch_siganture(uintptr_t address) {
		DWORD oldProtect;
		VirtualProtect(reinterpret_cast<LPVOID>(address), 1, PAGE_EXECUTE_READWRITE, &oldProtect);

		*reinterpret_cast<BYTE*>(address) = 0x75; 

		VirtualProtect(reinterpret_cast<LPVOID>(address), 1, oldProtect, &oldProtect);
	}
private:

}; static function_storage* functions = new function_storage();


class global
{
public:
	bool log_requests;
	bool login_bypass;
	bool download_dumper;
	bool integrity_bypass;
	bool error_bypass;
	std::string jsonString = (R"({"success":true,"message":"Logged into gelion","info":{"username":"gelion","subscriptions":[{"subscription":"default","key":"gelion","expiry":"132353782990","timeleft":130645673640}],"ip":"191.129.123.134","hwid":"S-5-5-21-5-5-5-1001","createdate":"1708109350","lastlogin":"1708109350"},"nonce":"5a37ff61-1777-409d-98c6-17a51cdceaef"})");
	std::string current_time_as_string() {
		auto now = std::chrono::system_clock::now();
		auto time = std::chrono::system_clock::to_time_t(now);
		std::tm* tmPtr = std::localtime(&time);
		int year = tmPtr->tm_year + 1900;
		int month = tmPtr->tm_mon + 1;
		int day = tmPtr->tm_mday;
		int hour = tmPtr->tm_hour;
		int minute = tmPtr->tm_min;
		std::ostringstream oss;
		oss << std::setw(4) << std::setfill('0') << year << "-"
			<< std::setw(2) << std::setfill('0') << month << "-"
			<< std::setw(2) << std::setfill('0') << day << "-"
			<< std::setw(2) << std::setfill('0') << hour << "-"
			<< std::setw(2) << std::setfill('0') << minute;
		return oss.str();
	}

	void create_settings() {
		nlohmann::json config;
		config["log_requests"] = true;
		config["login_bypass"] = true;
		config["download_dumper"] = false;
		config["integrity_bypass"] = true;
		config["error_bypass"] = true;

		std::ofstream file("config.json");
		file << config.dump(4);
		file.close();
	}

	void does_settings_exist() {
		if (!std::filesystem::exists("config.json")) {
			create_settings();
		}
	}

private:

}; static global* globals = new global();


class hooked_functions {

public:


	std::string login_bypass(std::string data, std::string url) {
		
		MessageBoxA(NULL, "hooked requests", "gelion", MB_OK);

		std::string result = functions->keyauth_request_address_original(data, url);

		if (globals->log_requests) {
			std::ofstream logging("gelion_hook_logs.txt", std::ios::app);
			while (logging.is_open()) {
				logging << data << url;
				logging.close();
			}
		}
		nlohmann::json gelion_intercepter;
		try {
			gelion_intercepter = nlohmann::json::parse(result);
		}
		catch (const std::exception& exception) {
			MessageBoxA(NULL, exception.what(), "json parse failure.", MB_OK | MB_ICONERROR);
			return result;
		}
		if (globals->log_requests)
			MessageBoxA(NULL, gelion_intercepter.dump().c_str(), "dumped json", MB_OK);

		if (data.find("type=license&key=") != std::string::npos) {

			return globals->jsonString;
		}

	}

	std::string download_dumper(std::string data, std::string url) {
		
		std::string result = functions->keyauth_request_address_original(data, url);

		if (globals->log_requests) {
			std::ofstream logging("gelion_hook_logs.txt", std::ios::app);
			while (logging.is_open()) {
				logging << data << url;
				logging.close();
			}
		}
		nlohmann::json gelion_intercepter;
		try {
			gelion_intercepter = nlohmann::json::parse(result);
		}
		catch (const std::exception& exception) {
			MessageBoxA(NULL, exception.what(), "json parse failure.", MB_OK | MB_ICONERROR);
			return result;
		}

		if (data.find("type=file&fileid=") != std::string::npos) {

			std::regex regex_scanning("\\b\\d{6}\\b");
			std::sregex_iterator iteration(data.begin(), data.end(), regex_scanning);
			std::sregex_iterator end_iteration;
			std::string searchable_fileid;

			if (iteration != end_iteration) {
				std::smatch match = *iteration;

				searchable_fileid = match.str();

				if (globals->log_requests) {
					std::ofstream logging("gelion_hook_logs.txt", std::ios::app);
					while (logging.is_open()) {
						logging << data << url;
						logging << "file ID found : " << searchable_fileid;
						logging.close();
					}
					nlohmann::json gelion_intercepter;
					auto json = gelion_intercepter.parse(result);
					if (json.contains("contents")) {
						std::string file_contents_decoded = functions->hexDecode(json[("contents")]);
						std::vector<unsigned char> file_data(file_contents_decoded.begin(), file_contents_decoded.end());
						if (!file_data.empty()) {
							std::string current_time = globals->current_time_as_string();
							std::string folder_name = "gelion dumps";
							std::string file_path = folder_name + "\\" + current_time + ".gelion";
							if (!std::filesystem::exists("gelion dumps"))
							{
								CreateDirectoryA(folder_name.c_str(), nullptr);

							}
							std::ofstream dumped_file(file_path, std::ios::out | std::ios::binary);
							while (dumped_file.is_open()) {
								dumped_file.write(reinterpret_cast<char*>(file_data.data()), file_data.size());
								dumped_file.close();
								if (globals->log_requests) {
									std::string success = "[+] file dumped to: " + file_path;
									MessageBoxA(NULL, success.c_str(), "dump success", MB_OK | MB_ICONINFORMATION);
								}	
							}
						}
					}
				}
			}
		}
	}

	std::string error_bypass(std::string message) {
		return "";
	}
	auto integrity_check_bypass(const char* section, bool fix) -> bool {
		return false;
	}

}; static hooked_functions* hooks = new hooked_functions();

class gelion_keyauth{

public:
	std::uintptr_t keyauth_request_address;
	std::uintptr_t keyauth_error_address;
	std::uintptr_t keyauth_integrity_check_address;
	std::uintptr_t keyauth_CMD_error;
	std::uintptr_t signature_check;
	std::uintptr_t modify;

	void scan_signatures() {
		//keyauth_request_address = scanner()->find_pattern("48 89 5C 24 20 55 56 57 41 56 41 57 48 8D 6C 24 C9").get(); // old keyauth
		keyauth_request_address = scanner()->find_pattern("48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C").get(); // newest example
		keyauth_error_address = scanner()->find_pattern("48 89 5C 24 10 48 89 74 24 18 57 48 81 EC").get(); // can use keyauth_CMD_error instead.
		keyauth_integrity_check_address = scanner()->find_pattern("48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 81 EC 80 02 00 00").get();
		modify = scanner()->find_pattern("48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 55 41 56").get();
		keyauth_CMD_error = scanner()->find_pattern("48 89 5C 24 10 57 48 81 EC A0").get();
		signature_check = scanner()->find_pattern("74 ? 48 B8 ? ? ? ? ? ? ? ? 48 8B").get();

		void* keyauth_request_address_ptr = reinterpret_cast<void*>(keyauth_request_address);
		void* keyauth_error_address_ptr = reinterpret_cast<void*>(keyauth_error_address);
		void* keyauth_integrity_check_address_ptr = reinterpret_cast<void*>(keyauth_integrity_check_address);

		// Converting addresses to string format
		char address_str[20];
		sprintf(address_str, "%p", keyauth_request_address_ptr);
		char error_str[20];
		sprintf(error_str, "%p", keyauth_error_address_ptr);
		char integrity_str[20];
		sprintf(integrity_str, "%p", keyauth_integrity_check_address_ptr);

		// Displaying message boxes
		MessageBoxA(NULL, address_str, "Keyauth Request Address", MB_OK | MB_ICONINFORMATION);
		MessageBoxA(NULL, error_str, "Keyauth Error Address", MB_OK | MB_ICONINFORMATION);
		MessageBoxA(NULL, integrity_str, "Keyauth Integrity Address", MB_OK | MB_ICONINFORMATION);
	}

	static std::string login_bypass_wrapper(std::string data, std::string url) {
		return hooks->login_bypass(data, url);
	}
	static std::string download_dumper_wrapper(std::string data, std::string url) {
		return hooks->download_dumper(data, url);
	}
	static std::string error_bypass_wrapper(std::string message) {
		return hooks->error_bypass(message);
	}
	static bool integrity_check_bypass_wrapper(const char* section, bool fix) {
		return hooks->integrity_check_bypass(section, fix);
	}

	void initialize_hooks() {
		
		std::ifstream settings("config.json");
		nlohmann::json loaded_config;
		settings >> loaded_config;


		if (loaded_config["log_requests"]) {
			globals->log_requests = true;
		}

		MH_Initialize();

		//functions->nop_memory(keyauth_CMD_error);
	    //functions->remove_global_check(signature_check);
		//functions->nop_memory(keyauth_integrity_check_address);
		//functions->nop_memory(modify);

		if (loaded_config["integrity_bypass"]) {
			if (MH_CreateHook((void**)keyauth_integrity_check_address, &integrity_check_bypass_wrapper, reinterpret_cast<void**>(&functions->keyauth_integrity_check_original)) != MH_OK) {
				MessageBoxW(NULL, L"failed to hook keyauth integrity check", L"gelion", MB_OK);
			}
		}
		if (loaded_config["error_bypass"]) {
			if (MH_CreateHook((void**)keyauth_error_address, &error_bypass_wrapper, reinterpret_cast<void**>(&functions->keyauth_error_address_original)) != MH_OK) {
				MessageBoxW(NULL, L"failed to hook keyauth error", L"gelion", MB_OK);
			}
		}

		if (loaded_config["login_bypass"]) {
			if (MH_CreateHook((void**)keyauth_request_address, &login_bypass_wrapper, reinterpret_cast<LPVOID*>(&functions->keyauth_request_address_original)) != MH_OK) {
				MessageBoxW(NULL, L"failed to hook keyauth requests", L"gelion", MB_OK);
			}
		}

		if (loaded_config["download_dumper"]) {
			if (MH_CreateHook((void**)keyauth_request_address, &download_dumper_wrapper, reinterpret_cast<LPVOID*>(&functions->keyauth_request_address_original)) != MH_OK) {
				MessageBoxW(NULL, L"failed to hook keyauth requests", L"gelion", MB_OK);
			}
		}

		if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
			MessageBoxW(NULL, L"failed to enable all hooks.", L"Gelion", MB_OK);
		}

		functions->patch_siganture(signature_check);
	}

}; static gelion_keyauth* keyauth = new gelion_keyauth();
