# Malware Classifier: How to run Docker

Analyze and classify `.exe` files for malware using the `mabonmn/malarena-defender` Docker image. 

---

## Pull the Docker Image

```
docker pull mabonmn/malarena-defender:latest
```


---

## Run the Malware Classifier Container
```
 docker run --rm -it -p 8080:8080 -m 1g mabonmn/malarena-defender:latest
```

- Exposes REST API at `localhost:8080`
- `--rm` ensures cleanup after exit

---

## Scan a Single `.exe` File
```
curl -XPOST --data-binary @yourfile.exe http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream
```


- Replace `/path/to/file.exe` with your test file path
- Returns JSON with classification result

---

## Batch Scan with a Shell Script
if you wish to process multiple samples at once, you can run this shell script:
```
DIR="/path/to/input/files"
OUT="/path/to/output/results.csv"
URL="http://127.0.0.1:8080/"

printf "path,result,status,error\n" > "$OUT"
find "$DIR" -type f -print0 | while IFS= read -r -d '' f; do
  resp=$(curl -sS --max-time 20 -H "Content-Type: application/octet-stream" --data-binary @"$f" "$URL")
  if [ $? -eq 0 ]; then
    res=$(printf "%s" "$resp" | sed -n 's/.*\"result\":[[:space:]]*\([0-9]\{1,\}\).*/\1/p')
    if [ -n "$res" ]; then
      printf "%s,%s,ok,\n" "$f" "$res" >> "$OUT"
    else
      printf "%s,,bad_json,%s\n" "$f" "$(printf "%s" "$resp" | tr -d '\n' | tr ',' ';')" >> "$OUT"
    fi
  else
    printf "%s,,error,curl_failed\n" "$f" >> "$OUT"
  fi
done
echo "CSV written to $OUT"

```
text

- Edit `DIR` for your input directory.
- Edit `OUT` for your output directory.
- Each file scanned with result and status logged.

---

## Output CSV Format

path, result, status, error
example: /path/to/file.exe,1,ok,


text

- `result`: classifier output (`0` = benign, `1` = malicious)
- `status`: `ok`, `bad_json`, or `error`
- `error`: additional info if relevant

---

## Notes

- Always scan malware in a secure, isolated environment.
- API returns JSON: `{ "result": 1 }`
- Script detects failed or incomplete responses for troubleshooting.

# Attack

## Gemini generated attacks
All attacks are in `attacker/generated`.

This content was generated with the help of AI models to demonstrate potential attack scenarios. Please use responsibly and ethically.
Get you API key for Gooogle Gemini and modify `GEMINI_API_KEY = "key-here"` in the script.
This has been only used on linux systems, so use mingw crosscompiler to build windows executables.
Run the attack generation script:
```
python <script_name>.py <ip_address (x.x.x.x)>
```
Both attacks send the data to the specified IP address using POST requests. There is a C2 server in `attacker/test_srv.py` that can be used to receive the exfiltrated data.
Attacks:
- gemini_recon_tool_generator.py - Generates a reconnaissance tool that gathers system information and sends it to a C2 server.
- gpt3_keylogger_generator.py - Generates a keylogger that captures keystrokes and sends them to a C2 server.
- gpt3_no_antidebug.py - Generates a simple malware that does not contain anti debugging mechanism (does not contain that building block).

## Armorning exe files
The armoring script is `armor.py`. It implements the follwing workflow: `Astral-PE → Packing → Astral-PE → Signing`.
Prerequisites:
- Get Astral-PE from https://github.com/DosX-dev/Astral-PE call it `Astral-PE`
- Get UPX from https://upx.github.io/ call it `upx`
- https://github.com/Systemcluster/wrappe call it `wrappe`
- generate certificate called `codesign.crt` and `mykey.pem` using openssl
Run the armoring script:
```
python armor.py  <exe_directory>
```
For aditional options run:
```
python armor.py -h
```
Default output is `output_linux/final_<timestamp>/`

## Goodware samples
Goodware samples are in `goodware/` directory. There is 50 samples this is just for testing purposes, they are armored and submitted in the zip file.

## Colorful malware
Malware samples are encoded to bmp imase using orchestrator_bmp_only.py script. The script uses steganography to hide the malware binary in green and blue channels. Additionally it adds goodware bytes to red channel.
To run the script:
```
python orchestrator_bmp_only.py <malware_directory> <goodware_directory>
```
Outputs are bmp images in the output_v3/ directory.

## Dropper
The ropper is in Dropper/ directory. It loads the bmp image, extracts the malware binary and executes it in new process.
In order to build the dropper exe copy one of the bmp images to Dropper/ directory as mw.bmp and compile using Visual Studio.

## Misc scripts
There are aditional unused scripts:
- code_cave_inserter.py
- pe_string_injector.py
- bmp_compress.py & decompmpress(.cpp/.exe)

These scripts were used during the development but are not part of the main workflow. Maily because Images are too large as they are. They are morstly functional but not fully tested.


## Reports
Reports related to the project are in the `sandbox_report/` directory. These are AnyRun sandbox outputs. `sandbox_report/mw_reports/original` conains full reports for original unmodified samples (2 amlware, and 7zip installer). `sandbox_report/mw_reports/my_imp`.
compare_malware_reports.py is very primitive tool to compare two reports and extract some basic information, and compute similarity score.
`result_report/` contains txt files maually anotated to show which differences originate from armor and which from dropper.
`sample_1_vt/` conatins capabilities report for the sample 1 from VirtusTotal to show that all of the capabilities are still there.

## Disclaimer
This repository is intended for educational and research purposes only. The author is not responsible for any misuse or damage caused by the materials provided herein. Always ensure you have proper authorization before conducting any security testing or analysis on systems and software.