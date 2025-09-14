# Malware Classifier: How to run Docker

Analyze and classify `.exe` files for malware using the `mabonmn/malarena-defender` Docker image. 

---

## Pull the Docker Image

```
docker pull mabonmn/malarena-defender:82bc78d78970aec7a5b50485f367f3e7e02c65c1
```


---

## Run the Malware Classifier Container
```
docker run --rm -p 8080:8080 mabonmn/malarena-defender:82bc78d78970aec7a5b50485f367f3e7e02c65c1
```

- Exposes REST API at `localhost:8080`
- `--rm` ensures cleanup after exit

---

## Scan a Single `.exe` File
```
curl -s -X POST
-H "Content-Type: application/octet-stream"
--data-binary @/path/to/file.exe
http://127.0.0.1:8080/
```


- Replace `/path/to/file.exe` with your test file path
- Returns JSON with classification result

---

## Batch Scan with a Shell Script
if you wish to process multiple samples at once, you can run this shell script:
```
DIR="/path/to/input/files"
OUT"/path/to/output/results.csv"
URL="http://127.0.0.1:8080/"

printf "path,result,status,error\n" > "$OUT"

find "$DIR" -type f -print0 | while IFS= read -r -d '' f; do
resp=$(curl -sS --max-time 20 -H "Content-Type: application/octet-stream" --data-binary @"$f" "$URL")
if [ $? -eq 0 ]; then
    # crude JSON extract of {"result":X} without jq
    res=$(printf "%s" "$resp" | sed -n 's/.*"result":[[:space:]]*\\([0-9]\\{1,\\}\\).*/\\1/p')
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

