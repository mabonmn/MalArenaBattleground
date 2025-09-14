
docker build -t mydefender .
docker run --rm -it -p 8080:8080 mydefender
 python3 /home/mabon/MarcusClass/MLSEC.competition/defender/tools/batch_scan.py   --dir /mnt/data_disk1/mabon/datacopy/goodware/bundle/   --workers 8   --out-csv /home/mabon/scan_results_gw.csv
 curl -s -X POST   -H "Content-Type: application/octet-stream"   --data-binary @/mnt/data_disk1/mabon/datacopy/UCSB/ http://127.0.0.1:8080/
