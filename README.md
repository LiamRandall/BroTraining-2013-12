2013-12 Bro Training Syllabus:
===============

0. Setup VM
  1. COPY files from stick to USB
  2. Install VirtualBox & VirtualBox Extensions
  3. Uncompress files- 7-zip on Windows, "The Unarchiver" on Mac
  4. logon bro/bro
1. Class files, either:
  1. /home/bro/training/
2. What is Bro?
  1. Bro is a language first
  2. Event-driven
  3. Built-in variables like IP address and time interval are designed for network analysis
  4. Built-in functions can be implemented in C++ for speed and integration with other tools
3. A Tour of the Bro logs
  1. Run Bro against a PCAP (e.g. /opt/TrafficSamples/faf-traffic.pcap)
  2. Go through some of the logs (e.g. cat files.log | colorize)
4. SSL/TLS
  1. Exercise: bro -C -r rsasnakeoil2.cap
  2. Exercise: bro -r basic-gmail.pcap
5. HTTP Auth
  1. Exercise: ```bro -C -r http-auth.pcap``` ([pcap](https://github.com/broala/training-resources/raw/master/http-auth/http-auth.pcap))
  2. Exercise: ```bro -C -r http-auth.pcap http-auth.bro``` ([script](https://github.com/broala/training-resources/raw/master/http-auth/http-auth.bro))
6. bro-cut
  1. Exercise: ```bro -C -r http-basic-auth-multiple-failures.pcap```
  2. What is the count of the distinct status_code: ```cat http.log | bro-cut status_code | sort | uniq -c | sort -n``` 
  3. What were the status codes by username?
7. Sumstats Introduction
  1. What is sumstats
  2. Review [FTP Bruteforcing](https://github.com/LiamRandall/BroTraining-2013-12/blob/master/brute-force.md)
  3. Review the previous exercise- can we apply this model to detect http basic auth bruteforcing?  Suggest some methods.
  4. Based on the previous example can you implement a solution?  For bruteforcers?  For the bruteforced?
  5. Review [HTTP Basic Auth Brute Forcer Solution](https://github.com/LiamRandall/BroTraining-2013-12/blob/master/detect-http-basic-auth-bruteforcer.bro)
  6. Review [HTTP Basic Auth Server Brute Forced Solution](https://github.com/LiamRandall/BroTraining-2013-12/blob/master/detect-http-basic-auth-server-bruteforced.bro)
  7. Execute both detections: ```bro -C -r http-basic-auth-multiple-failures.pcap detect-http-basic-auth-bruteforcer.bro detect-http-basic-auth-server-bruteforced.bro```
  8. Discuss derivations and improvements- tracking by ASN, remote subnet, whitelisting, blacklisting
  9. Additional Demonstrations of the same technique.
8. Notice Framework
  1. Exercise: ```bro -r 01_emailing_simple.bro synscan.pcap``` 
  2. Exercise: ```bro -r 02_emailing_complex.bro synscan.pcap```
  3. Exercise: ```bro -r 03_avoid_some_scanners.bro synscan.pcap```
  4. Exercise: ```bro -r 04_create_a_new_notice.bro mbam_download.trace```
  5. Walk-through ```05_create_an_action.bro```
7. Intel Framework
  1. Exercise 1: [Create An Intel File](https://github.com/LiamRandall/BroTraining-2013-12/blob/master/1-create-intel.md)
  2. Exercise 2: [Notice on Intel Hits](https://github.com/LiamRandall/BroTraining-2013-12/blob/master/2-intel-do-notice.md)
  2. Exercise 3: [Notice on Spcific Types of Intel Hits](https://github.com/LiamRandall/BroTraining-2013-12/blob/master/3-intel-notice-on-types.md)  
  
8. Files Framework
  1. File extraction demo
    1. Extract files: ```bro -r /opt/TrafficSamples/exercise-traffic.pcap extract-all-files.bro```
    2. Show files: ```nautilus extract_files/```
    3. Play a video: ```totem "extract_files/"`ls -S1 extract_files | head -n 1````
  3. Writing a script, beginging with the template, can you generate a notice on a specific file type? 
    1. ```01_notice_on_mimetype_shell.bro```
    2. Solution: ````01_notice_on_mimetype.bro````
  4. Running the script: ```bro -r /opt/TrafficSamples/faf-traffic.pcap 01_notice_on_mimetype.bro```
  5. Walk-through ````02_run_exiftool.bro````
    1. Install exiftool.log
    
```
mkdir exiftool
cd exiftool/
wget http://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-9.43.tar.gz
tar -xzf Image-ExifTool-9.43.tar.gz
```

    2. Modify ```02_run_exiftool.bro``` with the correct path: ```/home/bro/training/files-framework/exiftool/Image-ExifTool-9.43```
	3. Run ```bro -r /opt/TrafficSamples/faf-traffic.pcap 02_run_exiftool.bro```
	4. Examine exiftool.log

9. Signature Framework
  1. Exercise: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/APT/mswab_yayih/Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap local```
  2. With file extraction: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/APT/mswab_yayih/Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap site/local.bro extract-all-files.bro```   
  3. Analyze requests/responses: ```for i in `bro-grep info.asp http.log | bro-cut orig_fuids resp_fuids | sed -e 's/\t/\n/' | grep -v '-'`; do cat "extract_files/extract-HTTP-$i"; echo; echo "-------"; done```
