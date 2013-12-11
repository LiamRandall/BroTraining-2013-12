2013-10 BsidesDC Syllabus:
===============

0. Setup VM
  1. COPY files from stick to USB
  2. Install VirtualBox & VirtualBox Extensions
  3. Uncompress files- 7-zip on Windows, "The Unarchiver" on Mac
  4. Open the VM (replace BroTraining.vbox)
  5. logon bro/bro
1. Class files, either:
  1. Mount the folder
  2. git clone https://github.com/LiamRandall/BsidesDC-Training.git
  3. Download zip from https://github.com/LiamRandall/BsidesDC-Training/archive/master.zip
2. [What is Bro?](https://github.com/broala/training-resources/raw/master/0.broala-what-is-bro.pptx)
  1. Bro is a language first
  2. Event-driven
  3. Built-in variables like IP address and time interval are designed for network analysis
  4. Built-in functions can be implemented in C++ for speed and integration with other tools
3. A Tour of the Bro logs
  1. Run Bro against a PCAP (e.g. /opt/TrafficSamples/faf-traffic.pcap)
  2. Go through some of the logs (e.g. cat files.log | colorize)
4. [SSL/TLS](https://github.com/broala/trainings-resources/raw/master/ssl-exercises/Broala-bro-ids-SSL-TLS-security-primer.pptx)
  1. Exercise: ```bro -C -r rsasnakeoil2.cap``` ([pcap](https://github.com/broala/training-resources/raw/master/ssl-exercises/rsasnakeoil2.cap)) 
  2. Exercise: ```bro -r basic-gmail.pcap``` ([pcap](https://github.com/broala/training-resources/raw/master/ssl-exercises/basic-gmail.pcap)) 
5. HTTP Auth
  1. Exercise: ```bro -C -r http-auth.pcap``` ([pcap](https://github.com/broala/training-resources/raw/master/http-auth/http-auth.pcap))
  2. Exercise: ```bro -C -r http-auth.pcap http-auth.bro``` ([script](https://github.com/broala/training-resources/raw/master/http-auth/http-auth.bro))
6. bro-cut
  1. Exercise: ```bro -C -r http-basic-auth-multiple-failures.pcap```
  2. What is the count of the distinct status_code: ```cat http.log | bro-cut status_code | sort | uniq -c | sort -n``` 
  3. What were the status codes by username?
  4. What happened here:  ```1 -  test```  Why is this line missing the status_code?  (hint: conn.log)
6. [Notice Framework](https://github.com/broala/trainings-resources/raw/master/notice-framework/broala-bro-ids-v2.2-notice.log_Overview.pptx)
  1. Exercise: ```bro -r 01_emailing_simple.bro synscan.pcap``` ([script](https://github.com/broala/training-resources/raw/master/notice-framework/01_emailing_simple.bro), [pcap](https://github.com/broala/training-resources/raw/master/notice-framework/synscan.pcap))
  2. Exercise: ```bro -r 02_emailing_complex.bro synscan.pcap``` ([script](https://github.com/broala/training-resources/raw/master/notice-framework/02_emailing_complex.bro), [pcap](https://github.com/broala/training-resources/raw/master/notice-framework/synscan.pcap))
  3. Exercise: ```bro -r 03_avoid_some_scanners.bro synscan.pcap``` ([script](https://github.com/broala/training-resources/raw/master/notice-framework/03_avoid_some_scanners.bro), [pcap](https://github.com/broala/training-resources/raw/master/notice-framework/synscan.pcap))
  4. Exercise: ```bro -r 04_create_a_new_notice.bro mbam_download.trace``` ([script](https://github.com/broala/training-resources/raw/master/notice-framework/04_create_a_new_notice.bro), [pcap](https://github.com/broala/training-resources/raw/master/notice-framework/mbam_download.trace))
  5. Walk-through [05_create_an_action.bro](https://github.com/broala/training-resources/raw/master/notice-framework/05_create_an_action.bro)
7. [Intel Framework](https://github.com/broala/training-resources/raw/master/intel-framework/intel-framework.key)
  1. [Exercise](https://gist.github.com/grigorescu/6495962)
  2. [Exercise](https://gist.github.com/grigorescu/6496507)
  3. [Exercise](https://gist.github.com/grigorescu/6497534)
8. [Files Framework](https://github.com/broala/training-resources/raw/master/files-framework/files-framework.key)
  1. File extraction demo
    1. Extract files: ```bro -r /opt/TrafficSamples/exercise-traffic.pcap extract-all-files.bro``` ([script](https://github.com/broala/training-resources/raw/master/files-framework/extract-all-files.bro))
    2. Show files: ```nautilus extract_files/```
    3. Play a video: ```totem "extract_files/"`ls -S1 extract_files | head -n 1````
  3. Writing a script: ([shell](https://github.com/broala/training-resources/raw/master/files-framework/01_notice_on_mimetype_shell.bro), [solution](https://github.com/broala/training-resources/raw/master/files-framework/01_notice_on_mimetype.bro))
  4. Running the script: ```bro -r 01_notice_on_mimetype.bro /opt/TrafficSamples/faf-traffic.pcap```
  5. Walk-through [02_run_exiftool.bro](https://github.com/broala/training-resources/raw/master/files-framework/02_run_exiftool.bro)
9. [Signature Framework](https://github.com/broala/training-resources/raw/master/signature-framework/signature-framework.key)
  1. Exercise: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/APT/mswab_yayih/Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap site/local.bro```
  2. With file extraction: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/APT/mswab_yayih/Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap site/local.bro extract-all-files.bro``` ([script](https://github.com/broala/training-resources/raw/master/files-framework/extract-all-files.bro))
  3. Analyze requests/responses: ```for i in `bro-grep info.asp http.log | bro-cut orig_fuids resp_fuids | sed -e 's/\t/\n/' | grep -v '-'`; do cat "extract_files/extract-HTTP-$i"; echo; echo "-------"; done```
