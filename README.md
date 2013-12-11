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
  6. Modify ```02_run_exiftool.bro``` with the correct path: ```/home/bro/training/files-framework/exiftool/Image-ExifTool-9.43```
  7. Run ```bro -r /opt/TrafficSamples/faf-traffic.pcap 02_run_exiftool.bro```
  8. Examine exiftool.log
9. ICS
  1. Let's start by looking at the Bro default modbus.log; let's replay some traffic ```bro -r modbus.pcap local```
  2. What does the modbus.log show?
  3. It would be nice to have a simple listing of all of modbus pairs for documenting master/slaves; fortunately Bro includes a policy file to perform this for you.  From ~/training/modbus/known_modbus ```bro -C -r ../modbus.pcap /opt/bro/share/bro/policy/protocols/modbus/known-masters-slaves.bro```
  4. It would be nice to have some additional detail about the ICS traffic we are seeing on the network.  From ~/training/modbus/dump_registers ```bro -r ../modbus.pcap /opt/bro/share/bro/policy/protocols/modbus/track-memmap.bro```
  5. What are the most frequently accessed registers?
  6. Inspect the script ```rogue_modbus.bro```- what does it do?
  7. From ~/training/modbus/rogue_modbus let's go ahead and test it: ```bro -r ../modbus.pcap local ../rogue_modbus.bro```
  8. Inspect the script ```modbus_master_slave_pairs.bro```- what does it do?
  9. From ~/training/modbus/discovered_modbus_pair let's execute the script ```bro -r ../modbus.pcap local ../modbus_master_slave_pairs.bro```
  10. Demonstration & Discussion
10. Signature Framework
  1. Exercise: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/APT/mswab_yayih/Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap local```
  2. With file extraction: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/APT/mswab_yayih/Mswab_Yayih_FD1BE09E499E8E380424B3835FC973A8_2012-03.pcap site/local.bro extract-all-files.bro```   
  3. Analyze requests/responses: ```for i in `bro-grep info.asp http.log | bro-cut orig_fuids resp_fuids | sed -e 's/\t/\n/' | grep -v '-'`; do cat "extract_files/extract-HTTP-$i"; echo; echo "-------"; done```
  4. blackhole-medfos
    1. Let's get started with a couple of warm up exercises.  Blackhole is one of the most common and frequently updated exploit kits around.  Let's see what they look like with Bro's new File Analysis Framework.
	2. How many executable files were downloaded to the host?
    3. ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/CRIME/blackhole-medfos
EK_BIN_Blackhole_leadingto_Medfos_0512E73000BCCCE5AFD2E9329972208A_2013-04.pcap local```
    4. How many executable files were downloaded?
	5. ```less files.log | grep "application" | wc -l```
	6. What notices were fired?
    7. ```less notice.log```
  5-smokekt150
    1. We have Bro identifying signatures in ports and protocols that it understands; in this example, we are going to have Bro key on a specific protocol related feature.
    2. Let's replay the sample with Bro: ```bro -r /opt/PCAPS_TRAFFIC_PATTERNS/CRIME/EK_Smokekt150\(Malwaredontneedcoffee\)_2012-09.pcap local```
	3. Explore the log files; I see a number of potential canidates for items we could fire on.  Let's look a little deeper.  Take a look at the specified .bro file; what are we doing here?  Let's replay the pcap extracting header names and values. [script](https://github.com/LiamRandall/BroTraining-2013-12/blob/master/extract-header-names-and-values.bro)
    4. Now let's investigate the http.log a little further.  Lets look a little closer at those http header values:
    5. ```less http.log | bro-cut server_header_names server_header_values```

This content type looks a little weird to me..

			text/html; charset=win-1251

What is that?
```
http://en.wikipedia.org/wiki/Windows-1251
	Windows-1251 (a.k.a. code page CP1251) is a popular 8-bit character encoding, designed to cover languages that use the Cyrillic script such as Russian, Bulgarian, Serbian Cyrillic and other languages. It is the most widely used for encoding the Bulgarian, Serbian and Macedonian languages
```
Is that normal for our environment?  Let's see if we can match on that.

```bro
@load base/protocols/http/main
@load base/frameworks/notice

module HTTP;
 
export {
	redef enum Notice::Type += {
		## raised once per host per 10 min
		Bad_Header
	};

	global bad_header: set[addr] &create_expire = 10 min;
}
 
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
  {
     if ( name == "CONTENT-TYPE" && value == "text/html; charset=win-1251" )
     {	
	 if ( c$id$orig_h !in bad_header )
	 {
		add bad_header[c$id$orig_h];
		NOTICE([$note=HTTP::Bad_Header,
		 $msg=fmt("Bad header \"%s\" seen in %s", value,c$uid),
		 $sub=name,
		 $conn=c,
		 $identifier=fmt("%s", c$id$orig_h)]);
		

		print fmt("%s :name:value:  %s:%s",c$uid,name,value);
	 }
     }
  }
```

This code is overly simple; every time we see an http header key pair this event fires.  We simply look the event and are checking specifically for the Cyrillic language.

Did you count how many times this header pair was transmitted in the sample?  Here we are thresholding the notice with a global variable called "bad header"; and we time hosts out using the **&create_expire = 10** .
    global bad_header: set[addr] &create_expire = 10 min;
    
Let's go ahead and replay the sample using our new detector.

	bro -r EK_Smokekt150\(Malwaredontneedcoffee\)_2012-09.pcap local  ../solutions/match-headers.bro 

You should now see a thresholded alert in the notice.log.


