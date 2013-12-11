Perhaps you decided though that seeing hits on your intelligence in certain locations is not actually what you wanted. The same **do_notice** script has the ability to limit your notices by the location that the intelligence was seen. Create a new **intel-3.dat** file that shows you are only interested in matching the intelligence if it was seen in the host header.

```
#fields<TAB>indicator<TAB>indicator_type<TAB>meta.source<TAB>meta.do_notice<TAB>meta.if_in
fetchback.com<TAB>Intel::DOMAIN<TAB>my_special_source<TAB>T<TAB>HTTP::IN_HOST_HEADER
```

The only change that needs to happen in the script is to load the new intelligence file, but we will include the new script here. Name it **intel-3.bro**.

```bro
@load frameworks/intel/seen
@load frameworks/intel/do_notice

redef Intel::read_files += {
    "/home/bro/pcap/intel-3.dat"
};
```

Now run this script:
```
bro -r /opt/TrafficSamples/exercise-traffic.pcap intel-3.bro
```