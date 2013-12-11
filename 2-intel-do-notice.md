It’s very possible that hits on intelligence could be something that you want turned into a notice even though the basic intel framework does not provide that functionality. This is an example of data driven notice creation with the **do_notice.bro** script that is included with Bro. 

We need to create a new intelligence file. Create **intel-2.dat**.

```
#fields<TAB>indicator<TAB>indicator_type<TAB>meta.source<TAB>meta.do_notice
fetchback.com<TAB>Intel::DOMAIN<TAB>my_special_source<TAB>T
```

The only difference from the previous intelligence file is the do_notice column.

Now create a new Bro script named **intel-2.bro** with the following script.

```bro
@load frameworks/intel/seen
@load frameworks/intel/do_notice

redef Intel::read_files += {
    "/home/bro/pcap/intel-2.dat"
};
```

Now run.

```
bro -r /opt/TrafficSamples/exercise-traffic.pcap intel-2.bro
```