First we are going to do an extremely simple case of loading some data and matching it. First we will create an intelligence file in Bro’s intelligence format. Create a file named “intel1.dat” with the following content. Keep in mind that all field separation is with literal tabs! Double check that you don’t have spaces as separators.

```
#fields<TAB>indicator<TAB>indicator_type<TAB>meta.source
fetchback.com<TAB>Intel::DOMAIN<TAB>my_special_source
```

The next step will obviously be to load this data into Bro which is done as a configuration option. Put the following script into the same directory as your “intel1.dat” file and call it “intel-1.bro”.

```bro
@load frameworks/intel/seen

redef Intel::read_files += {
  "/home/bro/pcap/intel1.dat"
};
```

Now run.

```
bro -r /opt/TrafficSamples/exercise-traffic.pcap intel-1.bro
```

There should be no output in the terminal but there should be some content in a file named “intel.log”. Take a look at that file.