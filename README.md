# UDP-SHIM-NOKIA

Wireshark Packet Dissector for Nokia UDP Shim Sampled (Nokia 7750 FP4) - https://infocenter.nokia.com/public/7750SR207R1A/topic/com.sr.oam/html/mirror.html?cp=15_1_1_2_3#akalaitz5iwiulmnryg

## Installation

Install the .lua file into the plug-ins directory for wireshark (https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) in order to decode IP-only or Ethernet-only mirrors using the Nokia UDP Shim Header, available in 7750 SROS 20.6 and later w/ FP4 processor.

We have included .PCAP files as samples to be verify that the dissector is working.

NOTE: .png files provided to show how the decode will look if properly installed. 

 NOTE: .lua file is configured to use UDP source/dest port 3000. If you're using a different src/dst combination to deliver to a collector, change this port accordingly in the .lua file or modify your SROS router config to use port 3000.



## Contributing
Pull requests are welcome. 

Feel free to share or contribute.



## License
No license
