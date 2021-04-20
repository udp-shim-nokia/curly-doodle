# UDP-SHIM-NOKIA

Wireshark Packet Dissector for Nokia UDP Shim (Nokia 7750 FP4)

## Installation

Install the .lua file into the plug-ins directory for wireshark to decode IP-only or Ethernet-only mirrors using the Nokia UDP Shim Header available in SROS 20.6

.PNG files provided to show how the decode will look if properly installed

 NOTE: .lua file is configured to use UDP source/dest port 3000. If you're using a different src/dst combination to deliver to a collector, change this port accordingly in the .lua file or modify your SROS router config to use port 3000.



## Contributing
Pull requests are welcome. Feel free to share or contribute.

Please make sure to update tests as appropriate.

## License
No license
