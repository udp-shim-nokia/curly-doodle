# curly-doodle
# Wireshark Packet Dissector for Nokia UDP-SHIM header
# Install the .lua file into the plug-ins directory for wireshark to decode IP-only or Ethernet-only mirrors using the Nokia UDP Shim Header available in SROS 20.6
# .png files provided to show how the decode will look if properly installed
# NOTE: .lua file is setup to use UDP source/dest port 3000. If you're using a different src/dst combination to deliver to a collector, change this port accordingly in the .lua file or modify your SROS router config to use port 3000.
