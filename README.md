# Sublime Text 3 Plugin to create packet log from HCI Dump

This Plug-In converts the textual dump of [BTstack's](https://github.com/bluekitchen/btstack/) output into a PacketLogger file (.pklg), and opens it with  Wireshark or Apple's PacketLogger tool.

The BTstack Bluetooth stack inlines application logs with HCI traffic. We call this output "HCI dump". BTstack's [HCI Dump functionality](http://bluekitchen-gmbh.com/btstack/how_to/index.html#bluetooth-hci-packet-logs) is quite flexible and can also be used on an embedded target with just a regular UART debug output or the faster [SEGGER RTT](https://www.segger.com/products/development-tools/ozone-j-link-debugger/). The usual HCI dump form on embedded targets is text. The text output can be stored and converted into a PacketLogger file (.pklg) for further analysis in Wireshark or Apple's PacketLogger tool.

To convert the textual HCI dump output into a PacketLogger file (.pklg) with this Plug-In, you need to perform the following steps:
1. select and copy the HCI dump output
2. create a new file in Sublime
3. paste the HCI dump
4. run command via Command Palete "BTstack: Convert HCI Packet Log (pklg)"

The plugin will automatically open the newly created pklg file, which is stored under a random name in your temp folder. 

