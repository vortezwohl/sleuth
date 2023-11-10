# SLEUTH
Sleuth is a network sniffer based on [scapy](https://github.com/secdev/scapy)
# CLI
![image](https://github.com/vortezwohl/sleuth-network-sniffer/assets/117743023/07cc9165-af8f-4edf-97a6-6e9ff50e2fb2)
# Get Started
install requirements then run sleuth.py
# Usage
```
----------------------------------------------------------------------

mntr [on/off]                                                         : start monitoring or stop monitoring.

ms [-p #port/-P #protocol]                                            : measure networking speed over a port or a protocol.

ls ip [-dsc/-asc #number] / ls int / ls pk [-sm/-dt]                  : list ipv4 addresses, interfaces and captured packets.

cap [-i #interface][-a #method][-c #counts][-f #filter][-t #seconds]  : capture packets over conditions.

save [#filepath]                                                      : save packets into file. if no filepath specified, save to ./sleuth.pcap by default.

load [#filepath]                                                      : load packets from a file into memory. if no filepath specified, load from ./sleuth.pcap by default.

discard                                                               : discard all packets captured which stored in memory

sys [#shell-commands]                                                 : execute shell command from os.

echo [#strings]                                                       : print back your input to screen.

exec [#scripts]                                                       : execute python script.

bye                                                                   : exit sleuth.

----------------------------------------------------------------------
```
