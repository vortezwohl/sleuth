# SLEUTH
Sleuth is a network sniffer or a proxy firewall

# Libs related
[scapy](https://github.com/secdev/scapy), [colorama](https://github.com/tartley/colorama), [pydivert](https://github.com/ffalcinelli/pydivert)

# CLI
as user
![image](https://github.com/vortezwohl/sleuth-network-sniffer/assets/117743023/df728a13-f3ef-4cee-b21c-06ca7487531d)
as administrator
![image](https://github.com/vortezwohl/sleuth-network-sniffer/assets/117743023/a127a9d8-debf-46db-828c-53fe041c7770)

# Get Started
Step 1.
Install packages from requirements.txt
Step 2.
Install [npcap](https://npcap.com/)/[winpcap](https://www.winpcap.org/) on your windows device to support [scapy](https://github.com/secdev/scapy)
Step 3.
Run sleuth.py

# Built-in Commands
```
----------------------------------------------------------------------

mntr [on/off]                                                         : start monitoring or stop monitoring.

ms [-p #port/-P #protocol]                                            : measure networking speed over a port or a protocol.

prx-win on / off / conf                                               : run, terminate or configurate (auto reboot) net proxy (on windows)

ls ip [-dsc/-asc #number] / ls int / ls pk [-sm/-dt] / ls wplog       : list ipv4 addresses, interfaces, captured packets and proxy log.

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

# Capture Filter Language
[Berkeley Packet Filter]([https://scapy.readthedocs.io/en/latest/usage.html#filters](https://dl.acm.org/doi/fullHtml/10.5555/2642922.2642925))

# Abbreviations References
```
mntr - monitor
prx-win - proxy for windows
ms - measure {
 p(lower case) - port
 P(upper case) - protocol
}
ls - list {
 int - interface
 pk - packet
 wplog - log by proxy for windows
 dsc - descend
 asc - ascend
 sm - summaried
 dt - detailed
}
cap - capture {
 i - interface
 a - analysis
 c - count
 f - filter
 t - timeout
}
s - save
l - load
d - discard
sys - system
exec - execute
```
