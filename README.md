# SLEUTH
-   [Get Started](#get-started)
-   [Libs related](#libs-related)
-   [Commands](#build-in-commands)
-   [Filter Languages](#capture-filter-script)
-   [Run NonAdmin](#run-as-user-proxy-doesnt-work-but-other-features-work-well)
-   [Run Admin](#run-as-administrator-proxy-works)
-   [Abbreviations](#abbreviations-references)

# Libs related
[scapy](https://github.com/secdev/scapy), [colorama](https://github.com/tartley/colorama), [pydivert](https://github.com/ffalcinelli/pydivert)

# Run as user (Proxy doesn't work but other features work well)
![image](https://github.com/vortezwohl/sleuth-network-sniffer/assets/117743023/df728a13-f3ef-4cee-b21c-06ca7487531d)

# Run as administrator (Proxy works)
![image](https://github.com/vortezwohl/sleuth-network-sniffer/assets/117743023/a127a9d8-debf-46db-828c-53fe041c7770)

# Get Started
- Step 1.
  Install packages from [requirements.txt](https://github.com/vortezwohl/sleuth-network-sniffer/blob/main/requirements.txt)
- Step 2.
  Install [npcap](https://npcap.com/)/[winpcap](https://www.winpcap.org/) on your windows device to support [scapy](https://github.com/secdev/scapy)
- Step 3.
  Run [sleuth.py](https://github.com/vortezwohl/sleuth-network-sniffer/blob/main/sleuth.py)

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

# Capture Filter Script
[Berkeley Packet Filter](https://dl.acm.org/doi/fullHtml/10.5555/2642922.2642925)

# Proxy Configuration Filter Script
[Windows Packet Divert](https://reqrypt.org/windivert-doc.html#filter_language)

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
