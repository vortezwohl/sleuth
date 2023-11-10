from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.all import *
from datetime import datetime
import time
from termcolor import colored

Protocol = {'ip': IP,
            'icmp': ICMP,
            'tcp': TCP,
            'udp': UDP,
            'arp': ARP}

protocol_traffic = {protocol: 0.01 for protocol in Protocol.values()}
protocol_packet_arrival_time = {protocol: time.time() for protocol in Protocol.values()}
port_traffic = {i: 0.01 for i in range(0, 65536)}
prev_tcp_udp_arrival_time = {i: time.time() for i in range(0, 65536)}
general_packet_arrival_time = time.time()
general_packet_traffic = 0.01
ip_record = {}
traffic_monitors = []
thread_running = 0  # monitor on/off
refresh_running = 1
main_running = 1
packet_count = 0  # count packets while capturing
stored = 1  # param for sniff()
packet_list_to_save = []  # packets captured to save


def threading_status(p):
    global thread_running
    return thread_running


def packet_handler_for_traffic_monitor(packet):
    global general_packet_arrival_time, general_packet_traffic, ip_record
    ip_layer = packet.getlayer(Protocol['ip'])
    if ip_layer:
        if ip_layer.src not in ip_record:
            ip_record[ip_layer.src] = 1
        else:
            ip_record[ip_layer.src] += 1
        if ip_layer.dst not in ip_record:
            ip_record[ip_layer.dst] = 1
        else:
            ip_record[ip_layer.dst] += 1
    packet_size = len(packet)
    arrival_time = time.time()
    time_difference = arrival_time - general_packet_arrival_time
    if time_difference == 0.0:
        time_difference += 0.001
    general_packet_arrival_time = arrival_time
    general_packet_traffic = packet_size / time_difference


def traffic_monitor():
    while main_running:
        sniff(prn=packet_handler_for_traffic_monitor, count=0, store=0, lfilter=threading_status, timeout=5)


def packet_handler_for_traffic_monitor_on_port(packet):
    global port_traffic, prev_tcp_udp_arrival_time
    tcplayer = packet.getlayer(Protocol['tcp'])
    udplayer = packet.getlayer(Protocol['udp'])
    if tcplayer is not None or udplayer is not None:
        if udplayer is None:
            packet_size = len(packet)
            arrival_time = time.time()
            time_difference = arrival_time - prev_tcp_udp_arrival_time[packet[TCP].sport]
            if time_difference == 0.0:
                time_difference += 0.001
            prev_tcp_udp_arrival_time[packet[TCP].sport] = arrival_time
            port_traffic[packet[TCP].sport] = packet_size / time_difference
            # print(f"Port:{packet[TCP].sport}, Bps:{port_traffic[packet[TCP].sport]:.0f}")
        else:
            if udplayer is None:
                packet_size = len(packet)
                arrival_time = time.time()
                time_difference = arrival_time - prev_tcp_udp_arrival_time[packet[UDP].sport]
                if time_difference == 0.0:
                    time_difference += 0.001
                prev_tcp_udp_arrival_time[packet[UDP].sport] = arrival_time
                port_traffic[packet[UDP].sport] = packet_size / time_difference
                # print(f"Port:{packet[UDP].sport}, Bps:{port_traffic[packet[UDP].sport]:.0f}")


def traffic_monitor_on_port():
    while main_running:
        sniff(prn=packet_handler_for_traffic_monitor_on_port, count=0, store=0, lfilter=threading_status,
              timeout=5)


def packet_handler_for_traffic_monitor_on_protocol_ip(packet):
    packet_size = len(packet)
    arrival_time = time.time()
    time_difference = arrival_time - protocol_packet_arrival_time[Protocol['ip']]
    if time_difference == 0.0:
        time_difference += 0.001
    protocol_packet_arrival_time[Protocol['ip']] = arrival_time
    protocol_traffic[Protocol['ip']] = packet_size / time_difference
    # print(f"Protocol:{Protocol['ip']}, Bps:{protocol_traffic[Protocol['ip']]:.0f}")


def traffic_monitor_on_protocol_ip():
    while main_running:
        sniff(prn=packet_handler_for_traffic_monitor_on_protocol_ip, count=0, store=0, filter='ip',
              lfilter=threading_status, timeout=5)


def packet_handler_for_traffic_monitor_on_protocol_icmp(packet):
    packet_size = len(packet)
    arrival_time = time.time()
    time_difference = arrival_time - protocol_packet_arrival_time[Protocol['icmp']]
    if time_difference == 0.0:
        time_difference += 0.001
    protocol_packet_arrival_time[Protocol['icmp']] = arrival_time
    protocol_traffic[Protocol['icmp']] = packet_size / time_difference
    # print(f"Protocol:{Protocol['icmp']}, Bps:{protocol_traffic[Protocol['icmp']]:.0f}")


def traffic_monitor_on_protocol_icmp():
    while main_running:
        sniff(prn=packet_handler_for_traffic_monitor_on_protocol_icmp, count=0, store=0, filter='icmp',
              lfilter=threading_status, timeout=5)


def packet_handler_for_traffic_monitor_on_protocol_tcp(packet):
    packet_size = len(packet)
    arrival_time = time.time()
    time_difference = arrival_time - protocol_packet_arrival_time[Protocol['tcp']]
    if time_difference == 0.0:
        time_difference += 0.001
    protocol_packet_arrival_time[Protocol['tcp']] = arrival_time
    protocol_traffic[Protocol['tcp']] = packet_size / time_difference
    # print(f"Protocol:{Protocol['tcp']}, Bps:{protocol_traffic[Protocol['tcp']]:.0f}")


def traffic_monitor_on_protocol_tcp():
    while main_running:
        sniff(prn=packet_handler_for_traffic_monitor_on_protocol_tcp, count=0, store=0, filter='tcp',
              lfilter=threading_status, timeout=5)


def packet_handler_for_traffic_monitor_on_protocol_udp(packet):
    packet_size = len(packet)
    arrival_time = time.time()
    time_difference = arrival_time - protocol_packet_arrival_time[Protocol['udp']]
    if time_difference == 0.0:
        time_difference += 0.001
    protocol_packet_arrival_time[Protocol['udp']] = arrival_time
    protocol_traffic[Protocol['udp']] = packet_size / time_difference
    # print(f"Protocol:{Protocol['udp']}, Bps:{protocol_traffic[Protocol['udp']]:.0f}")


def traffic_monitor_on_protocol_udp():
    while main_running:
        sniff(prn=packet_handler_for_traffic_monitor_on_protocol_udp, count=0, store=0, filter='udp',
              lfilter=threading_status, timeout=5)


def packet_handler_for_traffic_monitor_on_protocol_arp(packet):
    packet_size = len(packet)
    arrival_time = time.time()
    time_difference = arrival_time - protocol_packet_arrival_time[Protocol['arp']]
    if time_difference == 0.0:
        time_difference += 0.001
    protocol_packet_arrival_time[Protocol['arp']] = arrival_time
    protocol_traffic[Protocol['arp']] = packet_size / time_difference
    # print(f"Protocol:{Protocol['arp']}, Bps:{protocol_traffic[Protocol['arp']]:.0f}")


def traffic_monitor_on_protocol_arp():
    while main_running:
        sniff(prn=packet_handler_for_traffic_monitor_on_protocol_arp, count=0, store=0, filter='arp',
              lfilter=threading_status, timeout=5)


def refresh_traffic():
    global protocol_traffic, port_traffic, general_packet_traffic, Protocol, refresh_running
    while refresh_running:
        time.sleep(3.25)
        for protocol in Protocol.values():
            protocol_traffic[protocol] = 0.01
        for i in range(0, 65535):
            port_traffic[i] = 0.01
        general_packet_traffic = 0.01


# 读取pcap文件

# run threads
number_of_threads = 0

Thread(target=refresh_traffic).start()
traffic_monitors.append(Thread(target=traffic_monitor))
traffic_monitors.append(Thread(target=traffic_monitor_on_port))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_ip))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_icmp))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_tcp))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_udp))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_arp))
for monitor in traffic_monitors:
    monitor.start()
    number_of_threads += 1
print(colored('[INFO] ', "green") + f'{number_of_threads+1} threads running..')
print(colored('[WARNING] ', "yellow") + 'Stop threads before you exit (by typing "exit", "bye" etc).')


# TODO instructions
def traffic_on_general_packet():
    global general_packet_traffic
    return general_packet_traffic


def traffic_on_port(port):
    global port_traffic
    return port_traffic[port]


def traffic_on_ip():
    global protocol_traffic
    return protocol_traffic[IP]


def traffic_on_icmp():
    global protocol_traffic
    return protocol_traffic[ICMP]


def traffic_on_tcp():
    global protocol_traffic
    return protocol_traffic[TCP]


def traffic_on_udp():
    global protocol_traffic
    return protocol_traffic[UDP]


def traffic_on_arp():
    global protocol_traffic
    return protocol_traffic[ARP]


def get_ip_addrs():
    global ip_record
    return ip_record


def show_ifaces():
    network_interfaces = get_working_ifaces()
    if network_interfaces:
        for intf in network_interfaces:
            print(colored(f"MAC: {get_if_hwaddr(intf):<17} | ", "blue", "on_white"), end='')
            print(colored(f"interface: {intf}", "blue", "on_white"))
    else:
        print(colored(f"how? i mean how could you not have an net interface!", "yellow"))


# TODO analyse command
def extract_command(input_str):
    result = {}
    options = re.findall(r'-(\w+)\s+([^ ]+)', input_str)
    if not options:
        return None
    for option, value in options:
        result[option] = value
    return result


def capture(filter, timemout_, extract_packet="count", count=0, iface=None):
    global packet_count, stored, packet_list_to_save

    def packet_handler_sm(packet):
        global packet_count, packet_list_to_save
        packet_count += 1
        packet_list_to_save.append(packet)
        return colored("[" + str(packet_count) + "]", "green") + str(datetime.now()) + " | " + packet.summary()

    def packet_handler_dt(packet):
        global packet_count, packet_list_to_save
        packet_count += 1
        packet_list_to_save.append(packet)
        print(colored("[" + str(packet_count) + "]", "green"))
        return packet.show()

    def packet_handler_count(packet):
        global packet_count, packet_list_to_save
        packet_list_to_save.append(packet)
        if not packet_count % 25 and packet_count != 0:
            print()
        elif packet_count:
            print(colored(">", "green"), end="", flush=True)
        packet_count += 1

    if not timemout_:
        timemout_ = 1
    if filter:
        filterlist = filter.split("-")
        filter = ""
        for filterstr in filterlist:
            filter += f"{filterstr} "
    interface = "any" if not iface else iface
    filtering = "any" if not filter else filter
    print(f"Interface: {interface}\nFilter: {filtering}\nTimeout: {timemout_}s\n" + colored("capturing...", "yellow"))
    try:
        if extract_packet in ("summary", "smr", "summarized", "sm"):
            sniff(count=count, filter=filter, timeout=timemout_, iface=iface, prn=packet_handler_sm, quiet=0, store=stored)
            print(colored(f"\n--{packet_count} packets captured--", "yellow"))
            packet_count = 0
        elif extract_packet in ("detail", "dtl", "detailed", "dt"):
            sniff(count=count, filter=filter, timeout=timemout_, iface=iface, prn=packet_handler_dt, quiet=0, store=stored)
            print(colored(f"\n--{packet_count} packets captured--", "yellow"))
            packet_count = 0
        elif extract_packet in ("hide", "quiet", "count"):
            sniff(count=count, filter=filter, timeout=timemout_, iface=iface, prn=packet_handler_count, quiet=0,
                  store=stored)
            print(colored(f"\n--{packet_count} packets captured--", "yellow"))
            packet_count = 0
    except:
        print(colored("something went wrong during capturing", "red"))


sleuth = '''

                {/H/SL/U/H//}           |    welcome to sleuth
               {T/W//LE/TH/L/}          |    type "help" to learn
              {S/O//SL/U/H//U/L}}       |    
            {SLEUTH/SLEUTH/O/SSTO}}}    |    contact: vortezwohl@proton.me
              ///           |)          |    
               //             \\         |    have fun! ;)
                /           =|          
                 |            \\         
                 /           _/         
                /          \\         
                 
'''
print(sleuth)
while main_running:
    input_ = input('>')
    cmd = input_.split(' ')
    if input_ == '':
        pass
    elif cmd[0] in ("help", "guide"):
        print(f"{'-' * 70}\n\n"
              f"{'mntr [on/off]':<70}: start monitoring or stop monitoring.\n\n"
              f"{'ms [-p #port/-P #protocol]':<70}: measure networking speed over a port or a protocol.\n\n"
              f"{'ls ip [-dsc/-asc #number] / ls int / ls pk [-sm/-dt]':<70}: list ipv4 addresses, interfaces and captured packets.\n\n"
              f"{'cap [-i #interface][-a #method][-c #counts][-f #filter][-t #seconds]':<70}: capture packets over conditions.\n\n"
              f"{'save [#filepath]':<70}: save packets into file. if no filepath specified, save to ./sleuth.pcap by default.\n\n"
              f"{'load [#filepath]':<70}: load packets from a file into memory. if no filepath specified, load from ./sleuth.pcap by default.\n\n"
              f"{'discard':<70}: discard all packets captured which stored in memory\n\n"
              f"{'sys [#shell-commands]':<70}: execute shell command from os.\n\n"
              f"{'echo [#strings]':<70}: print back your input to screen.\n\n"
              f"{'exec [#scripts]':<70}: execute python script.\n\n"
              f"{'bye':<70}: exit sleuth.\n\n"
              f"{'-' * 70}")
    elif cmd[0] in ("exit", "bye", "quit", "salut", "ciao"):
        thread_running = 0
        refresh_running = 0
        main_running = 0
        print(colored("[WARNING]Please wait a few seconds before closing CLI!\nstopping threads", "yellow"), end='')
        for i in range(0, 8):
            time.sleep(0.6)
            print(colored(".", "yellow"), end='', flush=True)
        print(colored("done", "green"))
        sys.exit(0)
    elif cmd[0] in ("os", "sys", "cmd", "system"):
        shell_cmd = ""
        for shellcmd in cmd[1:]:
            shell_cmd += f"{shellcmd}&"
        os.system(shell_cmd)
    elif cmd[0] in ("echo", "print", "out"):
        for output in cmd[1:]:
            print(f"{output} ", end="")
        print()
    elif cmd[0] in ("py", "python", "script", "scr", "exec"):
        script = ""
        for scr in cmd[1:]:
            script += f"{scr};"
        try:
            exec(script)
        except:
            print(colored(f"something went wrong while scripting \"{script}\"", "red"))
    elif cmd[0] in ("mntr", "monitor") and len(cmd) == 2:
        if cmd[1] in ("r", "run", "on"):
            thread_running = 1
            print(colored("traffic monitor running...", "yellow"))
        elif cmd[1] in ("s", "stop", "off"):
            thread_running = 0
            print(colored("traffic monitor stopped", "yellow"))
        else:
            print(colored(f"invalid option \"{cmd[1]}\"", "red"))
    elif cmd[0] in ("measure", "ms") and len(cmd) < 4:
        if len(cmd) == 1:
            traffic = traffic_on_general_packet()
            print(
                f"{datetime.now()}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8:.0f} bits/s")
        else:
            try:
                if cmd[1] in ("-p", "--port"):
                    if int(cmd[2]) not in range(0, 65536):
                        print(colored(f"port {cmd[2]} doesn't exist", "red"))
                    else:
                        traffic = traffic_on_port(int(cmd[2]))
                        print(
                            f"{datetime.now()}\nPort: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                elif cmd[1] in ("-P", "--protocol"):
                    if cmd[2] == 'ip' and traffic_on_ip():
                        traffic = traffic_on_ip()
                        print(
                            f"{datetime.now()}\nProtocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                    elif cmd[2] == 'icmp' and traffic_on_icmp():
                        traffic = traffic_on_icmp()
                        print(
                            f"{datetime.now()}\nProtocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                    elif cmd[2] == 'tcp' and traffic_on_tcp():
                        traffic = traffic_on_tcp()
                        print(
                            f"{datetime.now()}\nProtocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                    elif cmd[2] == 'udp' and traffic_on_udp():
                        traffic = traffic_on_udp()
                        print(
                            f"{datetime.now()}\nProtocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                    elif cmd[2] == 'arp' and traffic_on_arp():
                        traffic = traffic_on_arp()
                        print(
                            f"{datetime.now()}\nProtocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                    else:
                        print(colored(f"protocol \"{cmd[2]}\" not supported", "red"))
                else:
                    print(colored(f"invalid option \"{cmd[1]}\"", "red"))
            except ValueError:
                print(colored(f"\"{cmd[2]}\" isn't a number", "red"))
    elif cmd[0] in ("list", "ls") and len(cmd) in range(2, 6):
        if cmd[1] == "ip" and len(cmd) == 3:
            if cmd[2] in ("-asc", "--ascend", "-dsc", "--descend"):
                if cmd[2] in ("-asc", "--ascend"):
                    if ip_record.items():
                        for ip, count in sorted(ip_record.items(), key=lambda this: this[1], reverse=0):
                            print(colored(f"IP: {ip:<15} | Freq: {count}", "blue", "on_white"))
                    else:
                        print(colored(
                            "IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)",
                            "yellow"))
                else:
                    if ip_record.items():
                        for ip, count in sorted(ip_record.items(), key=lambda this: this[1], reverse=1):
                            print(colored(f"IP: {ip:<15} | Freq: {count}", "blue", "on_white"))
                    else:
                        print(colored(
                            "IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)",
                            "yellow"))
            else:
                print(colored(f"invalid option \"{cmd[2]}\"", "red"))
        elif cmd[1] == "ip" and len(cmd) == 4:
            if cmd[2] in ("-asc", "--ascend", "-dsc", "--descend"):
                try:
                    if cmd[2] in ("-asc", "--ascend") and len(cmd) == 4:
                        entry = int(cmd[3])
                        if entry > len(ip_record.keys()) or entry < 0:
                            print(colored(f"index {cmd[3]} out of range", "red"))
                        else:
                            if ip_record.items():
                                entry_count = 0
                                for ip, count in sorted(ip_record.items(), key=lambda this: this[1], reverse=0):
                                    if entry_count == entry:
                                        break
                                    print(colored(f"IP: {ip:<15} | Freq: {count}", "blue", "on_white"))
                                    entry_count += 1
                            else:
                                print(colored(
                                    "IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)",
                                    "yellow"))
                    elif cmd[2] in ("-dsc", "--descend") and len(cmd) == 4:
                        entry = int(cmd[3])
                        if entry > len(ip_record.keys()) or entry < 0:
                            print(colored(f"index {cmd[3]} out of range", "red"))
                        else:
                            if ip_record.items():
                                entry_count = 0
                                for ip, count in sorted(ip_record.items(), key=lambda this: this[1], reverse=1):
                                    if entry_count == entry:
                                        break
                                    print(colored(f"IP: {ip:<15} | Freq: {count}", "blue", "on_white"))
                                    entry_count += 1
                            else:
                                print(colored(
                                    "IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)",
                                    "yellow"))
                except ValueError:
                    print(colored(f"\"{cmd[3]}\" isn't a number", "red"))
            else:
                print(colored(f"invalid option \"{cmd[2]}\"", "red"))
        elif cmd[1] == "ip" and len(cmd) == 2:
            if ip_record.items():
                for ip, count in ip_record.items():
                    print(colored(f"IP: {ip:<15} | Freq: {count}", "blue", "on_white"))
            else:
                print(colored("IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)",
                              "yellow"))
        elif cmd[1] in ("int", "interface", "iface"):
            if len(cmd) == 2:
                show_ifaces()
            else:
                print(colored(f"invalid option \"{cmd[2]}\"", "red"))
        elif cmd[1] in ("packets", "pk"):
            if len(cmd) == 2:
                if packet_list_to_save:
                    for pack in packet_list_to_save:
                        packet_count += 1
                        print(colored(f"[{packet_count}]", "green"), end="")
                        print(pack.summary())
                    packet_count = 0
                else:
                    print(colored("Packet list is empty. Capture packets then try again. (type \"cap\" to capture)",
                                  "yellow"))
            elif len(cmd) == 3:
                if cmd[2] in ("-sm", "-smr", "--summary", "--summarized", "--detail", "-dtl", "--detailed", "-dt"):
                    if packet_list_to_save:
                        for pack in packet_list_to_save:
                            if cmd[2] in ("-sm", "-smr", "--summary", "--summarized"):
                                packet_count += 1
                                print(colored(f"[{packet_count}]", "green"), end="")
                                print(pack.summary())
                            else:
                                packet_count += 1
                                print(colored(f"[{packet_count}]", "green"))
                                pack.show()
                        packet_count = 0
                    else:
                        print(colored("Packet list is empty. Capture packets then try again. (type \"cap\" to capture)",
                                      "yellow"))
                else:
                    print(colored(f"invalid option \"{cmd[2]}\"", "red"))
        else:
            print(colored(f"object \"{cmd[1]}\" not found", "red"))
    elif cmd[0] in ("cap", "sniff", "capture", "snf"):
        legit_input = 1
        illegal_params = []
        instructions_abbreviation = ("f", "t", "a", "i", "c")
        instructions_extended = ("filter", "timeout", "analysis", "interface", "count")
        instru_param = {}
        extracted = {param: None for param in instructions_abbreviation + instructions_extended}
        if extract_command(input_):
            extracted.update(extract_command(input_))
            for instruction in extract_command(input_).keys():
                if instruction not in instructions_extended + instructions_abbreviation:
                    legit_input = 0
                    illegal_params.append(instruction)
        else:
            legit_input = 0
            for err_cmd in cmd[1:]:
                illegal_params.append(err_cmd)
            if len(cmd) == 1:
                legit_input = 1
        if legit_input:
            instru_param["filter"] = extracted["f"] if extracted["f"] else extracted["filter"]
            instru_param["timeout"] = float(extracted["t"]) if extracted["t"] else extracted["timeout"]
            instru_param["analysis"] = extracted["a"] if extracted["a"] else extracted["analysis"]
            instru_param["interface"] = extracted["i"] if extracted["i"] else extracted["interface"]
            instru_param["count"] = int(extracted["c"]) if extracted["c"] else extracted["count"]
            if instru_param["count"] is None:
                instru_param["count"] = 0
            if instru_param["analysis"]:
                capture(filter=instru_param["filter"],
                        timemout_=instru_param["timeout"],
                        extract_packet=instru_param["analysis"],
                        iface=instru_param["interface"],
                        count=instru_param["count"])
            else:
                capture(filter=instru_param["filter"],
                        timemout_=instru_param["timeout"],
                        iface=instru_param["interface"],
                        count=instru_param["count"])
        else:
            print(colored(f"param ", "red"), end="")
            for param in illegal_params:
                if len(param) == 1:
                    print(colored(f"\"{param}\" ", "red"), end="")
                else:
                    print(colored(f"\"{param}\" ", "red"), end="")
            print(colored("illegal or lacking of value", "red"))
    elif cmd[0] in ("save", "s"):
        if packet_list_to_save and len(cmd) == 1:
            wrpcap("./sleuth.pcap", packet_list_to_save)
            print(colored(f"packets saved\npath: {os.getcwd()}\\sleuth.pcap", "yellow"))
        elif packet_list_to_save and len(cmd) == 2:
            try:
                wrpcap(cmd[1], packet_list_to_save)
                print(colored(f"packets saved\npath: {cmd[1]}", "yellow"))
            except FileNotFoundError:
                print(colored(f'something went wrong when locating file "{cmd[1]}"', "red"))
        else:
            print(colored(f'something went wrong when saving .pcap file (maybe packet list is empty)', "red"))
    elif cmd[0] in ("discard", "d"):
        packet_list_to_save.clear()
        print(colored(f"packets stored in memory have been discarded", "yellow"))
    elif cmd[0] in ("load", "l"):
        if len(cmd) == 1:
            try:
                packs = rdpcap("./sleuth.pcap")
                for pack in packs:
                    packet_list_to_save.append(pack)
                print(colored(f'loaded ./sleuth.pcap to memory (type "ls pk" to view)', "yellow"))
            except FileNotFoundError:
                print(colored(f'file ./sleuth.pcap missing', "red"))
        if len(cmd) == 2:
            try:
                packs = rdpcap(cmd[1])
                for pack in packs:
                    packet_list_to_save.append(pack)
                print(colored(f'loaded {cmd[1]} to memory (type "ls pk" to view)', "yellow"))
            except FileNotFoundError:
                print(colored(f'something went wrong when locating file "{cmd[1]}"', "red"))
    else:
        print(colored(f"invalid command \"{input_}\"", "red"))
