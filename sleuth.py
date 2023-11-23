from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.all import *
from datetime import datetime
import time
import pydivert
from colorama import Fore, Back, Style, init

# colorama config
init(autoreset=True)

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

# proxy for win config
log_on_win_proxy = []  # log list for win proxy
proxy_win_run = 0
proxy_win_expression = "true"  # true and divert all traffic
listener_win_proxy = pydivert.WinDivert()
proxy_activated = 0
count_prx_packet = 0

sync_thread_main_lock = 1  # semaphore between main and other threads


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
            print(f"{Fore.BLUE}{Back.WHITE}MAC: {get_if_hwaddr(intf):<17} | ", end='')
            print(f"{Fore.BLUE}{Back.WHITE}interface: {intf}")
    else:
        print(f"{Fore.YELLOW}how? i mean how could you not have an net interface!")


# TODO analyse command
def extract_command(input_str):
    result = {}
    options = re.findall(r'-(\w+)\s+([^ ]+)', input_str)
    if not options:
        return None
    for option, value in options:
        result[option] = value
    return result


# TODO capture and blocking
# for windows
def proxy_intercept_win():
    global log_on_win_proxy, proxy_win_expression, proxy_win_run, listener_win_proxy, sync_thread_main_lock, proxy_activated, count_prx_packet
    listener = listener_win_proxy
    while main_running:
        listener._filter = proxy_win_expression.encode()
        if proxy_win_run:
            proxy_activated = 1
            sync_thread_main_lock = 0
            if not main_running:
                break
            try:
                listener.open()
                sync_thread_main_lock = 1
            except OSError:
                sync_thread_main_lock = 0
                proxy_win_expression = "true"
                proxy_win_run = 0
                time.sleep(0.3)
                # print(f"{Fore.RED}{Back.WHITE}{OSError.with_traceback()}\n")
                print(f"{Fore.YELLOW}proxy for windows terminated")
                print(
                    f"{Fore.RED}proxy for windows went wrong due to unexpected circumstances. "
                    f"maybe check your script syntax or your current privilege")
                sync_thread_main_lock = 1
                continue
            if not main_running:
                listener.close()
                break
            while proxy_win_run:
                if not main_running or not proxy_win_run:
                    listener.close()
                    break
                try:
                    packet_prx = listener.recv()
                    if not main_running or not proxy_win_run:
                        listener.close()
                        break
                    else:
                        # TODO proxy log
                        count_prx_packet += 1
                        new_log = (
                                f"{Fore.YELLOW}[PROXY-INTERCEPT#{count_prx_packet}]{Fore.RESET} " + f"FROM: {packet_prx.ipv4.src_addr}, " + f"TO: {packet_prx.ipv4.dst_addr}, " + f"DST_PORT: {packet_prx.dst_port}, " + f"TIME: {datetime.now()}" + f"\nPAYLOAD: {packet_prx.payload}")
                        log_on_win_proxy.append(new_log)
                except AttributeError:
                    pass
            if listener.is_open:
                listener.close()
        else:
            proxy_activated = 0


def capture(filter, timemout_, extract_packet="count", count=0, iface=None):
    global packet_count, stored, packet_list_to_save

    def packet_handler_sm(packet):
        global packet_count, packet_list_to_save
        packet_count += 1
        packet_list_to_save.append(packet)
        return f"{Fore.GREEN}[" + str(packet_count) + f"]{Fore.RESET}" + str(datetime.now()) + " | " + packet.summary()

    def packet_handler_dt(packet):
        global packet_count, packet_list_to_save
        packet_count += 1
        packet_list_to_save.append(packet)
        print(f"{Fore.GREEN}[" + str(packet_count) + "]")
        return packet.show()

    def packet_handler_count(packet):
        global packet_count, packet_list_to_save
        packet_list_to_save.append(packet)
        if not packet_count % 49 and packet_count != 0:
            print()
        elif packet_count:
            print(f"{Fore.YELLOW}{Back.YELLOW}>", end="", flush=True)
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
    print(f"Interface: {interface}\nFilter: {filtering}\nTimeout: {timemout_}s\n" + f"{Fore.YELLOW}capturing...")
    try:
        if extract_packet in ("summary", "smr", "summarized", "sm"):
            sniff(count=count, filter=filter, timeout=timemout_, iface=iface, prn=packet_handler_sm, quiet=0,
                  store=stored)
            print(f"\n{Fore.YELLOW}--{packet_count} packets captured--")
            packet_count = 0
        elif extract_packet in ("detail", "dtl", "detailed", "dt"):
            sniff(count=count, filter=filter, timeout=timemout_, iface=iface, prn=packet_handler_dt, quiet=0,
                  store=stored)
            print(f"\n{Fore.YELLOW}--{packet_count} packets captured--")
            packet_count = 0
        elif extract_packet in ("hide", "quiet", "count"):
            sniff(count=count, filter=filter, timeout=timemout_, iface=iface, prn=packet_handler_count, quiet=0,
                  store=stored)
            print(f"{Fore.LIGHTWHITE_EX}{Back.YELLOW}done", end="")
            print(f"\n{Fore.YELLOW}--{packet_count} packets captured--")
            packet_count = 0
    except:
        print(f"{Fore.RED}something went wrong during capturing")


# run threads
number_of_monitors = 0
Thread(target=refresh_traffic).start()
Thread(target=proxy_intercept_win).start()
traffic_monitors.append(Thread(target=traffic_monitor))
traffic_monitors.append(Thread(target=traffic_monitor_on_port))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_ip))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_icmp))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_tcp))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_udp))
traffic_monitors.append(Thread(target=traffic_monitor_on_protocol_arp))
for monitor in traffic_monitors:
    monitor.start()
    number_of_monitors += 1

print(f'{Fore.GREEN}[INFO]{Fore.RESET} ' + f'{len(threading.enumerate())} threads running.')
print(f'{Fore.YELLOW}[WARNING]{Fore.RESET} ' + 'Terminate threads before you exit sleuth (by typing "exit", "bye" etc).')

sleuth = '''

                {/H/SL/U/H//}           |    
               {T/W//LE/TH/L/}          |    welcome to sleuth v0.3.10
              {S/{W/Z/H//H//U/L}}       |    type "help" to learn
            {SLEU/H/SL/UTH/O/S0TO}}}    |    
              ///           |)          |    https://github.com/vortezwohl/sleuth-network-sniffer
               //             \\         |    
                /           =|          |    have fun! ;)
                 |            \\         |    
                 /           _/         
                /          \\            
                 
'''
print(sleuth)
while main_running:
    if sync_thread_main_lock:
        input_ = input(f'{Fore.LIGHTWHITE_EX}sleuth>>{Fore.RESET}')
        cmd = input_.split(' ')
        if input_ == '':
            pass
        elif cmd[0] in ("help", "guide"):
            print(f"{'-' * 70}\n\n"
                  f"{'mntr [on/off]':<70}: start monitoring or stop monitoring.\n\n"
                  f"{'ms [-p #port/-P #protocol]':<70}: measure networking speed over a port or a protocol.\n\n"
                  f"{'prx-win on / off / conf':<70}: run, terminate or configurate (auto reboot) net proxy (on windows)\n\n"
                  f"{'ls ip [-dsc/-asc #number] / ls int / ls pk [-sm/-dt] / ls wplog':<70}: list ipv4 addresses, interfaces, captured packets and proxy log.\n\n"
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
            sync_thread_main_lock = 0
            main_running = 0
            thread_running = 0
            refresh_running = 0
            proxy_win_run = 0
            print(f"{Fore.YELLOW}[WARNING]{Fore.RESET} Please wait a few seconds before closing CLI!\n{Fore.YELLOW}terminating threads...\n", end='')
            print(f"{Fore.YELLOW}{Back.YELLOW}.", end='', flush=True)
            time.sleep(0.05)
            print(f"{Fore.YELLOW}{Back.YELLOW}.", end='', flush=True)
            # TODO check threads
            ended_thread_count = 0
            threads = threading.enumerate()
            all_thread_count = len(threading.enumerate())
            # TODO wait until all threads terminated
            while 1:
                for thread in threads:
                    if not thread.is_alive():
                        ended_thread_count += 1
                        print(f"{Fore.YELLOW}{Back.YELLOW}.", end='', flush=True)
                        time.sleep(0.02)
                        print(f"{Fore.YELLOW}{Back.YELLOW}.", end='', flush=True)
                        time.sleep(0.05)
                        print(f"{Fore.YELLOW}{Back.YELLOW}.", end='', flush=True)
                        time.sleep(0.03)
                        print(f"{Fore.YELLOW}{Back.YELLOW}.", end='', flush=True)
                        time.sleep(0.04)
                        print(f"{Fore.YELLOW}{Back.YELLOW}.", end='', flush=True)
                        if ended_thread_count == all_thread_count:
                            print(f"{Fore.LIGHTWHITE_EX}{Back.YELLOW} done")
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
                print(f"{Fore.RED}something went wrong while scripting \"{script}\"")
        elif cmd[0] in ("mntr", "monitor") and len(cmd) == 2:
            if cmd[1] in ("r", "run", "on"):
                thread_running = 1
                print(f"{Fore.YELLOW}traffic monitor activated")
            elif cmd[1] in ("s", "stop", "off"):
                thread_running = 0
                print(f"{Fore.YELLOW}traffic monitor terminated")
            else:
                print(f"{Fore.RED}invalid option \"{cmd[1]}\"")
        elif cmd[0] in ("measure", "ms") and len(cmd) < 4:
            if len(cmd) == 1:
                refresh_running = 0
                thread_running = 0
                print(f"{Fore.YELLOW}traffic{Fore.RESET} at {datetime.now()}")
                traffic = traffic_on_general_packet()
                print(
                    f"Speed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8:.0f} bits/s")
                refresh_running = 1
                thread_running = 1
            else:
                refresh_running = 0
                thread_running = 0
                print(f"{Fore.YELLOW}traffic{Fore.RESET} at {datetime.now()}")
                try:
                    if cmd[1] in ("-p", "--port"):
                        if int(cmd[2]) not in range(0, 65536):
                            print(f"{Fore.RED}port {cmd[2]} doesn't exist")
                        else:
                            traffic = traffic_on_port(int(cmd[2]))
                            print(
                                f"Port: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                    elif cmd[1] in ("-P", "--protocol"):
                        if cmd[2] == 'ip' and traffic_on_ip():
                            traffic = traffic_on_ip()
                            print(
                                f"Protocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                        elif cmd[2] == 'icmp' and traffic_on_icmp():
                            traffic = traffic_on_icmp()
                            print(
                                f"Protocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                        elif cmd[2] == 'tcp' and traffic_on_tcp():
                            traffic = traffic_on_tcp()
                            print(
                                f"Protocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                        elif cmd[2] == 'udp' and traffic_on_udp():
                            traffic = traffic_on_udp()
                            print(
                                f"Protocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                        elif cmd[2] == 'arp' and traffic_on_arp():
                            traffic = traffic_on_arp()
                            print(
                                f"Protocol: {cmd[2]}\nSpeed:\n{traffic / 1024.0:.0f} kb/s\n{traffic:.0f} bytes/s\n{traffic * 8.0:.0f} bits/s")
                        else:
                            print(f"{Fore.RED}protocol \"{cmd[2]}\" not supported")
                    else:
                        print(f"{Fore.RED}invalid option \"{cmd[1]}\"")
                except ValueError:
                    print(f"{Fore.RED}\"{cmd[2]}\" isn't a number")
                refresh_running = 1
                thread_running = 1
        elif cmd[0] in ("list", "ls") and len(cmd) in range(2, 6):
            if cmd[1] == "ip" and len(cmd) == 3:
                thread_running = 0
                if cmd[2] in ("-asc", "--ascend", "-dsc", "--descend"):
                    if cmd[2] in ("-asc", "--ascend"):
                        if ip_record.items():
                            for ip, count in sorted(ip_record.items(), key=lambda this: this[1], reverse=0):
                                print(f"{Fore.BLUE}{Back.WHITE}IP: {ip:<15} | Freq: {count}")
                        else:
                            print(f"{Fore.YELLOW}IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)")
                    else:
                        if ip_record.items():
                            for ip, count in sorted(ip_record.items(), key=lambda this: this[1], reverse=1):
                                print(f"{Fore.BLUE}{Back.WHITE}IP: {ip:<15} | Freq: {count}")
                        else:
                            print(f"{Fore.YELLOW}IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)")
                else:
                    print(f"{Fore.RED}invalid option \"{cmd[2]}\"")
                thread_running = 1
            elif cmd[1] == "ip" and len(cmd) == 4:
                thread_running = 0
                if cmd[2] in ("-asc", "--ascend", "-dsc", "--descend"):
                    try:
                        if cmd[2] in ("-asc", "--ascend") and len(cmd) == 4:
                            entry = int(cmd[3])
                            if entry > len(ip_record.keys()) or entry < 0:
                                print(f"{Fore.RED}index {cmd[3]} out of range")
                            else:
                                if ip_record.items():
                                    entry_count = 0
                                    for ip, count in sorted(ip_record.items(), key=lambda this: this[1], reverse=0):
                                        if entry_count == entry:
                                            break
                                        print(f"{Fore.BLUE}{Back.WHITE}IP: {ip:<15} | Freq: {count}")
                                        entry_count += 1
                                else:
                                    print(f"{Fore.YELLOW}IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)")
                        elif cmd[2] in ("-dsc", "--descend") and len(cmd) == 4:
                            entry = int(cmd[3])
                            if entry > len(ip_record.keys()) or entry < 0:
                                print(f"{Fore.RED}index {cmd[3]} out of range")
                            else:
                                if ip_record.items():
                                    entry_count = 0
                                    for ip, count in sorted(ip_record.items(), key=lambda this: this[1], reverse=1):
                                        if entry_count == entry:
                                            break
                                        print(f"{Fore.BLUE}{Back.WHITE}IP: {ip:<15} | Freq: {count}")
                                        entry_count += 1
                                else:
                                    print(f"{Fore.YELLOW}IP list is empty. Run network monitor and try again. (type \"mntr on\" to run monitor)")
                    except ValueError:
                        print(f"{Fore.RED}\"{cmd[3]}\" isn't a number")
                else:
                    print(f"{Fore.RED}invalid option \"{cmd[2]}\"")
                thread_running = 1
            elif cmd[1] == "ip" and len(cmd) == 2:
                thread_running = 0
                if ip_record.items():
                    for ip, count in ip_record.items():
                        print(f"{Fore.BLUE}{Back.WHITE}IP: {ip:<15} | Freq: {count}")
                else:
                    print(f"{Fore.YELLOW}IP list is empty. Activate network monitor and try again. (type \"mntr on\" to activate monitor)")
                thread_running = 1
            elif cmd[1] == "ip" and len(cmd) > 4:
                print(f"{Fore.RED}invalid command {cmd[4:]}")
            elif cmd[1] in ("int", "interface", "iface"):
                if len(cmd) == 2:
                    show_ifaces()
                elif len(cmd) > 2:
                    print(f"{Fore.RED}invalid command {cmd[2:]}")
                else:
                    print(f"{Fore.RED}invalid option \"{cmd[2]}\"")
            elif cmd[1] in ("packets", "pk"):
                if len(cmd) == 2:
                    if packet_list_to_save:
                        for pack in packet_list_to_save:
                            packet_count += 1
                            print(f"{Fore.GREEN}[{packet_count}]", end="")
                            print(pack.summary())
                        packet_count = 0
                    else:
                        print(f"{Fore.YELLOW}Packet list is empty. Capture packets then try again. (type \"cap\" to capture)")
                elif len(cmd) == 3:
                    if cmd[2] in ("-sm", "-smr", "--summary", "--summarized", "--detail", "-dtl", "--detailed", "-dt"):
                        if packet_list_to_save:
                            for pack in packet_list_to_save:
                                if cmd[2] in ("-sm", "-smr", "--summary", "--summarized"):
                                    packet_count += 1
                                    print(f"{Fore.GREEN}[{packet_count}]", end="")
                                    print(pack.summary())
                                else:
                                    packet_count += 1
                                    print(f"{Fore.GREEN}[{packet_count}]")
                                    pack.show()
                            packet_count = 0
                        else:
                            print(f"{Fore.YELLOW}Packet list is empty. Capture packets then try again. (type \"cap\" to capture)")
                    else:
                        print(f"{Fore.RED}invalid option \"{cmd[2]}\"")
                elif len(cmd) > 3:
                    print(f"{Fore.RED}invalid command {cmd[3:]}")
            elif cmd[1] in ("wplog", "wpl"):  # win proxy log
                if log_on_win_proxy:
                    for one_log in log_on_win_proxy:
                        print(f"{one_log.split('PAYLOAD')[0]}", end="")
                else:
                    print(f"{Fore.YELLOW}win proxy haven't logged anything")
            else:
                print(f"{Fore.RED}object \"{cmd[1]}\" not found")
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
                print(f"{Fore.RED}param ", end="")
                for param in illegal_params:
                    if len(param) == 1:
                        print(f"{Fore.RED}\"{param}\" ", end="")
                    else:
                        print(f"{Fore.RED}\"{param}\" ", end="")
                print(f"{Fore.RED}illegal or lacking of value")
        elif cmd[0] in ("save", "s"):
            if packet_list_to_save and len(cmd) == 1:
                wrpcap("./sleuth.pcap", packet_list_to_save)
                print(f"{Fore.YELLOW}packets saved\npath: {os.getcwd()}\\sleuth.pcap")
            elif packet_list_to_save and len(cmd) == 2:
                try:
                    wrpcap(cmd[1], packet_list_to_save)
                    print(f"{Fore.YELLOW}packets saved\npath: {cmd[1]}")
                except FileNotFoundError:
                    print(f'{Fore.RED}something went wrong when locating file {cmd[1]}')
            elif not packet_list_to_save:
                print(f'{Fore.RED}packet list is empty to save')
        elif cmd[0] in ("discard", "d"):
            packet_list_to_save.clear()
            print(f"{Fore.YELLOW}packets in memory are discarded")
        elif cmd[0] in ("load", "l"):
            if len(cmd) == 1:
                try:
                    packs = rdpcap("./sleuth.pcap")
                    for pack in packs:
                        packet_list_to_save.append(pack)
                    print(f'{Fore.YELLOW}packets loaded\npath: {os.getcwd()}\\sleuth.pcap')
                except FileNotFoundError:
                    print(f'{Fore.RED}file {os.getcwd()}\\sleuth.pcap not found')
                except Scapy_Exception:
                    print(f'{Fore.RED}file {os.getcwd()}\\sleuth.pcap is not a supported capture file')
            if len(cmd) == 2:
                try:
                    packs = rdpcap(cmd[1])
                    for pack in packs:
                        packet_list_to_save.append(pack)
                    print(f'{Fore.YELLOW}packets loaded\npath: {cmd[1]}')
                except FileNotFoundError:
                    print(f'{Fore.RED}something went wrong when locating file {cmd[1]}')
                except Scapy_Exception:
                    print(f'{Fore.RED}file {cmd[1]} is not a supported capture file')
        elif cmd[0] in ("proxy-windows", "prx-win", "wpx") and len(cmd) == 2:  # TODO simple firewall
            if cmd[1] in ("on", "off"):
                if len(cmd) == 2:
                    # TODO config proxy
                    if cmd[1] == "on":
                        if not proxy_win_run and main_running:
                            sync_thread_main_lock = 0
                            proxy_win_expression = input(f"{Fore.GREEN}-" * 20 + "Configuration Script" + "-" * 20 + "\n")
                            print(f"{Fore.GREEN}-" * 40 + "-" * 20)
                            # read script from file
                            if proxy_win_expression == "false":
                                print(f'{Fore.RED}"false" is not supported. switch to default config "true"')
                                proxy_win_expression = "true"
                            sleuth_scripts = proxy_win_expression.split(" ")
                            if sleuth_scripts[0] in ("import", "imp") and len(sleuth_scripts) == 2:
                                try:
                                    with open(sleuth_scripts[1], 'r') as file:
                                        proxy_win_expression = file.read().replace("\n", " ")
                                        if proxy_win_expression == "false":
                                            print(f'{Fore.RED}"false" is not supported. switch to default config "true"')
                                            proxy_win_expression = "true"
                                except OSError:
                                    print(f'{Fore.RED}failed to read {sleuth_scripts[1]}. switch to default config "true"')
                                    proxy_win_expression = "true"
                                print(f"{Fore.YELLOW}traffic monitor activated")
                                print(f"{Fore.YELLOW}proxy for windows activating...")
                                proxy_win_run = 1
                                thread_running = 1
                            else:
                                print(f"{Fore.YELLOW}traffic monitor activated")
                                print(f"{Fore.YELLOW}proxy for windows activating...")
                                proxy_win_run = 1
                                thread_running = 1
                            sync_thread_main_lock = 0

                            time.sleep(0.01)
                            print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                            time.sleep(0.02)
                            print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                            time.sleep(0.01)
                            print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                            time.sleep(0.03)
                            print(f"{Fore.YELLOW}{Back.YELLOW}>>>", end="")
                            while not proxy_activated:
                                time.sleep(0.02)
                                print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                                time.sleep(0.01)
                                print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                                print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                                time.sleep(0.02)
                                print(f"{Fore.YELLOW}{Back.YELLOW}>>>>", end="")
                            print(f"{Fore.LIGHTWHITE_EX}{Back.YELLOW}done")

                        else:
                            print(f"{Fore.YELLOW}proxy for windows is already activated")
                    else:  # off
                        if proxy_win_run and main_running:
                            proxy_win_run = 0
                            proxy_win_expression = "true"

                            print(f"{Fore.YELLOW}terminating proxy...")
                            time.sleep(0.01)
                            print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                            time.sleep(0.02)
                            print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                            time.sleep(0.01)
                            print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                            time.sleep(0.03)
                            print(f"{Fore.YELLOW}{Back.YELLOW}>>>", end="")
                            while proxy_activated:
                                time.sleep(0.03)
                                print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                                time.sleep(0.03)
                                print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                                print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                                time.sleep(0.02)
                                print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                            print(f"{Fore.LIGHTWHITE_EX}{Back.YELLOW}done")

                            print(f"{Fore.YELLOW}export log to file? y for export, n for discard")
                            save_log = input("(y/n) ")
                            if save_log in ("yes", "Y", "y"):
                                # keep log
                                with open("sleuth-proxy-win.log", "a") as f:
                                    for one_log in log_on_win_proxy:
                                        log_split = one_log.split(f"{Fore.RESET} ")
                                        f.write(log_split[0].split(f"{Fore.YELLOW}")[1]+" ")
                                        f.write(log_split[1]+"\n")
                                log_on_win_proxy.clear()  # initialize log
                                count_prx_packet = 0
                                print(f"{Fore.YELLOW}log exported\npath: {os.getcwd()}\\sleuth-proxy-win.log")
                            elif save_log in ("No", "N", "n"):
                                # discard log
                                log_on_win_proxy.clear()  # initialize log
                                count_prx_packet = 0
                                print(f"{Fore.YELLOW}log discarded")
                            else:
                                # discard log
                                log_on_win_proxy.clear()  # initialize log
                                count_prx_packet = 0
                                print(f"{Fore.YELLOW}invalid option \"{save_log}\" log discarded by default")
                        else:
                            print(f"{Fore.YELLOW}proxy for windows wasn't activated yet")
                else:
                    print(f"{Fore.RED}invalid command {cmd[2:]}")
            elif cmd[1] in ("conf", "config", "reboot"):
                if proxy_win_run and main_running:
                    sync_thread_main_lock = 0

                    proxy_win_expression = input(f"{Fore.GREEN}-" * 20 + "Configuration Script" + "-" * 20 + "\n")
                    print(f"{Fore.GREEN}-" * 40 + "-" * 20)

                    # terminate proxy first
                    proxy_win_run = 0

                    # read script from file
                    sleuth_scripts = proxy_win_expression.split(" ")
                    if proxy_win_expression == "false":
                        print(f'{Fore.RED}"false" is not supported. switch to default config "true"')
                        proxy_win_expression = "true"

                    print(f"{Fore.YELLOW}terminating proxy...")
                    time.sleep(0.01)
                    print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                    time.sleep(0.02)
                    print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                    time.sleep(0.01)
                    print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                    time.sleep(0.03)
                    print(f"{Fore.YELLOW}{Back.YELLOW}>>>", end="")
                    while proxy_activated:
                        time.sleep(0.03)
                        print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                        time.sleep(0.03)
                        print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                        print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                        time.sleep(0.02)
                        print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                    print(f"{Fore.LIGHTWHITE_EX}{Back.YELLOW}done")

                    if sleuth_scripts[0] in ("import", "imp") and len(sleuth_scripts) == 2:
                        try:
                            with open(sleuth_scripts[1], 'r') as file:
                                proxy_win_expression = file.read().replace("\n", " ")
                                if proxy_win_expression == "false":
                                    print(f'{Fore.RED}"false" is not supported. switch to default config "true"')
                                    proxy_win_expression = "true"
                        except OSError:
                            print(f'{Fore.RED}failed to read {sleuth_scripts[1]}. switch to default config "true"')
                            proxy_win_expression = "true"
                        # print(f"{Fore.YELLOW}proxy for windows rebooted")
                        proxy_win_run = 1
                    else:
                        # print(f"{Fore.YELLOW}proxy for windows rebooted")
                        proxy_win_run = 1
                    sync_thread_main_lock = 0

                    print(f"{Fore.YELLOW}rebooting proxy...")
                    time.sleep(0.01)
                    print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                    time.sleep(0.02)
                    print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                    time.sleep(0.01)
                    print(f"{Fore.YELLOW}{Back.YELLOW}>>>", end="")
                    time.sleep(0.03)
                    print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                    while not proxy_activated:
                        time.sleep(0.02)
                        print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                        time.sleep(0.03)
                        print(f"{Fore.YELLOW}{Back.YELLOW}>>", end="")
                        print(f"{Fore.YELLOW}{Back.YELLOW}>", end="")
                        time.sleep(0.02)
                        print(f"{Fore.YELLOW}{Back.YELLOW}>>>", end="")
                    print(f"{Fore.LIGHTWHITE_EX}{Back.YELLOW}done")

                else:
                    print(f"{Fore.YELLOW}proxy for windows wasn't activated yet")

            else:
                print(f"{Fore.RED}invalid operation {cmd[1]} for proxy")
        elif cmd[0] in ("proxy-windows", "prx-win", "wprx") and len(cmd) == 1:
            print(f"{Fore.RED}proxy lack of operation provided")
        else:
            print(f"{Fore.RED}invalid command \"{input_}\"")
