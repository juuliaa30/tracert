import socket
import os
import struct
import time
import select
import sys

ICMP_ECHO_REQUEST = 8
ICMP_PROTOCOL = socket.getprotobyname('icmp')


def calculate_checksum(data_string):
    total = 0
    count_to = (len(data_string) // 2) * 2
    index = 0
    while index < count_to:
        value = data_string[index + 1] * 256 + data_string[index]
        total += value
        total &= 0xffffffff
        index += 2
    if count_to < len(data_string):
        total += data_string[len(data_string) - 1]
        total &= 0xffffffff
    total = (total >> 16) + (total & 0xffff)
    total += (total >> 16)
    result = ~total
    result &= 0xffff
    result = result >> 8 | (result << 8 & 0xff00)
    return result


def create_icmp_packet(sequence_number):
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, os.getpid() & 0xFFFF, sequence_number)
    data = struct.pack("d", time.time())
    checksum_value = calculate_checksum(header + data)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum_value), os.getpid() & 0xFFFF, sequence_number)
    return header + data


def send_icmp_ping(socket_instance, address, time_to_live):
    socket_instance.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, time_to_live)
    packet = create_icmp_packet(time_to_live)
    socket_instance.sendto(packet, (address, 0))


def format_ping_time(elapsed_time):
    if elapsed_time is None:
        return "*"
    elif elapsed_time < 0.001:
        return "<1 мс"
    else:
        return f"{elapsed_time * 1000:.0f} мс"


def receive_icmp_ping(socket_instance, timeout_duration):
    remaining_time = timeout_duration
    while remaining_time > 0:
        start_time = time.time()
        ready = select.select([socket_instance], [], [], remaining_time)
        time_in_select = (time.time() - start_time)
        if ready[0] == []:
            return None, None

        time_received = time.time()
        received_packet, addr = socket_instance.recvfrom(1024)

        icmp_header = received_packet[20:28]
        icmp_type, icmp_code, checksum, process_id, sequence = struct.unpack("bbHHh", icmp_header)

        if icmp_type == 11:
            ip_header = received_packet[0:20]
            ip_source = struct.unpack("!4B", ip_header[12:16])
            current_address = ".".join(str(x) for x in ip_source)
            return time_received - start_time, current_address

        elif icmp_type == 0:
            return time_received - start_time, addr[0]

        remaining_time -= time_in_select
    return None, None


def traceroute(destination_address, maximum_hops=30, timeout_duration=3, pings_per_hop=3, resolve_hostnames=False):
    try:
        destination_ip = socket.gethostbyname(destination_address)
    except socket.gaierror:
        print(f"Не удается разрешить адрес {destination_address}")
        sys.exit()

    print(f"Трассировка маршрута к {destination_address} [{destination_ip}] с максимальным числом прыжков {maximum_hops}:")

    for time_to_live in range(1, maximum_hops + 1):
        print(f"{time_to_live:2}", end="  ")
        current_address = None
        ping_times = []
        timeouts = 0

        for attempt in range(pings_per_hop):
            try:
                sock_instance = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTOCOL)
                sock_instance.settimeout(timeout_duration)
                send_icmp_ping(sock_instance, destination_ip, time_to_live)
                elapsed_time, addr = receive_icmp_ping(sock_instance, timeout_duration)
                sock_instance.close()

                if elapsed_time is not None:
                    ping_times.append(format_ping_time(elapsed_time))
                    current_address = addr if current_address is None else current_address
                else:
                    ping_times.append(format_ping_time(None))
                    timeouts += 1

                time.sleep(1)

            except socket.error as e:
                print(f"Ошибка при отправке пакета: {e}")
                sys.exit()

        for time_value in ping_times:
            print(time_value, end="  ")

        if timeouts == pings_per_hop:
            print(" Превышен интервал ожидания для запроса.",end=' ')
        elif current_address:
            if resolve_hostnames:
                try:
                    current_host = socket.gethostbyaddr(current_address)[0]
                    print(f"{current_host} [{current_address}]", end="  ")
                except socket.herror:
                    print(f"{current_address} (не удалось разрешить)", end="  ")
            else:
                print(current_address, end="  ")

        print()

        if current_address == destination_ip:
            print("\nТрассировка завершена.")
            return

    print("Трассировка завершена.")


if __name__ == "__main__":
    traceroute(input())