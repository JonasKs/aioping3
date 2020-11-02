import asyncio
import logging
import socket
import struct
import time
import uuid
import zlib
from functools import partial
from typing import Coroutine

import async_timeout

from aioping3.enums import ICMP_DEFAULT_CODE, IcmpDestinationUnreachableCode, IcmpTimeExceededCode, IcmpType
from aioping3.exceptions import (
    DestinationHostUnreachable,
    DestinationUnreachable,
    HostUnknown,
    PingError,
    TimeExceeded,
    TimeToLiveExpired,
)

__version__ = "1.0.0"
EXCEPTIONS = False  # EXCEPTIONS: Raise exception when delay is not available.

# According to netinet/ip_icmp.h. !=network byte order(big-endian), B=unsigned char, H=unsigned short
ICMP_HEADER_FORMAT = "!BBHHH"
IP_HEADER_FORMAT = "!BBHHHBBHII"
ICMP_TIME_FORMAT = "!d"  # d=double
SOCKET_SO_BINDTODEVICE = 25  # socket.SO_BINDTODEVICE


proto_icmp = socket.getprotobyname("icmp")
proto_icmp6 = socket.getprotobyname("ipv6-icmp")


logger = logging.getLogger('aioping3')


def _raise(err):
    """Raise exception if `ping3.EXCEPTIONS` is True.
    Args:
        err: Exception.
    Raise:
        Exception: Exception passed in args will be raised if `ping3.EXCEPTIONS` is True.
    """
    if EXCEPTIONS:
        raise err


def ones_comp_sum16(num1: int, num2: int) -> int:
    """Calculates the 1's complement sum for 16-bit numbers.
    Args:
        num1: 16-bit number.
        num2: 16-bit number.
    Returns:
        The calculated result.
    """
    carry = 1 << 16
    result = num1 + num2
    return result if result < carry else result + 1 - carry


def checksum(source: bytes) -> int:
    """Calculates the checksum of the input bytes.
    RFC1071: https://tools.ietf.org/html/rfc1071
    RFC792: https://tools.ietf.org/html/rfc792
    Args:
        source: The input to be calculated.
    Returns:
        Calculated checksum.
    """
    if len(source) % 2:  # if the total length is odd, padding with one octet of zeros for computing the checksum
        source += b'\x00'
    x = 0
    for i in range(0, len(source), 2):
        x = ones_comp_sum16(x, (source[i + 1] << 8) + source[i])
    return ~x & 0xFFFF


def read_icmp_header(raw: bytes) -> dict:
    """Get information from raw ICMP header data.
    Args:
        raw: Bytes. Raw data of ICMP header.
    Returns:
        A map contains the infos from the raw header.
    """
    icmp_header_keys = ('type', 'code', 'checksum', 'id', 'seq')
    return dict(zip(icmp_header_keys, struct.unpack(ICMP_HEADER_FORMAT, raw)))


def read_ip_header(raw: bytes) -> dict:
    """Get information from raw IP header data.
    Args:
        raw: Bytes. Raw data of IP header.
    Returns:
        A map contains the infos from the raw header.
    """

    def stringify_ip(ip: int) -> str:
        return ".".join([str(ip >> offset & 0xFF) for offset in (24, 16, 8, 0)])  # str(ipaddress.ip_address(ip))

    ip_header_keys = ('version', 'tos', 'len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr')
    ip_header = dict(zip(ip_header_keys, struct.unpack(IP_HEADER_FORMAT, raw)))
    ip_header['src_addr'] = stringify_ip(ip_header['src_addr'])
    ip_header['dest_addr'] = stringify_ip(ip_header['dest_addr'])
    return ip_header


async def send_one_ping(sock: socket, dest_addr: str, icmp_id: int, seq: int, size: int) -> Coroutine:
    """Sends one ping to the given destination.
    ICMP Header (bits): type (8), code (8), checksum (16), id (16), sequence (16)
    ICMP Payload: time (double), data
    ICMP Wikipedia: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    Args:
        sock: Socket.
        dest_addr: The destination address, can be an IP address or a domain name. Ex. "192.168.1.1"/"example.com"
        icmp_id: ICMP packet id. Calculated from Process ID and Thread ID.
        seq: ICMP packet sequence, usually increases from 0 in the same process.
        size: The ICMP packet payload size in bytes. Note this is only for the payload part.
    Raises:
        HostUnkown: If destination address is a domain name and cannot resolved.
    """
    loop = asyncio.get_running_loop()
    try:
        # Domain name will translated into IP address, and IP address leaves unchanged.
        dest_addr = await loop.run_in_executor(
            None, partial(socket.gethostbyname, dest_addr)
    )
    except socket.gaierror as err:
        raise HostUnknown(dest_addr) from err
    # Pseudo checksum is used to calculate the real checksum.
    pseudo_checksum = 0
    icmp_header = struct.pack(
        ICMP_HEADER_FORMAT, IcmpType.ECHO_REQUEST, ICMP_DEFAULT_CODE, pseudo_checksum, icmp_id, seq
    )
    padding = (size - struct.calcsize(ICMP_TIME_FORMAT)) * "Q"  # Using double to store current time.
    icmp_payload = struct.pack(ICMP_TIME_FORMAT, time.time()) + padding.encode()
    # Calculates the checksum on the dummy header and the icmp_payload.
    real_checksum = checksum(icmp_header + icmp_payload)

    # Don't know why I need socket.htons() on real_checksum since ICMP_HEADER_FORMAT
    # already in Network Bytes Order (big-endian)
    # Put real checksum into ICMP header.
    icmp_header = struct.pack(
        ICMP_HEADER_FORMAT, IcmpType.ECHO_REQUEST, ICMP_DEFAULT_CODE, socket.htons(real_checksum), icmp_id, seq
    )

    icmp_header_read = read_icmp_header(icmp_header)
    logger.debug("Sent ICMP Header, %s", icmp_header_read)
    logger.debug('Sent ICMP Payload: %s', icmp_payload)

    packet = icmp_header + icmp_payload
    # addr = (ip, port). Port is 0 respectively the OS default behavior will be used.
    # Create callback : https://stackoverflow.com/a/46779849
    return loop.run_in_executor(
        None, partial(sock.sendto, packet, (dest_addr, 0))
    )


async def receive_one_ping(sock: socket, icmp_id: int, seq: int, timeout: int) -> float:
    """Receives the ping from the socket.
    IP Header (bits): version (8), type of service (8), length (16), id (16), flags (16), time to live (8),
    protocol (8), checksum (16), source ip (32), destination ip (32).

    ICMP Packet (bytes): IP Header (20), ICMP Header (8), ICMP Payload (*).
    Ping Wikipedia: https://en.wikipedia.org/wiki/Ping_(networking_utility)
    ToS (Type of Service) in IP header for ICMP is 0. Protocol in IP header for ICMP is 1.

    Args:
        sock: The same socket used for send the ping.
        icmp_id: ICMP packet id. Sent packet id should be identical with received packet id.
        seq: ICMP packet sequence. Sent packet sequence should be identical with received packet sequence.
        timeout: Timeout in seconds.
    Returns:
        The delay in seconds or None on timeout.
    Raises:
        TimeToLiveExpired: If the Time-To-Live in IP Header is not large enough for destination.
        TimeExceeded: If time exceeded but Time-To-Live does not expired.
        DestinationHostUnreachable: If the destination host is unreachable.
        DestinationUnreachable: If the destination is unreachable.
    """
    ip_header_slice = slice(0, struct.calcsize(IP_HEADER_FORMAT))  # [0:20]
    icmp_header_slice = slice(
        ip_header_slice.stop, ip_header_slice.stop + struct.calcsize(ICMP_HEADER_FORMAT)
    )  # [20:28]
    timeout_time = time.time() + timeout  # Exactly time when timeout.
    logger.debug('Timeout time: %s', time.ctime(timeout_time))

    loop = asyncio.get_event_loop()
    try:
        with async_timeout.timeout(timeout):
            while True:
                recv_data = await loop.sock_recv(sock, 1024)
                time_recv = time.time()
                ip_header_raw, icmp_header_raw, icmp_payload_raw = (
                    recv_data[ip_header_slice],
                    recv_data[icmp_header_slice],
                    recv_data[icmp_header_slice.stop :],
                )
                ip_header = read_ip_header(ip_header_raw)
                logger.debug('Received IP header: %s', ip_header)
                icmp_header = read_icmp_header(icmp_header_raw)
                logger.debug('Received ICMP Header: %s', icmp_header)
                logger.debug('Received ICMP Payload: %s', icmp_payload_raw)
                if icmp_header['id'] and icmp_header['id'] != icmp_id:  # ECHO_REPLY should match the ID field.
                    logger.debug('ICMP ID dismatch. Packet filtered out.')
                    continue
                if (
                    icmp_header['type'] == IcmpType.TIME_EXCEEDED
                ):  # TIME_EXCEEDED has no icmp_id and icmp_seq. Usually they are 0.
                    if icmp_header['code'] == IcmpTimeExceededCode.TTL_EXPIRED:
                        raise TimeToLiveExpired()  # Some router does not report TTL expired and then timeout shows.
                    raise TimeExceeded()
                if (
                    icmp_header['type'] == IcmpType.DESTINATION_UNREACHABLE
                ):  # DESTINATION_UNREACHABLE has no icmp_id and icmp_seq. Usually they are 0.
                    if icmp_header['code'] == IcmpDestinationUnreachableCode.DESTINATION_HOST_UNREACHABLE:
                        raise DestinationHostUnreachable()
                    raise DestinationUnreachable()
                if icmp_header['id'] and icmp_header['seq'] == seq:  # ECHO_REPLY should match the SEQ field.
                    if icmp_header['type'] == IcmpType.ECHO_REQUEST:  # filters out the ECHO_REQUEST itself.
                        logger.debug('ECHO_REQUEST received. Packet filtered out.')
                        continue
                    if icmp_header['type'] == IcmpType.ECHO_REPLY:
                        time_sent = struct.unpack(ICMP_TIME_FORMAT, icmp_payload_raw[0:struct.calcsize(ICMP_TIME_FORMAT)])[0]
                        return time_recv - time_sent
                logger.debug('Uncatched ICMP Packet: %s', icmp_header)
    except asyncio.TimeoutError:
        loop.remove_reader(sock)
        loop.remove_writer(sock)
        sock.close()


async def ping(
    dest_addr: str,
    timeout: int = 4,
    unit: str = "s",
    src_addr: str = None,
    ttl: int = None,
    seq: int = 0,
    size: int = 56,
    interface: str = None,
) -> float:
    """
    Send one ping to destination address with the given timeout.
    Args:
        dest_addr: The destination address, can be an IP address or a domain name. Ex. "192.168.1.1"/"example.com"
        timeout: Time to wait for a response, in seconds. Default is 4s, same as Windows CMD. (default 4)
        unit: The unit of returned value. "s" for seconds, "ms" for milliseconds. (default "s")
        src_addr: WINDOWS ONLY. The IP address to ping from. This is for multiple network interfaces.
            Ex. "192.168.1.20". (default None)
        interface: LINUX ONLY. The gateway network interface to ping from. Ex. "wlan0". (default None)
        ttl: The Time-To-Live of the outgoing packet. Default is None, which means using OS default ttl --
            64 onLinux and macOS, and 128 on Windows. (default None)
        seq: ICMP packet sequence, usually increases from 0 in the same process. (default 0)
        size: The ICMP packet payload size in bytes. If the input of this is less than the bytes of a double format
            (usually 8), the size of ICMP packet payload is 8 bytes to hold a time. The max should be the
            router_MTU(Usually 1480) - IP_Header(20) - ICMP_Header(8). Default is 56, same as in macOS. (default 56)
    Returns:
        The delay in seconds/milliseconds or None on timeout.
    Raises:
        PingError: Any PingError will raise again if `ping3.EXCEPTIONS` is True.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.setblocking(False)
        if ttl:
            try:  # IPPROTO_IP is for Windows and BSD Linux.
                if sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL):
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            except OSError as err:
                logger.debug('Set Socket Option `IP_TTL` in `IPPROTO_IP` Failed: %s', err)
            try:
                if sock.getsockopt(socket.SOL_IP, socket.IP_TTL):
                    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            except OSError as err:
                logger.debug('Set Socket Option `IP_TTL` in `SOL_IP` Failed: %s', err)
        if interface:
            sock.setsockopt(
                socket.SOL_SOCKET, SOCKET_SO_BINDTODEVICE, interface.encode()
            )  # packets will be sent from specified interface.
            logger.debug('Socket Interface Binded: %s', interface)
        if src_addr:
            sock.bind((src_addr, 0))  # only packets send to src_addr are received.
            logger.debug('Socket Source Address Binded: %s', src_addr)

        icmp_id = zlib.crc32(uuid.uuid4().hex.encode()) & 0xFFFF  # to avoid icmp_id collision.
        try:
            await send_one_ping(sock=sock, dest_addr=dest_addr, icmp_id=icmp_id, seq=seq, size=size)
            delay = await receive_one_ping(sock=sock, icmp_id=icmp_id, seq=seq, timeout=timeout)  # in seconds
        except HostUnknown as err:  # Unsolved
            logger.exception('Uncaught exception: %s', err)
            _raise(err)
            return False
        except PingError as err:
            logger.warning('Ping error: %s', err)
            _raise(err)
            return None
        if delay is None:
            return None
        if unit == 'ms':
            delay *= 1000  # in milliseconds
    return delay
