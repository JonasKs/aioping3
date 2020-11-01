# aioping3
`aioping3` is a pure python3 version of ICMP ping implementation using socket and `run_in_executor` for asyncio support.
(Note that ICMP messages can only be sent from processes running as root.)

This is a `asyncio` rewrite and clean up from `ping3` to become a pure SDK, 
originally written by [kyan001](https://github.com/kyan001/ping3)

> The Python2 version originally from [here](http://github.com/samuel/python-ping).  
> The Python3 version originally from [here](https://github.com/kyan001/ping3).  
> This version is "maintained"/developed at [this github repo](https://github.com/JonasKs/aioping3).



## Get Started

```shell
pip install <removed - not sure if this will become a package>
```

```python
>>> from ping3 import ping, verbose_ping
>>> ping('example.com')  # Returns delay in seconds.
0.215697261510079666


## Functions

```python
>>> ping('example.com')  # Returns delay in seconds.
0.215697261510079666

>>> ping('not.exist.com')  # if host unknown (cannot resolve), returns False
False

>>> ping("224.0.0.0")  # If timed out (no reply), returns None
None

>>> ping('example.com', timeout=10)  # Set timeout to 10 seconds. Default timeout=4 for 4 seconds.
0.215697261510079666

>>> ping('example.com', unit='ms')  # Returns delay in milliseconds. Default unit='s' for seconds.
215.9627876281738

>>> ping('example.com', src_addr='192.168.1.15')  # WINDOWS ONLY. Set source ip address for multiple interfaces. Default src_addr=None for no binding.
0.215697261510079666

>>> ping('example.com', interface='eth0')  # LINUX ONLY. Set source interface for multiple network interfaces. Default interface=None for no binding.
0.215697261510079666

>>> ping('example.com', ttl=5)  # Set packet Time-To-Live to 5. The packet is discarded if it does not reach the target host after 5 jumps. Default ttl=64.
None

>>> ping('example.com', size=56)  # Set ICMP packet payload to 56 bytes. The total ICMP packet size is 8 (header) + 56 (payload) = 64 bytes. Default size=56.
0.215697261510079666

>>> verbose_ping('example.com')  # Ping 4 times in a row.
ping 'example.com' ... 215ms
ping 'example.com' ... 216ms
ping 'example.com' ... 219ms
ping 'example.com' ... 217ms

>>> verbose_ping('example.com', timeout=10)  # Set timeout to 10 seconds. Default timeout=4 for 4 seconds.
ping 'example.com' ... 215ms
ping 'example.com' ... 216ms
ping 'example.com' ... 219ms
ping 'example.com' ... 217ms

>>> verbose_ping('example.com', count=6)  # Ping 6 times. Default count=4
ping 'example.com' ... 215ms
ping 'example.com' ... 216ms
ping 'example.com' ... 219ms
ping 'example.com' ... 217ms
ping 'example.com' ... 215ms
ping 'example.com' ... 216ms

>>> verbose_ping('example.com', src_addr='192.168.1.15')  # WINDOWS ONLY. Ping from source IP address. Default src_addr=None
ping 'example.com' from '192.168.1.15' ... 215ms
ping 'example.com' from '192.168.1.15' ... 216ms
ping 'example.com' from '192.168.1.15' ... 219ms
ping 'example.com' from '192.168.1.15' ... 217ms

>>> verbose_ping('example.com', interface='wifi0')  # LINUX ONLY. Ping from network interface 'wifi0'. Default interface=None
ping 'example.com' from '192.168.1.15' ... 215ms
ping 'example.com' from '192.168.1.15' ... 216ms
ping 'example.com' from '192.168.1.15' ... 219ms
ping 'example.com' from '192.168.1.15' ... 217ms

>>> verbose_ping('example.com', unit='s')  # Displays delay in seconds. Default unit="ms" for milliseconds.
ping 'example.com' ... 1s
ping 'example.com' ... 2s
ping 'example.com' ... 1s
ping 'example.com' ... 1s

>>> verbose_ping('example.com', ttl=5)  # Set TTL to 5. Default is 64.
ping 'example.com' ... Timeout
ping 'example.com' ... Timeout
ping 'example.com' ... Timeout
ping 'example.com' ... Timeout

>>> verbose_ping('example.com', interval=5)  # Wait 5 seconds between each packet. Default is 0.
ping 'example.com' ... 215ms  # wait 5 secs
ping 'example.com' ... 216ms  # wait 5 secs
ping 'example.com' ... 219ms  # wait 5 secs
ping 'example.com' ... 217ms

>>> verbose_ping('example.com', size=56)  # Set ICMP payload to 56 bytes. Default size=56.
ping 'example.com' ... 215ms
ping 'example.com' ... 216ms
ping 'example.com' ... 219ms
ping 'example.com' ... 217ms
```

### EXCEPTIONS mode

Raise exceptions when there are errors instead of return None

```python
>>> import ping3
>>> ping3.EXCEPTIONS = True  # Default is False.

>>> ping3.ping("example.com", timeout=0.0001)  # All Exceptions are subclasses of PingError
[... Traceback ...]
error.Timeout: Request timeout for ICMP packet. (Timeout = 0.0001s)

>>> ping3.ping("not.exist.com")
[... Traceback ...]
error.HostUnknown: Cannot resolve: Unknown host. (Host = not.exist.com)

>>> ping3.ping("example.com", ttl=1)
[... Traceback ...]
error.TimeToLiveExpired: Time exceeded: Time To Live expired.
```
