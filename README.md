# Python-tcpdump-Utility
Linux tcpdump Utility Implementation using Python 


# Basic Info 
This is the basic implementation of the Linux tcpdump utility using Python. I capture the packets using python raw sockets and print them as formatted way.
Also user can define the interface name that he needs to sniff the packets.

# Usage

I developed this tool using Ubuntu 20.04 VM with Python 3.8.2 and also recommended to use that version. Fire up the terminal, navigate to tcpdump utility directory 
and execute the following command:</br></br>
``` python3 tcpdump.py ens33 ``` </br>
</br>
ens33 : Interface name that you need to sniff traffic from</br>

![Python TCPDUMP Image](https://i.ibb.co/Vw8DwFF/Screenshot-2021-04-11-at-23-22-54.png)</br>

### This Program able to Capture following Protocols
* ICMP
* TCP
* UDP
* ARP
