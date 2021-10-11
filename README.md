# Simple-NIDS
This is an implementation of a simple Network Intrusion Detection System

# Running
Needs to be run on a linux distro. Windows does not allow for the socket module from python to grab packets at a low 
enough level.
Windows restricts to higher level packet captures and this system needs the packet headers to operate, which are found 
at the base level.

# Known errors
Bit shifting the packet data does not correctly grab the ipv4 sender and recipient ips
Formatting multiline data from the data portion of the packets does not work
Packet final data section is not parsed correctly and needs to be cleaned and formatted
