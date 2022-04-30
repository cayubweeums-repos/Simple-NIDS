# Simple-NIDS (WIP)
This is an implementation of a simple Network Intrusion Detection System

## Prerequisites 
- `python 3.8`
- run `pip3 install requirements.txt`

## Assumptions
This code-base makes a few assumptions currently. It has not been abstracted or implemented in a generic enough sense to
accommodate a wide array of data. Currently, I would feel uncomfortable with the results of any data set besides the one
I used for testing. Below are the assumptions the code-base makes:
- You are using the 'DEF CON 23 ICS Village.pcap' file from [netresec.com](https://media.defcon.org/DEF CON 23/DEF CON 23 villages/DEF CON 23 ics village/DEF CON 23 ICS Village packet captures.rar) 
- The attacks being sent to your network are relatively basic
  - i.e. Nmap portscans and DoS sprays
- There are no files in the data/training_sets folder. This means the program needs to parse the specific pcap used and create those .csv files for you.

## Installation 
Simply grab the zip, extract it, open in your favorite IDE and follow the prompts
- Use `pip3 install -r requirements.txt` when in the project to get the dependencies

## Running
Needs to be run on a linux distro. Windows does not allow for the socket module from python to grab packets at a low 
enough level.
Windows restricts to higher level packet captures and this system needs the packet headers to operate, which are found 
at the base level.
Currently, the NIDS can only sniff on an ethernet interface. Future updates may result in wireless coverage. 

- Run the following command `sudo python3 main.py` or if you are already a root user `python3 main.py` to run the project

## Future work
- Make the parsing of datasets, packets more generic and not proprietary 
- Make documentation inside the code all encompassing and this file more useful for anyone wanting to do similar work
- Expand signature-based rule checks for inbound and outbound traffic
- Allow the user to specify various aspects of the IDS. Interface to be used, rule set to be used (aggressive or relaxed) 
- Create a way to label traffic as "Home_Net" and "External_Net" to further increase effective rule comparing
- Implement a way to label an IP as suspicious and watch for any further traffic including that IP to compare against specific rules for tracking multiple packets over a set amount of time
- Expand the Anomaly-based IDS to track the connections/flows instead of looking at individual packets

## Known errors
Can only run on eth interface. Cannot be changed unless altering multiple lines of code.
Specifically, eth0 is the interface the IDS recognizes and sniffs on.
