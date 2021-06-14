# PortScanDetector

This application uses NetFlow data analysis to discover port scanning activities.<br/>
The results are just a suggestion, not a certainty.

## Requirements

**nProbes**

PortScanDetector needs to receive NetFlow data in JSON format.<br/>
To do so I used [nProbe](https://www.ntop.org/products/netflow/nprobe/) from ntop:
* [Download nProbe](https://packages.ntop.org).
* Run it according to your configuration but make sure to specifying the following options in order to make it work with *PortScanDetector*:
	 ```bash
	 #Send TCP packets containing flows in JSON format
	 --tcp (application_address):(port)
	 ```
	
	 ```bash
  	 #Use a NetFlow template containing at least the following fields
	 -T "%IPV4_SRC_ADDR %IPV4_DST_ADDR %PROTOCOL %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %IN_PKTS"
	 ```
  	e.g.: 
  	
  	```bash
	./nprobes -i eth0 -b 2 -V 10 --tcp 127.0.0.1:2055 -T "%IPV4_SRC_ADDR %IPV4_DST_ADDR %PROTOCOL %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %IN_PKTS"
   	```
	
***PortScanDetector***

* Clone the repo:
	```bash
	git clone https://github.com/TommasoLencioni/PortScanDetector.git port_scan_detector && cd port_scan_detector
	```
* [Optional] Enter a virtual environment.
* Check if the required packages are installed:
	```bash
	pip3 install -r requirements.txt
	```
 
## Usage

Please note that the address on which the application creates the TCP socket must be reachable by the probe.
```bash
python3 port_scan_detector.py [-h] [-a address] [-p port] [-d seconds] [-e seconds] [--version] 
```

**Optional Arguments:**

| Flag | Description |
| --- | :--- |
| -h, --help | Show help message and exit. |
| -a address,<br/> --address address | Address on which to open the TCP socket (default 127.0.0.1). |
| -p port,<br/> --port port | Port on which to receive JSON-formatted flows as TCP stream (deafult 2055). |
| -d seconds,<br/> --des seconds | Seconds between two double exponential smoothing prevision on UDP host/port couples (default 10). |
| -e seconds,<br/> --erase seconds | Seconds bewteen two resets of UDP host/port couples (default 180). |
| --version | Show program's version number and exit.|

## How it works

*PortScanDetector* analyzes the flows and decide wether the traffic could be due to port scanning or not.<br/>
*PortScanDetector* uses 2 different metric for either TCP and UDP:

### TCP
The flows are analyzed looking at the TCP_FLAGS field and clasified based on the following criterias (nmap flags inside parentheses):
* 0 -> NULL Scan (-sN, No bits set)
* 1 -> FIN Scan (-sF, FIN bit set)
* 2 -> SYN Scan (-sS, SYN bit set)
* 22 -> RST Scan (-sT, RST bit set)
* 41 -> Xmas Scan (-sX, FIN, PSH, and URG bits set)
	
If a flow matches one of those cases the user is notified through CLI.

### UDP
The flows are analyzed looking at the number of couples host/port contacted by each source host.<br/>
If it exceeds the double exponential smoothing prevision (made with the time serie of the last 10 averages of couples among all source hosts) * 1.75 the user is notified through CLI.

