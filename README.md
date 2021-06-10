# PortScanDetector

This application uses NetFlow data analysis to discover port scanning activities.
The results, due to some behaviors in networking, are just a suggestion, not a certainty.

## Requirements

**nProbes**

PortScanDetector needs to receive NetFlow data in JSON format.<br/>
To do so:
* Download [nProbe](https://packages.ntop.org) from ntop.
* Run it according to your configuration but make sure to specifying the following option in order to make it work with the application:
	 ```bash
	 #Send TCP packets containing flows in JSON format
	 --tcp (application address):(port)
	 ```
	
	 ```bash
  	 #Use a NetFlow template containing at least the following field
	 -T "%IPV4_SRC_ADDR %IPV4_DST_ADDR %PROTOCOL %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %IN_PKTS"
	 ```
  	e.g.: 
  	
  	```bash
	./nprobes -i eth0 -b 2 -V 10 --tcp 127.0.0.1:2055 -T "%IPV4_SRC_ADDR %IPV4_DST_ADDR %PROTOCOL %L4_SRC_PORT %L4_DST_PORT %TCP_FLAGS %IN_PKTS"
   	```
	
**PortScanDetector**

* Clone the repo:
	```bash
	git clone port_scan_detector && cd port_scan_detector
	```
 * [Optional] Enter a virtual environment.
* Check if the required packages are installed:
	```bash
	pip install -r requirements.txt
	```
 
##Usage
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
