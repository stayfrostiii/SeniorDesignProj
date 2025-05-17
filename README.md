# Hardware Firewall
## Authors: J. Wulf, J. Tung, D. Zheng
### Link to project: https://github.com/stayfrostiii/SeniorDesignProj
### Link to demo (4 min version): https://youtu.be/nHRneyYoXfI
## Requirements
- Raspberry Pi with Ubuntu Server OS installed
- USB to ethernet adapter for extra ethernet connection
- 2 ethernet cables
- Power source for the Pi
## Structure of Project
There are 3 main parts to the project: UI (Frontend), UI (Backend), and Packet Capture. The UI (Frontend) is implemented using React.js, the UI (Backend) is implemented using in Python using Flask and WebSockets, and the Packet Capture application is implemented in C with various C libraries. All of these parts must be running at the same time for the project to work.
## How To Build
### UI (Frontend)
CD into the /ui/client folder of the project. Once in the directory, run 
```npm install``` (ensure npm is already installed on the system). Next, to the run the frontend, run the command ```npm run dev``` in the same directory

### UI (Backend)
CD into the /ui/server folder of the project. Once in the directory, run ```pip install -r requirements.txt``` (ensure that pip and python is installed on the system). Next, to run the backend, run the command ```path/to/python main.py c2p.py```. Both of the files need to be running in order for the backend to fully work

### Packet Capture
CD into the firewall folder. Create two folders in this directory: ```build``` and ```logs```. Install all of the required libraries using this command ```sudo apt install build-essential libpcap-dev libmsgpack-dev```. Next, run the command ```sudo gcc src/pcap.c -o build/pcap -lpcap -lmsgpackc -pthread``` to create the executable file which will be stored in the /firewall/build directory. Next, to run the packet capturing, run the command ```sudo build/pcap```.

### Raspberry Pi
You will have to configure the Pi to operate in bridge mode to bridge the ethernet interfaces. In the yaml file located in /etc/netplan on your Raspberry pi, insert the information below and save. This will create the necessary bridge interface
```
network:
  version: 2
  renderer: networkd

  ethernets:
    eth0: {}
    enxc8a362c471b3: {}

  bridges:
    br0:
      interfaces:
        - eth0
        - enxc8a362c471b3
      addresses:
        - 10.0.0.100/24
      routes:
        - to: 0.0.0.0/0
          via: 10.0.0.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```

Additionally, you will have to initially setup nftables to be able to change rules. In any directory run the commands on boot up:
```
sudo nft add table bridge filter
sudo nft add chain bridge filter input { type filter hook input priority 0 \; policy accept \; }
sudo nft add chain bridge filter forward { type filter hook forward priority 0 \; policy accept \; }
sudo nft add chain bridge filter output { type filter hook output priority 0 \; policy accept \; }
```
As mentioned in the Notes section, we opted to let the user determine when the application will run (whether on boot up or started by the user), thus these commands will have to be ran after each boot unless the rules are saved and restored on reboot.

### Notes
- Both the backend and packet capture need to run at the same time for the application to work.
- For the development process, the Pi was configured to run the applications on boot up. However, we deemed that a user preference and did not include how to do that in the build 
- The current iteration of the project was developed in an XFinity network environment, so it will only work on XFinity networks unless configured otherwise