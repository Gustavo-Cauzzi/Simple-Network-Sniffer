# Simple Packet Sniffer

This is a simple packet sniffer written in python. Intercepts packets in the network and prints both on stdout and in a file. Here's an example of the output:

```
Ethernet frame:
        Destination: 00:00:00:00:00:00, Source: 00:00:00:00:00:00, Ethernet Protocol: 8
Detected ethernet protocol IPv4
        IPv4 package:
                Version: 1
                Header length: 20
                TTL: 64
                Source: 127.0.0.1
                Target: 127.0.0.1
                Proto ID: 6
                Detected IPv4 protocol: TCP
                        Source port: 9229
                        Target port: 36490
                        Sequence: 0
                        Acknowledgment: 69078021
                        Flags: Urg: 0 | Ack: 1 | Psh: 0
                               Rst: 1 | Syn: 0 | Fin: 0
                        Data: 40 00 40 06 3C CE 7F 00 00 01 7F 00 00 01 24 0D 8E 8A 00 00 00 00 04 1E 0C 05 50 14 00 00 EF 13 00 00
```

This sniffer only detects and log extra informations for TCP and UDP packets of IPv4 trafic.

## Run:
To run the code, you need to run the `main.py` file with python as sudo user. 

```shell
sudo python3 main.py
```

> This code was written and tested on a Linux machine. It wasn`t tested on windows.
