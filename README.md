# Detection-and-Prevention-of-DDOS-and-HTTP-Flood-Attacks-Using-Snort-Intrusion-Detection-Techniques
Source code and configuration files used in the network protection system presented in the published research paper, including Snort 3 rules, automation scripts, systemd service files, and network bridge configuration.
<img width="1920" height="1046" alt="untitled - GNS3 09_09_2026 11_01_28 م" src="https://github.com/user-attachments/assets/4fd3d8a7-d878-43d9-8058-a5b248bda885" />
# Detection and Prevention of DDoS and HTTP Flood Attacks Using Snort

## Project Overview

This repository contains the source code and configuration files used in the network protection system presented in the published research paper:

**Detection and Prevention of DDOS and HTTP Flood Attacks Using Snort Intrusion Detection Techniques**

The project presents a network protection system designed to detect and automatically respond to network attacks using Snort 3 and iptables. The system is implemented on Ubuntu Server and deployed transparently within the network using a Linux Layer 2 bridge.

The main objective of the project is to combine intrusion detection with automated response, allowing detected malicious source IP addresses to be temporarily blocked without requiring continuous manual intervention.

---

## Project Architecture

The experimental laboratory was built using **VMware Workstation** and **GNS3**, providing a virtualized and controlled environment for implementing, testing, and evaluating the proposed network protection system.

GNS3 was used to design and simulate the network topology and the communication between the different network components, while VMware Workstation provided the virtualization environment for the required virtual machines.

The Ubuntu Server protection system is positioned transparently between the network router and the internal network. The server uses a Linux bridge to forward traffic at Layer 2 while Snort 3 monitors the traffic for suspicious activity.

The experimental topology includes:

- Attacker machine
- Windows 10 client
- Internet/cloud segment
- Router (R1)
- Ubuntu Server security system
- Network switch
- Web server representing the protected service/network

The topology allows attack traffic to pass through the Ubuntu Server while the protection system monitors and responds to malicious traffic.

---

## Experimental Environment

### Virtualization and Network Simulation

The experimental laboratory was built using **VMware Workstation** and **GNS3**.

VMware Workstation was used as the virtualization platform for the virtual machines required for the experimental environment, while GNS3 was used to create and simulate the network topology and connect the different network components.

This combination provides a controlled virtualized environment for implementing and testing the network protection system without requiring a physical network infrastructure.

### Network Simulation

The network topology was created using **GNS3**.

The simulated environment contains different systems representing external attackers, legitimate clients, network infrastructure, and the protected server.

The Ubuntu Server is deployed as a transparent security device between the router and the internal network.

### Security Server

The protection system runs on:

- Ubuntu Server
- Snort 3
- iptables
- Linux Bridge
- Bash scripts
- systemd services

The Linux bridge operates at Layer 2 and does not require an IP address on the bridge itself. This allows the security system to be inserted into the network path without changing the existing network addressing structure.

---

## Protection System Components

### Snort 3

Snort 3 is used as the intrusion detection component of the system.

It monitors network traffic and generates alerts when traffic matches the configured detection rules.

The project includes Snort 3 rules and configuration files used to detect attack traffic such as:

- DDoS / DoS traffic
- HTTP Flood attacks
- Port scanning
- Other suspicious network activity

### iptables

iptables is used as the automated response mechanism.

When Snort detects malicious traffic, the automation scripts extract the source IP address from the alert and dynamically apply a temporary blocking rule.

The blocking mechanism allows malicious source addresses to be blocked automatically for a defined period of time.

### Linux Transparent Bridge

The Ubuntu Server uses a Linux Layer 2 bridge to operate transparently within the network.

The bridge connects the network interfaces between the external and internal sides of the network and forwards traffic without acting as a conventional Layer 3 router.

This design allows the protection system to be introduced into an existing network topology with minimal changes to IP addressing.

### Bash Automation

Bash scripts are used to automate the response process.

The scripts monitor Snort alerts, identify source IP addresses associated with detected attacks, apply iptables blocking rules, and manage temporary blocking and rule cleanup.

### systemd

systemd service files are used to run the automation components as background services.

This allows the required scripts to start automatically and continue running as system services.

---

## Attack and Testing Environment

The system was evaluated in a controlled virtualized environment built using **VMware Workstation and GNS3**, using attack traffic and legitimate traffic.

The testing environment was used to evaluate the ability of the system to:

1. Detect malicious traffic using Snort 3.
2. Generate security alerts.
3. Identify the source IP associated with detected traffic.
4. Automatically apply an iptables blocking rule.
5. Maintain legitimate network traffic.
6. Remove temporary blocking rules after the configured blocking period.

The tested attack scenarios included:

- DDoS / DoS traffic
- HTTP Flood
- Port Scanning
- IP spoofing

---

## Detection and Response Process

The general operation of the system is:

```text
Network Traffic
      |
      v
Linux Transparent Bridge
      |
      v
Snort 3 Monitoring
      |
      v
Detection Alert
      |
      v
Automation Script
      |
      v
Source IP Extraction
      |
      v
iptables
      |
      v
Temporary IP Blocking
