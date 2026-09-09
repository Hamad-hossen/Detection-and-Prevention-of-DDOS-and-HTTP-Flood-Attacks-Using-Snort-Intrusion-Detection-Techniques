# Detection-and-Prevention-of-DDOS-and-HTTP-Flood-Attacks-Using-Snort-Intrusion-Detection-Techniques
Source code and configuration files used in the network protection system presented in the published research paper, including Snort 3 rules, automation scripts, systemd service files, and network bridge configuration.
<img width="1920" height="1046" alt="untitled - GNS3 09_09_2026 11_01_28 م" src="https://github.com/user-attachments/assets/4fd3d8a7-d878-43d9-8058-a5b248bda885" />

🔗 Research Link (DOI):
[https://doi.org/10.62341/istj-vol39-1-jr27]

## Project Overview

This repository contains the source code and configuration files used in the network protection system presented in the published research paper:

The project presents a network protection system designed to detect and automatically respond to network attacks using **Snort 3** and **iptables**. The system is implemented on **Ubuntu Server** and deployed transparently within the network using a **Linux Layer 2 bridge**. It also includes a custom **web-based management and monitoring dashboard** for real-time security monitoring and log visualization.

The main objective of the project is to combine **intrusion detection, automated response, and security monitoring**. When malicious source IP addresses are detected, they can be automatically blocked for a predefined period and monitored through the web-based dashboard without requiring continuous manual intervention or direct command-line access.

---

## Project Architecture

The experimental laboratory was built using **VMware Workstation** and **GNS3**, providing a virtualized and controlled environment for implementing, testing, and evaluating the network protection system.

**VMware Workstation** was used as the virtualization platform for the required virtual machines, while **GNS3** was used to design and simulate the network topology and the communication between the different network components.

The Ubuntu Server protection system is positioned transparently between the network router and the internal network. It uses a **Linux Layer 2 bridge** to forward network traffic transparently, while Snort 3 monitors the traffic for suspicious activity.

### Experimental Topology

The experimental topology includes:

- Attacker machine
- Windows 10 client
- Internet / Cloud segment
- Router (R1)
- Ubuntu Server security system
- Network switch
- Web server representing the protected service

The topology allows attack and legitimate traffic to pass through the Ubuntu Server while the protection system monitors the traffic, detects malicious activity, automatically responds to detected threats, and provides security statistics through the web dashboard.

---

## Experimental Environment

### Virtualization and Network Simulation

The experimental laboratory was built using **VMware Workstation** and **GNS3**.

VMware Workstation provides the virtualization environment for the virtual machines used in the laboratory, while GNS3 is used to create and simulate the network topology and connect the different network components.

This combination provides a controlled virtualized environment for implementing and testing the network protection system without requiring physical network infrastructure.

### Security Server

The protection system runs on:

- Ubuntu Server
- Snort 3
- iptables
- Linux Bridge
- Bash scripts
- Python Web Dashboard
- systemd services

The Linux bridge operates at **Layer 2** and does not require an IP address on the bridge itself. This allows the security system to be placed transparently within the network path without requiring changes to the existing network addressing structure.

---

## Protection System Components

### Snort 3

Snort 3 is used as the **intrusion detection component** of the system.

It monitors network traffic and generates security alerts when traffic matches the configured detection rules. The alerts provide information used by the automated response mechanism, including the source IP address and attack classification.

The project includes Snort 3 rules and configuration files used to detect attack traffic such as:

- DDoS / DoS traffic
- HTTP Flood attacks
- Port scanning
- Other suspicious network activity

### iptables

iptables is used as the **automated response mechanism**.

When Snort detects malicious traffic, the automation scripts process the generated alert, extract the source IP address, and dynamically apply a temporary blocking rule using iptables.

The blocking mechanism allows detected malicious source addresses to be blocked automatically for a predefined period.

### Linux Transparent Bridge

The Ubuntu Server uses a **Linux Layer 2 bridge** to operate transparently within the network.

The bridge connects the network interfaces between the external and internal sides of the network and forwards traffic at Layer 2 without assigning an IP address to the bridge itself.

This design allows the protection system to be placed within the network path without operating as a conventional Layer 3 router or requiring changes to the existing IP addressing structure.

### Bash Automation

Bash scripts automate the core response process.

The automation scripts continuously monitor Snort alert logs, extract attacker source IP addresses, apply dynamic iptables blocking rules for a predefined period, and automatically clean up expired blocking rules.

### Web-Based Security Monitoring Dashboard

A custom **Python-based web dashboard** provides a centralized interface for security monitoring, log visualization, and analysis without requiring direct interaction with the Ubuntu Server command-line environment.

Key dashboard features include:

#### System Overview and Analytics

Displays security statistics such as:

- Total alert counts
- Top targeted / attacked IP addresses
- Percentage breakdown of detected malicious traffic

#### Attacker Ranking

Provides a **Top 5 Most Dangerous External Attackers** table containing information such as:

- Attacker IP address
- Alert count
- Threat percentage

#### Real-Time Logs and Search

Provides a searchable interface for inspecting:

- Snort alerts
- Timestamps
- Protocol types
- Active blocking status
- Other available security information

### systemd Services

The Bash automation component and the Python web dashboard run as **systemd background services**.

This allows the required components to start automatically at system boot and enables service restart and recovery according to their systemd configuration.

---

## Detection and Response Process

The integrated protection and monitoring workflow can be represented as follows:

```text
                    Network Traffic
                           |
                           v
              Linux Transparent Bridge
                    (Layer 2)
                           |
                           v
                 Network Forwarding
                           |
              +------------+------------+
              |                         |
              v                         v
        Snort 3 Monitoring       Legitimate Traffic
              |
              v
        Detection Alert
              |
              v
      Bash Automation Script
              |
              v
     Source IP Extraction
              |
              v
           iptables
              |
              v
    Temporary IP Blocking
              |
              v
       Security Logs
              |
              v
     Python Web Dashboard
              |
              v
     Monitoring & Analytics
