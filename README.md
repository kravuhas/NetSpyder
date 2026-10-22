# 🕷️ NetSpyder

### Network Monitoring & Security Analysis Platform

**Version:** 0.1.0 — Early Development

NetSpyder is an experimental network monitoring and security analysis platform developed using Rust, Python, PostgreSQL, and Docker.

The project focuses on packet capture, protocol analysis, network visibility, and security monitoring.

## Overview

NetSpyder uses a Python-based packet sniffer to collect network traffic metadata and a Rust backend to process, store, and expose the information through a REST API.

A web dashboard displays network statistics, observed IP addresses, and captured packet information.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Rust + Axum |
| Packet Capture | Python |
| Database | PostgreSQL |
| Frontend | HTML, CSS, JavaScript |
| Infrastructure | Docker Compose |
| Network Laboratory (planned) | Containerlab |

## Current Features

- IPv4 packet capture and analysis
- TCP, UDP, and ICMP protocol identification
- Source and destination IP tracking
- TCP/UDP port identification
- IP address filtering
- REST API for network data
- PostgreSQL storage
- Web-based monitoring dashboard

## How It Works

1. The Python sniffer captures network packets from an authorized network interface.
2. The script extracts packet metadata, including protocol, IP addresses, ports, and packet length.
3. Captured metadata is submitted to the Rust REST API.
4. The backend stores the information in PostgreSQL.
5. The dashboard requests information from the API and presents network statistics and traffic records.

## Getting Started

### Requirements

- Linux
- Docker and Docker Compose
- Python 3
- Python dependencies required by `sniffer_analyse.py`

### Start the Backend

From the project directory:

```bash
docker compose up -d --build
```

Check the API:

```bash
curl http://127.0.0.1:3000/api
```

### Start the Python Sniffer

Create and configure a Python virtual environment using the project's dependencies.

For a trusted local development environment where the virtual environment is already configured:

```bash
sudo ./venv/bin/python sniffer_analyse.py
```

Raw packet capture requires appropriate Linux permissions. Run the sniffer only on networks you own or are explicitly authorized to monitor.

### Open the Dashboard

Visit:

```text
http://127.0.0.1:3000
```

### Stop the Services

Stop packet capture with `Ctrl+C`.

Stop the backend services:

```bash
docker compose down
```

## Network Laboratory — Planned

A Containerlab-based environment is planned to support reproducible network monitoring experiments.

The proposed topology includes:

- A client node to generate authorized test traffic
- A router node to connect test segments
- A server node to receive test traffic
- A monitored network interface or traffic mirror
- NetSpyder as the monitoring and analysis platform

The laboratory topology is not yet part of the tested v0.1.0 release.

## Roadmap

- [x] Python packet sniffer
- [x] Rust REST API
- [x] PostgreSQL integration
- [x] Basic network dashboard
- [ ] Containerlab network topology
- [ ] Real-time event streaming
- [ ] Security detection rules
- [ ] Threat intelligence integration
- [ ] Authentication and access control
- [ ] Digital forensic analysis
- [ ] Desktop application

## Security Notice

NetSpyder is intended for educational purposes, defensive security research, and authorized network monitoring.

Do not use it to capture or analyze traffic from networks without permission.

## Author

Developed by Felipe Roberto.

**Project status:** Active development.
<img width="1600" height="895" alt="image" src="https://github.com/user-attachments/assets/d573ef9f-d1c0-4542-86f9-f6836128f976" />
