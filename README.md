# ZyraSIEM - Quick Start Guide

## Prerequisites
1. Python 3.8 or higher installed
2. Windows OS (required for agent)
3. Administrator privileges

## Installation Steps

### 1. Install Dependencies
Open Command Prompt or PowerShell in the ZyraSIEM directory and run:
```bash
pip install -r requirements.txt
```

### 2. Setup Npcap (Required for Network Monitoring)
Run as Administrator:
```bash
python setup.py
```
This will download and install Npcap for packet capture.

## Running the System

You need to run 3 components in separate terminals:

### Terminal 1: Start the API Server
```bash
python server.py
```
- Runs on: http://localhost:5000
- Creates: server_local_storage.db
- Handles all data storage and API requests

### Terminal 2: Start the Agent (Run as Administrator)
```bash
python agent.py
```
- Collects system metrics, logs, network traffic
- Monitors for security events and malware
- Stores data locally and syncs to server

### Terminal 3: Start the Web UI
```bash
python app.py
```
- Runs on: http://localhost:5001
- Access dashboard at: http://localhost:5001

## Accessing the Dashboard

Open your browser and go to:
- **Main Dashboard**: http://localhost:5001 (NOT 0.0.0.0:5001)
- **Alerts**: http://localhost:5001/alerts
- **Logs**: http://localhost:5001/logs
- **Agents**: http://localhost:5001/agents
- **Malware**: http://localhost:5001/malware

## Troubleshooting

### Agent won't start
- Make sure you're running as Administrator
- Check agent.log for errors

### No data showing
- Ensure server.py is running first
- Check that agent.py is running
- Wait 5-10 seconds for first data collection

### Network monitoring not working
- Install Npcap using setup.py
- Restart agent.py after Npcap installation

## Database Files
- `server_local_storage.db` - Server's central database
- `local_storage.db` - Agent's local cache (syncs to server)

## Logs
- `server.log` - Server activity
- `agent.log` - Agent activity
- `webui.log` - Web UI activity
- `setup.log` - Setup process

## Stopping the System
Press `Ctrl+C` in each terminal to stop the components gracefully.
