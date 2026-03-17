import asyncio
import logging
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import uvicorn
from contextlib import asynccontextmanager
import sqlite3
import json
from threading import Lock
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", filename="server.log")
logger = logging.getLogger(__name__)

# SQLite connection
DB_FILE = "server_local_storage.db"
db_lock = Lock()

def get_db_connection():
    """Get a thread-safe database connection"""
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize SQLite database with required tables and indexes"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                data TEXT NOT NULL
            )
        ''')
        
        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                type TEXT,
                severity TEXT,
                details TEXT,
                data TEXT NOT NULL
            )
        ''')
        
        # Create device_info table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT UNIQUE NOT NULL,
                hostname TEXT,
                os TEXT,
                first_seen TEXT,
                last_updated TEXT NOT NULL,
                data TEXT NOT NULL
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_agent_timestamp ON logs(agent_id, timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_agent_timestamp ON alerts(agent_id, timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_device_agent ON device_info(agent_id)')
        
        conn.commit()
        conn.close()
        logger.info("SQLite database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing SQLite database: {e}")
        raise

# Lifespan handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    logger.info("Server started with SQLite database")
    yield
    logger.info("Server shutting down")

# FastAPI app
app = FastAPI(title="Zyra SIEM Server", version="1.0.0", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper functions
async def fetch_data_from_table(table: str, where_clause: str = "", params: tuple = (), 
                                 sort_by: str = "timestamp", sort_order: str = "DESC", 
                                 limit: int = 100, offset: int = 0) -> Dict:
    """Fetch data from SQLite table with filtering, sorting, and pagination"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Count total records
        count_query = f"SELECT COUNT(*) FROM {table}"
        if where_clause:
            count_query += f" WHERE {where_clause}"
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Fetch paginated data
        data_query = f"SELECT * FROM {table}"
        if where_clause:
            data_query += f" WHERE {where_clause}"
        data_query += f" ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?"
        
        cursor.execute(data_query, params + (limit, offset))
        rows = cursor.fetchall()
        
        # Convert rows to dictionaries
        data = []
        for row in rows:
            row_dict = dict(row)
            if 'data' in row_dict:
                try:
                    row_dict.update(json.loads(row_dict['data']))
                except:
                    pass
            data.append(row_dict)
        
        conn.close()
        return {"total": total, "data": data, "limit": limit, "offset": offset}
    except Exception as e:
        logger.error(f"Error fetching data from {table}: {e}")
        return {"total": 0, "data": [], "limit": limit, "offset": offset}

def build_where_clause(search: Optional[str] = None, filters: Dict = None) -> tuple:
    """Build WHERE clause and parameters for SQL query"""
    conditions = []
    params = []
    
    if search:
        # Simple search across JSON data
        conditions.append("data LIKE ?")
        params.append(f"%{search}%")
    
    if filters:
        for key, value in filters.items():
            if value:
                conditions.append(f"{key} = ?")
                params.append(value)
    
    where_clause = " AND ".join(conditions) if conditions else ""
    return where_clause, tuple(params)

# API Endpoints
@app.get("/api/v1/dashboard")
async def get_dashboard_data():
    try:
        agents = await fetch_data_from_table("device_info", sort_by="last_updated", limit=1000)
        logs = await fetch_data_from_table("logs", sort_by="timestamp", limit=1000)
        alerts = await fetch_data_from_table("alerts", sort_by="timestamp", limit=1000)

        recent_alerts = []
        for alert in alerts["data"][:8]:
            severity = alert.get("severity", "low")
            recent_alerts.append({
                "timestamp": alert.get("timestamp", "N/A"),
                "source": alert.get("agent_id", "Unknown"),
                "event": alert.get("type", "Unknown"),
                "severity": severity,
                "status": "Open" if severity in ["high", "critical"] else "Resolved"
            })

        return {
            "total_agents": agents["total"],
            "total_logs": logs["total"],
            "total_alerts": alerts["total"],
            "recent_alerts": recent_alerts
        }
    except Exception as e:
        logger.error(f"Error in dashboard: {e}")
        return {"total_agents": 0, "total_logs": 0, "total_alerts": 0, "recent_alerts": []}

@app.get("/api/v1/logs")
async def get_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None)
):
    try:
        filters = {}
        if source:
            filters["agent_id"] = source
        
        where_clause, params = build_where_clause(search, filters)
        result = await fetch_data_from_table("logs", where_clause, params, sort_by, sort_order.upper(), limit, offset)
        
        logs = []
        for log in result["data"]:
            source_id = log.get("agent_id", "Unknown")
            event_type = next((k for k in log.keys() if k not in ["agent_id", "timestamp", "id", "data"]), "Unknown")
            severity_level = "low"
            if "system_metrics" in log and log.get("system_metrics", {}).get("cpu_percent", 0) > 90:
                severity_level = "high"
            logs.append({
                "timestamp": log.get("timestamp", "N/A"),
                "source": source_id,
                "event": event_type.capitalize().replace("_", " "),
                "severity": severity_level,
                "status": "Open"
            })
        return {"logs": logs, "total": result["total"], "limit": limit, "offset": offset}
    except Exception as e:
        logger.error(f"Error fetching logs: {e}")
        return {"logs": [], "total": 0, "limit": limit, "offset": offset}

@app.get("/api/v1/alerts")
async def get_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc"),
    severity: Optional[str] = Query(None)
):
    try:
        filters = {}
        if severity:
            filters["severity"] = severity
        
        where_clause, params = build_where_clause(search, filters)
        result = await fetch_data_from_table("alerts", where_clause, params, sort_by, sort_order.upper(), limit, offset)
        
        alerts = []
        for alert in result["data"]:
            severity_level = alert.get("severity", "low")
            alerts.append({
                "timestamp": alert.get("timestamp", "N/A"),
                "source": alert.get("agent_id", "Unknown"),
                "event": alert.get("type", "Unknown"),
                "severity": severity_level,
                "status": "Open" if severity_level in ["high", "critical"] else "Resolved",
                "details": alert.get("details", "N/A")
            })
        return {"alerts": alerts, "total": result["total"], "limit": limit, "offset": offset}
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return {"alerts": [], "total": 0, "limit": limit, "offset": offset}

@app.get("/api/v1/agents")
async def get_agents(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("last_updated"),
    sort_order: str = Query("desc")
):
    try:
        result = await fetch_data_from_table("device_info", "", (), sort_by, sort_order.upper(), limit, offset)
        return {"agents": result["data"], "total": result["total"], "limit": limit, "offset": offset}
    except Exception as e:
        logger.error(f"Error fetching agents: {e}")
        return {"agents": [], "total": 0, "limit": limit, "offset": offset}

@app.get("/api/v1/agent/{agent_id}")
async def get_agent(agent_id: str):
    try:
        where_clause = "agent_id = ?"
        params = (agent_id,)
        
        device = await fetch_data_from_table("device_info", where_clause, params, "last_updated", "DESC", 1, 0)
        logs = await fetch_data_from_table("logs", where_clause, params, "timestamp", "DESC", 100, 0)
        alerts = await fetch_data_from_table("alerts", where_clause, params, "timestamp", "DESC", 100, 0)

        agent_logs = []
        for log in logs["data"]:
            source = log.get("agent_id", "Unknown")
            event_type = next((k for k in log.keys() if k not in ["agent_id", "timestamp", "id", "data"]), "Unknown")
            severity = "low"
            if "system_metrics" in log and log.get("system_metrics", {}).get("cpu_percent", 0) > 90:
                severity = "high"
            agent_logs.append({
                "timestamp": log.get("timestamp", "N/A"),
                "source": source,
                "event": event_type.capitalize().replace("_", " "),
                "severity": severity,
                "status": "Open"
            })

        agent_alerts = []
        for alert in alerts["data"]:
            severity = alert.get("severity", "low")
            agent_alerts.append({
                "timestamp": alert.get("timestamp", "N/A"),
                "source": alert.get("agent_id", "Unknown"),
                "event": alert.get("type", "Unknown"),
                "severity": severity,
                "status": "Open" if severity in ["high", "critical"] else "Resolved",
                "details": alert.get("details", "N/A")
            })

        return {
            "agent": device["data"][0] if device["data"] else {},
            "logs": agent_logs,
            "alerts": agent_alerts
        }
    except Exception as e:
        logger.error(f"Error fetching agent {agent_id}: {e}")
        return {"agent": {}, "logs": [], "alerts": []}

@app.get("/api/v1/malware")
async def get_malware(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc")
):
    try:
        where_clause = "type = ?"
        params = ("Malware Detected",)
        result = await fetch_data_from_table("alerts", where_clause, params, sort_by, sort_order.upper(), limit, offset)
        
        malware = []
        for alert in result["data"]:
            severity = alert.get("severity", "low")
            malware.append({
                "timestamp": alert.get("timestamp", "N/A"),
                "source": alert.get("agent_id", "Unknown"),
                "severity": severity,
                "details": alert.get("details", "N/A")
            })
        return {"malware": malware, "total": result["total"], "limit": limit, "offset": offset}
    except Exception as e:
        logger.error(f"Error fetching malware: {e}")
        return {"malware": [], "total": 0, "limit": limit, "offset": offset}

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await websocket.accept()
    connected = True
    while connected:
        try:
            data = await get_dashboard_data()
            await websocket.send_json(data)
            await asyncio.sleep(2)
        except WebSocketDisconnect:
            logger.info("WebSocket disconnected")
            connected = False
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            connected = False
    await websocket.close()

# Agent command endpoints
@app.get("/get_vt_api_key")
async def get_vt_api_key():
    """Return VirusTotal API key for agent"""
    # You can set your VirusTotal API key here or in environment variable
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    return {"api_key": VT_API_KEY}

@app.get("/command")
async def get_command():
    """Return commands for agent (placeholder for future remote control)"""
    # This can be extended to send commands to agents
    return {"action": None}

@app.post("/command/result")
async def post_command_result(result: Dict[str, Any]):
    """Receive command results from agent"""
    logger.info(f"Received command result: {result}")
    return {"status": "received"}

# Data ingestion endpoints for agents
@app.post("/api/v1/ingest/log")
async def ingest_log(log_data: Dict[str, Any]):
    """Receive log data from agent"""
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO logs (agent_id, timestamp, data) VALUES (?, ?, ?)",
                (log_data.get("agent_id"), log_data.get("timestamp"), json.dumps(log_data))
            )
            conn.commit()
            conn.close()
        logger.info(f"Ingested log from agent {log_data.get('agent_id')}")
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error ingesting log: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ingest/alert")
async def ingest_alert(alert_data: Dict[str, Any]):
    """Receive alert data from agent"""
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO alerts (agent_id, timestamp, type, severity, details, data) VALUES (?, ?, ?, ?, ?, ?)",
                (alert_data.get("agent_id"), alert_data.get("timestamp"), alert_data.get("type"),
                 alert_data.get("severity"), alert_data.get("details"), json.dumps(alert_data))
            )
            conn.commit()
            conn.close()
        logger.info(f"Ingested alert from agent {alert_data.get('agent_id')}")
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error ingesting alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ingest/device")
async def ingest_device(device_data: Dict[str, Any]):
    """Receive device info from agent"""
    try:
        with db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO device_info (agent_id, hostname, os, first_seen, last_updated, data) VALUES (?, ?, ?, ?, ?, ?)",
                (device_data.get("agent_id"), device_data.get("hostname"), device_data.get("os"),
                 device_data.get("first_seen"), device_data.get("last_updated"), json.dumps(device_data))
            )
            conn.commit()
            conn.close()
        logger.info(f"Ingested device info from agent {device_data.get('agent_id')}")
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error ingesting device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    logger.info("Starting FastAPI server...")
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")
