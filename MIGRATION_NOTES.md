# ZyraSIEM - MongoDB to SQLite Migration

## Changes Made

### 1. Server (server.py)
- Removed MongoDB/PyMongo dependencies
- Implemented SQLite with proper connection handling
- Created tables: `logs`, `alerts`, `device_info`
- Added indexes for performance optimization
- All API endpoints now query SQLite instead of MongoDB

### 2. Agent (agent.py)
- Removed MongoDB connection code
- Uses only SQLite for local storage
- Data syncs to server's SQLite database when accessible
- Falls back to local storage when server is unavailable

### 3. Database Files
- `local_storage.db` - Agent's local database
- `server_local_storage.db` - Server's central database

## Benefits
- No internet dependency
- No cloud service costs
- Simpler deployment
- Lower latency

## Installation
No additional dependencies needed. SQLite is built into Python.

## Running the System
1. Start server: `python server.py`
2. Start agent: `python agent.py` (as Administrator)
3. Access web UI: `python app.py`

## Notes
- Data is stored locally first, then synced to server
- Thread-safe database operations with locks
- Automatic table creation on first run
