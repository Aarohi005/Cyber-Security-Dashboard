# Cyber Threat Dashboard — Portfolio Edition

A **full-stack cybersecurity dashboard** that visualizes and manages cyber threat alerts in real-time. Includes:
- **Flask backend** with JWT authentication, SQLite database, Nmap integration for network scans, and Socket.IO for live updates.
- **React frontend** with charts, filters, and live severity indicators.

## Features
- **User Authentication** (JWT-based)
- **Role-based Access Control** (Admin, Analyst, Viewer)
- **Alerts Management** (view, filter, add, delete)
- **Live Alerts** via WebSockets
- **Nmap Integration** for network port scanning
- **Charts & Analytics** for alert severity distribution

## Requirements
### Backend
- Python 3.9+
- Packages (install via `pip install -r backend/requirements.txt`):
  - flask
  - flask-cors
  - pyjwt
  - werkzeug
  - flask-socketio
  - python-nmap
  - passlib
  - eventlet
- **Nmap binary** installed on your system (`sudo apt install nmap` or equivalent)

### Frontend
- Node.js 16+
- npm or yarn
- Packages (install via `npm install` in `frontend/`):
  - react
  - react-dom
  - socket.io-client
  - recharts

## Running the Project
### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Backend runs on http://localhost:5000.

### Frontend
```bash
cd frontend
npm install
npm start
```
Frontend runs on http://localhost:3000.