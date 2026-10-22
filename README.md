# Network Sentinel — Network Intrusion Detection System (NIDS)

## Project Overview
Network Sentinel is an educational cybersecurity project built using Python, Flask, HTML, CSS, and JavaScript. It provides a security dashboard to analyze event descriptions and identify suspicious activity using predefined detection rules.

## Features
- Security monitoring dashboard
- Rule-based threat detection
- Detection of port scanning indicators
- Detection of brute-force login indicators
- Malware-related pattern detection
- Suspicious network activity detection
- SQL injection pattern detection
- Event and threat counters
- Threat event list
- Session report download
- Health-check endpoint
- Responsive dashboard interface

## Technologies Used
- Python
- Flask
- HTML5
- CSS3
- JavaScript
- Regular Expressions (Regex)

## Project Structure
```text
Network_Intrusion_Detection_System/
├── app.py
├── detector.py
├── config.py
├── requirements.txt
├── README.md
├── rules/
│   └── local.rules
├── logs/
├── reports/
├── static/
│   ├── style.css
│   └── script.js
├── templates/
│   └── index.html
└── tests/
    └── test_detector.py
```

## Installation and Setup

### 1. Install Python
Install Python 3.10 or a compatible newer version.

### 2. Open the project
Open the project folder in Visual Studio Code.

### 3. Install dependencies
Open the VS Code terminal and run:

```bash
python -m pip install -r requirements.txt
```

### 4. Start the application
Run:

```bash
python app.py
```

### 5. Open the dashboard
Open this address in your browser:

```text
http://127.0.0.1:5000
```

## How to Use
1. Start the Flask application.
2. Open the Network Sentinel dashboard.
3. Enter an event description in the analysis section.
4. Click the Analyze button.
5. Review the detection result and severity.
6. View the session counters and detected events.
7. Download the session report from the Reports section.

## Example Test Events

Normal event:
```text
Normal network activity
```

Suspicious event:
```text
Multiple failed logins detected
```

Port scan indicator:
```text
Suspicious port scan detected
```

Malware indicator:
```text
Ransomware detected
```

## API Endpoints
- `/` — Displays the dashboard.
- `/analyze` — Analyzes an event submitted as a POST request.
- `/api/stats` — Returns