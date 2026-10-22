APP_NAME = "SENTINEL NIDS"
APP_VERSION = "1.0.0"
HOST = "127.0.0.1"
PORT = 5000
DEBUG = True

LOG_DIR = "logs"
REPORT_DIR = "reports"
RULES_FILE = "rules/local.rules"

# Detection thresholds
PORT_SCAN_THRESHOLD = 10
ALERT_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]