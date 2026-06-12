# config.py — IDS Configuration

FEATURE_COLUMNS = [
    'dur', 'proto', 'service', 'state',
    'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
    'sinpkt', 'smean', 'dmean',
    'ct_src_ltm', 'ct_srv_dst'
]

MODEL_PATH  = "models/dos_model.pkl"
SCALER_PATH = "models/scaler.pkl"
LOG_FILE    = "traffic_log.csv"

# Requests-per-IP threshold for rate-based pre-block (HTTP layer)
RATE_BLOCK_THRESHOLD = 300

# ML confidence threshold to call something an attack
ATTACK_CONFIDENCE_THRESHOLD = 0.5

# Proto / service / state encoding maps (match UNSW_NB15)
PROTO_MAP = {
    'tcp': 0, 'udp': 1, 'arp': 2, 'igmp': 3,
    'ospf': 4, 'sctp': 5, 'gre': 6, 'http': 0,
    'https': 0
}
SERVICE_MAP = {
    '-': 0, 'http': 1, 'ftp': 2, 'ftp-data': 3,
    'smtp': 4, 'pop3': 5, 'dns': 6, 'snmp': 7,
    'ssl': 8, 'dhcp': 9
}
STATE_MAP = {
    'INT': 0, 'FIN': 1, 'REQ': 2, 'ACC': 3,
    'CON': 4, 'RST': 5, 'CLO': 6
}
