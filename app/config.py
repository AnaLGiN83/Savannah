DB_NAME = "savannahData.db"
HOST = "127.0.0.1"  # 0.0.0.0 for global access. Do not use 0.0.0.0 in production!
# Nginx or other proxy should be used to provide HTTPS connection with global network.

# Flask Secret key. WARNING: Set your own random key here!
SECRET_KEY = "bf92e84436d835e0acec32029f5790447ad99d4b6464a8b6"

EVE_PATH = "/var/log/suricata/eve.json"
SURICATA_LOG_PATH = "/var/log/suricata/suricata.log"

REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_STATS_NAME = "suricata-stats"
REDIS_ALERTS_NAME = "suricata-alerts"
