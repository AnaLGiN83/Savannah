# Savannah
Savannah is a simple open source web UI for IDS/IPS Suricata.  

1. Configure your app/config.py
2. Add to suricata.yaml outputs redis section:
```
...
    # Configure the type of alert (and other) logging you would like.
outputs:
  # a line based alerts log similar to Snort's fast.log
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
      #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'

  - eve-log:
      enabled: yes
      filetype: redis
      redis:
        server: 127.0.0.1
        port: 6379
        mode: list
        key: suricata-alerts
      types:
        - alert:
            tagged_packets: yes

  - eve-log:
      enabled: yes
      filetype: redis
      redis:
        server: 127.0.0.1
        port: 6379
        mode: list
        key: suricata-stats
      types:
        - stats:
            totals: yes
            threads: no
            deltas: no

  # Extensible Event Format (nicknamed EVE) event log in JSON format
  - eve-log:
      enabled: yes
      filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
...
```
3.Install and run Savannah:

    pip install -r requirements.txt
    python3 run.py
