# Operations Runbook

## Install path (2 minutes)

1) Run the installer script (prints commands only):
```
./deploy/install_services.sh
```

2) Verify systemd status:
```
sudo systemctl status pumpkin.service
sudo systemctl status pumpkin-voice.service
```

3) Run smoke test:
```
./scripts/smoke_test.sh
```

4) Apply Cloudflare voice snippet on Proxmox:
```
python3 -m pumpkin ops cloudflare-voice
```

## Systemd service

Unit file location: `/etc/systemd/system/pumpkin.service`

### Install
```
sudo mkdir -p /etc/pumpkin
sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin.service /etc/systemd/system/pumpkin.service
sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin-voice.service /etc/systemd/system/pumpkin-voice.service
sudo systemctl daemon-reload
sudo systemctl enable pumpkin.service
sudo systemctl enable pumpkin-voice.service
```

### Start/stop
```
sudo systemctl start pumpkin.service
sudo systemctl start pumpkin-voice.service
sudo systemctl stop pumpkin.service
sudo systemctl stop pumpkin-voice.service
```

### Status
```
sudo systemctl status pumpkin.service
sudo systemctl status pumpkin-voice.service
python3 -m pumpkin status
```

### Uninstall
```
sudo systemctl disable pumpkin.service
sudo systemctl disable pumpkin-voice.service
sudo systemctl stop pumpkin.service
sudo systemctl stop pumpkin-voice.service
sudo rm /etc/systemd/system/pumpkin.service
sudo rm /etc/systemd/system/pumpkin-voice.service
sudo systemctl daemon-reload
```

## Environment configuration

Optional environment file:
- `/etc/pumpkin/pumpkin.env`

Example entries:
```
PUMPKIN_PLANNER_MODE=stub
PUMPKIN_VOICE_PORT=9000
PUMPKIN_AUDIT_MAX_BYTES=52428800
```

## Voice input server

Run manually (foreground):
```
python3 -m pumpkin voice server
```

Send a test voice input:
```
python3 -m pumpkin voice send "turn the lounge lamp on"
```
