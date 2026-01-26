# Pumpkin Runbook

## Start
```
python3 -m pumpkin daemon
python3 -m pumpkin voice server
```

## Systemd
```
sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin.service /etc/systemd/system/pumpkin.service
sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin-voice.service /etc/systemd/system/pumpkin-voice.service
sudo systemctl enable --now pumpkin.service pumpkin-voice.service
```

## Verify
```
curl -sS http://127.0.0.1:9000/health
curl -sS http://127.0.0.1:9000/status
```

## Safe Mode
Set `PUMPKIN_SAFE_MODE=true` and restart services.

## Backup
- DB: `data/pumpkin.db`
- Audit: `data/audit.jsonl`
- Config: `modules/config.yaml`, `policy.yaml`

## Troubleshoot
- Check `data/audit.jsonl` for last decisions
- Check `/summary` for active issues
- Use `/demo/incidents` to verify detection and briefings
