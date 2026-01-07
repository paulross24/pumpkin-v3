# Cloudflare Voice Exposure

## Ingress rule (cloudflared)

```yaml
ingress:
  - hostname: voice.rosshome.co.uk
    service: http://<local-ip>:9000
  - service: http_status:404
```

Known good (replace the IP if different):
```yaml
ingress:
  - hostname: voice.rosshome.co.uk
    service: http://<local-ip>:9000
  - service: http_status:404
```

## DNS route command (tunnel name required)

```
cloudflared tunnel route dns <tunnel-name> voice.rosshome.co.uk
```

## Restart cloudflared

```
sudo systemctl restart cloudflared
sudo systemctl restart cloudflared@tunnel
```

## Remote POST test

```
curl -sS -X POST https://voice.rosshome.co.uk/voice \
  -H 'Content-Type: application/json' \
  -d '{"text":"voice test"}'
```

## Troubleshooting

- 404: ingress rule ordering; ensure hostname rule is above the 404 catch-all.
- Wrong IP: verify local IP and port 9000 are correct in ingress.
- Port not listening: ensure `pumpkin-voice.service` is running and bound.
- Service name mismatch: check service name matches your cloudflared installation.

## Green/Red checklist
- Green: `python3 -m pumpkin ops verify` shows `cloudflare_voice_ready: true`
- Green: `cloudflared tunnel --config /etc/cloudflared/config.yml ingress validate` passes on Proxmox
- Green: ingress rule ordering is correct (voice rule above 404)
