# Home Assistant presence lookup

PumpkinVoice can answer questions like "is Steph home" if Home Assistant is configured.

## Requirements
- Home Assistant observer module enabled
- HA base_url and token configured
- A people mapping in modules/config.yaml

Example modules/config.yaml snippet:

```yaml
version: 1
enabled:
  - homeassistant.observer
modules:
  homeassistant.observer:
    base_url: "http://homeassistant.local:8123"
    token_env: "PUMPKIN_HA_TOKEN"
    people:
      steph: person.steph
      paul: person.paul
```

Set the token in the environment:

```bash
export PUMPKIN_HA_TOKEN="<long-lived-access-token>"
```

Then restart PumpkinVoice:

```bash
sudo systemctl restart pumpkin-voice.service
```
