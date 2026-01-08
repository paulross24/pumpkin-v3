# Home Assistant to PumpkinVoice webhook

Use this to stream HA events into PumpkinVoice for real-time awareness.

## 1) Add rest_command (configuration.yaml)

```yaml
rest_command:
  pumpkin_voice_webhook:
    url: "http://192.168.1.157:9000/ha/webhook"
    method: POST
    content_type: "application/json"
    payload: "{{ payload }}"
```

Restart Home Assistant after editing.

## 2) Add automation (automations.yaml or UI)

```yaml
alias: Pumpkin Voice Webhook
trigger:
  - platform: event
    event_type: state_changed
condition: []
action:
  - service: rest_command.pumpkin_voice_webhook
    data:
      event_type: "{{ trigger.event.event_type }}"
      time_fired: "{{ trigger.event.time_fired }}"
      data:
        entity_id: "{{ trigger.event.data.entity_id }}"
        state: "{{ trigger.event.data.new_state.state if trigger.event.data.new_state else None }}"
        attributes: "{{ trigger.event.data.new_state.attributes if trigger.event.data.new_state else None }}"
mode: queued
```

## 3) Verify

Trigger a state change and check:

```bash
curl -sS http://127.0.0.1:9000/summary | jq '.homeassistant_last_event'
```

Or:

```bash
curl -sS -X POST http://127.0.0.1:9000/ha/webhook \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"state_changed","entity_id":"binary_sensor.front_door","state":"on"}'
```
