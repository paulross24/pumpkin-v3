#!/usr/bin/env bash
set -euo pipefail

cat <<'CMDS'
sudo mkdir -p /etc/pumpkin
sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin.service /etc/systemd/system/pumpkin.service
sudo cp /home/rossp/pumpkin-v3/deploy/pumpkin-voice.service /etc/systemd/system/pumpkin-voice.service
sudo systemctl daemon-reload
sudo systemctl enable pumpkin.service
sudo systemctl enable pumpkin-voice.service
sudo systemctl start pumpkin.service
sudo systemctl start pumpkin-voice.service
sudo systemctl status pumpkin.service
sudo systemctl status pumpkin-voice.service
python3 -m pumpkin status

# uninstall
sudo systemctl disable pumpkin.service
sudo systemctl disable pumpkin-voice.service
sudo systemctl stop pumpkin.service
sudo systemctl stop pumpkin-voice.service
sudo rm /etc/systemd/system/pumpkin.service
sudo rm /etc/systemd/system/pumpkin-voice.service
sudo systemctl daemon-reload
CMDS
