#!/usr/bin/env bash
# Install sysguard as a systemd --user service.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_DIR="$HOME/.config/systemd/user"
STATE_DIR="$HOME/.local/share/sysguard"

mkdir -p "$UNIT_DIR" "$STATE_DIR"

install -m 644 "$SRC/sysguard.service" "$UNIT_DIR/sysguard.service"
chmod +x "$SRC/sysguard.py"

systemctl --user daemon-reload
systemctl --user enable sysguard.service

echo
echo "sysguard installed."
echo "  config:    $SRC/config.yaml   (dry_run: true by default)"
echo "  state:     $STATE_DIR/"
echo "  decisions: $STATE_DIR/decisions.jsonl"
echo
echo "Start:    systemctl --user start sysguard"
echo "Status:   systemctl --user status sysguard"
echo "Logs:     journalctl --user -u sysguard -f"
echo "Audit:    tail -f $STATE_DIR/decisions.jsonl"
echo
echo "Currently in dry-run. Watch decisions.jsonl for a week, then flip"
echo "dry_run: false in config.yaml and restart the service."
