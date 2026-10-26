#!/usr/bin/env bash
# One-time setup on Ubuntu 20.04 / 22.04 / 24.04 (VM or native, NOT WSL1).
set -e
sudo apt update
sudo apt install -y mininet openvswitch-switch openvswitch-testcontroller \
                    python3 git iperf3 net-tools
sudo systemctl enable --now openvswitch-switch
# POX controller (gar branch supports Python 3)
if [ ! -d "$HOME/pox" ]; then
  git clone https://github.com/noxrepo/pox "$HOME/pox"
fi
# link our controller module into POX's ext/ folder
REPO="$(cd "$(dirname "$0")/.." && pwd)"
ln -sf "$REPO/controller/host_blocker.py" "$HOME/pox/ext/host_blocker.py"
sudo mn --test pingall   # sanity check Mininet itself
sudo mn -c
echo "Setup done."
