# SSH Monitor

**SSH Monitor** is a lightweight Linux tool that monitors SSH login attempts in real-time and sends email alerts for:

* Successful logins
* Failed logins (aggregated per IP to avoid spam)

It automatically creates a config file at `~/.config/ssh-monitor/config.yaml`.

---

## Features

* Real-time SSH login detection 
* Styled HTML email alerts for success and failure
* Aggregated failed login alerts to avoid inbox spam
* Optional systemd service for auto-start on boot
* Easy installation via single script

---

## Installation

Run this command to install `ssh-monitor` directly from GitHub:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Caleb-ne1/ssh-monitor/main/setup.sh)
```

This will:

1. Download the prebuilt `ssh-monitor` binary
2. Copy it to `/usr/local/bin/ssh-monitor`
3. Create the config folder `~/.config/ssh-monitor/`
4. Set up a systemd service to run the monitor automatically
5. Start the monitor immediately

---

## Configuration

The default config is stored at:

```
~/.config/ssh-monitor/config.yaml
```

Example config:

```yaml
# Log path to monitor
auth_log: "/var/log/auth.log"

# Email alert settings
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  sender_email: "youremail@gmail.com"
  app_password: "your-app-password"
  recipient_email: "recipient@example.com"
```

**Note:** Any changes to this file will need a restart the ssh-monitor to apply the new settings.

---

## Usage

* Check logs:

```bash
sudo journalctl -u ssh-monitor -f
```

* Stop the monitor:

```bash
sudo systemctl stop ssh-monitor.service
```

* Restart the monitor:

```bash
sudo systemctl restart ssh-monitor.service
```

* Enable auto-start at boot (already enabled during setup):

```bash
sudo systemctl enable ssh-monitor.service
```

---


