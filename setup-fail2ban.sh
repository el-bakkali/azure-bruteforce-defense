#!/bin/bash
set -e
sudo apt-get update -y
sudo apt-get install -y fail2ban auditd jq curl

# auditd rules for SSH
sudo tee /etc/audit/rules.d/ssh.rules > /dev/null << 'AUDITEOF'
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /var/log/auth.log -p r -k auth_log_read
AUDITEOF
sudo systemctl enable auditd && sudo systemctl restart auditd

# Fail2ban jail
sudo tee /etc/fail2ban/jail.local > /dev/null << 'JAILEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
action   = iptables-multiport[name=sshd, port="ssh", protocol=tcp]
           azure-nsg-block
JAILEOF

# Custom action → Function App webhook
sudo tee /etc/fail2ban/action.d/azure-nsg-block.conf > /dev/null << 'ACTIONEOF'
[Definition]
actionban = curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"ip": "<ip>", "action": "ban", "jail": "<name>", "hostname": "'"$(hostname)"'"}' \
    "FUNCTION_URL_PLACEHOLDER" || true

actionunban = curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"ip": "<ip>", "action": "unban", "jail": "<name>", "hostname": "'"$(hostname)"'"}' \
    "FUNCTION_URL_PLACEHOLDER" || true
ACTIONEOF

sudo systemctl enable fail2ban && sudo systemctl restart fail2ban
echo "Fail2ban + auditd configured"