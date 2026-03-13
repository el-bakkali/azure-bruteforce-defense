#!/bin/bash
# Usage: ./update-f2b-url.sh <functionAppUrl> <functionKey>
# Example: ./update-f2b-url.sh https://your-func-app.azurewebsites.net YOUR_FUNCTION_KEY

FUNC_URL="${1:?Usage: $0 <functionAppUrl> <functionKey>}"
FUNC_KEY="${2:?Usage: $0 <functionAppUrl> <functionKey>}"

sudo sed -i "s|FUNCTION_URL_PLACEHOLDER|${FUNC_URL}/api/BanIP?code=${FUNC_KEY}|g" /etc/fail2ban/action.d/azure-nsg-block.conf
sudo systemctl restart fail2ban
echo "Fail2ban updated and restarted"
sudo fail2ban-client status sshd