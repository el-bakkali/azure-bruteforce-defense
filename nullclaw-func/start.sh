#!/bin/sh
# Startup wrapper — reads the Functions port and launches NullClaw gateway
cd "$(dirname "$0")"
exec ./nullclaw gateway --port "${FUNCTIONS_CUSTOMHANDLER_PORT:-3000}"
