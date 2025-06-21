#!/bin/bash
cd /home/kavia/workspace/code-generation/tickettrack-web-55120-11ed2883/ticketing_frontend_workspace/ticketing_frontend
npm run build
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
   exit 1
fi

