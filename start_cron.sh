#!/bin/sh
echo "Update Pihole config every ${update_frequency} minutes"
echo "*/${update_frequency}   *   *   *   *   /update_dns.py > /dev/stdout 2>&1" | crontab -
/update_dns.py > /dev/stdout 2>&1
exec cron -f