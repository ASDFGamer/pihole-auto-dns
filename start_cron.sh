#!/bin/sh
echo "Update Pihole config every ${update_frequency} minutes"
echo "*/${update_frequency} *   * * *    . /.env && /update_dns.py >> /dev/stdout 2>&1" | crontab -
# echo "*/${update_frequency} *   * * *    . /.env && /update_dns.py >> /dev/stdout 2>&1" >> /etc/cron.d/pihole_config
# echo "*/${update_frequency} *   * * *    . /.env && env >> /dev/stdout 2>&1" | crontab -
# echo "*/${update_frequency} *   * * *    . /.env && env >> /dev/stdout 2>&1" >> /etc/cron.d/pihole_config
# chmod 0644 /etc/cron.d/pihole_config
# crontab /etc/cron.d/pihole_config

env > /.env
sed -i 's/^/export /g' /.env
/update_dns.py > /dev/stdout 2>&1
# exec cron -f
exec crond -f