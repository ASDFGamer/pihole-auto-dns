# Pihole-Autoconfig

This project is intended to add dns entries from other docker-containers
automatically to the pihole config. It is also possible to set some config
options via this script that are helpful, when setting the dns entries.  

A example docker-compose file and a example config file are this directory.

## Quickstart

```bash
git clone git@github.com:ASDFGamer/pihole-auto-dns.git
docker compose build
docker compose up -d
```

After this you can change the config in the pihole_config.json and it gets
applied every minute.  
You can also add the following labels to docker containers that should have a
domain that is managed by pihole.

```yaml
pihole_config.local_dns.cname.domain=SERVICE_DOMAIN
pihole_config.local_dns.cname.target=CNAME_TARGET
```
