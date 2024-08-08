FROM python:3.12.5-alpine3.19

# RUN apt-get update && apt-get install -y cron

COPY ./update_dns.py /
COPY ./start_cron.sh /

ENV update_frequency=1
ENV pihole_base_url="http://pi.hole"
ENV pihole_password="HPVXTA1G"
ENV pihole_cname_target="server.lan"
ENV docker_endpoint="http://docker_socket_proxy:2375"
CMD [ "/start_cron.sh" ]