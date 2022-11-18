FROM python:3.11
RUN pip install certgrinder
RUN apt update
RUN apt install -y cron
RUN echo "* * * * * root /usr/local/bin/certgrinder -c /etc/certgrinder/certgrinder.conf periodic > /proc/1/fd/1 2>/proc/1/fd/2" > /etc/crontab
CMD sh -c 'trap "exit" TERM; cron -f'
