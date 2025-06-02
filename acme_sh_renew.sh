#!/bin/bash

# 用于 cron 计划任务定时更新证书

acme_sh_home="$HOME/.acme.sh"
acme_sh_file="$acme_sh_home/acme.sh"

sudo service nginx stop
bash $acme_sh_file --cron --home "$acme_sh_home"
sudo service nginx restart
