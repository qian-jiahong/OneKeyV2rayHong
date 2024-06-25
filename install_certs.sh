#!/bin/bash

#====================================================
# 复制证书
#====================================================

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

export one_key_conf_dir="$HOME/.one_key_v2ray_hong"
onekey_conf="${one_key_conf_dir}/onekey.conf"

read_config() {
    # $1 文件
    # $2 静默模式
    local conf_file=$onekey_conf
    local silence=0
    
    if [[ -n "$1" ]]; then
        conf_file=$1
    fi
    
    if [[ -n "$2" ]]; then
        silence=$2
    fi
    
    if [[ -f $conf_file ]]; then
        source $conf_file
    elif [[ silence -eq 0 ]]; then
        show_error_message "配置文件不存在: $conf_file"
        exit 1
    fi
}

install_certs() {
    if [ -z "$domain" ]; then
        exit 0
    fi

    local to_path=/etc/ssl/cert_list/$domain
    if [[ ! -d "$to_path" ]]; then
        mkdir -p "$to_path"
    fi

    acme.sh --install-cert -d $domain \
        --cert-file      $to_path/cert.pem  \
        --key-file       $to_path/key.pem  \
        --fullchain-file $to_path/fullchain.pem \
        --reloadcmd      "service nginx restart"
}

read_config
# install_certs

random_minute=1
random_hour=6
_CRONTAB_STDIN="crontab -"
_CRONTAB="crontab"
install_certs_script="install_certs.sh"
$_CRONTAB -l | sed "/$install_certs_script/d" | $_CRONTAB_STDIN
$_CRONTAB -l | {
    cat
    echo "$random_minute $random_hour * * *  $install_certs_script > /root/${install_certs_script}.log"
} | $_CRONTAB_STDIN

$_CRONTAB -l
