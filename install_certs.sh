#!/bin/bash

#====================================================
# 复制证书
#====================================================

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

export one_key_conf_dir="$HOME/.one_key_v2ray_hong"
onekey_conf="${one_key_conf_dir}/onekey.conf"
ssl_cert_base_dir="/etc/ssl/cert_list"

acme_sh_dir="$HOME/.acme.sh"
acme_sh_file="$acme_sh_dir/acme.sh"

show_message() {
    echo -e "$1"
}

log() {
    local message="$1"
    echo $(date +"%Y-%m-%d_%H%M%S") $message >> "$one_key_conf_dir/install_certs.log"
}

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

    local sslDir="${ssl_cert_base_dir}/$domain"
    local sslKeyFile="${sslDir}/key.pem"
    local sslCertFile="${sslDir}/cert.pem"
    local sslFullchainFile="${sslDir}/fullchain.pem"
    local reload_cmd="service nginx restart; service v2ray restart; nps restart; x-ui restart"

    # 创建证书目录
    if [[ ! -d "$sslDir" ]]; then
        sudo mkdir -p "$sslDir"
    fi

    sudo service nginx stop

    # 安装证书
    show_message "\n安装 SSL 证书到目录: $sslDir"
    bash $acme_sh_file \
        --install-cert -d $domain \
        --cert-file       $sslCertFile  \
        --key-file        $sslKeyFile  \
        --fullchain-file  $sslFullchainFile \
        --ecc

    if [[ 0 -eq $? ]]; then
        log "install cert success! Domain: $domain"

        service nginx restart
        service v2ray restart
        nps restart
        x-ui restart
    else
        log "install cert failed! Domain: $domain"
        exit 1
    fi  
}
 
read_config
install_certs
