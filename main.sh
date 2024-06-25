#!/bin/bash

#====================================================
#	System Request:Debian 8+/Ubuntu 16+/Centos 7+
#	Author:	qian-jiahong
#	Dscription: 一键 V2ray 安装管理脚本 Hong
#	Version: 1.0
#	email:
#	Official document:
#   提供两种方式:
#   1. NGINX + WS + TLS, 有伪装网站, 数据通过网站端口传输
#   2. HTTP/2 + TLS, 无伪装网站
#====================================================

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 启动器所在目录
if [[ -z "${one_key_launch_dir}" ]]; then
    one_key_launch_dir="$(pwd)"
fi

show_one_key_logo() {
    # ./figlet -w 5000 -d fonts -f slant One Key V2ray - Hong
    echo '   ____                __ __              _    _____                                __  __                 '
    echo '  / __ \____  ___     / //_/__  __  __   | |  / /__ \ _________ ___  __            / / / /___  ____  ____ _'
    echo ' / / / / __ \/ _ \   / ,< / _ \/ / / /   | | / /__/ // ___/ __ `/ / / /  ______   / /_/ / __ \/ __ \/ __ `/'
    echo '/ /_/ / / / /  __/  / /| /  __/ /_/ /    | |/ // __// /  / /_/ / /_/ /  /_____/  / __  / /_/ / / / / /_/ / '
    echo '\____/_/ /_/\___/  /_/ |_\___/\__, /     |___//____/_/   \__,_/\__, /           /_/ /_/\____/_/ /_/\__, /  '
    echo '                             /____/                           /____/                              /____/   '
}

# 0/1, 1 为调试时使用
if [ -z "${debug_mode}" ]; then
    debug_mode=0
fi

# 文字前景色
F_GREEN="\033[32m"
F_RED="\033[31m"
F_YELLOW="\033[33m"

# 文字背景色
F_GREEN_BG="\033[42;37m"
F_BLUE_BG="\033[44;37m"
F_RED_BG="\033[41;37m"

# 重置
F_END="\033[0m"

# 标题
OK="${F_GREEN}[OK]${F_END}"
ERROR="${F_RED}[错误]${F_END}"
WARN="${F_YELLOW}[警告]${F_END}"

TRUE=0
FALSE=1

############################
# 脚本及配置文件目录
if [[ -z "${one_key_conf_dir}" ]]; then
    one_key_conf_dir="$HOME/.onekey_v2ray_hong"
fi

[[ ! -d ${one_key_conf_dir} ]] && mkdir -p ${one_key_conf_dir}
cd "${one_key_conf_dir}" || exit

# git 分支名称配置
if [[ -z "${git_branch_conf}" ]]; then
    git_branch_conf="${one_key_conf_dir}/git_branch.conf"
fi

# git 分支名称
if [[ -z "${git_branch}" ]] && [[ -f "${git_branch_conf}" ]]; then
    source "${git_branch_conf}"
fi

if [[ -z "${git_branch}" ]]; then
    git_branch="master"
fi

echo "git_branch=${git_branch}" >${git_branch_conf}

############################
onekey_conf="${one_key_conf_dir}/onekey.conf"
onekey_conf_bak="${one_key_conf_dir}/onekey.conf.bak"

############################
# 项目信息
############################
project_name='OneKeyV2rayHong'
project_owner='qian-jiahong'
# 版本库地址
git_project=https://github.com/${project_owner}/${project_name}
# 直连基本地址
onekey_base_url=https://raw.githubusercontent.com/${project_owner}/${project_name}/${git_branch}

# 本脚本信息
onekey_script_name="OneKeyV2rayHong"
onekey_script_title="一键 V2ray 安装管理脚本"

# 版本号, 升级时需要检查
onekey_script_version="2024.06.25.01"
remote_version=""

# 必须的脚本名称
launcher_script="one_key_v2ray_hong.sh"
main_script="main.sh"
v2ray_script="fhs-install-v2ray.sh"
install_certs_script="install_certs.sh"
json_utils_script="json_utils.sh"

# V2Ray core
v2ray_conf_dir="/usr/local/etc/v2ray"
v2ray_conf="${v2ray_conf_dir}/config.json"
v2ray_qr_config_file="/tmp/vmess_qr.tmp"
v2ray_systemd_file="/etc/systemd/system/v2ray.service"
v2ray_log_dir=/var/log/v2ray
v2ray_access_log="$v2ray_log_dir/access.log"
v2ray_error_log="$v2ray_log_dir/error.log"

# Nginx
nginx_version="1.20.1"
source_dir_for_install="/usr/local/src"
nginx_dir="/etc/nginx"
nginx_conf="/etc/nginx/conf/conf.d/v2ray.conf"
nginx_systemd_file="/etc/systemd/system/nginx.service"
nginx_package_base=nginx-$nginx_version
nginx_package_name=${nginx_package_base}.tar.gz
nginx_source_url=http://nginx.org/download/${nginx_package_name}

# 伪装 web
webroot_dir="/var/www"
web_dir="v2ray_ws_tls_website"
web_install_path="${webroot_dir}/$web_dir"
web_url=https://github.com/${project_owner}/${web_dir}.git

# SSL 证书
acme_sh_dir="$HOME/.acme.sh"
acme_sh_file="$acme_sh_dir/acme.sh"
ssl_cert_update_sh="/usr/bin/ssl_cert_update.sh"
get_acme_sh_url=https://get.acme.sh
ssl_cert_fullchain_path="${one_key_conf_dir}/ssl_fullchain_file"
ssl_cert_key_path="${one_key_conf_dir}/ssl_key_file"
install_certs_script_path="${one_key_conf_dir}/${install_certs_script}"

openssl_version="1.1.1k"
openssl_package_base=openssl-$openssl_version
openssl_package_name=${openssl_package_base}.tar.gz
openssl_source_url=https://www.openssl.org/source/${openssl_package_name}

jemalloc_version="5.2.1"
jemalloc_package_base=jemalloc-$jemalloc_version
jemalloc_package_name=${jemalloc_package_base}.tar.bz2
jemalloc_source_url=https://github.com/jemalloc/jemalloc/releases/download/$jemalloc_version/${jemalloc_package_name}

system_tcp_speed_up_install_sh_url=https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh

# Nginx 配置模板变量, 用于定位修改
_bash_var_modify_id_port_1='MODIFY_ID_PORT_1'
_bash_var_modify_id_port_2='MODIFY_ID_PORT_2'
_bash_var_modify_id_inbound_port='MODIFY_ID_INBOUND_PORT'
_bash_var_modify_id_obfs_path='MODIFY_ID_OBFS_PATH'
_bash_var_modify_id_domain_1='MODIFY_ID_DOMAIN_1'
_bash_var_modify_id_domain_2='MODIFY_ID_DOMAIN_2'
_bash_var_modify_id_domain_3='MODIFY_ID_DOMAIN_3'
_bash_var_modify_id_tls_version='MODIFY_ID_TLS_VERSION'

# 主机 CPU 核心数量
THREAD=$(grep 'processor' /proc/cpuinfo | sort -u | wc -l)

# Linux 发行版信息
linux_distribution=""
linux_distribution_name=""
linux_distribution_version=""

# 必须的脚本下载地址
declare -A SCRIPTS_URL_ARRAY=(
    ["$launcher_script"]="${onekey_base_url}/$launcher_script"
    ["$main_script"]="${onekey_base_url}/$main_script"
    ["$json_utils_script"]="${onekey_base_url}/$json_utils_script"
    ["$v2ray_script"]="${onekey_base_url}/$v2ray_script"
    ["$install_certs_script"]="${onekey_base_url}/$install_certs_script"
)

backup_one_key_script_tar='backup_one_key_script.tar.gz'

#####################################################
# 配置变量
#####################################################

# Nginx 网站服务使用的 TLS 版本
declare -A TLS_VERSION_CAPTION_ARRAY=(
    ["1"]="1. TLS1.1 TLS1.2 and TLS1.3 (兼容模式)"
    ["2"]="2. TLS1.2 and TLS1.3 (兼容模式)"
    ["3"]="3. TLS1.3 only"
)
declare -A TLS_VERSION_VALUE_ARRAY=(
    ["1"]="TLSv1.1 TLSv1.2 TLSv1.3"
    ["2"]="TLSv1.2 TLSv1.3"
    ["3"]="TLSv1.3"
)

# Nginx 默认的 tls 版本
tls_version_default=1

# V2Ray 配置变量
configAlias=""
domain=""
port=443
uuid=""
alterID=0
obfsPath=""

# V2Ray 端口，只用于新安装情境
inbound_port=10000

# Nginx 配置变量(仅用于 ws 方式)
tls_version=1

# 混淆方式(ws/h2)
obfsType=""

# 启用 acme.sh 脚本管理 SSL 证书 (0 - 禁用, 1 - 启用)
acme_sh_enabled=1

#####################################################
# 函数
#####################################################

##############################
# 一键安装管理脚本参数
##############################

# 初始化默认值
init_default_value() {
    # V2Ray 配置变量
    configAlias=""
    domain=""
    port=443
    inbound_port=$((RANDOM + 10000))
    uuid="$(gen_uuid)"
    alterID=0
    obfsPath="/$(gen_obfs_path)/"

    # Nginx 配置变量(仅用于 ws 方式)
    tls_version=1

    # 混淆方式(ws/h2)
    obfsType="None"

    # 启用 acme.sh 脚本管理 SSL 证书 (0 - 禁用, 1 - 启用)
    acme_sh_enabled=1
}

save_onekey_config() {
    if [[ $obfsType == "ws" ]]; then
        configAlias="${domain}_VMESS+WS+TLS"
    elif [[ $obfsType == "h2" ]]; then
        configAlias="${domain}_VMESS+HTTP2+TLS"
    else
        configAlias="${domain}"
    fi

    cat >$onekey_conf <<-EOF
configAlias="$configAlias"
domain="$domain"
port=$port
inbound_port=$inbound_port
uuid="$uuid"
alterID=$alterID
obfsPath="$obfsPath"
obfsType="$obfsType"
tls_version=$tls_version
acme_sh_enabled=$acme_sh_enabled
EOF
}

#########################
# 通用函数
#########################

show_error_message() {
    echo -e "${ERROR} $1"
}

show_ok_message() {
    echo -e "${OK} $1"
}

show_warn_message() {
    echo -e "${WARN} $1"
}

show_striking_message() {
    echo -e "${F_BLUE_BG}$1${F_END}"
}

show_message() {
    echo -e "$1"
}

#生成伪装路径
gen_obfs_path() {
    #简易随机数
    local random_num=$((RANDOM % 12 + 4))
    local obfs_path_tmp="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
    echo "$obfs_path_tmp"
}

gen_uuid() {
    echo $(cat /proc/sys/kernel/random/uuid)
}

# 复制关联数组
copy_assoc_array() {
    # $1 源数组名称
    # $2 目标数组名称
    local key
    eval "
        for key in \"\${!$1[@]}\"
        do
            $2[\"\$key\"]=\"\${$1[\$key]}\"
        done
    "
}

download() {
    local url=$1
    local dir=$2
    local parameter=$3

    local ret_value=${FALSE}
    local old_dir=$(pwd)

    if [ -z "${dir}" ]; then
        dir=${old_dir}
    fi

    if [ ! -d "${dir}" ]; then
        show_error_message "目录不存在: ${dir}"
        return ${FALSE}
    fi

    if [ -z "$parameter" ]; then
        parameter="--no-check-certificate -N -q"
    fi

    cd "${dir}" || exit

    wget $parameter "$url"
    [[ 0 -eq $? ]] && ret_value=${TRUE}

    cd ${old_dir}

    return ${ret_value}
}

identify_the_operating_system_and_architecture() {
    if [[ "$(uname)" == 'Linux' ]]; then
        if [[ ! -f '/etc/os-release' ]]; then
            show_error_message "不支持过时的 Linux 发行版."
            exit 1
        fi

        linux_distribution=$(cat /etc/os-release | awk -F'[="]' '{if($1=="ID") print $3}')
        linux_distribution_name=$(cat /etc/os-release | awk -F'[="]' '{if($1=="PRETTY_NAME") print $3}')
        linux_distribution_version=$(cat /etc/os-release | awk -F'[="]' '{if($1=="VERSION_ID") print $3}')

        show_striking_message "当前系统为: ${linux_distribution_name}"

        # 请勿将此判断条件与以下判断条件组合使用。
        # 请注意 Gentoo 等 Linux 发行版，其内核支持在 Systemd 和 OpenRC 之间切换。
        # 参考: https://github.com/v2fly/fhs-install-v2ray/issues/84#issuecomment-688574989
        if [[ -f /.dockerenv ]] || grep -q 'docker\|lxc' /proc/1/cgroup && [[ "$(type -P systemctl)" ]]; then
            true
        elif [[ -d /run/systemd/system ]] || grep -q systemd <(ls -l /sbin/init); then
            true
        else
            show_error_message "仅支持使用 systemd 的 Linux 发行版."
            exit 1
        fi
        if [[ "$(type -P apt)" ]]; then
            PACKAGE_MANAGEMENT_UPDATE='apt -y --no-install-recommends update'
            PACKAGE_MANAGEMENT_INSTALL='apt -y --no-install-recommends install'
            PACKAGE_MANAGEMENT_REMOVE='apt purge'
            package_provide_tput='ncurses-bin'
        elif [[ "$(type -P dnf)" ]]; then
            PACKAGE_MANAGEMENT_UPDATE='dnf -y update'
            PACKAGE_MANAGEMENT_INSTALL='dnf -y install'
            PACKAGE_MANAGEMENT_REMOVE='dnf remove'
            package_provide_tput='ncurses'
        elif [[ "$(type -P yum)" ]]; then
            PACKAGE_MANAGEMENT_UPDATE='yum makecache --refresh'
            PACKAGE_MANAGEMENT_INSTALL='yum -y install'
            PACKAGE_MANAGEMENT_REMOVE='yum remove'
            package_provide_tput='ncurses'
        elif [[ "$(type -P zypper)" ]]; then
            PACKAGE_MANAGEMENT_UPDATE='zypper update -y --no-recommends'
            PACKAGE_MANAGEMENT_INSTALL='zypper install -y --no-recommends'
            PACKAGE_MANAGEMENT_REMOVE='zypper remove'
            package_provide_tput='ncurses-utils'
        elif [[ "$(type -P pacman)" ]]; then
            PACKAGE_MANAGEMENT_UPDATE='pacman update -Syu --noconfirm'
            PACKAGE_MANAGEMENT_INSTALL='pacman -Syu --noconfirm'
            PACKAGE_MANAGEMENT_REMOVE='pacman -Rsn'
            package_provide_tput='ncurses'
        else
            show_error_message "不支持此操作系统中的包管理器."
            exit 1
        fi
    else
        show_error_message "不支持此操作系统."
        exit 1
    fi
}

install_init() {
    if [[ "${linux_distribution}" == "centos" && ${linux_distribution_version} -ge 7 ]]; then
        true
    elif [[ "${linux_distribution}" == "debian" && ${linux_distribution_version} -ge 8 ]]; then
        apt update
    elif [[ "${linux_distribution}" == "ubuntu" && $(echo "${linux_distribution_version}" | cut -d '.' -f1) -ge 16 ]]; then
        rm /var/lib/dpkg/lock
        dpkg --configure -a
        rm /var/lib/apt/lists/lock
        rm /var/cache/apt/archives/lock
        apt update
    fi

    ${PACKAGE_MANAGEMENT_INSTALL} dbus

    # systemctl stop firewalld
    # systemctl disable firewalld
    # show_ok_message "firewalld 已关闭"

    # systemctl stop ufw
    # systemctl disable ufw
    # show_ok_message "ufw 已关闭"
}

install_software() {
    package_name="$1"
    file_to_detect="$2"
    type -P "$file_to_detect" >/dev/null 2>&1 && return 0
    if ${PACKAGE_MANAGEMENT_INSTALL} "$package_name"; then
        show_message "$package_name 已安装."
    else
        show_error_message "安装 $package_name 失败，请检查您的网络。"
        exit 1
    fi
}

check_if_running_as_root() {
    if [[ "$UID" -ne '0' ]]; then
        show_error_message "请以 root 用户执行脚本, 终止!"
        exit 1
    fi
}

kill_port_if_exist() {
    local p_port=$1
    if [[ 0 -ne $(lsof -i:"$p_port" | grep -i -c "listen") ]]; then
        # show_ok_message "$p_port 端口未被占用"
        # sleep 1
        # else
        show_warn_message "检测到 $p_port 端口被占用，以下为 $p_port 端口占用信息"
        lsof -i:"$p_port"
        show_striking_message "正在 kill 占用进程"
        sleep 2
        lsof -i:"$p_port" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        show_ok_message "kill 完成"
        sleep 1
    fi
}

service_is_running() {
    local service=$1
    local status=''
    local ret_value=${FALSE}

    status=$(systemctl list-units | grep -wv '●' | awk 'BEGIN{IGNORECASE=1}{if($1~/^'$service'/){print $4}}')
    [ "${status}" == 'running' ] && ret_value=${TRUE}
    return ${ret_value}
}

onekey_installed() {
    if [ -f $v2ray_systemd_file ] && [ -f $onekey_conf ]; then
        return ${TRUE}
    else
        return ${FALSE}
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        show_ok_message "$1 成功"
        sleep 1
    else
        show_error_message "$1 失败"
        exit 1
    fi
}

# 时间同步
# Chrony是NTP（Network Time Protocol，网络时间协议，服务器时间同步的一种协议）
chrony_install() {
    app_name="chrony"
    service_name="chrony"
    if [[ "${linux_distribution}" == "centos" ]]; then
        service_name="chronyd"
    fi

    ${PACKAGE_MANAGEMENT_UPDATE}
    
    result=$(systemctl status $service_name)
    if [[ -z $result ]]; then
        ${PACKAGE_MANAGEMENT_INSTALL} $app_name
        judge "安装 $app_name "
    fi

    systemctl enable $service_name && systemctl restart $service_name
    judge "$service_name 服务自启动"

    # 开启网络时间同步, 每10秒同步一次
    timedatectl set-ntp true
    show_ok_message "网络时间同步已启用"

    timedatectl set-timezone "Asia/Shanghai"
    show_ok_message "设置时区为: Asia/Shanghai"

    if [[ -n $(chronyc activity | head -1 | grep -i "200 OK") ]]; then
        # 立即同步时间
        chronyc makestep
    else
        show_error_message "不能访问时间服务器, 无法自动对时"
    fi

    timedatectl status
}

# 安装依赖的程序
dependency_install() {
    install_software wget wget
    install_software git git
    install_software lsof lsof
    install_software unzip unzip
    install_software qrencode qrencode
    install_software curl curl

    #########################
    # crontabs 任务调度
    #########################
    app_name="cron"
    service_name="cron"
    if [[ "${linux_distribution}" == "centos" ]]; then
        app_name="crontabs"
        service_name="crond"
    fi

    result=$(systemctl status $service_name)
    if [[ -z $result ]]; then
        ${PACKAGE_MANAGEMENT_INSTALL} $app_name
        judge "安装 $app_name "
    fi

    if [[ $(bash service --status-all | grep -c cron) -gt 0 ]]; then
        systemctl enable $service_name && systemctl restart $service_name
        judge "$service_name 服务启动"
    fi

    #########################
    # haveged - 随机数生成器
    #########################
    if [[ $(ls '/dev/urandom' >/dev/null 2>&1 && echo 0) ]]; then
        echo ''
    else
        install_software haveged haveged
        systemctl start haveged && systemctl enable haveged
        judge "haveged 启动"
    fi

    mkdir -p /usr/local/bin >/dev/null 2>&1
}

# Development tools
# 包含常用的开发包，包括gcc，g++等
development_tools_install() {
    if [[ "${linux_distribution}" == "centos" ]]; then
        yum -y groupinstall "Development tools"
    else
        ${PACKAGE_MANAGEMENT_INSTALL} build-essential
    fi
    judge "编译工具包 安装"

    if [[ "${linux_distribution}" == "centos" ]]; then
        ${PACKAGE_MANAGEMENT_INSTALL} pcre pcre-devel zlib-devel epel-release
    else
        ${PACKAGE_MANAGEMENT_INSTALL} libpcre3 libpcre3-dev zlib1g-dev dbus
    fi
}

nginx_install_service() {
    cat >$nginx_systemd_file <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge "Nginx systemd service 安装"
    systemctl daemon-reload
}

nginx_install() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        show_ok_message "Nginx 已安装，不再重复安装"
        return ${TRUE}
    elif [[ -d "/usr/local/nginx/" ]]; then
        show_error_message "发现其他套件安装的 Nginx，继续安装会造成冲突，请处理后安装"
        exit 1
    fi

    # 安装常用开发包
    development_tools_install

    local old_dir=$(pwd)

    [[ -d ${source_dir_for_install} ]] || mkdir -p ${source_dir_for_install}
    cd ${source_dir_for_install}

    show_striking_message "下载 Nginx ..."
    download "$nginx_source_url" "${source_dir_for_install}" "--no-check-certificate -N"
    judge "Nginx 下载"

    show_striking_message "下载 Openssl ..."
    download "$openssl_source_url" "${source_dir_for_install}" "--no-check-certificate -N"
    judge "openssl 下载"

    show_striking_message "下载 Jemalloc ..."
    download "$jemalloc_source_url" "${source_dir_for_install}" "--no-check-certificate -N"
    judge "jemalloc 下载"

    # 解压
    rm -rf ${nginx_package_base}
    tar -zxvf ${nginx_package_name}

    rm -rf ${openssl_package_base}
    tar -zxvf ${openssl_package_name}

    rm -rf ${jemalloc_package_base}
    tar -xvf ${jemalloc_package_name}

    # 编译安装 jemalloc
    show_ok_message "即将开始编译安装 jemalloc"
    sleep 2
    cd "${source_dir_for_install}/${jemalloc_package_base}" || exit
    bash configure
    judge "Jemalloc Configure"
    make -j "${THREAD}" && make install
    judge "Jemalloc 编译安装"
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    ldconfig

    # 编译安装 Nginx
    show_ok_message "即将开始编译安装 Nginx, 过程稍久，请耐心等待"
    sleep 2
    rm -rf ${nginx_dir}
    cd "${source_dir_for_install}/${nginx_package_base}" || exit
    bash configure --prefix="${nginx_dir}" \
        --with-http_ssl_module \
        --with-http_sub_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-pcre \
        --with-http_realip_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_secure_link_module \
        --with-http_v2_module \
        --with-cc-opt='-O3' \
        --with-ld-opt="-ljemalloc" \
        --with-openssl=${source_dir_for_install}/${openssl_package_base}
    judge "Nginx Configure"
    make -j "${THREAD}" && make install
    judge "Nginx 编译安装"

    cd ${old_dir}

    # 清理安装源文件
    rm -rf ${nginx_package_base} ${nginx_package_name}
    rm -rf ${openssl_package_base} ${openssl_package_name}
    rm -rf ${jemalloc_package_base} ${jemalloc_package_name}

    # 修改基本配置
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf

    # 添加配置文件夹，适配旧版脚本
    mkdir ${nginx_dir}/conf/conf.d

    # 安装 Nginx 服务
    nginx_install_service
}

# 卸载 nginx
nginx_uninstall() {
    if [[ -d $nginx_dir ]]; then
        read -rp "要卸载 Nginx? [Y/N](默认:Y, 直接回车, 卸载): " uninstall_nginx
        [[ -z $uninstall_nginx ]] && uninstall_nginx="Y"
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            systemctl daemon-reload
            systemctl stop nginx
            systemctl disable nginx
            systemctl daemon-reload
            rm -rf $nginx_dir $nginx_systemd_file

            show_ok_message "已卸载 Nginx"
            ;;
        *)
            show_striking_message "不卸载"
            ;;
        esac
    else
        show_error_message "未安装"
    fi
}

basic_optimization() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # 关闭 Selinux
    # if [[ "${linux_distribution}" == "centos" ]]; then
        # sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        # setenforce 0
    # fi

}

v2ray_install() {
    if [ -f $v2ray_systemd_file ]; then
        uninstall_v2ray_silence
    fi

    bash ${v2ray_script} --force
    ls "${v2ray_systemd_file}"  > /dev/null 2>&1
    judge "安装 V2ray"
}

# 升级 v2ray core
v2ray_upgrade() {
    local check_result=$(bash "${v2ray_script}" --check)
    if (( $(echo check_result | grep -Ec "Found the latest") == 0)); then
        show_striking_message "V2ray 无新版本"
        return 0
    fi

    read -rp "要升级 V2Ray? [Y/N](默认:Y, 直接回车, 升级): " confirm_install
    [[ -z $confirm_install ]] && confirm_install="Y"
    case $confirm_install in
    [yY][eE][sS] | [yY])
        systemctl daemon-reload
        systemctl stop v2ray

        v2ray_install
        v2ray_test_config

        systemctl daemon-reload
        systemctl enable v2ray
        systemctl start v2ray
        judge "V2ray 启动"
        ;;
    *)
        show_striking_message "已取消"
        return 0
        ;;
    esac
}

# 卸载 v2ray core
uninstall_v2ray_silence() {
    bash ${v2ray_script} --remove
    rm -rf $v2ray_log_dir
}

uninstall_v2ray() {
    show_striking_message "卸载 V2ray 时, 配置文件将会备份, 并在重新安装时, 提供可选项。"
    read -rp "要卸载 V2Ray? [Y/N](默认:Y, 直接回车, 卸载): " confirm_uninstall_all
    [[ -z $confirm_uninstall_all ]] && confirm_uninstall_all="Y"
    case $confirm_uninstall_all in
    [yY][eE][sS] | [yY])
        ;;
    *)
        show_striking_message "不卸载"
        exit 0
        ;;
    esac

    uninstall_v2ray_silence
    rm -rf ${v2ray_conf_dir}

    # 备份并卸载本脚本配置文件
    if [ -f $onekey_conf ]; then
        mv -f $onekey_conf $onekey_conf_bak
    fi

    show_ok_message "已卸载"
}

#####################################################
# 实用程序
#####################################################

download_web_camouflage() {
    [ ! -d "${webroot_dir}" ] && mkdir -p "${webroot_dir}"
    local old_dir=$(pwd)

    local ret_error=${FALSE}
    if [ ! -d ${web_install_path} ]; then
        cd "${webroot_dir}"
        git clone ${web_url}
        [[ 0 -ne $? ]] && ret_error=${TRUE}

        if [ $ret_error == ${FALSE} ] && [ -d ${web_install_path} ]; then
            show_ok_message "伪装网站文件下载成功"
            show_striking_message "伪装网站路径： ${web_install_path}"
        else
            show_error_message "伪装网站文件下载失败, 请重试. ${web_install_path}"
        fi
    else
        show_ok_message "伪装网站文件已存在"
        show_striking_message "伪装网站路径： ${web_install_path}"
    fi

    cd ${old_dir}
}

domain_check() {
    show_ok_message "正在获取 $domain 的公网ip，请耐心等待"
    ping_result=$(ping $domain -c 1)
    domain_ip=$(echo $ping_result | grep "PING" | awk -F ' ' '{print $3}' | sed 's/(//g' | sed 's/)//g')

    if [[ -z $domain_ip ]]; then
        show_error_message "无法获取 $domain 的公网ip，请确认域名输入是否正确"
        exit 2
    fi

    show_message "$domain 的 DNS 解析到: ${domain_ip}"

    local_ipv4=$(curl -s https://api-ipv4.ip.sb/ip -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36’')
    local_ipv6=$(curl -s https://api-ipv6.ip.sb/ip -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36’')
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        echo nameserver 2a01:4f8:c2c:123f::1 >/etc/resolv.conf
        show_ok_message "识别为 IPv6 Only 的 VPS，自动添加 DNS64 服务器"
    fi

    show_message "本机IPv4: ${local_ipv4}"
    show_message "本机IPv6: ${local_ipv6}"

    if [[ ${domain_ip} = ${local_ipv4} ]]; then
        show_ok_message "域名 DNS 解析 IP 与本机 IPv4 匹配"
    elif [[ ${domain_ip} = ${local_ipv6} ]]; then
        show_ok_message "域名 DNS 解析 IP 与本机 IPv6 匹配"
    else
        show_error_message "域名 DNS 解析 IP 与 本机 IPv4 / IPv6 不匹配"
        show_error_message "请确保域名添加了正确的 A / AAAA 记录，否则将无法正常使用 V2ray，也无法申请 SSL 证书"
        read -rp "是否继续安装? [Y/N](默认:Y, 直接回车, 继续安装): " -t 10 install_confirm
        [[ -z $install_confirm ]] && install_confirm="Y"
        case $install_confirm in
        [yY][eE][sS] | [yY])
            show_striking_message "${F_GREEN_BG} 继续安装"
            sleep 2
            ;;
        *)
            show_striking_message "${F_RED_BG} 安装终止"
            exit 2
            ;;
        esac
    fi
}

########################
# 修改 V2Ray 配置文件
########################

modify_alterid() {
    json_set_value $v2ray_conf 'alterId' $alterID
    judge "V2ray alterid 修改"
}

modify_inbound_port() {
    local new_port=$1
    json_set_value $v2ray_conf 'port' $new_port
    judge "V2ray inbound port 修改"
}

modify_UUID() {
    [ -z "$uuid" ] && uuid="$(gen_uuid)"
    json_set_value $v2ray_conf 'id' $uuid
    judge "V2ray UUID 修改"
}

modify_ssl_cert_path() {
    json_set_value $v2ray_conf 'certificateFile' $ssl_cert_fullchain_path
    json_set_value $v2ray_conf 'keyFile' $ssl_cert_key_path
}

modify_obfs_path() {
    json_set_value $v2ray_conf 'path' $obfsPath
    judge "V2ray 配置伪装路径修改"
}

when_after_modify() {
    save_onekey_config
    nginx_and_v2ray_service_restart
    show_v2ray_config_desc
}

v2ray_test_config() {
    if ! v2ray test -c ${v2ray_conf}; then
        show_error_message "V2Ray 验证配置失败"
        exit 1
    fi
}

v2ray_conf_init_ws() {
    cd $v2ray_conf_dir || exit
    wget --no-check-certificate "${onekey_base_url}/v2ray_config_templates/VMess-Websocket-TLS/config.json" -O config.json
    modify_obfs_path
    modify_alterid
    modify_inbound_port $inbound_port
    modify_UUID

    v2ray_test_config
}

v2ray_conf_init_h2() {
    cd $v2ray_conf_dir || exit
    wget --no-check-certificate "${onekey_base_url}/v2ray_config_templates/VMess-HTTP2-TLS/config.json" -O config.json
    modify_obfs_path
    modify_alterid
    modify_inbound_port $port
    modify_UUID
    modify_ssl_cert_path

    v2ray_test_config
}

########################
# 修改 Nginx 配置文件
########################

# 修改 Nginx 配置文件通用函数, 替换 modify_id 注释的下一行内容为 value
nginx_conf_modify() {
    local conf_file=$1
    local modify_id=$2
    local value=$3

    local full_string=$(grep -n -E "$modify_id" "${conf_file}")
    local row_number=${full_string%%:*}
    ((row_number = row_number + 1))

    sed -i "${row_number}a\\${value}" "${conf_file}"
    sed -i "${row_number}d" "${conf_file}"
}

modify_nginx_obfs_path() {
    nginx_conf_modify $nginx_conf $_bash_var_modify_id_obfs_path "    location ${obfsPath}"
    judge "Nginx 配置伪装路径修改"
}

modify_nginx_port() {
    local new_port=$1
    nginx_conf_modify $nginx_conf $_bash_var_modify_id_port_1 "    listen ${new_port} ssl http2;"
    nginx_conf_modify $nginx_conf $_bash_var_modify_id_port_2 "    listen [::]:${new_port} http2;"

    judge "Nginx port 修改"
}

modify_nginx_tls_version() {
    if [[ ! -f "$nginx_conf" ]]; then
        show_error_message "Nginx 配置文件不存在: $nginx_conf"
        exit 1
    fi

    if [[ "$obfsType" != "ws" ]]; then
        show_error_message "只适用于混淆类型 ws, 当前为: $obfsType"
        exit 1
    fi

    local max_index=${#TLS_VERSION_CAPTION_ARRAY[@]}

    if (( tls_version > max_index )); then
        local _bash_var_tls_version=${TLS_VERSION_VALUE_ARRAY["$tls_version"]}
        nginx_conf_modify $nginx_conf $_bash_var_modify_id_tls_version "    ssl_protocols         ${_bash_var_tls_version};"
        show_ok_message "已切换至 ${TLS_VERSION_CAPTION_ARRAY["$tls_version"]}"
    else
        show_error_message "参数错误"
        exit 1
    fi
}

modify_nginx_domain() {
    nginx_conf_modify $nginx_conf $_bash_var_modify_id_domain_1 "    server_name           ${domain};"
    nginx_conf_modify $nginx_conf $_bash_var_modify_id_domain_2 "    server_name           ${domain};"
    nginx_conf_modify $nginx_conf $_bash_var_modify_id_domain_3 "    return 301 https://${domain}\$request_uri;"

    judge "Nginx 配置域名修改"
}

modify_nginx_inbound_port() {
    nginx_conf_modify $nginx_conf $_bash_var_modify_id_inbound_port "        proxy_pass http://127.0.0.1:${inbound_port};"
    judge "Nginx 配置的 V2Ray inbound port 修改"
}

build_nginx_config_for_v2ray() {
    local _bash_var_port=$port
    local _bash_var_obfsPath=$obfsPath
    local _bash_var_domain=$domain
    local _bash_var_inbound_port=$inbound_port
    local _bash_var_tls_version=${TLS_VERSION_VALUE_ARRAY["$tls_version"]}

    local _bash_var_do_not_modify="The following line is managed by ${onekey_script_name}. don't modify!!!"

    # 备份
    if [ -f $nginx_conf ]; then
        local nginx_conf_backup="${nginx_conf}.bak"
        rm -rf $nginx_conf_backup
        cp $nginx_conf $nginx_conf_backup
    fi

    cat >${nginx_conf} <<EOF
server {
    ### ${_bash_var_do_not_modify} ${_bash_var_modify_id_port_1} ###
    listen ${_bash_var_port} ssl http2;

    ### ${_bash_var_do_not_modify} ${_bash_var_modify_id_port_2} ###
    listen [::]:${_bash_var_port} http2;

    ssl_certificate       ${ssl_cert_fullchain_path};
    ssl_certificate_key   ${ssl_cert_key_path};

    ### ${_bash_var_do_not_modify} ${_bash_var_modify_id_tls_version} ###
    ssl_protocols         ${_bash_var_tls_version};

    ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;

    ### ${_bash_var_do_not_modify} ${_bash_var_modify_id_domain_1} ###
    server_name           ${_bash_var_domain};

    index index.html index.htm;
    root ${web_install_path};
    error_page 400 = /400.html;

    # Config for 0-RTT in TLSv1.3
    ssl_early_data on;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security "max-age=31536000";

    ### ${_bash_var_do_not_modify} ${_bash_var_modify_id_obfs_path} ###
    location ${_bash_var_obfsPath}
    {
        proxy_redirect off;
        proxy_read_timeout 1200s;

        ### ${_bash_var_do_not_modify} ${_bash_var_modify_id_inbound_port} ###
        proxy_pass http://127.0.0.1:${_bash_var_inbound_port};

        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;

        # Config for 0-RTT in TLSv1.3
        proxy_set_header Early-Data \$ssl_early_data;
    }
}

server {
    listen 80;
    listen [::]:80;

    ### ${_bash_var_do_not_modify} ${_bash_var_modify_id_domain_2} ###
    server_name           ${_bash_var_domain};

    ### ${_bash_var_do_not_modify} ${_bash_var_modify_id_domain_3} ###
    return 301 https://${_bash_var_domain}\$request_uri;
}
EOF

    judge "Nginx 配置修改"
}

nginx_and_v2ray_service_stop() {
    systemctl daemon-reload
    if [[ $obfsType == "ws" ]]; then
        systemctl stop nginx
    fi
    systemctl stop v2ray
}

# 重启 Nginx 和 v2ray 服务
nginx_and_v2ray_service_restart() {
    nginx_and_v2ray_service_stop

    rm -rf $v2ray_log_dir
    mkdir -p $v2ray_log_dir
    chown -R root.root $v2ray_log_dir

    if [[ $obfsType == "ws" ]]; then
        local service='nginx'
        systemctl start ${service}
        if service_is_running "${service}"; then
            show_ok_message "Nginx 启动成功"
        else
            show_error_message "Nginx 启动失败"
            systemctl status ${service}
        fi
    fi

    local service='v2ray'
    systemctl start ${service}
    if service_is_running "${service}"; then
        show_ok_message "V2ray 启动成功"
    else
        show_error_message "V2ray 启动失败"
        systemctl status ${service}
    fi
}

# Nginx 和 v2ray 服务设置为开机时启动
nginx_and_v2ray_service_enable() {
    systemctl enable v2ray
    judge "设置 v2ray 开机自启"
    if [[ $obfsType == "ws" ]]; then
        systemctl enable nginx
        judge "设置 Nginx 开机自启"
    fi
}

nginx_process_disabled() {
    [ -f $nginx_systemd_file ] && systemctl stop nginx && systemctl disable nginx
}

#debian 系 9 10 适配
#rc_local_initialization(){
#    if [[ -f /etc/rc.local ]];then
#        chmod +x /etc/rc.local
#    else
#        touch /etc/rc.local && chmod +x /etc/rc.local
#        echo "#!/bin/bash" >> /etc/rc.local
#        systemctl start rc-local
#    fi
#
#    judge "rc.local 配置"
#}

build_v2rayn_config_ws() {
    local output_file=$1

    cat >$output_file <<-EOF
{
  "v": "2",
  "ps": "${configAlias}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${uuid}",
  "aid": "${alterID}",
  "net": "ws",
  "type": "none",
  "host": "${domain}",
  "path": "${obfsPath}",
  "tls": "tls"
}
EOF
}

build_v2rayn_config_h2() {
    local output_file=$1

    cat >$output_file <<-EOF
{
  "v": "2",
  "ps": "${configAlias}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${uuid}",
  "aid": "${alterID}",
  "net": "h2",
  "type": "none",
  "path": "${obfsPath}",
  "tls": "tls"
}
EOF
}

build_quantumult_config_ws() {
    local output_file=$1

    cat >$output_file <<-EOF
$configAlias = vmess, $domain, $port, chacha20-ietf-poly1305, "$uuid", \
        over-tls=true, certificate=1, obfs=ws, obfs-path="$obfsPath",
EOF
}

# 将配置文件编码为 base64，生成文本二维码，针对 V2RayNG/V2RayN/Fair 客户端
build_vmess_link_for_v2rayn() {
    if [[ $obfsType == "ws" ]]; then
        build_v2rayn_config_ws $v2ray_qr_config_file
    elif [[ $obfsType == "h2" ]]; then
        build_v2rayn_config_h2 $v2ray_qr_config_file
    fi

    vmess_link="vmess://$(base64 -w 0 $v2ray_qr_config_file)"

    show_message ""
    show_message "1: 适用 V2RayNG(Android), V2RayN(Android), Fair(iOS) 客户端"
    show_message "链接: ${vmess_link}"
    echo -n "${vmess_link}" | qrencode -o - -t utf8
}

# 将配置文件编码为 base64，生成文本二维码，针对 quantumult 客户端
build_vmess_link_for_quantumult() {
    build_quantumult_config_ws $v2ray_qr_config_file

    vmess_link="vmess://$(base64 -w 0 $v2ray_qr_config_file)"

    show_message ""
    show_message "2: 适用 Quantumult(iOS) 客户端"
    show_message "链接: ${vmess_link}"
    echo -n "${vmess_link}" | qrencode -o - -t utf8
}

# 生成客户端 vmess link 和二维码
build_client_vmess_link_and_qrcode() {
    build_vmess_link_for_v2rayn
    if [[ $obfsType == "ws" ]]; then
        build_vmess_link_for_quantumult
    fi
}

# 生成直观的设置信息
build_v2ray_config_desc() {
    if [[ -f $onekey_conf ]]; then
        show_message "配置别名: $configAlias"
        show_message "地址（address）: $domain"
        show_message "端口（port）: $port"
        show_message "用户id（UUID）: $uuid"
        show_message "额外id（alterId）: $alterID"
        show_message "加密方式（security）: auto"
        show_message "传输协议（network）: $obfsType"
        show_message "伪装类型（type）: none"
        show_message "路径（不要漏掉 /）: $obfsPath"
        show_message "底层传输安全: tls"
        if [[ $obfsType == "ws" ]]; then
            show_message ""
            show_message "Nginx TLS 版本:${TLS_VERSION_CAPTION_ARRAY["$tls_version"]}"
        fi
    else
        show_error_message "配置文件不存在: $onekey_conf, 请确认已经成功安装。"
    fi
}

show_v2ray_config_desc() {
    show_message "---------------------------------"
    show_message "V2ray 配置信息"
    show_message "---------------------------------"
    build_v2ray_config_desc

    show_message ""
    show_message "---------------------------------"
    show_message "V2ray 客户端配置导入链接和二维码"
    show_message "---------------------------------"
    show_message "在客户端通过输入以下链接或扫描二维码导入配置"
    build_client_vmess_link_and_qrcode
}

ask_config_domain() {
    read -rp "请输入你的主机域名(eg:youwebsite.com):" domain
    if [[ -z "$domain" ]]; then
        show_error_message "域名不能为空"
        ask_config_domain
    else
        show_ok_message "正在获取 $domain 的公网ip，请耐心等待"
        ping_result=$(ping $domain -c 1)
        domain_ip=$(echo $ping_result | grep "PING" | awk -F ' ' '{print $3}' | sed 's/(//g' | sed 's/)//g')

        if [[ -z $domain_ip ]]; then
            show_error_message "域名无法访问，请重新输入"
            ask_config_domain
        fi
    fi

    show_ok_message "域名: $domain"
}

ask_alterid() {
    read -rp "请输入alterID [仅允许填数字](默认:0): " input_cache_alterID
    if [[ -n ${input_cache_alterID} ]]; then
        local tmp_input=$(echo ${input_cache_alterID} | grep -Eo "[[:digit:]]+")
        if [[ -z ${tmp_input} ]] || [[ ${tmp_input} != ${input_cache_alterID} ]]; then
            show_error_message "仅允许填数字"
            ask_alterid
        else
            ((alterID=input_cache_alterID+0))
        fi
    else
        alterID=0
    fi

    json_set_value $v2ray_conf 'alterId' "$alterID"
    show_ok_message "alterID:${alterID}"
}

ask_port() {
    read -rp "请输入端口 [仅允许填数字](默认:443): " input_cache_port
    if [[ -n ${input_cache_port} ]]; then
        local tmp_input=$(echo ${input_cache_port} | grep -Eo "[[:digit:]]+")
        if [[ -z ${tmp_input} ]] || [[ ${tmp_input} != ${input_cache_port} ]]; then
            show_error_message "仅允许填数字, 请重新输入"
            ask_port
        else
            ((port=input_cache_port+0))
        fi
    else
        port=443
    fi
}

show_tls_version_tips() {
    show_message "请选择支持的 TLS 版本:"
    show_message "请注意,如果你使用 Quantaumlt X / 路由器 / 旧版 Shadowrocket / 低于 4.18.1 版本的 V2ray core 请选择 兼容模式"
    for key in ${!TLS_VERSION_CAPTION_ARRAY[*]}; do
        show_message "${TLS_VERSION_CAPTION_ARRAY[$key]}"
    done
    show_message "0. 取消"
}

ask_tls_version() {
    if [[ -z "${is_show_tls_version_tips}" ]] || (( is_show_tls_version_tips == 1 )); then
        show_tls_version_tips
    fi

    local max_index=${#TLS_VERSION_CAPTION_ARRAY[@]}
    local tls_version_input=''
    read -rp "请输入菜单编号 [仅允许填数字](默认:$tls_version_default): " tls_version_input

    if [[ -n ${tls_version_input} ]]; then
        local tmp_input=$(echo "${tls_version_input}" | grep -Eo "[[:digit:]]+")
        if [[ -z ${tmp_input} ]] || [[ ${tmp_input} -ne ${tls_version_input} ]]; then
            show_error_message "仅允许填数字, 请重新输入"
            is_show_tls_version_tips=0
            ask_tls_version
        elif (( tls_version_input > max_index )); then
            show_error_message "超出范围(0 ~ ${max_index}), 请重新输入"
            is_show_tls_version_tips=0
            ask_tls_version
        fi
    else
        tls_version_input=$tls_version_default
    fi

    if (( tls_version_input != 0 )); then
        ((tls_version=tls_version_input+0))
    else
        show_striking_message "已取消"
        exit 1
    fi
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
        init_default_value
        source $conf_file
    elif [[ silence -eq 0 ]]; then
        show_error_message "配置文件不存在: $conf_file"
        exit 1
    fi
}

# 询问用户
ask_user_input() {
    ask_config_domain
    ask_enable_acme_sh
    show_ok_message "提问完毕, 接着将执行静默安装..."
    sleep 2
}

ask_use_old_config() {
    if [ -f $onekey_conf_bak ]; then
        show_striking_message "检测到旧配置文件: $onekey_conf_bak"
        echo ""
        cat ${onekey_conf_bak}
        echo ""
        read -p "是否依照旧配置安装? [Y/N](默认:Y, 直接回车, 依照旧配置安装): " confirm_use_old_config
        [[ -z $confirm_use_old_config ]] && confirm_use_old_config=y
        case $confirm_use_old_config in
        [nN][oO] | [nN])
            ask_user_input
            ;;
        [yY][eE][sS] | [yY])
            local bak_obfsType=${obfsType}
            read_config $onekey_conf_bak
            obfsType=${bak_obfsType}
            show_ok_message "已读取旧配置文件, 接着将执行静默安装..."
            sleep 2
            ;;
        *)
            show_error_message "不能识别的值，请重新输入"
            ask_use_old_config
            ;;
        esac
    fi
}

input_config() {
    if [[ -f "$onekey_conf_bak" ]]; then
        ask_use_old_config
    else
        ask_user_input
    fi
}

#####################################################
# 证书
#####################################################

acme_sh_is_enabled() {
    if [[ $acme_sh_enabled -eq 1 ]]; then
        return ${TRUE}
    else
        return ${FALSE}
    fi
}

acme_sh_cert_exist() {
    # 从列表中搜索域名, 包括备用域名, 不包括测试的证书
    if [[ $(bash $acme_sh_file --list | grep "${domain}" | awk '{if($4=="LetsEncrypt.org") print $0}' |
        awk '{print $1,$3}' | tr ',\n' ' ' | xargs | awk '{split($0,array," ")} {for(i in array) print array[i]}' |
        grep -c "^${domain}$") -gt 0 ]]; then
        # .acme.sh 目录下已有证书
        return ${TRUE}
    else
        return ${FALSE}
    fi
}

show_enable_acme_sh_tips() {
    show_message "启用 acme 管理 SSL 证书, 可以自动申请免费证书, 并定期更新证书"
    if [[ ! -f $ssl_cert_fullchain_path ]] || [[ ! -f $ssl_cert_key_path ]]; then
        show_message "如果不启用 acme, 你需要首先复制已有的证书到以下路径才能继续安装: "
        show_message "  $ssl_cert_fullchain_path"
        show_message "  $ssl_cert_key_path"
    fi
}

ask_enable_acme_sh() {
    if [[ -z "${is_show_enable_acme_sh_tips}" ]] || (( is_show_enable_acme_sh_tips == 1 )); then
        show_enable_acme_sh_tips
    fi

    read -rp "是否启用 acme? [Y/N](默认:Y, 不知道是什么, 就直接回车): " confirm_acme_sh_enabled
    [[ -z $confirm_acme_sh_enabled ]] && confirm_acme_sh_enabled="Y"

    case $confirm_acme_sh_enabled in
    [yY][eE][sS] | [yY])
        acme_sh_enabled=1
        show_striking_message "启用 acme 管理 SSL 证书"
        ;;
    [[nN][oO] | [nN])
        acme_sh_enabled=0
        show_striking_message "不启用 acme 管理 SSL 证书"
        if [[ ! -f $ssl_cert_fullchain_path ]] || [[ ! -f $ssl_cert_key_path ]]; then
            show_error_message "未发现证书，安装中断"
            show_error_message "你需要首先复制已有的证书到以下路径才能继续安装:"
            show_message "  $ssl_cert_fullchain_path"
            show_message "  $ssl_cert_key_path"
            exit 1
        fi
        ;;
    *)
        show_error_message "输入错误, 请重新输入"
        is_show_enable_acme_sh_tips=0
        ask_enable_acme_sh
        ;;
    esac

    is_show_enable_acme_sh_tips=1
}

# 安装 SSL 证书申请脚本
acme_sh_install() {
    install_software socat socat
    install_software nmap netcat

    if [[ ! -f $acme_sh_file ]]; then
        wget -O - $get_acme_sh_url | sh
        judge "安装 SSL 证书管理脚本 acme"
    fi

    # acme.sh 自动更新
    $acme_sh_file --upgrade --auto-upgrade

    # 安装添加定期更新任务
    $acme_sh_file --install-cronjob
    
    # 添加定期复制证书任务
    local CRONTAB_STDIN="crontab -"
    local CRONTAB="crontab"

    local time_str=$($CRONTAB -l | grep -E "^\s*.+/acme.sh --cron --home" | grep -Eo "^\s*[0-9]+\s+[0-9*]+\s+[0-9*]+\s+[0-9*]+\s+[0-9*]+\s+")
    local minute=$(echo $time_str | awk '{print $1}')
    ((minute++))
    local new_time_str="$minute $(echo $time_str | awk '{print $2,$3,$4,$5}')" 

    $CRONTAB -l | sed "/$install_certs_script/d" | $CRONTAB_STDIN
    $CRONTAB -l | {
        cat
        # echo "$new_time_str $install_certs_script_path  > /dev/null
        echo "$new_time_str $install_certs_script_path > /root/${install_certs_script}.log"
    } | $CRONTAB_STDIN
}

# 卸载 SSL 证书管理脚本, 会自动删除 crontab 任务
acme_sh_uninstall() {
    read -rp "是否卸载 SSL 证书管理脚本? [Y/N](默认:Y, 直接回车, 卸载): " uninstall_acme
    [[ -z $uninstall_acme ]] && uninstall_acme="Y"
    case $uninstall_acme in
    [yY][eE][sS] | [yY])
        [[ -f $acme_sh_file ]] && bash $acme_sh_file uninstall
        judge "SSL 证书管理脚本 acme 卸载"
        ;;
    *)
        show_striking_message "不卸载 SSL 证书管理脚本 acme"
        ;;
    esac
}

# 签发证书.
# 有限制，7天内超过 5 次, 提示 Error creating new order :: too many certificates (5) already issued
# 但仍然下载此前签发的证书
acme_sh_issue_cert() {
    # 切换证书签发机构
    bash $acme_sh_file --set-default-ca --server letsencrypt
    if (! acme_sh_cert_exist); then
        # 请求签发证书
        show_message "\n请求签发 SSL 证书 ... \n"
        bash $acme_sh_file --issue --insecure -d "${domain}" --standalone -k ec-256 --ecc --force >/dev/null 2>&1
    fi

    show_message "当前可用证书"
    bash $acme_sh_file --list | head -1
    bash $acme_sh_file --list | awk '{if($4=="LetsEncrypt.org") print $0}'

    if (acme_sh_cert_exist); then
        show_ok_message "SSL 证书签发成功"
    else
        show_error_message "SSL 证书签发失败"
        exit 1
    fi
}

# 安装证书
acme_sh_install_cert() {
    if acme_sh_cert_exist; then
        local main_domail=$domain
        if [[ $(bash $acme_sh_file --list | awk '{if($4=="LetsEncrypt.org") print $1}' | grep -c "^${domain}$") == 0 ]]; then
            # 在 acme 列表中查找主域名
            # 如果主域名列中找不到 $domain, 则在 SAN_Domains 列查找并返回主域名
            local tmp_str=$(bash $acme_sh_file --list | awk '{if($4=="LetsEncrypt.org") print $0}' |
                awk -v domail_tmp=$domain '{split($3,array,",")} {for(i in array){if(array[i]==domail_tmp) print $1}}' |
                head -1)
            [[ -n $tmp_str ]] && main_domail=$tmp_str
        fi

        # 本地已有证书, 则安装证书
        show_message "\n安装 SSL 证书 ..."
        # bash $acme_sh_file --install-cert -d "${main_domail}" --fullchain-file "$ssl_cert_fullchain_path" --key-file "$ssl_cert_key_path" --ecc --force
        bash $install_certs_script
        judge "安装 SSL 证书 ${main_domail}"
    else
        show_error_message "本地无 SSL 证书, 安装中断"
        exit 1
    fi
}

# 手动更新证书. 有限制，7天内不超过 5 次
ssl_cert_update_manuel() {
    if onekey_installed; then
        nginx_and_v2ray_service_stop
        bash $acme_sh_file --cron
        bash $acme_sh_file --list
        acme_sh_install_cert
        nginx_and_v2ray_service_restart
    fi
}

# 生成安装证书脚本, 用于被 crontabs 定期调用, 以安装更新的证书（已过时）
build_ssl_cert_update_sh() {
    cat >${ssl_cert_update_sh} <<EOF
#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

if [[ -f "$onekey_conf" ]]; then
    source "$onekey_conf"
    if [[ -f "$acme_sh_dir/\${domain}_ecc/\${domain}.key" && -f "$acme_sh_dir/\${domain}_ecc/\${domain}.cer" ]]; then
        systemctl stop nginx &> /dev/null
        sleep 1
        bash $acme_sh_file --cron --home "$acme_sh_dir" &> /dev/null
        bash $acme_sh_file --install-cert -d "\$domain" --fullchain-file "$ssl_cert_fullchain_path" --key-file "$ssl_cert_key_path" --ecc
        sleep 1
        systemctl start nginx &> /dev/null
    fi
fi
EOF
}

# 添加证书定期更新任务（已过时）
add_ssl_cert_update_cron() {
    remove_ssl_cert_update_cron
    build_ssl_cert_update_sh

    # crontab 任务格式: minute hour day month week command
    sed -i "/acme.sh/a\50 0 * * * ( bash $ssl_cert_update_sh )  >> /root/crontab.log" $crontabs_path
    judge "添加证书定期更新任务"
    crontab -l
}

# 移除证书定期更新任务（已过时）
remove_ssl_cert_update_cron() {
    local file_path=$(echo $ssl_cert_update_sh | sed 's#/#\\/#g')
    sed -i "/$file_path/d" $crontabs_path
    judge "移除证书定期更新任务"

    rm -rf $ssl_cert_update_sh
    crontab -l
}

#####################################################
# 其它功能
#####################################################

show_access_log() {
    [ -f ${v2ray_access_log} ] && tail -f ${v2ray_access_log} || show_error_message "log文件不存在"
}

show_error_log() {
    [ -f ${v2ray_error_log} ] && tail -f ${v2ray_error_log} || show_error_message "log文件不存在"
}

run_system_tcp_speed_up() {
    local system_tcp_speed_up_sh="tcp.sh"
    local system_tcp_speed_up_dir="system_tcp_speed_up"

    [ ! -d "${system_tcp_speed_up_dir}" ] && mkdir "${system_tcp_speed_up_dir}"
    cd "${system_tcp_speed_up_dir}"
    rm -rf "${system_tcp_speed_up_sh}"
    download ${system_tcp_speed_up_install_sh_url}
    if [ ! -f "${system_tcp_speed_up_sh}" ]; then
        show_error_message "脚本下载失败: ${system_tcp_speed_up_install_sh_url}"
        return 1
    fi

    bash "${system_tcp_speed_up_sh}"
}

mtproxy_sh() {
    show_error_message "功能维护，暂不可用"
}

#####################################################
# 安装与配置 v2ray (ws tls 方式)
#####################################################
install_v2ray_ws_tls() {
    obfsType="ws"

    install_init
    basic_optimization

    # 获得参数
    input_config
    domain_check

    # 依赖的软件
    chrony_install
    dependency_install

    nginx_and_v2ray_service_stop
    kill_port_if_exist 80
    kill_port_if_exist ${port}

    # 安装及设置 acme SSL 证书管理脚本
    if acme_sh_is_enabled; then
        acme_sh_install
        acme_sh_issue_cert
        acme_sh_install_cert
    fi

    # 安装及设置 v2ray core
    v2ray_install
    v2ray_conf_init_ws

    # 安装及设置 nginx
    nginx_install
    build_nginx_config_for_v2ray
    download_web_camouflage

    # 启动服务
    nginx_and_v2ray_service_restart
    nginx_and_v2ray_service_enable

    # 显示客户端配置二维码或连接
    save_onekey_config
    show_v2ray_config_desc

    show_ok_message "安装成功"
}

#####################################################
# 安装与配置 v2ray (HTTP/2 方式)
#####################################################
install_v2ray_h2() {
    obfsType="h2"

    install_init
    basic_optimization

    # 获得参数
    input_config
    domain_check

    # 依赖的软件
    chrony_install
    dependency_install

    systemctl stop v2ray
    kill_port_if_exist 80
    kill_port_if_exist "${port}"

    # 安装及设置 acme SSL 证书管理脚本
    if acme_sh_is_enabled; then
        acme_sh_install
        acme_sh_issue_cert
        acme_sh_install_cert
    fi

    # 安装及设置 v2ray core
    v2ray_install
    v2ray_conf_init_h2

    # 启动服务
    nginx_and_v2ray_service_restart
    nginx_and_v2ray_service_enable

    # 显示客户端配置二维码或连接
    save_onekey_config
    show_v2ray_config_desc

    show_ok_message "安装成功"
}

#####################################################
# 检查脚本更新
#####################################################
onekey_script_new_version_found() {
    remote_version=$(wget -q -O - "${onekey_base_url}/${main_script}" | grep "onekey_script_version=" | head -1 | awk -F '=|"' '{print $3}')
    [ -z "${remote_version}" ] && remote_version="0"
    if [[ ${onekey_script_version} < ${remote_version} ]]; then
        return ${TRUE}
    else
        return ${FALSE}
    fi
}

# 更新脚本
onekey_script_update() {
    if onekey_installed; then
        show_error_message "请先卸载 V2ray\n"
        uninstall_v2ray
    elif onekey_script_new_version_found; then
        show_striking_message "发现新版本 “${onekey_script_title}”: ${remote_version}"
        read -rp "是否更新? [Y/N](默认:N, 直接回车, 不更新): " update_confirm
        [ -z $update_confirm ] && update_confirm="N"
        case $update_confirm in
        [yY][eE][sS] | [yY])
            # 下载到临时目录
            local cur_dir=$(pwd)
            local temp_dir=$(mktemp -d)
            cd ${temp_dir} || exit 1
            download_required_scripts
            cd ${cur_dir}

            # 备份
            backup_required_scripts

            # 复制到脚本目录
            local ret_error=${FALSE}
            \cp -r "${temp_dir}"/* "${one_key_conf_dir}"/ > /dev/null 2>&1
            if [[ 0 -ne $? ]]; then
                ret_error=${TRUE}
            fi

            rm -rf "${temp_dir}"
            if [ $ret_error != ${TRUE} ]; then
                local launcher_script_path="${one_key_conf_dir}/${launcher_script}"
                [ -f "${launcher_script_path}" ] && chmod a+x "${launcher_script_path}"

                # 为启动脚本建立软链接
                make_launcher_symbolic_link

                show_ok_message "已更新"
                exit 0
            else
                [ -f "${backup_one_key_script_tar}" ] && tar xzvf "${backup_one_key_script_tar}" > /dev/null 2>&1
                show_error_message "更新失败, 请重试."
                exit 1
            fi
            ;;
        *)
            show_striking_message "已取消"
            ;;
        esac
    else
        show_striking_message "“${onekey_script_title}”无新版本"
    fi
}

#####################################################
# 主菜单
#####################################################

# 菜单数据
# key 是动作 id, 必须是 menu_action 中定义的 id, 以 "_" 开头的 id 不响应动作
# menu_for_xxx_order_array  菜单顺序, 依照此数组顺序显示菜单
# menu_text_map             菜单文字

# 菜单动作 id
action_do_exit='action_do_exit'
action_install_v2ray_ws_tls='action_install_v2ray_ws_tls'
action_install_v2ray_h2='action_install_v2ray_h2'
action_show_v2ray_config_desc='action_show_v2ray_config_desc'
action_modify_UUID='action_modify_UUID'
action_modify_port='action_modify_port'
action_modify_nginx_tls_version='action_modify_nginx_tls_version'
action_modify_obfs_path='action_modify_obfs_path'
action_show_access_log='action_show_access_log'
action_show_error_log='action_show_error_log'
action_run_system_tcp_speed_up='action_run_system_tcp_speed_up'
action_mtproxy_sh='action_mtproxy_sh'
action_onekey_script_update='action_onekey_script_update'
action_v2ray_core_update='action_v2ray_core_update'
action_ssl_cert_update_manuel='action_ssl_cert_update_manuel'
action_nginx_and_v2ray_service_restart='action_nginx_and_v2ray_service_restart'
action_uninstall_v2ray='action_uninstall_v2ray'
action_nginx_uninstall='action_nginx_uninstall'
action_acme_sh_uninstall='action_acme_sh_uninstall'

# 未安装情况的菜单项
menu_for_not_installed_order_array=(
    "_title_1"                                  # [安装向导]
    "${action_install_v2ray_ws_tls}"            # 安装 V2Ray (Vmess + Websocket + TLS + Nginx + Website). 有伪装网站 (建议)
    "${action_install_v2ray_h2}"                # 安装 V2Ray (Vmess + Http2 + TLS). 无伪装网站
    "_separate_"
    "_title_3"                                  # [维护]
    "${action_onekey_script_update}"            # 升级一键安装管理脚本
    "${action_nginx_uninstall}"                 # 卸载 Nginx
    "${action_acme_sh_uninstall}"               # 卸载 SSL 证书管理脚本 acme.sh
)

# 已安装情况的菜单项
menu_for_installed_order_array=(
    "_title_2"                                  # [查看配置]
    "${action_show_v2ray_config_desc}"          # 查看 V2Ray 客户端配置
    "_separate_"
    "_title_3"                                  # [配置变更]
    "${action_modify_UUID}"                     # 变更 UUID
    "${action_modify_port}"                     # 变更 Port
    "${action_modify_nginx_tls_version}"        # 变更 TLS 版本
    "${action_modify_obfs_path}"                # 变更伪装路径
    "_separate_"
    "_title_4"                                  # [查看日志]
    "${action_show_access_log}"                 # 查看 实时访问日志
    "${action_show_error_log}"                  # 查看 实时错误日志
    "_separate_"
    "_title_5"                                  # [加速选项]
    "${action_run_system_tcp_speed_up}"         # 安装 4合1 bbr 锐速安装脚本
#   "${action_mtproxy_sh}"                      # 安装 MTproxy(支持TLS混淆)
    "_separate_"
    "_title_6"                                  # [维护]
    "${action_onekey_script_update}"            # 升级一键安装管理脚本
    "${action_v2ray_core_update}"               # 升级 V2Ray
    "${action_ssl_cert_update_manuel}"          # 证书有效期更新
    "${action_nginx_and_v2ray_service_restart}" # 重启服务
    "_separate_"
    "_title_7"                                  # [卸载]
    "${action_uninstall_v2ray}"                 # 卸载 V2Ray
    "${action_nginx_uninstall}"                 # 卸载 Nginx
    "${action_acme_sh_uninstall}"               # 卸载 SSL 证书管理脚本 acme.sh
)

# 字符资源. 无顺序. 左边是动作 id, 右边是显示文字, 不响应动作的项必须以 "_" 开头
declare -A menu_text_map=(
    ["_separate_"]=""

    ["_title_1"]="[安装向导]"
    ["${action_install_v2ray_ws_tls}"]="安装 V2Ray (Vmess + Websocket + TLS + Nginx + Website). 有伪装网站 (建议)"
    ["${action_install_v2ray_h2}"]="安装 V2Ray (Vmess + Http2 + TLS). 无伪装网站"

    ["_title_2"]="[查看配置]"
    ["${action_show_v2ray_config_desc}"]="查看 V2Ray 客户端配置"

    ["_title_3"]="[配置变更]"
    ["${action_modify_UUID}"]="变更 UUID"
    ["${action_modify_port}"]="变更 Port"
    ["${action_modify_nginx_tls_version}"]="变更 TLS 版本"
    ["${action_modify_obfs_path}"]="变更伪装路径"

    ["_title_4"]="[查看日志]"
    ["${action_show_access_log}"]="查看 实时访问日志"
    ["${action_show_error_log}"]="查看 实时错误日志"

    ["_title_5"]="[加速选项]"
    ["${action_run_system_tcp_speed_up}"]="安装 4合1 bbr 锐速安装脚本"
    ["${action_mtproxy_sh}"]="安装 MTproxy(支持TLS混淆)"

    ["_title_6"]="[维护]"
    ["${action_onekey_script_update}"]="升级${onekey_script_title}"
    ["${action_v2ray_core_update}"]="升级 V2Ray"
    ["${action_ssl_cert_update_manuel}"]="证书有效期更新"
    ["${action_nginx_and_v2ray_service_restart}"]="重启服务"

    ["_title_7"]="[卸载]"
    ["${action_uninstall_v2ray}"]="卸载 V2Ray"
    ["${action_nginx_uninstall}"]="卸载 Nginx"
    ["${action_acme_sh_uninstall}"]="卸载 SSL 证书管理脚本 acme.sh"
)

ask_input_menu_index() {
    read -rp "请输入菜单编号[仅允许填数字(0 ~ ${max_menu_index})](默认:0): " input_cache_menu_index

    selected_menu_index=0
    if [[ -n ${input_cache_menu_index} ]]; then
        local tmp_input=$(echo ${input_cache_menu_index} | grep -Eo "[[:digit:]]+")
        if [[ -z ${tmp_input} ]] || [[ ${tmp_input} != ${input_cache_menu_index} ]]; then
            show_error_message "仅允许填数字, 请重新输入"
            ask_input_menu_index
        elif (( input_cache_menu_index > max_menu_index)); then
            show_error_message "超出范围(0 ~ ${max_menu_index}), 请重新输入"
            ask_input_menu_index
        else
            ((selected_menu_index=input_cache_menu_index+0))
        fi
    fi

    echo ""
    if (( selected_menu_index != 0 )); then
        local action_index=$(( selected_menu_index-1 ))
        local key=${menu_action_current[${action_index}]}
        menu_action "$key"
    else
        menu_action "${action_do_exit}"
    fi
}

menu() {
    show_one_key_logo

    if onekey_script_new_version_found; then
        show_striking_message "发现新版本 “${onekey_script_title}”: ${remote_version}"
    fi

    show_message ""
    show_message "${onekey_script_title} [${onekey_script_version}]"
    show_message "开源项目: ${git_project}"

    local menu_action_current=()
    local menu_order_current=()
    declare -A menu_map_current

    # 获取菜单数据
    if onekey_installed; then
        show_striking_message "已安装。混淆类型:${obfsType}, 域名:$domain"
        menu_order_current=(${menu_for_installed_order_array[*]})
    else
        menu_order_current=(${menu_for_not_installed_order_array[*]})
    fi

    copy_assoc_array menu_text_map menu_map_current

    # 显示菜单
    show_message ""
    local index=0
    for ((i = 0; i < ${#menu_order_current[@]}; i++)); do
        local key=${menu_order_current[i]}
        local text=${menu_map_current[$key]}

        if [ $obfsType != "ws" ] && [ $key == "modify_nginx_tls_version" ]; then
            # modify_nginx_tls_version 仅 ws+tls 有效
            continue
        fi

        if [[ ! -d $nginx_dir ]] && [ $key == "nginx_uninstall" ]; then
            continue
        fi

        if [[ ! -f $acme_sh_file ]] && [ $key == "acme_sh_uninstall" ]; then
            continue
        fi

        if [ -z $(echo $key | grep "^_") ]; then
            menu_action_current[$index]=$key
            ((index++))
            local action_index=$(printf "%2d" $index)
            local test_tmp=$text
            if [ $debug_mode -eq 1 ]; then
                test_tmp="$text [$key]"
            fi
            show_message " ${F_GREEN}$action_index.${F_END} $test_tmp"
        else
            show_message "$text"
        fi
    done

    max_menu_index=${index}

    # 特殊编号的菜单项
    show_message ""
    show_message " ${F_GREEN} 0.${F_END} 退出\n"

    ask_input_menu_index
}

# 菜单动作, 动作 id 不能以 "_" 开头
menu_action() {
    local action=$1

    [ $debug_mode -eq 1 ] && show_message "执行: $action"

    case $action in
    ${action_do_exit})
        exit 0
        ;;
    ${action_install_v2ray_ws_tls})
        install_v2ray_ws_tls
        ;;
    ${action_install_v2ray_h2})
        install_v2ray_h2
        ;;
    ${action_show_v2ray_config_desc})
        show_v2ray_config_desc
        ;;
    ${action_modify_UUID})
        read -rp "请输入UUID(直接回车, 会随机生成): " uuid
        modify_UUID
        show_ok_message "UUID 已更改为:${uuid}"
        when_after_modify
        ;;
    ${action_modify_port})
        ask_port
        if [[ $obfsType == "ws" ]]; then
            modify_nginx_port $port
        elif [[ $obfsType == "h2" ]]; then
            modify_inbound_port $port
        fi
        show_ok_message "端口已更改为:${port}"
        when_after_modify
        ;;
    ${action_modify_nginx_tls_version})
        if [[ $obfsType != "ws" ]]; then
            show_error_message "此功能仅支持 WS+TLS 方式"
        else
            ask_tls_version
            modify_nginx_tls_version
            when_after_modify
        fi
        ;;
    ${action_modify_obfs_path})
        read -p "请输入伪装路径(不必加斜杠\"/\", 直接回车会随机生成): " obfsPath
        [[ -z $obfsPath ]] && obfsPath=$(gen_obfs_path)

        if (($(echo $obfsPath | grep -E -c "^/") == 0)); then
            obfsPath="/$obfsPath"
        fi

        if (($(echo $obfsPath | grep -E -c "/$") == 0)); then
            obfsPath="$obfsPath/"
        fi

        modify_obfs_path
        if [[ $obfsType == 'ws' ]]; then
            modify_nginx_obfs_path
        fi
        show_ok_message "伪装路径已更改为:${obfsPath}"
        when_after_modify
        ;;
    ${action_show_access_log})
        show_access_log
        ;;
    ${action_show_error_log})
        show_error_log
        ;;
    ${action_run_system_tcp_speed_up})
        run_system_tcp_speed_up
        ;;
    ${action_mtproxy_sh})
        mtproxy_sh
        ;;
    ${action_onekey_script_update})
        onekey_script_update
        ;;
    ${action_v2ray_core_update})
        v2ray_upgrade
        ;;
    ${action_ssl_cert_update_manuel})
        ssl_cert_update_manuel
        ;;
    ${action_nginx_and_v2ray_service_restart})
        nginx_and_v2ray_service_restart
        ;;
    ${action_uninstall_v2ray})
        # source '/etc/os-release'
        uninstall_v2ray
        ;;
    ${action_nginx_uninstall})
        # source '/etc/os-release'
        nginx_uninstall
        ;;
    ${action_acme_sh_uninstall})
        acme_sh_uninstall
        ;;
    *)
        show_error_message "无效命令"
        ;;
    esac
}

# 下载必需的脚本, 不覆盖已有文件
download_required_scripts() {
    for key in ${!SCRIPTS_URL_ARRAY[*]}; do
        local url="${SCRIPTS_URL_ARRAY[$key]}"
        if [ ! -f $key ]; then
            download "${url}"
            judge "下载脚本 ${key}"
        fi
    done
}

backup_required_scripts() {
    local cur_dir=$(pwd)
    cd ${one_key_conf_dir}

    local files=""
    local count=0
    for key in ${!SCRIPTS_URL_ARRAY[*]}; do
        if [ -f $key ]; then
            files="${files} ${key}"
            ((count++))
        fi
    done

    if ((count > 0)); then
        rm -rf "${backup_one_key_script_tar}"
        tar czvf "${backup_one_key_script_tar}" "${files}" > /dev/null 2>&1
    fi

    cd ${cur_dir}
}

# 为启动脚本建立软链接
make_launcher_symbolic_link(){
    if [[ ${one_key_launch_dir} != ${one_key_conf_dir} ]]; then
        local launcher_script_path="${one_key_conf_dir}/${launcher_script}"
        local launcher_symbolic_link_path="${one_key_launch_dir}/${launcher_script}"
        if [ ! -L "${launcher_symbolic_link_path}" ]; then
            rm -rf "${launcher_symbolic_link_path}"
            ln -s "${launcher_script_path}" "${launcher_symbolic_link_path}"
        fi
    fi
}

#####################################################
# 主程序
#####################################################
main() {
    if [ ${git_branch} != "master" ]; then
        show_striking_message "当前 Git 分支是 ${git_branch}"
    fi

    check_if_running_as_root
    identify_the_operating_system_and_architecture
    download_required_scripts
    local launcher_script_path="${one_key_conf_dir}/${launcher_script}"
    [ -f "${launcher_script_path}" ] && chmod a+x "${launcher_script_path}"

    # 为启动脚本建立软链接
    make_launcher_symbolic_link

    # JSON 读写, json_set_value
    source ${json_utils_script}

    init_default_value

    # 获取配置
    if onekey_installed; then
        read_config $onekey_conf 1
    fi

    menu
}

main "$1"