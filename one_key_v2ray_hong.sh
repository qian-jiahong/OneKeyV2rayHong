#!/bin/bash

#====================================================
#	System Request:Debian 8+/Ubuntu 16+/Centos 7+
#	Author:	qian-jiahong
#	Description: 一键 V2ray 安装管理脚本 Hong 启动器
#	Version: 1.0
#	email:
#====================================================

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
F_RESET="\033[0m"

# 标题
OK="${F_GREEN}[OK]${F_RESET}"
ERROR="${F_RED}[错误]${F_RESET}"
WARN="${F_YELLOW}[警告]${F_RESET}"

# 公共目录和文件, 供被调用的子脚本使用
export one_key_conf_dir="$HOME/.one_key_v2ray_hong"
export one_key_launch_dir="$(pwd)"
export git_branch_conf="${one_key_conf_dir}/git_branch.conf"

############################
# 项目信息
############################
project_name='OneKeyV2rayHong'
project_owner='qian-jiahong'
# 版本库地址
git_project=https://github.com/${project_owner}/${project_name}
# 直连基本地址
git_raw_base_url=https://raw.githubusercontent.com/${project_owner}/${project_name}

main_script="main.sh"

#####################################################
# 函数
#####################################################
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
    echo -e "${F_BLUE_BG}$1${F_RESET}"
}

show_message() {
    echo -e "$1"
}

check_if_running_as_root() {
    if [[ "$UID" -ne '0' ]]; then
        show_error_message "请以 root 用户执行脚本, 终止!"
        exit 1
    fi
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

install_software() {
    package_name="$1"
    file_to_detect="$2"
    type -P "$file_to_detect" >/dev/null 2>&1 && return
    if ${PACKAGE_MANAGEMENT_INSTALL} "$package_name"; then
        show_message "$package_name 已安装."
    else
        show_error_message "安装 $package_name 失败，请检查您的网络。"
        exit 1
    fi
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

main() {
    local branch=$1

    if [ -n "$branch" ]; then
        git_branch=$branch
    elif [[ -z "${git_branch}" ]] && [[ -f "${git_branch_conf}" ]]; then
        source "${git_branch_conf}"
    fi

    if [[ -z "${git_branch}" ]]; then
        git_branch="master"
    fi

    local base_url=$git_raw_base_url/$git_branch
    local main_script_url=${base_url}/${main_script}
    local main_script_path=${one_key_conf_dir}/${main_script}

    [[ -d ${one_key_conf_dir} ]] || mkdir -p "${one_key_conf_dir}"
    cd "${one_key_conf_dir}" || exit

    check_if_running_as_root
    identify_the_operating_system_and_architecture
    ${PACKAGE_MANAGEMENT_UPDATE}
    install_software wget wget
    if [ ! -f "${main_script_path}" ]; then
        local temp_dir=$(mktemp -d)
        if download "${main_script_url}" "$temp_dir"; then
            mv -f "$temp_dir/${main_script}" "${main_script_path}"
        else
            show_error_message "下载主脚本失败: ${main_script_url}"
        fi
        rm -rf "$temp_dir"
    fi

    if [[ ! -f "${main_script_path}" ]]; then
        show_error_message "主脚本不存在，无法继续执行: ${main_script_path}"
        exit 1
    fi

    echo "git_branch=$git_branch" >$git_branch_conf
    if (( debug_mode == 1 )); then
        show_ok_message "执行主脚本..."
        bash -x "${main_script_path}" "$@"
    else
        bash "${main_script_path}" "$@"
    fi
}

launcher=$0
main "$@"

if (( $(echo ${launcher} | grep -Ec "^/tmp/")>0 )); then
    show_striking_message "当前正在临时目录中运行, 下次可以在当前目录(${one_key_launch_dir})中执行: ./one_key_v2ray_hong.sh"
fi