# One Key V2ray Hong 傻瓜化安装脚本

一键 V2Ray 服务端安装，真正的傻瓜化安装脚本，只需要输入域名即可以完成 V2Ray 服务端安装与设置。

## 准备工作

准备一个域名，并将A记录添加好（即将域名指向服务主机）

## 系统要求

Debian 8+ / Ubuntu 16+ / Centos7+

## 如何选择 V2Ray 方案

参考： [如何选择 V2Ray 方案](how-to-choose-a-v2ray-plan.md)

## 安装

正式安装

```
tmpfile=/tmp/tmp_run.sh;wget --unlink -q -O $tmpfile https://raw.githubusercontent.com/qian-jiahong/OneKeyV2rayHong/dev/one_key_v2ray_hong.sh && bash $tmpfile
```

开发版

```
export git_branch=dev; tmpfile=/tmp/tmp_run.sh;wget --unlink -q -O $tmpfile https://raw.githubusercontent.com/qian-jiahong/OneKeyV2rayHong/dev/one_key_v2ray_hong.sh && bash $tmpfile
```

## 安装客户端

Windows 端： v2rayN（免费） (https://github.com/2dust/v2rayN/releases) ，打开 v2rayN，按 Ctrl+S 或点服务器/扫描屏幕二维码，即可以导入客户端设置

Android 端：V2RayNG（免费） (https://github.com/2dust/v2rayNG) ，打开 v2rayNG，扫描二维码，即可以导入客户端设置

iOS端：Fair（免费）, Quantumult（收费）

就可以愉快科学上网了。

## SSL 证书

- 如果你已经拥有了你所使用域名的 SSL 证书文件，可以将 crt 和 key 文件分别命名为 “ssl_fullchain_file”，“ssl_key_file” 放到`/root/.one_key_v2ray_hong` 目录下（若目录不存在请先建目录），请注意证书文件权限及证书有效期，自定义证书有效期过期后请自行续签
- 脚本支持自动生成 let's encrypted 证书，有效期3个月，自动生成的证书会自动续签

## 关于 V2ray

V2ray 原项目已经多年没人更新，已由另一个团队 v2fly 接着更新。

主页： https://www.v2fly.org/

工具： https://www.v2fly.org/awesome/tools.html

新 V2Ray 白话文指南： https://guide.v2fly.org

## 注意事项

- 推荐在纯净环境下使用本脚本

- 请勿在生产环境中的主机安装

- 此脚本会关闭 selinux和防火墙

- 当使用“Vmess + Websocket + TLS + Nginx + Website” 方案时，会自动安装 Nginx，未必兼容已安装的 Nginx，如遇不兼容的，请反馈

## V2ray 管理命令

启动 V2ray：`systemctl start v2ray`

停止 V2ray：`systemctl stop v2ray`

## Nginx 管理命令

启动 Nginx：`systemctl start nginx`

停止 Nginx：`systemctl stop nginx`

### 相关目录和文件

Web 目录：`/var/www/v2ray_ws_tls_website`

V2ray 服务端配置：`/usr/local/etc/v2ray/config.json`

本脚本配置： /root/.one_key_v2ray_hong/onekey.conf，可以将此文件备份。到，当

本脚本备份配置：/root/.one_key_v2ray_hong/onekey.conf.bak，只有使用本脚本卸载也会生成。当重新安装时，此文件会成为可选项。

Nginx 主页配置： `/etc/nginx/conf/conf.d/v2ray.conf`

证书文件: `/root/.one_key_v2ray_hong/ssl_fullchain_file 和 /root/.one_key_v2ray_hong/ssl_key_file`

## 鸣谢

- 本脚本基于 wulabing 的一键安装脚本 ([GitHub - wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey))，已对安装流程优化，尽量减少用户输入

- V2ray 安装脚本来源 ： https://github.com/v2fly/fhs-install-v2ray

- 本脚本中 锐速4合1脚本原项目引用 https://www.94ish.me/1635.html 

- 本脚本中 锐速4合1脚本修改版项目引用 [GitHub - ylx2016/Linux-NetSpeed: 将Linux现常用的网络加速集成在一起](https://github.com/ylx2016/Linux-NetSpeed)  
