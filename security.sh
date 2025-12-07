#!/bin/bash

# 安全配置脚本 - 支持Debian和Red Hat Enterprise Linux
# 功能：ICMP管理、SSH强化、密钥登录配置、Fail2ban防护、IP访问控制

# 日志文件位置
LOG_FILE="/var/log/security_config.log"
# 备份目录
BACKUP_DIR="/root/security_backups/$(date +%Y%m%d_%H%M%S)"
# 私钥保存目录
PRIVATE_KEY_DIR="/home"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log() {
    local message="$1"
    local level="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$LOG_FILE"
    echo -e "$message"
}

# 错误处理函数
error_handler() {
    local message="$1"
    log "${RED}错误: $message${NC}" "ERROR"
    exit 1
}

# 确认提示函数
confirm() {
    local message="$1"
    read -p "${YELLOW}$message (y/n): ${NC}" -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# 检测操作系统
detect_os() {
    log "${BLUE}检测操作系统类型...${NC}" "INFO"
    if [ -f /etc/debian_version ]; then
        OS="debian"
        log "检测到Debian系统" "INFO"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
        log "检测到Red Hat系统" "INFO"
    else
        error_handler "不支持的操作系统"
    fi
}

# 创建备份目录
create_backup_dir() {
    mkdir -p "$BACKUP_DIR" || error_handler "无法创建备份目录"
    log "创建备份目录: $BACKUP_DIR" "INFO"
}

# 备份文件
backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/" || error_handler "无法备份文件: $file"
        log "备份文件: $file -> $BACKUP_DIR/$(basename "$file")" "INFO"
    fi
}

# 一键配置功能
one_click_config() {
    log "${BLUE}=== 一键配置模式 ===${NC}" "INFO"
    if confirm "确定要执行一键安全配置吗？这将修改多项系统设置。"; then
        log "开始执行一键安全配置" "INFO"
        configure_icmp disable
        configure_ssh
        configure_ssh_keys
        configure_fail2ban
        configure_ip_access_control enable
        log "${GREEN}一键安全配置完成！${NC}" "INFO"
    else
        log "取消一键配置" "INFO"
    fi
}

# ICMP协议管理
configure_icmp() {
    local action="$1"
    log "${BLUE}=== ICMP协议管理 ===${NC}" "INFO"
    
    backup_file "/etc/sysctl.conf"
    
    if [ "$action" = "disable" ] || [ -z "$action" ]; then
        if confirm "确定要禁止ICMP ping响应吗？"; then
            echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
            sysctl -p || error_handler "无法应用sysctl配置"
            log "${GREEN}已禁止ICMP ping响应${NC}" "INFO"
        fi
    elif [ "$action" = "enable" ]; then
        if confirm "确定要启用ICMP ping响应吗？"; then
            sed -i '/net.ipv4.icmp_echo_ignore_all/d' /etc/sysctl.conf
            sysctl -p || error_handler "无法应用sysctl配置"
            log "${GREEN}已启用ICMP ping响应${NC}" "INFO"
        fi
    fi
}

# SSH服务
configure_ssh() {
    log "${BLUE}=== SSH服务 ===${NC}" "INFO"
    
    backup_file "/etc/ssh/sshd_config"
    
    # 检查当前SSH配置
    current_auth=$(grep -E "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
    
    # 只有当当前是密钥登录（PasswordAuthentication no）时，才开启密码登录
    if [ "$current_auth" = "no" ]; then
        log "当前仅允许密钥登录，将开启密码登录功能" "INFO"
        sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    else
        log "当前已允许密码登录，可修改SSH端口" "INFO"
        
        # 自定义SSH端口
        while true; do
            read -p "${YELLOW}请输入新的SSH端口号(1-65535，默认22): ${NC}" ssh_port
            ssh_port=${ssh_port:-22}
            
            if ! [[ $ssh_port =~ ^[0-9]+$ ]] || [ $ssh_port -lt 1 ] || [ $ssh_port -gt 65535 ]; then
                log "${RED}无效的端口号${NC}" "ERROR"
                continue
            fi
            
            # 检查端口是否被占用
            if ss -tuln | grep -q ":$ssh_port "; then
                log "${YELLOW}端口 $ssh_port 已被占用，请选择其他端口${NC}" "WARNING"
            else
                break
            fi
        done
        
        # 修改SSH端口
        sed -i "s/^Port .*/Port $ssh_port/" /etc/ssh/sshd_config
        sed -i "s/^#Port 22/Port $ssh_port/" /etc/ssh/sshd_config
    fi
    
    # 可选的root密码修改
    if confirm "是否要修改root密码？"; then
        passwd root || error_handler "修改root密码失败"
        log "已修改root密码" "INFO"
    fi
    
    # 重启SSH服务
    if [ "$OS" = "debian" ]; then
        systemctl restart sshd || error_handler "重启SSH服务失败"
    else
        systemctl restart sshd || error_handler "重启SSH服务失败"
    fi
    
    log "${GREEN}SSH服务配置完成${NC}" "INFO"
}

# 密钥登录配置
configure_ssh_keys() {
    log "${BLUE}=== 密钥登录配置 ===${NC}" "INFO"
    
    # 检查root用户的authorized_keys文件是否存在且有内容
    if [ -s "/root/.ssh/authorized_keys" ]; then
        log "检测到已配置密钥登录" "INFO"
        if confirm "是否要关闭密码登录，仅允许密钥登录？"; then
            # 关闭密码登录
            sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
            sed -i 's/^#PasswordAuthentication no/PasswordAuthentication no/' /etc/ssh/sshd_config
            
            # 重启SSH服务
            if [ "$OS" = "debian" ]; then
                systemctl restart sshd || error_handler "重启SSH服务失败"
            else
                systemctl restart sshd || error_handler "重启SSH服务失败"
            fi
            
            log "${GREEN}已关闭密码登录，仅允许密钥登录${NC}" "INFO"
        fi
        return 0
    fi
    
    # 生成ED25519密钥对
    read -p "${YELLOW}请输入密钥文件名(默认：id_ed25519): ${NC}" key_name
    key_name=${key_name:-id_ed25519}
    
    private_key="$PRIVATE_KEY_DIR/$key_name"
    public_key="$private_key.pub"
    
    if confirm "确定要生成ED25519密钥对吗？私钥将保存到：$private_key"; then
        ssh-keygen -t ed25519 -f "$private_key" -N "" || error_handler "生成密钥对失败"
        
        # 设置私钥权限
        chmod 600 "$private_key" || error_handler "无法设置私钥权限"
        
        # 配置公钥到authorized_keys
        mkdir -p /root/.ssh
        cat "$public_key" >> /root/.ssh/authorized_keys || error_handler "无法配置公钥"
        chmod 600 /root/.ssh/authorized_keys
        
        log "${GREEN}密钥登录配置完成！${NC}" "INFO"
        log "私钥文件：$private_key" "INFO"
        log "公钥文件：$public_key" "INFO"
    fi
}

# Fail2ban安全防护
configure_fail2ban() {
    log "${BLUE}=== Fail2ban安全防护 ===${NC}" "INFO"
    
    # 检查Fail2ban是否已安装
    if systemctl list-unit-files | grep -q fail2ban.service; then
        log "检测到Fail2ban已安装" "INFO"
        echo -e "${YELLOW}1. 重新配置Fail2ban${NC}"
        echo -e "${YELLOW}2. 卸载Fail2ban${NC}"
        read -p "${YELLOW}请选择: ${NC}" fail2ban_choice
        
        case $fail2ban_choice in
            1)
                log "重新配置Fail2ban..." "INFO"
                ;;
            2)
                if confirm "确定要卸载Fail2ban吗？"; then
                    # 停止并禁用服务
                    systemctl stop fail2ban
                    systemctl disable fail2ban
                    
                    # 卸载软件包
                    if [ "$OS" = "debian" ]; then
                        apt-get remove -y fail2ban || error_handler "卸载Fail2ban失败"
                    else
                        yum remove -y fail2ban || error_handler "卸载Fail2ban失败"
                    fi
                    
                    log "${GREEN}Fail2ban已成功卸载${NC}" "INFO"
                fi
                return 0
                ;;
            *)
                log "无效选择" "INFO"
                return 0
                ;;
        esac
    fi
    
    # 安装Fail2ban
    if [ "$OS" = "debian" ]; then
        apt-get update && apt-get install -y fail2ban || error_handler "安装Fail2ban失败"
    else
        yum install -y epel-release && yum install -y fail2ban || error_handler "安装Fail2ban失败"
    fi
    
    backup_file "/etc/fail2ban/jail.conf"
    
    # 自定义配置
    read -p "${YELLOW}请输入最大重试次数(默认：5): ${NC}" maxretry
    maxretry=${maxretry:-5}
    
    read -p "${YELLOW}请输入检测周期(秒，默认：600): ${NC}" findtime
    findtime=${findtime:-600}
    
    read -p "${YELLOW}请输入封禁时间(秒，默认：3600): ${NC}" bantime
    bantime=${bantime:-3600}
    
    # 创建配置文件
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
maxretry = $maxretry
findtime = $findtime
bantime = $bantime

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = $maxretry
EOF
    
    # 启动并设置开机自启
    systemctl start fail2ban || error_handler "启动Fail2ban失败"
    systemctl enable fail2ban || error_handler "设置Fail2ban开机自启失败"
    
    log "${GREEN}Fail2ban配置完成！${NC}" "INFO"
    log "最大重试次数：$maxretry" "INFO"
    log "检测周期：$findtime秒" "INFO"
    log "封禁时间：$bantime秒" "INFO"
}

# IP访问控制
configure_ip_access_control() {
    log "${BLUE}=== IP访问控制 ===${NC}" "INFO"
    
    # 检测并选择防火墙类型
    detect_firewall() {
        if systemctl is-active firewalld > /dev/null 2>&1; then
            FIREWALL_TYPE="firewalld"
            log "检测到firewalld正在运行" "INFO"
        elif systemctl is-active ufw > /dev/null 2>&1; then
            FIREWALL_TYPE="ufw"
            log "检测到ufw正在运行" "INFO"
        else
            # 安装优先的防火墙
            if [ "$OS" = "debian" ]; then
                log "安装ufw防火墙..." "INFO"
                apt-get update && apt-get install -y ufw ipset || error_handler "安装ufw和ipset失败"
                systemctl enable ufw && systemctl start ufw || error_handler "启动ufw失败"
                FIREWALL_TYPE="ufw"
            else
                log "安装firewalld防火墙..." "INFO"
                yum install -y firewalld ipset || error_handler "安装firewalld和ipset失败"
                systemctl enable firewalld && systemctl start firewalld || error_handler "启动firewalld失败"
                FIREWALL_TYPE="firewalld"
            fi
        fi
    }
    
    # 安装wget用于下载黑名单
    install_wget() {
        if [ "$OS" = "debian" ]; then
            apt-get install -y wget || error_handler "安装wget失败"
        else
            yum install -y wget || error_handler "安装wget失败"
        fi
    }
    
    # 下载并处理IP列表
    download_ip_list() {
        local list_type="$1"
        local output_file="$2"
        local url=""
        
        if [ "$list_type" = "blacklist" ]; then
            url="https://blackip.ustc.edu.cn/list.php?txt"
            log "下载黑名单IP列表..." "INFO"
        elif [ "$list_type" = "nonchina" ]; then
            url="https://raw.githubusercontent.com/houoop/not-china-ip-list/main/nonchina_ip_list.txt"
            log "下载非中国IP列表..." "INFO"
        else
            error_handler "无效的列表类型"
        fi
        
        wget -q -O "$output_file" "$url" || error_handler "下载IP列表失败"
        
        # 过滤有效IP地址
        grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' "$output_file" > "$output_file.filtered"
        log "已过滤IP列表，有效IP数量：$(wc -l < "$output_file.filtered")" "INFO"
    }
    
    # 配置ipset
    configure_ipset() {
        local ipset_name="$1"
        local input_file="$2"
        
        # 创建ipset
        ipset create "$ipset_name" hash:net family inet hashsize 1024 maxelem 65536 2>/dev/null || true
        
        # 清空现有ipset
        ipset flush "$ipset_name"
        
        # 添加IP到ipset
        while read -r ip; do
            ipset add "$ipset_name" "$ip" 2>/dev/null || true
        done < "$input_file.filtered"
        
        log "已添加$(ipset list "$ipset_name" | grep -c '^[0-9]')个IP到$ipset_name" "INFO"
    }
    
    # 使用firewalld配置
    configure_firewalld() {
        local ipset_name="$1"
        
        # 检查ipset是否存在于firewalld
        if ! firewall-cmd --get-ipsets | grep -q "$ipset_name"; then
            firewall-cmd --permanent --new-ipset="$ipset_name" --type=hash:net --option=family=inet --option=hashsize=1024 --option=maxelem=65536 || error_handler "创建firewalld ipset失败"
        fi
        
        # 重载firewalld以加载新ipset
        firewall-cmd --reload || error_handler "重载firewalld失败"
        
        # 添加规则
        firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source ipset=\"$ipset_name\" reject" || error_handler "添加firewalld规则失败"
        firewall-cmd --reload || error_handler "重载firewalld失败"
        
        log "firewalld已配置$ipset_name IP拦截" "INFO"
    }
    
    # 使用ufw配置
    configure_ufw() {
        local ipset_name="$1"
        
        # 创建ufw规则文件（如果不存在）
        UFW_RULE_FILE="/etc/ufw/before.rules"
        
        # 检查规则是否已存在
        if ! grep -q "ipset match $ipset_name" "$UFW_RULE_FILE"; then
            # 在文件开头添加规则
            sed -i '1i *filter\n:ufw-before-input - [0:0]\n:ufw-before-output - [0:0]\n:ufw-before-forward - [0:0]\n:ufw-not-local - [0:0]\n' "$UFW_RULE_FILE" 2>/dev/null || true
            # 添加ipset规则
            sed -i '/:ufw-before-input - \[0:0\]/a -A ufw-before-input -m set --match-set '$ipset_name' src -j DROP' "$UFW_RULE_FILE"
        fi
        
        ufw reload || error_handler "重载ufw失败"
        log "ufw已配置$ipset_name IP拦截" "INFO"
    }
    
    # 使用iptables配置
    configure_iptables() {
        local ipset_name="$1"
        
        # 添加iptables规则
        iptables -I INPUT -m set --match-set "$ipset_name" src -j DROP 2>/dev/null || true
        
        # 保存规则
        if [ "$OS" = "debian" ]; then
            iptables-save > /etc/iptables/rules.v4 || error_handler "保存iptables规则失败"
        else
            iptables-save > /etc/sysconfig/iptables || error_handler "保存iptables规则失败"
        fi
        
        log "iptables已配置$ipset_name IP拦截" "INFO"
    }
    
    # 启用IP访问控制
    enable_ip_access_control() {
        local list_type="$1"
        local ipset_name=""
        local output_file=""
        
        if [ "$list_type" = "blacklist" ]; then
            ipset_name="blacklist"
            output_file="/tmp/blacklist.txt"
        elif [ "$list_type" = "nonchina" ]; then
            ipset_name="nonchina"
            output_file="/tmp/nonchina.txt"
        else
            error_handler "无效的列表类型"
        fi
        
        log "启用IP访问控制..." "INFO"
        
        # 检测并安装防火墙
        detect_firewall
        
        # 安装wget
        install_wget
        
        # 下载IP列表
        download_ip_list "$list_type" "$output_file"
        
        # 配置ipset
        configure_ipset "$ipset_name" "$output_file"
        
        # 根据防火墙类型配置规则
        case "$FIREWALL_TYPE" in
            "firewalld")
                configure_firewalld "$ipset_name"
                ;;
            "ufw")
                configure_ufw "$ipset_name"
                ;;
            *)
                configure_iptables "$ipset_name"
                ;;
        esac
        
        log "${GREEN}IP访问控制已启用，$list_type列表已加载${NC}" "INFO"
    }
    
    # 禁用IP访问控制
    disable_ip_access_control() {
        local list_type="$1"
        local ipset_name=""
        
        if [ "$list_type" = "blacklist" ]; then
            ipset_name="blacklist"
        elif [ "$list_type" = "nonchina" ]; then
            ipset_name="nonchina"
        elif [ "$list_type" = "all" ]; then
            # 禁用所有类型的IP访问控制
            disable_ip_access_control "blacklist"
            disable_ip_access_control "nonchina"
            return 0
        else
            error_handler "无效的列表类型"
        fi
        
        log "禁用IP访问控制..." "INFO"
        
        # 根据防火墙类型移除规则
        case "$FIREWALL_TYPE" in
            "firewalld")
                firewall-cmd --permanent --remove-rich-rule="rule family=\"ipv4\" source ipset=\"$ipset_name\" reject" || true
                firewall-cmd --reload || true
                ;;
            "ufw")
                UFW_RULE_FILE="/etc/ufw/before.rules"
                sed -i '/-A ufw-before-input -m set --match-set '$ipset_name' src -j DROP/d' "$UFW_RULE_FILE" || true
                ufw reload || true
                ;;
            *)
                iptables -D INPUT -m set --match-set "$ipset_name" src -j DROP 2>/dev/null || true
                if [ "$OS" = "debian" ]; then
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                else
                    iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
                fi
                ;;
        esac
        
        # 清空并删除ipset
        ipset flush "$ipset_name" 2>/dev/null || true
        ipset destroy "$ipset_name" 2>/dev/null || true
        
        log "${GREEN}IP访问控制已禁用，$list_type列表已移除${NC}" "INFO"
    }
    
    # 主菜单
    echo -e "${YELLOW}1. 启用IP访问控制（屏蔽黑名单IP）${NC}"
    echo -e "${YELLOW}2. 启用海外IP屏蔽（仅允许中国IP访问）${NC}"
    echo -e "${YELLOW}3. 禁用黑名单IP屏蔽${NC}"
    echo -e "${YELLOW}4. 禁用海外IP屏蔽${NC}"
    echo -e "${YELLOW}5. 禁用所有IP访问控制${NC}"
    echo -e "${YELLOW}6. 查看当前配置${NC}"
    echo -e "${YELLOW}7. 返回主菜单${NC}"
    read -p "${YELLOW}请选择: ${NC}" ip_choice
    
    case $ip_choice in
        1)
            if confirm "确定要启用IP访问控制吗？这将屏蔽黑名单IP。"; then
                detect_firewall
                enable_ip_access_control "blacklist"
            fi
            ;;
        2)
            if confirm "确定要启用海外IP屏蔽吗？这将仅允许中国IP访问。"; then
                detect_firewall
                enable_ip_access_control "nonchina"
            fi
            ;;
        3)
            if confirm "确定要禁用黑名单IP屏蔽吗？"; then
                detect_firewall
                disable_ip_access_control "blacklist"
            fi
            ;;
        4)
            if confirm "确定要禁用海外IP屏蔽吗？"; then
                detect_firewall
                disable_ip_access_control "nonchina"
            fi
            ;;
        5)
            if confirm "确定要禁用所有IP访问控制吗？"; then
                detect_firewall
                disable_ip_access_control "all"
            fi
            ;;
        6)
            detect_firewall
            log "当前防火墙类型：$FIREWALL_TYPE" "INFO"
            if ipset list blacklist 2>/dev/null; then
                log "黑名单IP数量：$(ipset list blacklist | grep -c '^[0-9]')" "INFO"
            else
                log "未配置黑名单" "INFO"
            fi
            if ipset list nonchina 2>/dev/null; then
                log "非中国IP数量：$(ipset list nonchina | grep -c '^[0-9]')" "INFO"
            else
                log "未配置海外IP屏蔽" "INFO"
            fi
            ;;
        7)
            return 0
            ;;
        *)
            log "无效选择" "INFO"
            ;;
    esac
}

# 流量防护
configure_traffic_protection() {
    log "${BLUE}=== 流量防护 ===${NC}" "INFO"
    
    # 配置文件路径
    TRAFFIC_PROTECTION_CONFIG="/etc/traffic_protection.conf"
    
    # 安装必要工具
    install_network_tools() {
        log "安装必要的网络工具..." "INFO"
        if [ "$OS" = "debian" ]; then
            apt-get update && apt-get install -y iptables iptables-persistent tc || error_handler "安装网络工具失败"
        else
            yum install -y iptables-services tc || error_handler "安装网络工具失败"
        fi
    }
    
    # 显示当前配置
    show_current_config() {
        if [ -f "$TRAFFIC_PROTECTION_CONFIG" ]; then
            log "当前配置：" "INFO"
            cat "$TRAFFIC_PROTECTION_CONFIG"
        else
            log "未检测到现有配置" "INFO"
        fi
    }
    
    # 启用流量防护
    enable_traffic_protection() {
        log "启用流量防护..." "INFO"
        
        # 创建配置文件
        read -p "${YELLOW}请输入TCP连接数量限制(默认：35): ${NC}" tcp_conn_limit
        tcp_conn_limit=${tcp_conn_limit:-35}
        
        read -p "${YELLOW}请输入TCP连接速率限制(连接/秒，默认：10): ${NC}" tcp_rate_limit
        tcp_rate_limit=${tcp_rate_limit:-10}
        
        read -p "${YELLOW}请输入UDP每秒传输速率限制(KB/秒，默认：1024): ${NC}" udp_rate_limit
        udp_rate_limit=${udp_rate_limit:-1024}
        
        read -p "${YELLOW}请输入违规IP封禁时长(秒，默认：3600): ${NC}" ban_time
        ban_time=${ban_time:-3600}
        
        read -p "${YELLOW}请选择处理策略(1: IP封禁, 2: 流量限制，默认：1): ${NC}" action_policy
        action_policy=${action_policy:-1}
        
        # 写入配置文件
        cat > "$TRAFFIC_PROTECTION_CONFIG" << EOF
# 流量防护配置
TCP_CONN_LIMIT=$tcp_conn_limit
TCP_RATE_LIMIT=$tcp_rate_limit
UDP_RATE_LIMIT=$udp_rate_limit
BAN_TIME=$ban_time
ACTION_POLICY=$action_policy
ENABLED=1
EOF
        
        # 配置iptables规则
        log "配置iptables规则..." "INFO"
        
        # 根据处理策略配置规则
        if [ "$action_policy" = "1" ]; then
            # IP封禁策略
            iptables -A INPUT -p tcp -m connlimit --connlimit-above $tcp_conn_limit -j DROP
            iptables -A INPUT -p tcp -m limit --limit $tcp_rate_limit/second --limit-burst 5 -j ACCEPT
            iptables -A INPUT -p tcp -j DROP
        else
            # 流量限制策略
            # TCP流量限制
            tc qdisc add dev eth0 root handle 1: htb default 10
            tc class add dev eth0 parent 1: classid 1:1 htb rate ${tcp_rate_limit}kbit
            tc class add dev eth0 parent 1:1 classid 1:10 htb rate ${tcp_rate_limit}kbit
            
            # UDP流量限制
            tc qdisc add dev eth0 root handle 1: htb default 10 2>/dev/null || true
            tc class add dev eth0 parent 1: classid 1:2 htb rate ${udp_rate_limit}kbit 2>/dev/null || true
            tc class add dev eth0 parent 1:2 classid 1:20 htb rate ${udp_rate_limit}kbit 2>/dev/null || true
        fi
        
        # 保存规则
        if [ "$OS" = "debian" ]; then
            iptables-save > /etc/iptables/rules.v4 || error_handler "保存iptables规则失败"
        else
            iptables-save > /etc/sysconfig/iptables || error_handler "保存iptables规则失败"
        fi
        
        log "${GREEN}流量防护已启用${NC}" "INFO"
    }
    
    # 禁用流量防护
    disable_traffic_protection() {
        log "禁用流量防护..." "INFO"
        
        # 清除iptables规则
        iptables -F
        
        # 清除tc规则
        tc qdisc del dev eth0 root 2>/dev/null || true
        
        # 保存规则
        if [ "$OS" = "debian" ]; then
            iptables-save > /etc/iptables/rules.v4 || error_handler "保存iptables规则失败"
        else
            iptables-save > /etc/sysconfig/iptables || error_handler "保存iptables规则失败"
        fi
        
        # 更新配置文件
        if [ -f "$TRAFFIC_PROTECTION_CONFIG" ]; then
            sed -i 's/ENABLED=1/ENABLED=0/' "$TRAFFIC_PROTECTION_CONFIG"
        fi
        
        log "${GREEN}流量防护已禁用${NC}" "INFO"
    }
    
    # 主菜单
    echo -e "${YELLOW}1. 显示当前配置${NC}"
    echo -e "${YELLOW}2. 启用流量防护${NC}"
    echo -e "${YELLOW}3. 禁用流量防护${NC}"
    echo -e "${YELLOW}4. 返回主菜单${NC}"
    read -p "${YELLOW}请选择: ${NC}" protect_choice
    
    case $protect_choice in
        1)
            show_current_config
            ;;
        2)
            if confirm "确定要启用流量防护吗？这将修改iptables和tc规则。"; then
                install_network_tools
                enable_traffic_protection
            fi
            ;;
        3)
            if confirm "确定要禁用流量防护吗？这将清除相关规则。"; then
                disable_traffic_protection
            fi
            ;;
        4)
            return 0
            ;;
        *)
            log "无效选择" "INFO"
            ;;
    esac
}

# 主菜单
show_menu() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}      Linux服务器安全配置脚本          ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}1.${NC} 一键安全配置"
    echo -e "${GREEN}2.${NC} ICMP协议管理"
    echo -e "${GREEN}3.${NC} SSH服务"
    echo -e "${GREEN}4.${NC} 密钥登录配置"
    echo -e "${GREEN}5.${NC} Fail2ban安全防护"
    echo -e "${GREEN}6.${NC} IP访问控制"
    echo -e "${GREEN}7.${NC} 流量防护"
    echo -e "${GREEN}8.${NC} 退出"
    echo -e "${BLUE}========================================${NC}"
}

# 主程序
main() {
    # 检查root权限
    if [ "$EUID" -ne 0 ]; then
        error_handler "请以root用户运行此脚本"
    fi
    
    # 初始化
    detect_os
    create_backup_dir
    
    # 主循环
    while true; do
        show_menu
        read -p "${YELLOW}请选择操作 (1-8): ${NC}" choice
        case $choice in
            1)
                one_click_config
                ;;
            2)
                echo -e "${YELLOW}1. 禁止ICMP ping响应${NC}"
                echo -e "${YELLOW}2. 启用ICMP ping响应${NC}"
                read -p "${YELLOW}请选择: ${NC}" icmp_choice
                case $icmp_choice in
                    1)
                        configure_icmp disable
                        ;;
                    2)
                        configure_icmp enable
                        ;;
                    *)
                        log "无效选择" "INFO"
                        ;;
                esac
                ;;
            3)
                configure_ssh
                ;;
            4)
                configure_ssh_keys
                ;;
            5)
                configure_fail2ban
                ;;
            6)
                echo -e "${YELLOW}1. 启用IP访问控制${NC}"
                echo -e "${YELLOW}2. 禁用IP访问控制${NC}"
                read -p "${YELLOW}请选择: ${NC}" ip_choice
                case $ip_choice in
                    1)
                        configure_ip_access_control enable
                        ;;
                    2)
                        configure_ip_access_control disable
                        ;;
                    *)
                        log "无效选择" "INFO"
                        ;;
                esac
                ;;
            7)
                configure_traffic_protection
                ;;
            8)
                log "${GREEN}脚本执行完毕，退出。${NC}" "INFO"
                exit 0
                ;;
            *)
                log "无效选择，请输入1-8之间的数字" "INFO"
                ;;
        esac
        read -p "${YELLOW}按任意键继续...${NC}" -n 1 -r
        echo
    done
}

# 启动主程序
main
