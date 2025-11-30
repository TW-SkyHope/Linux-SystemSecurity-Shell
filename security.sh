#!/bin/bash

# =================================================
# 跨系统交互式脚本模板（RHEL & Debian 兼容）
# 功能菜单参考宝塔 bt 命令的交互方式
# 作者: YourName
# =================================================

# -------------------------------
# 全局变量：系统类型
# -------------------------------
DISTRO_TYPE="unknown"

# -------------------------------
# 系统检测函数
# -------------------------------
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            rhel|centos|rocky|almalinux|fedora)
                DISTRO_TYPE="rhel"
                ;;
            debian|ubuntu)
                DISTRO_TYPE="debian"
                ;;
            *)
                DISTRO_TYPE="unknown"
                ;;
        esac
    elif command -v rpm &> /dev/null; then
        DISTRO_TYPE="rhel"
    elif command -v dpkg &> /dev/null; then
        DISTRO_TYPE="debian"
    else
        DISTRO_TYPE="unknown"
    fi
}

# -------------------------------
# 各功能函数（示例框架，未实现具体功能）
# -------------------------------

# 功能 1：显示系统信息
func_1() {
    echo "=== 功能 1：显示系统信息 ==="
    if [ "$DISTRO_TYPE" = "rhel" ]; then
        echo "[RHEL 系逻辑] 获取系统版本、内核等信息"
        # 在这里写 RHEL 系的实践逻辑
    elif [ "$DISTRO_TYPE" = "debian" ]; then
        echo "[Debian 系逻辑] 获取系统版本、内核等信息"
        # 在这里写 Debian 系的实践逻辑
    else
        echo "未知系统类型"
    fi
}

# 功能 2：安装 Web 环境（示例）
func_2() {
    echo "=== 功能 2：安装 Web 环境 ==="
    if [ "$DISTRO_TYPE" = "rhel" ]; then
        echo "[RHEL 系逻辑] 安装 httpd/nginx + php + mariadb"
    elif [ "$DISTRO_TYPE" = "debian" ]; then
        echo "[Debian 系逻辑] 安装 apache2/nginx + php + mysql"
    else
        echo "未知系统类型"
    fi
}

# 功能 3：配置防火墙
func_3() {
    echo "=== 功能 3：配置防火墙 ==="
    if [ "$DISTRO_TYPE" = "rhel" ]; then
        echo "[RHEL 系逻辑] 使用 firewalld 配置规则"
    elif [ "$DISTRO_TYPE" = "debian" ]; then
        echo "[Debian 系逻辑] 使用 ufw 配置规则"
    else
        echo "未知系统类型"
    fi
}

# 功能 4：管理服务状态
func_4() {
    echo "=== 功能 4：管理服务状态 ==="
    if [ "$DISTRO_TYPE" = "rhel" ]; then
        echo "[RHEL 系逻辑] 使用 systemctl 管理系统服务"
    elif [ "$DISTRO_TYPE" = "debian" ]; then
        echo "[Debian 系逻辑] 使用 systemctl 管理系统服务"
    else
        echo "未知系统类型"
    fi
}

# 功能 0：退出脚本
func_0() {
    echo "退出脚本..."
    exit 0
}

# -------------------------------
# 显示菜单函数
# -------------------------------
show_menu() {
    clear
    echo "======================================"
    echo "          SkyCraft IT 管理脚本"
    echo "  当前系统类型: $DISTRO_TYPE"
    echo "======================================"
    echo "1) 显示系统信息"
    echo "2) 安装 Web 环境"
    echo "3) 配置防火墙"
    echo "4) 管理服务状态"
    echo "0) 退出"
    echo "======================================"
    echo -n "请输入数字选择功能: "
}

# -------------------------------
# 主程序入口
# -------------------------------
main() {
    detect_distro

    # 主循环
    while true; do
        show_menu
        read choice
        case "$choice" in
            1) func_1 ;;
            2) func_2 ;;
            3) func_3 ;;
            4) func_4 ;;
            0) func_0 ;;
            *) 
                echo "无效的选择，请重新输入。"
                sleep 2
                ;;
        esac
        echo ""
        echo "按 Enter 键继续..."
        read
    done
}

# -------------------------------
# 脚本开始执行
# -------------------------------
main
