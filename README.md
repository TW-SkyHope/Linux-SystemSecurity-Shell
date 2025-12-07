# Linux-SystemSecurity-Shell
用于linux系统安全配置的互动式shell脚本，减轻了手动输入命令以及部署各安全应用服务的负担  

## 功能特性

- 一键配置功能：自动化部署所有安全配置选项
- ICMP协议管理：禁止或开启服务器ping响应
- SSH服务：自定义端口、可选root密码修改、密码登录管理
- 密钥登录配置：生成ED25519算法的SSH密钥对并配置
- Fail2ban安全防护：安装、配置和卸载fail2ban服务
- IP访问控制：基于ipset的高效IP黑名单及海外ip屏蔽
- 流量防护：控制网络连接与数据传输

## 支持的操作系统

- Debian 9+
- Red Hat Enterprise Linux 7+
- CentOS 7+
- Ubuntu 18.04+

## 一键使用

   ```
   wget -O security.sh "https://raw.githubusercontent.com/TW-SkyHope/Linux-SystemSecurity-Shell/main/security.sh" && chmod +x security.sh && ./security.sh
   ```

## 功能详细说明

### 1. 一键配置
执行所有安全配置选项，包括：
- 禁止ICMP ping响应
- SSH服务配置
- 密钥登录配置
- Fail2ban安装与配置
- IP访问控制启用

### 2. ICMP协议管理
- 禁止ICMP ping响应：通过修改系统内核参数实现
- 启用ICMP ping响应：恢复默认设置

### 3. SSH服务
- 自定义SSH端口：支持1-65535范围内的端口，自动检查端口占用
- 可选的root密码修改：根据需要修改root密码
- 智能密码登录：仅当当前是密钥登录时，提供开启密码登录功能

### 4. 密钥登录配置
- 生成ED25519算法的SSH密钥对
- 将公钥自动配置到服务器authorized_keys文件
- 私钥文件保存至/home目录下，权限设置为600
- 检测现有密钥，如已存在则输出密钥文件路径
- 再次执行时关闭密码登录，仅允许密钥登录

### 5. Fail2ban安全防护
- 自动安装fail2ban服务
- 支持自定义设置：
  - 最大重试次数（默认：5次）
  - 检测周期（默认：600秒）
  - 封禁时间（默认：3600秒）
- 配置完成后自动启动并设置开机自启
- 支持卸载功能

### 6. IP访问控制
- 防火墙优先级：优先使用系统已安装的firewalld(centos)或ufw(ubuntu)
- 未安装时自动安装合适的防火墙
- 使用ipset功能实现高效IP屏蔽
- 从指定黑名单URL下载：`https://blackip.ustc.edu.cn/list.php?txt`
- 支持海外IP屏蔽，从指定URL下载非中国IP列表：`https://raw.githubusercontent.com/houoop/not-china-ip-list/main/nonchina_ip_list.txt`
- 可独立控制黑名单和海外IP屏蔽功能
- 不影响原有防火墙规则
- 支持随时启用或禁用

### 7. 流量防护
- 实时监控TCP连接数量
- 实时统计UDP传输速率
- 支持的配置参数：
  - TCP连接数量限制（默认：35个）
  - TCP连接速率限制（默认：10连接/秒）
  - UDP传输速率限制（默认：1024KB/秒）
  - 违规IP封禁时长（默认：3600秒）
- 处理策略：IP封禁或流量限制

## 注意事项

1. 请确保以root用户运行脚本
2. 脚本会修改系统关键配置，请谨慎使用
3. 在执行一键配置前，请确保了解所有配置项的含义
4. 执行SSH端口修改后，下次登录请使用新端口
5. 密钥文件生成后，请妥善保管私钥文件
6. 所有配置修改前会自动备份原始配置文件

## 日志和备份

- 操作日志记录到：`/var/log/security_config.log`
- 配置文件备份到：`/root/security_backups/[时间戳]/`

## 恢复配置

如果配置出现问题，可以通过以下方式恢复：

1. 查看备份目录：
   ```bash
   ls /root/security_backups/
   ```
2. 找到对应时间戳的备份目录
3. 将备份文件复制回原位置：
   ```bash
   cp /root/security_backups/[时间戳]/[文件名] /[原路径]/[文件名]
   ```
   
## 注意事项

- 本脚本还处于测试阶段

## 项目维护

若您正在使用我的项目对我的项目有新的需求或发现bug请向于本项目内报告，一般3-7天内会给出答复，后期可能会视作品小星星der数量增加更多功能！

## 作者的话：懒人脚本


