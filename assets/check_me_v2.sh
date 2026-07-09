#!/bin/bash

echo "============================================"
echo "  VPS 中国大陆连通性自检工具 (IPv4 + IPv6)"
echo "============================================"

# ──────────────────────────────────────────────
# 第一部分：IPv4 检测
# ──────────────────────────────────────────────
echo ""
echo "--- [IPv4] 正在获取本机公网 IP ---"
MY_IP4=$(curl -s4 --connect-timeout 5 --max-time 6 http://ifconfig.me 2>/dev/null \
      || curl -s4 --connect-timeout 5 --max-time 6 http://ip.sb 2>/dev/null \
      || curl -s4 --connect-timeout 5 --max-time 6 http://icanhazip.com 2>/dev/null)

if [ -n "$MY_IP4" ]; then
    echo "IPv4 地址: $MY_IP4"
else
    echo "⚠️  未检测到 IPv4 公网地址"
fi

# IPv4 中国目标
TARGETS_V4=("http://baidu.com")

echo ""
echo "--- [IPv4] 检测到中国大陆的连通性 ---"
V4_OK=0
V4_TOTAL=0
for site in "${TARGETS_V4[@]}"; do
    HTTP_CODE=$(curl -o /dev/null -s --connect-timeout 5 --max-time 8 -w "%{http_code}" "$site" 2>/dev/null)
    if [ -z "$HTTP_CODE" ]; then
        HTTP_CODE="000"
    fi
    ((V4_TOTAL++))
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
        echo "  ✅  [IPv4 SUCCESS] $site  (HTTP $HTTP_CODE)"
        ((V4_OK++))
    else
        echo "  ❌  [IPv4 FAILED]  $site  (HTTP $HTTP_CODE)"
    fi
done

# ──────────────────────────────────────────────
# 第二部分：IPv6 检测
# ──────────────────────────────────────────────
echo ""
echo "--- [IPv6] 正在获取本机公网 IP ---"

IPV6_AVAILABLE=false
if command -v ip &>/dev/null; then
    if ip -6 route show default &>/dev/null 2>&1 && [ -n "$(ip -6 route show default 2>/dev/null)" ]; then
        IPV6_AVAILABLE=true
    fi
elif [ -f /proc/net/if_inet6 ] && [ -s /proc/net/if_inet6 ]; then
    IPV6_AVAILABLE=true
fi

MY_IP6=""
if [ "$IPV6_AVAILABLE" = true ]; then
    MY_IP6=$(curl -s6 --connect-timeout 5 --max-time 6 http://ifconfig.me 2>/dev/null \
          || curl -s6 --connect-timeout 5 --max-time 6 http://ip.sb 2>/dev/null \
          || curl -s6 --connect-timeout 5 --max-time 6 http://icanhazip.com 2>/dev/null)
fi

if [ -n "$MY_IP6" ]; then
    echo "IPv6 地址: $MY_IP6"
else
    echo "⚠️  未检测到公网 IPv6 地址"
fi

echo ""
echo "--- [IPv6] 检测到中国大陆的连通性 ---"
echo "  (TCP 传输层检测比 HTTP/ping 更准确，可区分网络被墙与应用层问题)"

TARGETS_V6=(
    "baidu.com"
)

V6_OK=0
V6_TOTAL=0

if [ -n "$MY_IP6" ]; then
    echo ""

    for domain in "${TARGETS_V6[@]}"; do
        ((V6_TOTAL++))
        tcp_ok=false
        http_ok=false

        # 先解析 IPv6 地址，避免依赖系统 DNS 行为
        IP6=""
        if command -v dig &>/dev/null; then
            IP6=$(dig AAAA +short "$domain" 2>/dev/null | head -1)
        elif command -v host &>/dev/null; then
            IP6=$(host -t AAAA "$domain" 2>/dev/null | grep "has IPv6 address" | head -1 | awk '{print $NF}')
        elif command -v nslookup &>/dev/null; then
            IP6=$(nslookup -type=AAAA "$domain" 2>/dev/null | grep "AAAA" | head -1 | awk '{print $2}')
        fi

        if [ -n "$IP6" ]; then
            echo "  目标: $domain → $IP6"
        else
            echo "  目标: $domain (无法解析 AAAA 记录)"
        fi

        # ── TCP 传输层检测（最准确，分辨是否被墙） ──
        for port in 80 443; do
            # 尝试方法1: bash 内置 /dev/tcp（零依赖）
            if [ -n "$IP6" ]; then
                timeout 5 bash -c "echo > /dev/tcp/[$IP6]/$port" 2>/dev/null && { tcp_ok=true; break; }
            fi
            # 尝试方法2: nc（netcat）
            if command -v nc &>/dev/null; then
                if [ -n "$IP6" ]; then
                    nc -6 -z -w 5 "$IP6" "$port" 2>/dev/null && { tcp_ok=true; break; }
                fi
                # 也试 DNS 解析版，兼容没有 dig 的环境
                nc -6 -z -w 5 "$domain" "$port" 2>/dev/null && { tcp_ok=true; break; }
            fi
        done

        # ── HTTP 应用层检测（补充信息） ──
        HTTP_CODE=$(curl -o /dev/null -s -6 --connect-timeout 5 --max-time 10 -w "%{http_code}" "http://$domain" 2>/dev/null)
        if [ -n "$HTTP_CODE" ] && { [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; }; then
            http_ok=true
        fi
        # HTTPS 兜底
        if [ "$http_ok" = false ]; then
            HTTP_CODE=$(curl -o /dev/null -s -6 -k --connect-timeout 5 --max-time 10 -w "%{http_code}" "https://$domain" 2>/dev/null)
            if [ -n "$HTTP_CODE" ] && { [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; }; then
                http_ok=true
            fi
        fi

        # ── 结果判断 ──
        if [ "$tcp_ok" = true ]; then
            if [ "$http_ok" = true ]; then
                echo "  ✅  [IPv6 OK] $domain — TCP 可达 + HTTP 正常"
            else
                echo "  ⚠️  [IPv6 部分正常] $domain — TCP 可达但 HTTP/CDN 异常（网络未被墙，应用层问题）"
            fi
            ((V6_OK++))
        elif [ "$http_ok" = true ]; then
            # TCP 检测工具都不可用，但 HTTP 成功了
            echo "  ✅  [IPv6 OK] $domain — HTTP 正常"
            ((V6_OK++))
        else
            echo "  ❌  [IPv6 FAILED] $domain — TCP/HTTP 均无法连通"
            echo "      （可能是网络被墙，或路由/互联问题）"
        fi
        echo ""
    done

    # 额外诊断建议
    if [ "$V6_OK" -eq 0 ] && [ "$V6_TOTAL" -gt 0 ]; then
        echo "  💡 如需进一步诊断，可运行:"
        echo "     traceroute6 -n baidu.com   (追踪路由路径)"
        echo "     mtr -6 baidu.com           (查看丢包点)"
    fi
else
    echo "  本机无公网 IPv6，跳过 IPv6 连通性测试。"
fi

# ──────────────────────────────────────────────
# 第三部分：结论
# ──────────────────────────────────────────────
echo ""
echo "============================================"
echo "  检测汇总"
echo "============================================"
echo ""

# IPv4 结论
if [ "$V4_TOTAL" -gt 0 ]; then
    if [ "$V4_OK" -eq "$V4_TOTAL" ]; then
        echo "[IPv4] ✅ 全部通过（${V4_OK}/${V4_TOTAL}）"
    elif [ "$V4_OK" -gt 0 ]; then
        echo "[IPv4] ⚠️  部分通过（${V4_OK}/${V4_TOTAL}），网络可能存在抖动"
    else
        echo "[IPv4] 🚨 全部失败（0/${V4_TOTAL}）"
    fi
else
    echo "[IPv4] ⏭️  未执行检测"
fi

# IPv6 结论
if [ -n "$MY_IP6" ]; then
    if [ "$V6_TOTAL" -gt 0 ] && [ "$V6_OK" -eq "$V6_TOTAL" ]; then
        echo "[IPv6] ✅ 全部通过（${V6_OK}/${V6_TOTAL}）"
    elif [ "$V6_OK" -gt 0 ]; then
        echo "[IPv6] ⚠️  部分通过（${V6_OK}/${V6_TOTAL}），网络可能存在抖动"
    elif [ "$V6_TOTAL" -gt 0 ]; then
        echo "[IPv6] 🚨 全部失败（0/${V6_TOTAL}）"
    else
        echo "[IPv6] ⏭️  未执行检测"
    fi
else
    echo "[IPv6] ⏭️  本机无公网 IPv6，跳过"
fi

echo ""
echo "--- 综合结论 ---"

if [ -z "$MY_IP4" ] && [ -z "$MY_IP6" ]; then
    echo "🚨 无法获取任何公网 IP，请检查网络连接！"
elif [ "$V4_OK" -eq "$V4_TOTAL" ] && [ "$V4_TOTAL" -gt 0 ] && { [ -z "$MY_IP6" ] || [ "$V6_OK" -eq "$V6_TOTAL" ]; }; then
    echo "🎉 VPS 访问中国网络完全正常。"
elif [ "$V4_OK" -gt 0 ] || [ "$V6_OK" -gt 0 ]; then
    echo "⚠️  访问部分受阻，网络可能存在抖动或被部分封锁。"
else
    echo "🚨 无法访问中国网络！"
    echo ""
    echo "排查建议："
    echo "  1. 运行 'ping -c 2 8.8.8.8' 看外网是否通。"
    echo "  2. 如果外网通但国内不通，基本就是被墙了。"
    echo "  3. 检查 iptables / nftables 是否拦截了流量。"
    echo "  4. 如果只有 IPv6 不通，检查 VPS 是否分配了 IPv6 地址。"
fi

echo ""
echo "============================================"
