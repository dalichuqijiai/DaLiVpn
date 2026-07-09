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

TARGETS_V6=(
    "http://baidu.com"
)

V6_OK=0
V6_TOTAL=0

if [ -n "$MY_IP6" ]; then
    for site in "${TARGETS_V6[@]}"; do
        HTTP_CODE=$(curl -o /dev/null -s -6 --connect-timeout 5 --max-time 8 -w "%{http_code}" "$site" 2>/dev/null)
        if [ -z "$HTTP_CODE" ]; then
            HTTP_CODE="000"
        fi
        ((V6_TOTAL++))
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
            echo "  ✅  [IPv6 SUCCESS] $site  (HTTP $HTTP_CODE)"
            ((V6_OK++))
        else
            echo "  ❌  [IPv6 FAILED]  $site  (HTTP $HTTP_CODE)"
        fi
    done
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
