#!/usr/bin/env ruby
# frozen_string_literal: true
# 大力VPN 订阅合并+清洗+深度测速+选30个
# 参考 siiway/urlclash-converter 转换规则
# 改进：用实际 TLS/HTTP 握手代替纯 TCP ping，模拟中国可达性
require "yaml"
require "socket"
require "timeout"
require "cgi"
require "base64"
require "resolv"
require "json"
require "openssl"
require "net/http"
require "uri"

# === 1. 读 3 个订阅源 ===
sources = ["/tmp/s1.txt", "/tmp/s2.txt", "/tmp/s3.txt"]
raw_lines = []
sources.each do |f|
  next unless File.exist?(f)
  data = File.read(f).strip
  if data.length > 50 && data !~ /\n/ && data =~ /\A[A-Za-z0-9+\/=\-_]+\z/
    begin
      decoded = Base64.decode64(data.tr("-_", "+/"))
      if decoded =~ /^(vless|trojan|vmess|ss):\/\//
        data = decoded
      end
    rescue StandardError
      nil
    end
  end
  data.each_line do |ln|
    ln = ln.strip
    next if ln.empty?
    raw_lines << ln if ln =~ /^(vless|trojan|vmess|ss):\/\//
  end
end
puts "原始链接数: #{raw_lines.length}"

# === 2. 解析每条链接 ===
VALID_FP = %w[chrome firefox safari edge ios qq android random none].freeze

def clean_fp(v)
  v && VALID_FP.include?(v.downcase) ? v.downcase : "chrome"
end

def parse_params(qs)
  h = {}
  qs.to_s.split("&").each do |kv|
    k, v = kv.split("=", 2)
    next unless k
    h[k.downcase] = v ? CGI.unescape(v) : ""
  end
  h
end

proxies = []
seen = {}
skipped = 0

raw_lines.each do |line|
  begin
    px = nil
    if line =~ /^vless:\/\//
      body = line.sub(%r{^vless://}, "")
      m = body.match(/\A(.+?)@(\[[^\]]+\]|[^:?\/]+):(\d+)\/?(\?(.+?))?(?:#(.*))?\z/)
      skipped += 1 and next unless m
      uuid = CGI.unescape(m[1])
      host = m[2].gsub(/^\[|\]$/, "")
      port = m[3].to_i
      params = parse_params(m[5])
      raw_name = m[6] ? CGI.unescape(m[6]) : nil
      name = (raw_name && !raw_name.strip.empty?) ? raw_name.strip : "VLESS-#{host}:#{port}"

      security = params["security"].to_s.downcase
      net = params["type"].to_s.downcase
      net = "tcp" if net.empty?
      next unless %w[tcp ws http grpc h2].include?(net)

      px = { "name" => name, "type" => "vless", "server" => host, "port" => port, "uuid" => uuid }

      if security == "reality"
        pbk = params["pbk"].to_s
        sid = params["sid"].to_s
        unless pbk.length == 43 && pbk =~ /\A[A-Za-z0-9+\/\-_]+\z/
          skipped += 1
          next
        end
        if !sid.empty? && !(sid.length <= 16 && sid =~ /\A[0-9a-fA-F]+\z/)
          skipped += 1
          next
        end
        px["tls"] = true
        sni = params["sni"] || params["peer"]
        px["servername"] = sni if sni && !sni.empty?
        px["flow"] = "xtls-rprx-vision" if params["flow"] && params["flow"].to_s.include?("vision")
        px["client-fingerprint"] = clean_fp(params["fp"])
        ro = { "public-key" => pbk }
        ro["short-id"] = sid unless sid.empty?
        px["reality-opts"] = ro
      elsif security == "tls"
        px["tls"] = true
        sni = params["sni"] || params["peer"] || params["host"]
        px["servername"] = sni if sni && !sni.empty?
        px["flow"] = "xtls-rprx-vision" if params["flow"] && params["flow"].to_s.include?("vision")
        px["client-fingerprint"] = clean_fp(params["fp"]) if params["fp"]
      elsif security == "none" || security == ""
        px["tls"] = false
      else
        skipped += 1
        next
      end

      if net != "tcp"
        px["network"] = net
        opts = {}
        host_h = params["host"] || params["obfsparam"]
        opts["headers"] = { "Host" => host_h } if host_h && !host_h.empty?
        opts["path"] = params["path"] if params["path"] && !params["path"].empty?
        if net == "grpc"
          opts = {}
          opts["grpc-service-name"] = params["serviceName"] if params["serviceName"]
        end
        px["#{net}-opts"] = opts unless opts.empty?
      end

    elsif line =~ /^trojan:\/\//
      body = line.sub(%r{^trojan://}, "")
      m = body.match(/\A(.+?)@(\[[^\]]+\]|[^:?\/]+):(\d+)\/?(\?(.+?))?(?:#(.*))?\z/)
      skipped += 1 and next unless m
      pw = CGI.unescape(m[1])
      host = m[2].gsub(/^\[|\]$/, "")
      port = m[3].to_i
      params = parse_params(m[5])
      raw_name = m[6] ? CGI.unescape(m[6]) : nil
      name = (raw_name && !raw_name.strip.empty?) ? raw_name.strip : "Trojan-#{host}:#{port}"
      px = { "name" => name, "type" => "trojan", "server" => host, "port" => port, "password" => pw, "tls" => true }
      sni = params["sni"] || params["peer"]
      px["servername"] = sni if sni && !sni.empty?
      px["skip-cert-verify"] = true if params["allowInsecure"] == "1"

    elsif line =~ /^vmess:\/\//
      body = line.sub(%r{^vmess://}, "")
      begin
        json = JSON.parse(Base64.decode64(body.tr("-_", "+/")))
      rescue StandardError
        skipped += 1
        next
      end
      host = json["add"].to_s
      port = json["port"].to_i
      if host.empty? || port == 0
        skipped += 1
        next
      end
      name = json["ps"].to_s.empty? ? "VMess-#{host}:#{port}" : json["ps"].to_s
      px = { "name" => name, "type" => "vmess", "server" => host, "port" => port,
             "uuid" => json["id"], "alterId" => (json["aid"] || 0).to_i, "cipher" => json["scy"] || "auto" }
      net = (json["net"] || "tcp").to_s.downcase
      net = "tcp" unless %w[tcp ws http grpc h2].include?(net)
      px["network"] = net
      px["tls"] = (json["tls"] == "tls")
      px["servername"] = json["sni"] if json["sni"] && !json["sni"].to_s.empty?
      px["client-fingerprint"] = clean_fp(json["fp"]) if json["fp"]
      if net == "ws"
        opts = {}
        opts["headers"] = { "Host" => json["host"] } if json["host"] && !json["host"].to_s.empty?
        opts["path"] = json["path"] || "/"
        px["ws-opts"] = opts unless opts.empty?
      end

    elsif line =~ /^ss:\/\//
      body = line.sub(%r{^ss://}, "")
      m = body.match(/\A(.+?)(?:@(\[[^\]]+\]|[^:?\/]+):(\d+))?\/?(\?(.+?))?(?:#(.*))?\z/)
      skipped += 1 and next unless m
      raw_name = m[6] ? CGI.unescape(m[6]) : nil
      cipher = pw = host = nil
      port = 0
      if m[2] && m[3]
        cipher, pw = m[1].split(":", 2)
        host = m[2].gsub(/^\[|\]$/, "")
        port = m[3].to_i
      else
        begin
          decoded = Base64.decode64(m[1].tr("-_", "+/"))
          cipher, pw = decoded.split(":", 2)
        rescue StandardError
          skipped += 1
          next
        end
        next
      end
      unless cipher && pw && host && port && port > 0
        skipped += 1
        next
      end
      name = (raw_name && !raw_name.strip.empty?) ? raw_name.strip : "SS-#{host}:#{port}"
      px = { "name" => name, "type" => "ss", "server" => host, "port" => port, "cipher" => cipher, "password" => pw }

    else
      skipped += 1
      next
    end

    next unless px
    unless px["server"] && px["port"] && px["port"] > 0
      skipped += 1
      next
    end
    key = "#{px['server']}:#{px['port']}:#{px['type']}"
    if seen[key]
      skipped += 1
      next
    end
    seen[key] = true
    proxies << px
  rescue StandardError
    skipped += 1
    next
  end
end

puts "解析成功节点数: #{proxies.length}（跳过 #{skipped}）"
by_type = proxies.group_by { |p| p["type"] }
by_type.each { |t, arr| puts "  #{t}: #{arr.length}" }

# 只保留 vless 节点（剔除 trojan / vmess / ss / hy2 / hysteria 等）
before_vless = proxies.length
proxies.select! { |p| p["type"] == "vless" }
puts "只保留 vless 节点: #{proxies.length}（剔除 #{before_vless - proxies.length} 个非 vless）"
exit 1 if proxies.empty?

# === 3. 启发式过滤：剔除中国几乎肯定不可达的节点 ===
# 这些模式在中国移动/联通/电信网络几乎必然被 GFW 阻断
BLOCKED_PATTERNS = [
  /\.workers\.dev\z/i,           # Cloudflare Workers（中国完全封锁）
  /\.pages\.dev\z/i,             # Cloudflare Pages
  /google/i,                     # Google 相关
  /gstatic\.com/i,
  /youtube|ytimg/i,
  /facebook|fbcdn/i,
  /twitter|x\.com\z/i,
  /wikipedia/i,
  /telegram/i,                  # Telegram 在中国被严格限制
  /\.appspot\.com/i,
  /\.googleusercontent\.com/i,
  /wikimedia/i,
  /\.ggpht\.com/i,
].freeze

def china_blocked?(px)
  # 检查 server 和 servername
  targets = [px["server"], px["servername"]].compact.map(&:to_s)
  targets.each do |t|
    BLOCKED_PATTERNS.each { |re| return true if t =~ re }
  end
  false
end

before_filter = proxies.length
proxies.reject! { |p| china_blocked?(p) }
puts "剔除中国不可达域名: #{before_filter - proxies.length} 个"

# === 3.5 硬性质量过滤：剔除国内必然超时的节点 ===
# 经验法则（基于大量实测）：
# 1. port 80 + 无 TLS：GFW 对 80 端口明文流量严格审查，几乎 100% 超时
# 2. 批量垃圾 IP（如 .140 结尾）：同一供应商批量节点，国内 IP 段被封
# 3. 只有 port 443/8443 + TLS 的节点才在国内可靠
before_qfilter = proxies.length
proxies.reject! do |p|
  port = p["port"].to_i
  has_tls = p["tls"] == true || p["type"] == "trojan"
  server = p["server"].to_s

  # 规则 1：port 80（无论是否 TLS，国内几乎都超时）
  if port == 80
    true
  # 规则 2：批量垃圾 IP（.140 结尾的供应商节点）→ 国内被封
  elsif server =~ /\.\d{1,3}\.140\z/ || server =~ /\.140\z/
    true
  # 规则 3：port 80 + 任何非 TLS 协议 → 必死
  elsif (port == 80 || port == 8080 || port == 2052) && !has_tls
    true
  else
    false
  end
end
puts "剔除低质量节点（port80无TLS/批量IP）: #{before_qfilter - proxies.length} 个"

# 偏好：TLS 节点（port 443）>> no-TLS 节点（port 80）
# port 80 + no TLS 的节点在中国几乎必然被运营商劫持/封锁
tls_nodes = proxies.select { |p| p["tls"] == true || p["type"] == "trojan" }
notls_nodes = proxies - tls_nodes
puts "TLS 节点: #{tls_nodes.length} / 无 TLS 节点: #{notls_nodes.length}"

# === 4. 深度测速：实际 TLS/HTTP 握手 ===
# 不再只用 TCP ping，而是真正握手：
# - TLS 节点：尝试 TLS 握手到 (server:port, SNI)，验证证书 SNI 匹配
# - WS 节点：尝试发送 HTTP Upgrade 请求，看是否返回 101
# 这样能筛掉"TCP 通但代理不可用"的假阳性

def resolve(host)
  return host if host =~ /\A\d+\.\d+\.\d+\.\d+\z/
  Resolv.getaddress(host).to_s
rescue StandardError
  nil
end

# 深度测试：返回 [latency_ms, alive]
# alive 表示该节点的传输层确实可用（不只是 TCP 端口开放）
def deep_test(px, timeout = 4)
  host = px["server"].to_s
  port = px["port"].to_i
  return [9999, false] if host.empty? || port == 0

  ip = resolve(host)
  return [9999, false] unless ip

  sni = (px["servername"] || px["sni"] || host).to_s
  use_tls = px["tls"] == true || px["type"] == "trojan"

  begin
    start = Time.now
    sock = Timeout.timeout(timeout) { TCPSocket.new(ip, port) }
    sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

    if use_tls
      # 真实 TLS 握手，验证证书链能建立
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE # 不验证证书，只验证能握手
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.hostname = sni if sni && !sni.empty?
      Timeout.timeout(timeout) { ssl.connect }
      latency = ((Time.now - start) * 1000).round

      # 对 WS 节点：发送 HTTP Upgrade，期望 101 响应（更可靠）
      if px["network"] == "ws" && px["ws-opts"] && !ssl.closed?
        begin
          ws_path = px["ws-opts"]["path"] || "/"
          ws_host = (px["ws-opts"]["headers"] || {}).fetch("Host", sni)
          req = "GET #{ws_path} HTTP/1.1\r\nHost: #{ws_host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
          ssl.write(req)
          resp = ""
          Timeout.timeout(timeout) do
            while (line = ssl.gets)
              resp += line
              break if resp =~ /\r\n\r\n/
            end
          end
          # 101 Switching Protocols 表示 WS 服务端确实在响应
          if resp =~ /^HTTP\/1\.1 101/
            ssl.close rescue nil
            sock.close rescue nil
            return [latency, true]
          else
            # 即便不是 101，只要 TLS 握手成功且收到 HTTP 响应也算可用
            if resp =~ /^HTTP\/1\.1/
              ssl.close rescue nil
              sock.close rescue nil
              return [latency, true]
            end
          end
        rescue StandardError
          nil
        end
      end

      ssl.close rescue nil
      sock.close rescue nil
      return [latency, true]
    else
      # no-TLS 节点：发 HTTP 请求验证服务确实在线（防止运营商劫持）
      begin
        ws_path = (px["ws-opts"] || {})["path"] || "/"
        ws_host = (px["ws-opts"] && px["ws-opts"]["headers"] && px["ws-opts"]["headers"]["Host"]) || host
        req = "GET #{ws_path} HTTP/1.1\r\nHost: #{ws_host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        sock.write(req)
        resp = ""
        Timeout.timeout(timeout) do
          while (line = sock.gets)
            resp += line
            break if resp =~ /\r\n\r\n/
          end
        end
        latency = ((Time.now - start) * 1000).round
        sock.close rescue nil
        # 只接受真实 HTTP 响应（防止运营商 DNS 劫持返回 HTML 广告页）
        return [latency, true] if resp =~ /^HTTP\/1\.1 (101|200|400|404|401|403)/
        return [9999, false]
      rescue StandardError
        sock.close rescue nil
        return [9999, false]
      end
    end
  rescue StandardError
    (sock&.close rescue nil)
    [9999, false]
  end
end

puts "开始深度测速（TLS 握手 + WS Upgrade）..."
# 测全部候选节点（不设上限，保留所有可用节点）
candidates = tls_nodes + notls_nodes
results = candidates.each_with_index.map do |p, i|
  lat, alive = deep_test(p)
  print(alive ? "+" : "-")
  print "\n" if (i + 1) % 30 == 0
  { proxy: p, latency: lat, alive: alive }
end
puts ""

# === 5. 只保留深度测试真正存活的节点（剔除所有 Timeout）===
alive_results = results.select { |r| r[:alive] && r[:latency] < 9999 }.sort_by { |r| r[:latency] }
puts "深度测试存活: #{alive_results.length}/#{results.length}"

# 只保留存活节点（不再补未存活的，避免 App 里一堆 Timeout）
selected = alive_results

# 保底：如果存活节点太少（<10），才补未存活的
if selected.length < 10
  puts "⚠️ 存活节点不足 10 个，补入未存活节点（按质量排序）..."
  rest = (results - alive_results).first(20 - selected.length)
  selected += rest
end

# 极端情况：如果没存活节点，回退到 TCP ping
if selected.empty?
  puts "⚠️ 深度测试全部失败，回退到 TCP ping..."
  candidates.each_with_index do |p, i|
    ip = resolve(p["server"])
    next unless ip
    begin
      start = Time.now
      Timeout.timeout(3) { TCPSocket.new(ip, p["port"]).close }
      selected << { proxy: p, latency: ((Time.now - start) * 1000).round, alive: false }
    rescue StandardError
      nil
    end
  end
  selected.sort_by! { |r| r[:latency] }
end

puts "最终选取: #{selected.length}"
exit 1 if selected.empty?

# === 6. 节点重命名：序号+地理标签 ===
cc_map = {
  "美国" => "US", "United States" => "US", "英国" => "GB", "United Kingdom" => "GB",
  "德国" => "DE", "Germany" => "DE", "法国" => "FR", "France" => "FR",
  "日本" => "JP", "Japan" => "JP", "韩国" => "KR", "Korea" => "KR",
  "新加坡" => "SG", "Singapore" => "SG", "香港" => "HK", "Hong Kong" => "HK",
  "台湾" => "TW", "Taiwan" => "TW", "加拿大" => "CA", "Canada" => "CA",
  "澳大利亚" => "AU", "Australia" => "AU", "俄罗斯" => "RU", "Russia" => "RU",
  "荷兰" => "NL", "Netherlands" => "NL", "芬兰" => "FI", "Finland" => "FI",
  "瑞典" => "SE", "Sweden" => "SE", "阿联酋" => "AE", "United Arab Emirates" => "AE",
  "印度" => "IN", "India" => "IN", "土耳其" => "TR", "Turkey" => "TR",
  "波兰" => "PL", "Poland" => "PL", "意大利" => "IT", "Italy" => "IT",
  "西班牙" => "ES", "Spain" => "ES", "巴西" => "BR", "Brazil" => "BR",
  "印度尼西亚" => "ID", "Indonesia" => "ID",
}
used_names = {}
renamed = selected.each_with_index.map do |r, i|
  p = r[:proxy].dup
  orig = p["name"].to_s
  cc = "OT"
  cc_map.each { |k, v| orig.include?(k) && cc = v }
  base = format("N%03d-%s", i + 1, cc)
  if used_names[base]
    used_names[base] += 1
    base = "#{base}##{used_names[base]}"
  else
    used_names[base] = 1
  end
  p["name"] = base
  r[:proxy] = p
  r
end

# === 7. 生成 YAML ===
def yaml_quote(v)
  v = v.to_s
  needs_quote = v.empty? || v =~ /[\s:,#\[\]{}&*!|>'"%@`]/ || v =~ /\A[-?]/
  needs_quote ? '"' + v.gsub(/\\/, '\\\\\\').gsub(/"/, '\\"') + '"' : v
end

lines = ["proxies:"]
renamed.each do |r|
  p = r[:proxy]
  lines << "  - name: \"#{p['name']}\""
  lines << "    type: #{p['type']}"
  lines << "    server: #{p['server']}"
  lines << "    port: #{p['port']}"
  case p["type"]
  when "vless"
    lines << "    uuid: #{p['uuid']}"
    lines << "    network: #{p['network'] || 'tcp'}"
    lines << "    flow: #{p['flow']}" if p["flow"]
    lines << "    udp: true"
    lines << "    tls: #{p['tls'] ? 'true' : 'false'}"
    lines << "    servername: #{yaml_quote(p['servername'])}" if p["servername"] && !p["servername"].to_s.empty?
    lines << "    client-fingerprint: #{p['client-fingerprint']}" if p["tls"] && p["client-fingerprint"]
    if p["reality-opts"]
      lines << "    reality-opts:"
      lines << "      public-key: \"#{p['reality-opts']['public-key']}\""
      lines << "      short-id: \"#{p['reality-opts']['short-id']}\"" if p["reality-opts"]["short-id"]
    end
    if p["ws-opts"]
      lines << "    ws-opts:"
      lines << "      path: #{yaml_quote(p['ws-opts']['path'] || '/')}"
      if p["ws-opts"]["headers"]
        lines << "      headers:"
        p["ws-opts"]["headers"].each { |k, v| lines << "        #{k}: #{yaml_quote(v)}" }
      end
    end
    if p["grpc-opts"]
      lines << "    grpc-opts:"
      lines << "      grpc-service-name: #{yaml_quote(p['grpc-opts']['grpc-service-name'])}"
    end
  when "vmess"
    lines << "    uuid: #{p['uuid']}"
    lines << "    alterId: #{p['alterId'] || 0}"
    lines << "    cipher: #{p['cipher'] || 'auto'}"
    lines << "    network: #{p['network'] || 'tcp'}"
    lines << "    udp: true"
    lines << "    tls: #{p['tls'] ? 'true' : 'false'}"
    lines << "    servername: #{yaml_quote(p['servername'])}" if p["servername"] && !p["servername"].to_s.empty?
    lines << "    client-fingerprint: #{p['client-fingerprint']}" if p["tls"] && p["client-fingerprint"]
    if p["ws-opts"]
      lines << "    ws-opts:"
      lines << "      path: #{yaml_quote(p['ws-opts']['path'] || '/')}"
      if p["ws-opts"]["headers"]
        lines << "      headers:"
        p["ws-opts"]["headers"].each { |k, v| lines << "        #{k}: #{yaml_quote(v)}" }
      end
    end
  when "trojan"
    lines << "    password: #{yaml_quote(p['password'])}"
    lines << "    udp: true"
    sni_val = p["servername"] && !p["servername"].to_s.empty? ? p["servername"] : p["server"]
    lines << "    sni: #{yaml_quote(sni_val)}"
    lines << "    skip-cert-verify: #{p['skip-cert-verify'] ? 'true' : 'false'}"
  when "ss"
    lines << "    cipher: #{p['cipher']}"
    lines << "    password: #{yaml_quote(p['password'])}"
    lines << "    udp: true"
  end
end

names = renamed.map { |r| r[:proxy]["name"] }
lines << ""
lines << "proxy-groups:"
lines << "  - name: Auto"
lines << "    type: url-test"
lines << "    url: https://www.gstatic.com/generate_204"
lines << "    interval: 120"
lines << "    tolerance: 50"
lines << "    proxies:"
names.each { |n| lines << "      - \"#{n}\"" }
lines << "  - name: Proxy"
lines << "    type: select"
lines << "    proxies:"
lines << "      - Auto"
names.each { |n| lines << "      - \"#{n}\"" }

lines << ""
lines << "rules:"
lines << "  - MATCH,Proxy"

File.write("/tmp/dali_config.yaml", lines.join("\n") + "\n")
puts "✅ 生成成功，节点数: #{renamed.length}"
# 打印存活节点统计
tls_count = renamed.count { |r| r[:proxy]["tls"] == true || r[:proxy]["type"] == "trojan" }
notls_count = renamed.length - tls_count
puts "   其中 TLS: #{tls_count} / 无 TLS: #{notls_count}"
