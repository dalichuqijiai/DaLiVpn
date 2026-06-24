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

# === 1. 读 5 个订阅源 ===
sources = ["/tmp/s1.txt", "/tmp/s2.txt", "/tmp/s3.txt", "/tmp/s4.txt", "/tmp/s5.txt"]
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

# 测全部候选节点（不设上限，保留所有可用节点）
candidates = tls_nodes + notls_nodes
puts "开始深度测速（TLS 握手 + WS Upgrade，并发 50 / 共 #{candidates.length}）..."
# 并发测速：用工作队列限制并发数为 50，避免一次起上千线程
require "thread"
results = Array.new(candidates.length)
mutex = Mutex.new
done = [0]
queue = candidates.each_with_index.to_a
threads = 50.times.map do
  Thread.new do
    loop do
      item = mutex.synchronize { queue.shift }
      break if item.nil?
      p, idx = item  # each_with_index 返回 [element, index]
      lat, alive = deep_test(p)
      mutex.synchronize do
        results[idx] = { proxy: p, latency: lat, alive: alive }
        done[0] += 1
        print(alive ? "+" : "-")
        print "\n" if done[0] % 30 == 0
      end
    end
  end
end
threads.each(&:join)
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

# === 6. 节点重命名：序号+中文国家/地区名 ===
# 关键词 → 中文名（按匹配优先级排列，先匹配的优先）
# 同时支持中文关键词、英文国名、英文城市、国家代码 TLD
cc_map = [
  ["美国", "美国"], ["United States", "美国"], ["UnitedStates", "美国"], ["USA", "美国"], ["美国", "美国"], [".us", "美国"], ["Los Angeles", "美国"], ["New York", "美国"], ["San Jose", "美国"], ["Seattle", "美国"], ["Chicago", "美国"], ["Dallas", "美国"], ["Miami", "美国"], ["Washington", "美国"], ["Oregon", "美国"],
  ["香港", "香港"], ["Hong Kong", "香港"], ["HongKong", "香港"], ["HK", "香港"], [".hk", "香港"],
  ["台湾", "台湾"], ["Taiwan", "台湾"], [".tw", "台湾"], ["台北", "台湾"],
  ["日本", "日本"], ["Japan", "日本"], ["JP", "日本"], [".jp", "日本"], ["Tokyo", "日本"], ["大阪", "日本"], ["Osaka", "日本"],
  ["新加坡", "新加坡"], ["Singapore", "新加坡"], ["SG", "新加坡"], [".sg", "新加坡"],
  ["韩国", "韩国"], ["Korea", "韩国"], ["Seoul", "韩国"], ["首尔", "韩国"], [".kr", "韩国"],
  ["英国", "英国"], ["United Kingdom", "英国"], ["UK", "英国"], ["London", "英国"], ["伦敦", "英国"], [".uk", "英国"],
  ["德国", "德国"], ["Germany", "德国"], ["DE", "德国"], ["Frankfurt", "德国"], ["法兰克福", "德国"], [".de", "德国"],
  ["法国", "法国"], ["France", "法国"], ["Paris", "法国"], ["巴黎", "法国"], [".fr", "法国"],
  ["荷兰", "荷兰"], ["Netherlands", "荷兰"], ["Amsterdam", "荷兰"], ["阿姆斯特丹", "荷兰"], [".nl", "荷兰"],
  ["俄罗斯", "俄罗斯"], ["Russia", "俄罗斯"], ["RU", "俄罗斯"], ["Moscow", "俄罗斯"], ["莫斯科", "俄罗斯"], [".ru", "俄罗斯"],
  ["加拿大", "加拿大"], ["Canada", "加拿大"], ["Toronto", "加拿大"], ["Vancouver", "加拿大"], [".ca", "加拿大"],
  ["澳大利亚", "澳大利亚"], ["Australia", "澳大利亚"], ["Sydney", "澳大利亚"], ["悉尼", "澳大利亚"], [".au", "澳大利亚"],
  ["芬兰", "芬兰"], ["Finland", "芬兰"], ["Helsinki", "芬兰"], [".fi", "芬兰"],
  ["瑞典", "瑞典"], ["Sweden", "瑞典"], ["Stockholm", "瑞典"], [".se", "瑞典"],
  ["意大利", "意大利"], ["Italy", "意大利"], ["Milan", "意大利"], ["Rome", "意大利"], [".it", "意大利"],
  ["西班牙", "西班牙"], ["Spain", "西班牙"], ["Madrid", "西班牙"], [".es", "西班牙"],
  ["土耳其", "土耳其"], ["Turkey", "土耳其"], ["Istanbul", "土耳其"], [".tr", "土耳其"],
  ["波兰", "波兰"], ["Poland", "波兰"], ["Warsaw", "波兰"], [".pl", "波兰"],
  ["印度", "印度"], ["India", "印度"], ["Mumbai", "印度"], ["孟买", "印度"], [".in", "印度"],
  ["巴西", "巴西"], ["Brazil", "巴西"], ["Sao Paulo", "巴西"], [".br", "巴西"],
  ["阿联酋", "阿联酋"], ["United Arab Emirates", "阿联酋"], ["Dubai", "阿联酋"], ["迪拜", "阿联酋"], [".ae", "阿联酋"],
  ["印度尼西亚", "印度尼西亚"], ["Indonesia", "印度尼西亚"], ["Jakarta", "印度尼西亚"], [".id", "印度尼西亚"],
  ["泰国", "泰国"], ["Thailand", "泰国"], ["Bangkok", "泰国"], ["曼谷", "泰国"], [".th", "泰国"],
  ["越南", "越南"], ["Vietnam", "越南"], ["Viet Nam", "越南"], ["Hanoi", "越南"], [".vn", "越南"],
  ["菲律宾", "菲律宾"], ["Philippines", "菲律宾"], ["Manila", "菲律宾"], [".ph", "菲律宾"],
  ["马来西亚", "马来西亚"], ["Malaysia", "马来西亚"], ["Kuala Lumpur", "马来西亚"], [".my", "马来西亚"],
  ["阿根廷", "阿根廷"], ["Argentina", "阿根廷"], [".ar", "阿根廷"],
  ["墨西哥", "墨西哥"], ["Mexico", "墨西哥"], [".mx", "墨西哥"],
  ["瑞士", "瑞士"], ["Switzerland", "瑞士"], [".ch", "瑞士"],
  ["奥地利", "奥地利"], ["Austria", "奥地利"], [".at", "奥地利"],
  ["比利时", "比利时"], ["Belgium", "比利时"], [".be", "比利时"],
  ["捷克", "捷克"], ["Czech", "捷克"], [".cz", "捷克"],
  ["罗马尼亚", "罗马尼亚"], ["Romania", "罗马尼亚"], [".ro", "罗马尼亚"],
  ["乌克兰", "乌克兰"], ["Ukraine", "乌克兰"], [".ua", "乌克兰"],
  ["以色列", "以色列"], ["Israel", "以色列"], [".il", "以色列"],
  ["南非", "南非"], ["South Africa", "南非"], [".za", "南非"],
  ["立陶宛", "立陶宛"], ["Lithuania", "立陶宛"], [".lt", "立陶宛"],
  ["哈萨克斯坦", "哈萨克斯坦"], ["Kazakhstan", "哈萨克斯坦"], [".kz", "哈萨克斯坦"],
  ["白俄罗斯", "白俄罗斯"], ["Belarus", "白俄罗斯"], [".by", "白俄罗斯"],
  ["摩尔多瓦", "摩尔多瓦"], ["Moldova", "摩尔多瓦"], [".md", "摩尔多瓦"],
  ["保加利亚", "保加利亚"], ["Bulgaria", "保加利亚"], [".bg", "保加利亚"],
  ["塞尔维亚", "塞尔维亚"], ["Serbia", "塞尔维亚"], [".rs", "塞尔维亚"],
  ["拉脱维亚", "拉脱维亚"], ["Latvia", "拉脱维亚"], [".lv", "拉脱维亚"],
  ["葡萄牙", "葡萄牙"], ["Portugal", "葡萄牙"], [".pt", "葡萄牙"],
  ["爱尔兰", "爱尔兰"], ["Ireland", "爱尔兰"], [".ie", "爱尔兰"],
  ["丹麦", "丹麦"], ["Denmark", "丹麦"], [".dk", "丹麦"],
  ["挪威", "挪威"], ["Norway", "挪威"], [".no", "挪威"],
  ["希腊", "希腊"], ["Greece", "希腊"], [".gr", "希腊"],
  ["匈牙利", "匈牙利"], ["Hungary", "匈牙利"], [".hu", "匈牙利"],
  ["智利", "智利"], ["Chile", "智利"], [".cl", "智利"],
  ["哥伦比亚", "哥伦比亚"], ["Colombia", "哥伦比亚"], [".co", "哥伦比亚"],
  ["埃及", "埃及"], ["Egypt", "埃及"], [".eg", "埃及"],
  ["尼日利亚", "尼日利亚"], ["Nigeria", "尼日利亚"], [".ng", "尼日利亚"],
  ["肯尼亚", "肯尼亚"], ["Kenya", "肯尼亚"], [".ke", "肯尼亚"],
]
# Cloudflare CDN IP 段（单独归类为 美国-CDN，与普通美国节点区分）
CLOUDFLARE_RANGES = [
  /\A162\.159\.\d{1,3}\.\d{1,3}\z/,  # Cloudflare 主要段
  /\A104\.1[6-9]\.\d{1,3}\.\d{1,3}\z/,  # Cloudflare 104.16-19
  /\A104\.2[0-7]\.\d{1,3}\.\d{1,3}\z/,  # Cloudflare 104.20-27
  /\A172\.6[4-7]\.\d{1,3}\.\d{1,3}\z/,  # Cloudflare 172.64-67
  /\A188\.114\.\d{1,3}\.\d{1,3}\z/,  # Cloudflare
  /\A172\.7[0-1]\.\d{1,3}\.\d{1,3}\z/,  # Cloudflare 172.70-71
  /\A104\.1[5]\.\d{1,3}\.\d{1,3}\z/,  # Cloudflare 104.15
]
# 其他美国 CDN（Fastly/Vercel 等）
CDN_US_RANGES = [
  /\A141\.193\.\d{1,3}\.\d{1,3}\z/,  # Fastly
  /\A199\.232\.\d{1,3}\.\d{1,3}\z/,  # Fastly
  /\A151\.101\.\d{1,3}\.\d{1,3}\z/,  # Fastly
  /\A167\.82\.\d{1,3}\.\d{1,3}\z/,  # Vercel/Fastly
  /\A63\.141\.\d{1,3}\.\d{1,3}\z/,  # Kafka US
]
used_names = {}
renamed = selected.each_with_index.map do |r, i|
  p = r[:proxy].dup
  orig = p["name"].to_s
  # 同时检查原始 name 和 server 域名
  check_str = (orig + " " + p["server"].to_s + " " + (p["servername"] || p["sni"] || "").to_s).downcase
  region = "其他"
  # 1. 先用关键词匹配（国家名/城市/TLD）
  cc_map.each do |kw, cn|
    if check_str.include?(kw.downcase)
      region = cn
      break
    end
  end
  # 2. 如果没匹配到，检查是否是 CDN IP
  if region == "其他"
    server_ip = p["server"].to_s
    # 2a. Cloudflare 节点单独标记为 美国-CDN
    CLOUDFLARE_RANGES.each do |re|
      if server_ip =~ re
        region = "美国-CDN"
        break
      end
    end
    # 2b. 其他美国 CDN（Fastly/Vercel）归类美国
    if region == "其他"
      CDN_US_RANGES.each do |re|
        if server_ip =~ re
          region = "美国"
          break
        end
      end
    end
  end
  base = format("%s-%03d", region, i + 1)
  if used_names[base]
    used_names[base] += 1
    base = "#{base}-#{used_names[base]}"
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
