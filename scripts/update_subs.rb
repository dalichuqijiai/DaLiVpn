#!/usr/bin/env ruby
# frozen_string_literal: true
# 大力VPN 订阅合并+清洗+测速+选30个，参考 siiway/urlclash-converter 转换规则
# 输入: /tmp/s1.txt /tmp/s2.txt /tmp/s3.txt 三个订阅源
# 输出: /tmp/dali_config.yaml
require "yaml"
require "socket"
require "timeout"
require "cgi"
require "base64"
require "resolv"
require "json"

# === 1. 读 3 个订阅源 ===
sources = ["/tmp/s1.txt", "/tmp/s2.txt", "/tmp/s3.txt"]
raw_lines = []
sources.each do |f|
  next unless File.exist?(f)
  data = File.read(f).strip
  # 整文件 base64 解码
  if data.length > 50 && data !~ /\n/ && data =~ /\A[A-Za-z0-9+\/=\-_]+\z/
    begin
      decoded = Base64.decode64(data.tr("-_", "+/"))
      if decoded =~ /(vless|trojan|vmess|ss):\/\//
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
        # 严格校验: pbk 必须是 43 字符 urlsafe-base64，sid 必须是 ≤16 字符 hex
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
        # 仅当 security=tls 才启用 TLS（参考 siiway: security && security != "none"）
        px["tls"] = true
        sni = params["sni"] || params["peer"] || params["host"]
        px["servername"] = sni if sni && !sni.empty?
        px["flow"] = "xtls-rprx-vision" if params["flow"] && params["flow"].to_s.include?("vision")
        px["client-fingerprint"] = clean_fp(params["fp"]) if params["fp"]
      elsif security == "none" || security == ""
        # 无 TLS（port 80 等）
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
      px["servername"] = params["sni"] || params["peer"] || host if params["sni"] || params["peer"]
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
exit 1 if proxies.empty?

# === 3. TCP 测速（并发加速）===
def tcp_ping(host, port, timeout = 2)
  ip = nil
  begin
    ip = host =~ /\A\d+\.\d+\.\d+\.\d+\z/ ? host : Resolv.getaddress(host).to_s
  rescue StandardError
    return 9999
  end
  begin
    start = Time.now
    Timeout.timeout(timeout) do
      s = TCPSocket.new(ip, port)
      s.close
    end
    ((Time.now - start) * 1000).round
  rescue StandardError
    9999
  end
end

puts "开始 TCP 测速..."
results = proxies.each_with_index.map do |p, i|
  lat = tcp_ping(p["server"], p["port"])
  print "." if (i % 10).zero?
  { proxy: p, latency: lat }
end

# === 4. 选前 30 个存活节点 ===
alive = results.select { |r| r[:latency] < 9999 }.sort_by { |r| r[:latency] }
selected = alive.first(30)
selected += results.select { |r| r[:latency] >= 9999 }.first(30 - selected.length) if selected.length < 30
puts "\n存活: #{alive.length}, 最终选取: #{selected.length}"
exit 1 if selected.empty?

# === 5. 节点重命名：序号+地理标签 ===
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
  "西班牙" => "ES", "Spain" => "ES", "巴西" => "BR", "Brazil" => "BR"
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
  { proxy: p, latency: r[:latency] }
end

# === 6. 生成 YAML（手动构造，Mihomo 兼容）===
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
