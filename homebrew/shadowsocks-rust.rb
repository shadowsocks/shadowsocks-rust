class ShadowsocksRust < Formula
  desc "Rust port of Shadowsocks"
  homepage "https://github.com/shadowsocks/shadowsocks-rust"
  url "https://github.com/shadowsocks/shadowsocks-rust/archive/v1.15.3.tar.gz"
  sha256 "13b877b0961402310f45b814b1f4cefec141d0a2ff8be37d57f1ee966c41c497"
  license "MIT"
  head "https://github.com/shadowsocks/shadowsocks-rust.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
    (buildpath/"shadowsocks-rust.json").write <<~EOS
      {
          "server":"localhost",
          "server_port":8388,
          "password":"barfoo!",
          "timeout":600,
          "acl": "/usr/local/etc/chn.acl",
          "locals": [
              {
                  "protocol": "socks",
                  "local_address": "127.0.0.1",
                  "local_port": 1080
              },
              {
                  "protocol": "http",
                  "local_address": "127.0.0.1",
                  "local_port": 3128
              }
          ]
      }
    EOS
    etc.install "shadowsocks-rust.json"
  end

  service do
    run [opt_bin/"sslocal", "--config", etc/"shadowsocks-rust.json"]
    keep_alive true
  end

  test do
    server_port = free_port
    local_port = free_port

    (testpath/"server.json").write <<~EOS
      {
          "server":"127.0.0.1",
          "server_port":#{server_port},
          "password":"mypassword",
          "method":"aes-256-gcm"
      }
    EOS
    (testpath/"local.json").write <<~EOS
      {
          "server":"127.0.0.1",
          "server_port":#{server_port},
          "password":"mypassword",
          "method":"aes-256-gcm",
          "local_address":"127.0.0.1",
          "local_port":#{local_port}
      }
    EOS
    fork { exec bin/"ssserver", "-c", testpath/"server.json" }
    fork { exec bin/"sslocal", "-c", testpath/"local.json" }
    sleep 3

    output = shell_output "curl --socks5 127.0.0.1:#{local_port} https://example.com"
    assert_match "Example Domain", output
  end
end
