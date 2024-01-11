```
cargo run --package shadowsocks-rust --bin sslocal  -- --local-addr 0.0.0.0:2080 -k xxxxxx -v -m aes-256-gcm -s us.arloor.dev:444 --protocol http --use-http-tunnel=true
```

```bash
cargo install --path . --bin sslocal
sslocal --local-addr 0.0.0.0:2080 -k xxxxxx -v -m aes-256-gcm -s us.arloor.dev:444 --use-http-tunnel=true
curl https://baidu.com -x http://localhost:2080
```
