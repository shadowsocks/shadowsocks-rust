
```bash
cargo install --path . --bin sslocal --features https-tunnel
sslocal --local-addr 0.0.0.0:2080 -k username:password -v -m aes-256-gcm -s us.arloor.dev:444
curl https://baidu.com -x http://localhost:2080
```
