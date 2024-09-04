
```bash
cargo install --path . --bin sslocal --features https-tunnel
sslocal --local-addr 0.0.0.0:2080 -k username:password -v -m aes-256-gcm -s host:444
curl https://baidu.com -x http://localhost:2080
```

## run.vbs

```bash
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "taskkill /F /IM sslocal.exe", 0, True
WshShell.Run "sslocal --local-addr 0.0.0.0:2080 -k username:password -v -m aes-256-gcm -s host:444", 0
```
