# Shadowsocks SELinux Policy

## Prerequisites

Install required SELinux development tools:
```bash
dnf upgrade && dnf install setools-console policycoreutils-python-utils selinux-policy-devel make
```

## Creating SELinux Policy

### 1. Compile the policy

```bash
make -f /usr/share/selinux/devel/Makefile shadowsocks.pp
```

### 2. Install the policy module

```bash
semodule -i shadowsocks.pp
```

## Apply File Contexts

### 1. Add file context mappings

```bash
semanage fcontext -a -t shadowsocks_exec_t "/usr/bin/ssservice"
semanage fcontext -a -t shadowsocks_conf_t "/etc/shadowsocks(/.*)?"
semanage fcontext -a -t shadowsocks_unit_file_t "/usr/lib/systemd/system/ss-server@.*\.service"
```

### 2. Apply contexts to files

```bash
restorecon -v /etc/systemd/system/ss-server@.service
restorecon -R /usr/bin/ssservice /etc/shadowsocks
```

### 3. Start the service

```bash
systemctl start ss-server@main
```

### 4. Verify the policy is working

```bash
# Check that shadowsocks is running in the correct domain
ps -eZ | grep ssservice
# Should show: system_u:system_r:shadowsocks_t:s0 (not unconfined_service_t)
```

## Troubleshooting
### Check for SELinux denials

```bash
# View recent AVC denials
ausearch -m avc -ts recent | grep denied

# Generate additional policy rules if needed
ausearch -m avc -ts recent | grep shadowsocks | audit2allow
```

### Update policy if needed

If you need to add more permissions:

```bash
# Edit shadowsocks.te file
# Recompile and update
make -f /usr/share/selinux/devel/Makefile shadowsocks.pp
semodule -u shadowsocks.pp
```

### Remove policy (if needed)

```bash
# Remove file contexts first
semanage fcontext -d "/usr/bin/ssservice"
semanage fcontext -d "/etc/shadowsocks(/.*)?"
semanage fcontext -d "/usr/lib/systemd/system/ss-server@.*\.service"

# Reset file labels
restorecon -F /usr/bin/ssservice
restorecon -RF /etc/shadowsocks

# Remove the policy module
semodule -r shadowsocks
```

## Security Benefits

This policy provides several security improvements over running shadowsocks as `unconfined_service_t`:

- **Principle of least privilege**: Only grants necessary permissions
- **Network isolation**: Controls which ports and connections are allowed
- **File system protection**: Restricts file access to configuration and required system files
- **Process isolation**: Runs in a dedicated SELinux domain
- **Audit trail**: All access attempts are logged for security monitoring

## Notes

- The policy includes optional monitoring features (cgroup access, DNS watching)
- File contexts use equivalency rules between `/etc/systemd/system` and `/usr/lib/systemd/system`
