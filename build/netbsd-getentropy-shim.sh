#!/usr/bin/env bash
# NetBSD 9 (used by cross-rs's x86_64-unknown-netbsd image) lacks the
# `getentropy` symbol that `aws-lc-sys` references. `getentropy`/`getrandom`
# were only added in NetBSD 10.0.
#
# This script builds a small static shim that implements `getentropy` via
# the NetBSD `sysctl(CTL_KERN, KERN_ARND)` interface and installs it into
# the sysroot so the linker can resolve the symbol. The library is made
# available through RUSTFLAGS in Cross.toml.
#
# We use sysctl rather than /dev/urandom because:
#   - it avoids file descriptor allocation (no open/read/close)
#   - it does not depend on /dev being mounted (safe in chroot/containers)
#   - it is the same mechanism NetBSD 9's own arc4random uses internally
set -euo pipefail

SYSROOT="${CROSS_SYSROOT:-/usr/local/x86_64-unknown-netbsd}"
SHIMDIR="${SYSROOT}/shimlib"
mkdir -p "${SHIMDIR}"

# cross sets CC_<target> / AR_<target> as env vars in the container.
CC="${CC_x86_64_unknown_netbsd:-x86_64-unknown-netbsd-gcc}"
AR="${AR_x86_64_unknown_netbsd:-x86_64-unknown-netbsd-ar}"

cat > /tmp/getentropy_shim.c <<'EOF'
#include <stddef.h>
#include <sys/param.h>
#include <sys/sysctl.h>

/*
 * getentropy() was added in NetBSD 10.0. On NetBSD 9 we provide a shim
 * backed by sysctl(KERN_ARND), the same source the kernel uses to seed
 * user-space CSPRNGs (arc4random).
 */
int getentropy(void *buf, size_t buflen) {
    if (buflen > 256) return -1;

    int mib[2] = { CTL_KERN, KERN_ARND };
    size_t off = 0;
    while (off < buflen) {
        size_t rem = buflen - off;
        if (sysctl(mib, 2, (char *)buf + off, &rem, NULL, 0) == -1) {
            return -1;
        }
        if (rem == 0) return -1;
        off += rem;
    }
    return 0;
}
EOF

"${CC}" -c -fPIC /tmp/getentropy_shim.c -o /tmp/getentropy_shim.o
"${AR}" rcs "${SHIMDIR}/libgetentropy_shim.a" /tmp/getentropy_shim.o

echo "Installed getentropy shim to ${SHIMDIR}/libgetentropy_shim.a"
