DESTDIR = /usr
version = $(shell awk 'NR == 3 {print substr($$3, 2, length($$3)-2)}' Cargo.toml)

all:
	cargo build --release

install:
	install -Dm 755 "target/release/sslocal" "${DESTDIR}/bin/sslocal"
	install -Dm 755 "target/release/sslocal" "${DESTDIR}/bin/ssserver"
	install -Dm 755 "target/release/sslocal" "${DESTDIR}/bin/ssurl"
	install -Dm 644 README.md "${DESTDIR}/share/doc/shadowsocks-rust/README"
	install -Dm 644 LICENSE "${DESTDIR}/share/licenses/shadowsocks-rust/COPYING"

tar:
	install -Dm 755 "target/release/sslocal" "${DESTDIR}/bin/sslocal"
	install -Dm 755 "target/release/sslocal" "${DESTDIR}/bin/ssserver"
	install -Dm 755 "target/release/sslocal" "${DESTDIR}/bin/ssurl"
	install -Dm 644 README.md "${DESTDIR}/share/doc/shadowsocks-rust/README"
	install -Dm 644 LICENSE "${DESTDIR}/share/licenses/shadowsocks-rust/COPYING"
	tar cf - "shadowsocks-rust" | xz -zf > "shadowsocks-rust_$(version)_$(shell uname -m).tar.xz"

uninstall:
	rm "${DESTDIR}/bin/sslocal"
	rm "${DESTDIR}/bin/ssserver"
	rm "${DESTDIR}/bin/ssurl"
	rm "${DESTDIR}/share/doc/shadowsocks-rust/README"
	rm "${DESTDIR}/share/licenses/shadowsocks-rust/COPYING"

clean:
	cargo clean
