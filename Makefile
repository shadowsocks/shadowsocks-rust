DESTDIR = /usr/local
version = $(shell awk 'NR == 3 {print substr($$3, 2, length($$3)-2)}' Cargo.toml)

.PHONY: all
all: build

.PHONY: build
build:
	cargo build --release

.PHONY: build-dev
build-dev:
	cargo build

install: build
	install -Dm 755 "target/release/sslocal" "${DESTDIR}/bin/sslocal"
	install -Dm 755 "target/release/ssserver" "${DESTDIR}/bin/ssserver"
	install -Dm 755 "target/release/ssurl" "${DESTDIR}/bin/ssurl"
	install -Dm 644 README.md "${DESTDIR}/share/doc/shadowsocks-rust/README"
	install -Dm 644 LICENSE "${DESTDIR}/share/licenses/shadowsocks-rust/COPYING"

install-dev: build-dev
	install -Dm 755 "target/debug/sslocal" "${DESTDIR}/bin/sslocal"
	install -Dm 755 "target/debug/ssserver" "${DESTDIR}/bin/ssserver"
	install -Dm 755 "target/debug/ssurl" "${DESTDIR}/bin/ssurl"
	install -Dm 644 README.md "${DESTDIR}/share/doc/shadowsocks-rust/README"
	install -Dm 644 LICENSE "${DESTDIR}/share/licenses/shadowsocks-rust/COPYING"

.PHONY: uninstall
uninstall:
	rm "${DESTDIR}/bin/sslocal"
	rm "${DESTDIR}/bin/ssserver"
	rm "${DESTDIR}/bin/ssurl"
	rm "${DESTDIR}/share/doc/shadowsocks-rust/README"
	rm "${DESTDIR}/share/licenses/shadowsocks-rust/COPYING"

.PHONY: clean
clean:
	cargo clean
