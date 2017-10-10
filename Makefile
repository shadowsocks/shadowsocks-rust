PREFIX ?= /usr/local/bin
TARGET ?= debug

.PHONY: all build install uninstall clean
all: build

build:
ifeq (${TARGET}, release)
	cargo build --release
else
	cargo build
endif

install:
	install -Dm 755 target/${TARGET}/sslocal ${DESTDIR}${PREFIX}/sslocal
	install -Dm 755 target/${TARGET}/ssserver ${DESTDIR}${PREFIX}/ssserver
	install -Dm 755 target/${TARGET}/ssurl ${DESTDIR}${PREFIX}/ssurl

uninstall:
	rm ${DESTDIR}${PREFIX}/sslocal
	rm ${DESTDIR}${PREFIX}/ssserver
	rm ${DESTDIR}${PREFIX}/ssurl

clean:
	cargo clean
