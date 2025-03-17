PREFIX ?= /usr/local/bin
TARGET ?= debug

.PHONY: all build install uninstall clean
all: build

build:
ifeq (${TARGET}, release)
	cargo build --release --features "full"
else
	cargo build --features "full"
endif

install:
	install -d ${DESTDIR}${PREFIX}
	install -m 755 target/${TARGET}/sslocal ${DESTDIR}${PREFIX}/sslocal
	install -m 755 target/${TARGET}/ssserver ${DESTDIR}${PREFIX}/ssserver
	install -m 755 target/${TARGET}/ssurl ${DESTDIR}${PREFIX}/ssurl
	install -m 755 target/${TARGET}/ssmanager ${DESTDIR}${PREFIX}/ssmanager
	install -m 755 target/${TARGET}/ssservice ${DESTDIR}${PREFIX}/ssservice

uninstall:
	rm ${DESTDIR}${PREFIX}/sslocal
	rm ${DESTDIR}${PREFIX}/ssserver
	rm ${DESTDIR}${PREFIX}/ssurl
	rm ${DESTDIR}${PREFIX}/ssmanager
	rm ${DESTDIR}${PREFIX}/ssservice

clean:
	cargo clean
