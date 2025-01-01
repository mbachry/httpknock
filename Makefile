all: build/httpknock

build:
	meson setup build --buildtype=debug --warnlevel=2 -D dev=true

build/httpknock: build
	ninja -C build

test: build/httpknock
	pytest

release:
	scripts/release.sh

clean:
	rm -rf build
