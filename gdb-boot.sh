#! /bin/bash

exec /mnt/linaro/toolchains/aarch32/bin/arm-linux-gnueabihf-gdb \
	-x init-boot.gdb
