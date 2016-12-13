#! /bin/sh

source $(dirname $0)/target.sh

./zep2newt.py \
    --bin ../zephyr/samples/shell/outdir/$BOARD/zephyr.bin \
    --key root.pem \
    --sig RSA \
    --out shell.signed.bin \
    --bit --pad 0x20000

./zep2newt.py \
    --bin ../zephyr/samples/hello_world/outdir/$BOARD/zephyr.bin \
    --key root.pem \
    --sig RSA \
    --out hello.signed.bin
