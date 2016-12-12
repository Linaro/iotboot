#! /bin/sh

./zep2newt.py \
    --bin ../zephyr/samples/shell/outdir/96b_carbon/zephyr.bin \
    --out shell.signed.bin \
    --bit --pad 0x20000

./zep2newt.py \
    --bin ../zephyr/samples/hello_world/outdir/96b_carbon/zephyr.bin \
    --out hello.signed.bin
