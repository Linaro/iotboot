#! /bin/bash

source ../zephyr/zephyr-env.sh

# make BOARD=96b_carbon "$@"
make BOARD=frdm_k64f "$@"
