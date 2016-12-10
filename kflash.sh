#! /bin/bash

JLinkExe -device MK64FN1M0VLL12 -si SWD -speed auto \
	-CommanderScript flash_k64f.jlink
