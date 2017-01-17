subdir-ccflags-y += -DMCUBOOT_TARGET_CONFIG='"$(BOARD).h"'

ccflags-y += -I$(PROJECT)/targets
ccflags-y += -I$(PROJECT)/include
ccflags-y += -I$(PROJECT)/src/bootutil/include

obj-y += main.o flash_map.o hal_flash.o os.o
obj-y += keys.o

obj-y += bootutil/src/
