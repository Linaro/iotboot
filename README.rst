MCU Boot Loader
###############

This is a Zephyr port of the Mynewt project boot loader.  At the time
of writing, there is an effort to generalize the Mynewt bootloader.
This particular project should be considered temporary, until that
effort is finished.

Directory Layout
================

This project is organized as a Zephyr application.  As such, there is
a ``prj.conf`` file at the top level, and the source resides under
``src/``.  Within the source directory, ``src/bootutil/`` is a
snapshot of the Mynewt bootloader, with only minimal changes.  The
``design.txt`` file in this directory describes the details of this
bootloader.

Prerequisites
=============

There are a few Zephyr patches that need to be applied in order to be
able to use the bootloader.  If you are using a 96b_carbon, you will
need to make sure you use a tree that supports this board.  You will
also need the two patches:

- mbedTLS config for bootloader: This adds a configuration
  appropriate for the bootloader to mbedTLS.

- Create CONFIG_BOOT_HEADER: This places padding for a small header
  at the beginning of the image.

Building and using
==================

The bootloader is built as an ordinary Zephyr application.  Currently
the 96b_carbon is supported, and there is some support for the
frdm_k64f.  The k64f has some problems with the vector table when
chaining into the new image.

One way to build is to copy ``target.sh.example`` to ``target.sh`` and
edit appropriately.  Assuming your Zephyr tree is in ``../zephyr``,
you should then be able to run ``./build_boot.sh`` to build the
bootloader.

In order to load an application into the bootloader, you must change a
few configuration items:

- ``CONFIG_FLASH_BASE_ADDRESS``: The bootloader runs at the
  beginning of flash, and expects the first image currently to be
  loaded 0x20000 after this.  For 96b_carbon, this places the flash
  base address at 0x08020000.

- ``CONFIG_BOOT_HEADER``: This pads the beginning of the image with
  a space for the boot image header.  The header will be added by
  the signing script below.

Once the images have been built (this example places hello_world in
the first “primary” slot, and the shell in the second slot), they need
to be signed.  The ``sign.sh`` script will sign these particular
images, and can be used as an example.  Currently, RSA and bare SHA256
are supported by the signing script, and should match the
configuration of the bootloader in ``src/bootutil/src/Makefile``.

The ``flash.sh`` script is an example of flashing these images.  Upon
first boot, the bootloader should swap the images, and run the shell.
If nothing is done, a subsequent boot will swap the images back, and
consider the update as failed.

Changes from Mynewt
===================

In order to make this bootloader work in Zephyr, it was necessary to
wrap some of the OS APIS used by the code.  The dependency on
``malloc`` has been removed from this code, however mbedTLS still
needs an allocator.  By setting ``CONFIG_HEAP_MEM_POOL_SIZE`` to
16384, this provides sufficient memory for either RSA or ECDSA
verification.  The RAM will be completely reused by the run
application, so this memory is only needed while the bootloader runs.

The other dependency is on the ``flash_area_`` API, which is an
abstraction over both the flash driver, as well as partition
management.  Currently, the partition table is hardcoded.

There are two functions for querying flash alignment, and both
currently return 1.  These should be set to larger values for devices
that perform writes to flash in larger units than a byte (for example
K64F writes 8 bytes at a time).  This changes the layout of the image
trailer, as well as the address the magic value must be written in
order to initiate an upgrade, as well as the area where the 'boot
success' value should be written.
