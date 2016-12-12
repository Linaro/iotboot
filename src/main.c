/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <zephyr.h>
#include <misc/printk.h>
#include <flash.h>
#include <asm_inline.h>

#include "bootutil/image.h"
#include "bootutil/bootutil.h"

struct device *boot_flash_device;

struct vector_table {
	uint32_t msp;
	uint32_t reset;
};

void os_heap_init(void);

void main(void)
{
	struct boot_rsp rsp;
	struct vector_table *vt;
	int rc;

	os_heap_init();

	boot_flash_device = device_get_binding("STM32F4_FLASH");
	if (!boot_flash_device) {
		printk("Flash device not found\n");
		while (1)
			;
	}

	rc = boot_go(&rsp);
	if (rc != 0) {
		printk("Unable to find bootable image\n");
		while (1)
			;
	}

	printk("Bootloader chain: 0x%x\n", rsp.br_image_addr);
	vt = (struct vector_table *)(rsp.br_image_addr + 0x80);
	irq_lock();
	_MspSet(vt->msp);
	((void (*)(void))vt->reset)();

	printk("Never should get here\n");
	while (1)
		;
}
