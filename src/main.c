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

#include "bootutil/image.h"
#include "bootutil/bootutil.h"

void main(void)
{
	struct boot_rsp rsp;
	int rc;

	rc = boot_go(&rsp);
	if (rc != 0) {
		printk("Unable to find bootable image\n");
		while (1)
			;
	}
	printk("Hello World! %s\n", CONFIG_ARCH);
}
