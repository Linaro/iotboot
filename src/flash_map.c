/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <zephyr.h>
#include <misc/printk.h>

#include "flash_map/flash_map.h"

#define D(x) x { \
	printk("Unimplemented function: %s\n", __func__); \
	while (1) \
		; \
}

D(int flash_area_open(uint8_t id, const struct flash_area **area))
D(void flash_area_close(const struct flash_area *area))
D(int flash_area_read(const struct flash_area *area, uint32_t off, void *dst,
  uint32_t len))
D(int flash_area_write(const struct flash_area *area, uint32_t off, const void *src,
  uint32_t len))
D(int flash_area_erase(const struct flash_area *area, uint32_t off, uint32_t len))

D(uint8_t flash_area_align(const struct flash_area *area))

D(int flash_area_id_from_image_slot(int slot))
D(int flash_area_to_sectors(int idx, int *cnt, struct flash_area *ret))
