/*
 * Copyright (c) 2017 Linaro
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

/**
 * @file
 * @brief Bootloader device specific configuration.
 */

#define FLASH_DRIVER_NAME		"NRF5_FLASH"
#define FLASH_ALIGN			1
#define FLASH_AREA_IMAGE_0_OFFSET	0x08000
#define FLASH_AREA_IMAGE_0_SIZE		0x3A000
#define FLASH_AREA_IMAGE_1_OFFSET	0x42000
#define FLASH_AREA_IMAGE_1_SIZE		0x3A000
#define FLASH_AREA_IMAGE_SCRATCH_OFFSET	0x7c000
#define FLASH_AREA_IMAGE_SCRATCH_SIZE	0x01000
