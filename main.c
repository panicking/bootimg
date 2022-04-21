/*
** Copyright 2022, Amarula Solutions B.V.
** Copyright 2016, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

#include "bootimg.h"
#include "mincrypt/sha.h"

static char *read_hash(const byte *hash)
{
	char *str = malloc(SHA_DIGEST_SIZE * 2 + 1);
	char *c = str;
	const byte *h = hash;
	for (; c < str + SHA_DIGEST_SIZE * 2; h++) {
		c += sprintf(c, "%02x", *h);
	}
	*c = 0;
	return str;
}

void print_boot_info(const boot_img *image)
{
	char *hash = read_hash((byte*)image->hdr.hash);
	if (hash) {
		printf("IMAGE HASH 0x%s\n", hash);
		free(hash);
	}

	byte *bytes = bootimg_generate_hash(image);
	if (bytes) {
		char *hash = read_hash(bytes);
		if (hash) {
			printf("CALCULATE HASH 0x%s\n", hash);
			free(hash);
		}
		free(bytes);
	}
}

int main(const int argc, const char** argv)
{
	int ret = 0;
	boot_img *image = 0;

	if (argc < 2)
		printf("Not enough arguments!");

        if (!(image = load_boot_image(argv[1])) && (ret = EINVAL))
                printf("Fail to load boot image");

	print_boot_info(image);

	return ret;
}
