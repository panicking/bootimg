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
#include <stdbool.h>

#include "bootimg.h"
#include "mincrypt/sha.h"

#define HASH_LENGTH (SHA_DIGEST_SIZE * 2 + 1)

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

bool compare_hashes(char *info_hash, char *info_actual_hash)
{

	if (!info_hash || !info_actual_hash)
		return false;

	if (strncmp(info_hash, info_actual_hash, HASH_LENGTH) == 0)
		return true;

	return false;
}

void print_boot_info(const boot_img *image)
{
	bool equal_hashes = false;
	byte *bytes = NULL;
	char *hash2 = NULL;

	char *hash = read_hash((byte *)image->hdr.hash);

	bytes = bootimg_generate_hash(image);
	if (bytes) {
		hash2 = read_hash(bytes);
	}

	if (!hash2 || !hash) {
		printf("Unable to extract hashes from image\n");
		return;
	}

	equal_hashes = compare_hashes(hash, hash2);

	if (equal_hashes) {
		printf("Both the HASHES are equal to %s\n", hash);
	} else {
		printf("HASHES are different:\nIMAGE_HASH 0x%s\nCALCULATE_HASH 0x%s\n",
			   hash, hash2);
	}

	free(hash);
	free(hash2);
	free(bytes);
}

int main(const int argc, const char** argv)
{
	int ret = 0;
	boot_img *image = 0;

	if (argc <= 1) {
		printf("Not enough arguments!\nUse imageinfo <android boot image file>\n");
		return 0;
	}

	image = load_boot_image(argv[1]);
	if (!image) {
		printf("Fail to load boot image\n");
		return 0;
	}

	print_boot_info(image);

	return ret;
}
