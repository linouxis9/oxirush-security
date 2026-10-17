/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/* What lib/crypt/milenage.c and lib/crypt/ogs-aes.c of Open5GS take from
 * the rest of Open5GS, so that the two build alone: the integer types, the
 * assertions and the codes of ogs-aes.c, and a log that prints nothing.
 * build.rs puts this file beside copies of the two, where they look for
 * "ogs-crypt.h" first. */

#ifndef OGS_CRYPT_H
#define OGS_CRYPT_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define OGS_CRYPT_COMPILATION
#define OGS_OK 0
#define OGS_ERROR -1
#define ogs_assert(expression) assert(expression)
#define OGS_LOG_INFO 0
#define ogs_log_print(level, ...) ((void)0)
#define ogs_log_hexdump(level, data, length) ((void)0)

#include "ogs-aes.h"
#include "milenage.h"

#endif
