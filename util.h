/*
 * Copyright 2015, Aaron Conole
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PAMTFA_UTIL_H__
#define PAMTFA_UTIL_H__

#include <stdint.h>

/**
 * @brief encodes a buffer, and places the result as a string (which must be
 * freed)
 *
 * @param buffer [in] Input string to encode
 * @param length [in] Length of the input string
 * @return Malloc'd string which is the base 64 encoded string.
 */
char *base64_encode(const char *buffer, size_t length);

/**
 * @brief Retrieves a passwd structure, by username, from the /etc/passwd
 * database.
 *
 * @param username [in] Username of pwent structure
 * @param pwbuf [inout] Pointer to a passwd structure
 * @return 0 on success, and -1 on failure. When this function fails, use
 * errno to check on the cause.
 */
int32_t getPwEntryByName(const char *username, struct passwd *pwbuf);

/**
 * @brief Returns a 'cryptographically' sound 32-bits of randomness.
 * @return 4-byte value which is random. NOTE: it will return a known
 * pattern if the openssl routines on the local system fail.
 */
int32_t getRandomInt32(pam_handle_t *pamh);

/**
 * @brief 'Securely' deletes a heap allocated string (by 0'ing out the data).
 *
 * It is important to note that unless the buffer was allocated as locked into
 * memory, it will be possible that swapping will put it into a recoverable
 * data realm. This only positively prevents snooping when there's a heap
 * disclosure bug.
 */
void release_str(char *);

#endif
