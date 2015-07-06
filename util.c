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

#define __STDC_FORMAT_MACROS
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <pwd.h>
#include <syslog.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/fsuid.h>

#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>

#include "util.h"

char *base64_encode(const char *buffer, size_t length)
{
    char *b64txt;
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    (void)BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    b64txt = strdup((*bufferPtr).data);
    
    (void)BIO_set_close(bio, BIO_CLOSE);
    BIO_free_all(bio);
    return b64txt;
}

int32_t getPwEntryByName(const char *username, struct passwd *pwbuf)
{
    struct passwd output_buf, *pw;
    char *buf;
#ifdef _SC_GETPW_R_SIZE_MAX
    int len = sysconf(_SC_GETPW_R_SIZE_MAX);
    if( len <= 0 )
        len = 16384; // indeterminate - 16k should be enough?
#else
    int len = 16384;
#endif

    buf = (char *)malloc(len);
    if( !buf )
    {
        return -1;
    }

    if( getpwnam_r(username, &output_buf, buf, len, &pw) || !pw )
    {
        int errret = errno;
        free( buf ); // free is, in some corner cases, allowed to manipulate
        // errno. Not sure whether we should masque that...
        // @todo look at how others have solved this?
        errno = errret;
        return -1;
    }

    pwbuf->pw_uid  = output_buf.pw_uid;
    pwbuf->pw_gid  = output_buf.pw_gid;
    pwbuf->pw_name = strdup(output_buf.pw_name);
    
    if( output_buf.pw_passwd )
        pwbuf->pw_passwd = strdup(output_buf.pw_passwd);
    else
        pwbuf->pw_passwd = NULL;

    pwbuf->pw_gecos = strdup(output_buf.pw_gecos);
    pwbuf->pw_dir   = strdup(output_buf.pw_dir);
    pwbuf->pw_shell = strdup(output_buf.pw_shell);

    memset(buf, 0, len);
    
    free(buf);
    return 0;
}

int32_t getRandomInt32(pam_handle_t *pamh)
{
    int32_t randBuf = 0xff000a00;
    if( !RAND_bytes((unsigned char *)&randBuf, 4) )
    {
        pam_syslog(pamh, LOG_ERR, "Unable to achieve randomness for authentication. Possible known pattern is being returned.");
    }
    return randBuf;
}

void release_str(char *str)
{
    size_t lstr;
    if( !str ) return;
    lstr = strlen(str);
    memset(str, 0, lstr);
    free(str);
}
