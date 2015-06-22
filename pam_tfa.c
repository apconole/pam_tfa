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

#ifdef USE_CURL
#include <curl/curl.h>
#endif

#ifdef USE_SSL
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#endif

#define TFA_CONFIG "/.tfa_config"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define MODULE_NAME "pam_tfa"

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

//// Base64 routines

#ifdef USE_SSL
/**
 * @brief encodes a buffer, and places the result as a string (which must be
 * freed)
 *
 * @param buffer [in] Input string to encode
 * @param length [in] Length of the input string
 * @return String which is the base 64 encoded string.
 */
char *base64_encode(const unsigned char *buffer, size_t length)
{
    char *b64txt;
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    b64txt = strdup((*bufferPtr).data);
    BIO_set_close(bio, BIO_CLOSE);
    BIO_free_all(bio);
    return b64txt;
}
#endif
//// the following is the main entrypoint

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    char emailToAddr[256], emailFromAddr[256], emailServer[256],
        emailPort[256], emailUser[256], emailPass[256];

    struct tfa_file_param_map
    {
        const char *param_name;
        char *output_variable;
        size_t length_of_output;            
    } file_params[] = {
        {"email", emailToAddr, sizeof(emailToAddr)},
        {"from", emailFromAddr, sizeof(emailFromAddr)},
        {"server", emailServer, sizeof(emailServer)},
        {"port", emailPort, sizeof(emailPort)},
        {"username", emailUser, sizeof(emailUser)},
        {"password", emailPass, sizeof(emailPass)}
    };
    int debug = 0, opt_in = 1, i;
    struct passwd *findUser;
    const char *currentUser;
#ifdef USE_SSL
    unsigned char randBuf[8];
#endif
    
    char line[275];
    
    FILE *tfa_file = NULL;
    char *tfa_filename = "";
    struct stat tfa_stat;
    
    for( i = 0; i < argc; ++i ){
        if( strcmp("debug", argv[i]) == 0 )
            debug = 1;
        if( strcmp("noopt", argv[i]) == 0 )
            opt_in = 0;
    }
    
    if(pam_get_user(pamh, &currentUser, NULL) != PAM_SUCCESS ||
       currentUser == NULL || strlen(currentUser) == 0)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to determine target user.");
        return PAM_SYSTEM_ERR;
    }

    if(debug) pam_syslog(pamh, LOG_DEBUG, "TwoFactor for %s", currentUser);
    
    // seek through the pw entries
    setpwent(); // reset the pwentries
    errno = 0;
    findUser = getpwent();
    if( debug ) pam_syslog(pamh, LOG_DEBUG, "check against %s", findUser->pw_name);
    while( !errno && findUser && strcmp(findUser->pw_name, currentUser) )
    {
        findUser = getpwent();
        if( debug ) pam_syslog(pamh, LOG_DEBUG, "check against %s", findUser->pw_name);
    }
    
    if( errno )
    {
        endpwent(); // cleanup here to avoid squelching errno
        if( debug )
        {
            pam_syslog(pamh, LOG_DEBUG, "Error while using getpwent");
        }
        return PAM_SYSTEM_ERR;
    }

    if( !findUser )
    {
        pam_syslog(pamh, LOG_ERR, "Unable to find user id (%s) in the pwent database", currentUser);
        endpwent();
        return PAM_SYSTEM_ERR;
    }

    /// now we have the correct user - allocate strlen pwdir, strlen tfa_config and 1 terminating null byte
    tfa_filename = (char*)malloc(strlen(findUser->pw_dir)+strlen(TFA_CONFIG)+1);
    if( !tfa_filename )
    {
        pam_syslog(pamh, LOG_ERR, "Unable to alloc memory");
        endpwent();
        return PAM_SYSTEM_ERR;
    }

    *tfa_filename = 0; // set first byte to nil for favorable str* interaction

    // this should be okay, we used pw_dir to make the dest long
    // HOWEVER, we should probably figure out a 'safe' mechanism
    strcpy(tfa_filename, findUser->pw_dir);
    strcat(tfa_filename, TFA_CONFIG);
    
    endpwent(); // ensure we clean up

    /// 
    if(0 != stat(tfa_filename, &tfa_stat) )
    {
        if( opt_in )
        {
            pam_syslog(pamh, LOG_WARNING, "User '%s' not opted in for file '%s', allowing",
                       findUser->pw_name, tfa_filename);
            free(tfa_filename);
            return PAM_SUCCESS;
        }
        
        //@todo: is it safe to print this name this way? I guess so since
        // the root user would have set this up... still... shiver?
        pam_syslog(pamh, LOG_ERR, "Unable to stat '%s'", tfa_filename);
        free(tfa_filename);
        return PAM_SYSTEM_ERR;
    }
    
    if( tfa_stat.st_mode & (S_IRWXG | S_IRWXO) )
    {
        pam_syslog(pamh, LOG_ERR, "G/O are allowed to manipulate the secret seed on '%s'.", tfa_filename);
        free(tfa_filename);
        // explicit denial here
        return PAM_PERM_DENIED;
    }
    
    tfa_file = fopen(tfa_filename, "r");
    if( tfa_file == NULL )
    {
        pam_syslog(pamh, LOG_ERR, "Unable to open '%s'", tfa_filename);
        free(tfa_filename);
        return PAM_PERM_DENIED; // if we can stat but can't open for reading
        // there is some kind of hack afoot - explicit deny
    }

    if( debug ) pam_syslog(pamh, LOG_DEBUG, "Opened '%s' for reading.", tfa_filename);
    free(tfa_filename);

    while(fgets(line, sizeof(line), tfa_file) != NULL)
    {
        int iws = 0, iparam, found=0;;
        while(iws < sizeof(line) && (line[iws] == ' ' || line[iws] == '\r' || line[iws] == '\t')) ++iws;
        if( iws == sizeof(line) ) continue;
        if ( line[iws] == '#' || line[iws] == '\n' ) continue;

        for(iparam = 0; iparam < sizeof(file_params) / sizeof(file_params[0]); ++iparam)
        {
            if( strncmp(file_params[iparam].param_name, line+iws, strlen(file_params[iparam].param_name)) ) continue;
            found = 1;
            // skip more ws until =
            iws += strlen(file_params[iparam].param_name);
            while(line[iws] == ' ' || line[iws] == '\t') ++iws;
            if(iws == sizeof(line) || line[iws] != '=')
            {
                pam_syslog(pamh, LOG_ERR, "Invalid format for '%s'",
                           file_params[iparam].param_name);
                fclose(tfa_file);
                return PAM_SYSTEM_ERR;
            }
            ++iws;
            while(line[iws] == ' ' || line[iws] == '\t') ++iws;
            if(iws == sizeof(line))
            {
                pam_syslog(pamh, LOG_ERR, "Invalid format for '%s'",
                           file_params[iparam].param_name);
                fclose(tfa_file);
                return PAM_SYSTEM_ERR;
            }
            strncpy(file_params[iparam].output_variable,
                    line+iws, MIN(file_params[iparam].length_of_output,
                                  sizeof(line)-iws));
            file_params[iparam].output_variable[file_params[iparam].length_of_output-1] = 0;
        }

        if(!found)
        {
            pam_syslog(pamh, LOG_WARNING, "Unknown element '%s' is being ignored.", line+iws);
        }
    }
    fclose(tfa_file); // later

    if( debug )
    {
        pam_syslog(pamh, LOG_DEBUG, "Email to: %s", emailToAddr);
        pam_syslog(pamh, LOG_DEBUG, "Email from: %s", emailFromAddr);
        pam_syslog(pamh, LOG_DEBUG, "Email server: %s", emailServer);
        pam_syslog(pamh, LOG_DEBUG, "Email port: %s", emailPort);
        pam_syslog(pamh, LOG_DEBUG, "Email username: %s", emailUser);
    }
    
#ifdef USE_SSL
    // get the random data
    if( !RAND_bytes(randBuf, 8) )
    {
        /// okay something bad happened. this is a case of really bail
        pam_syslog(pamh, LOG_ERR, "Unable to achieve randomness for authentication. Denying");
        return PAM_PERM_DENIED;
    }
#endif
    
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    return pam_sm_acct_mgmt(pamh, flags, argc, argv);
}
