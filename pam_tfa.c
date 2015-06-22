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
#include <pwd.h>
#include <syslog.h>

#define TFA_CONFIG "/.tfa_config"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define MODULE_NAME "pam_tfa"

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

//// the following is the main entrypoint

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    int debug = 0, opt_in = 1, i;
    struct passwd *findUser;
    const char *currentUser;
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
    free(tfa_filename);

    if( debug ) pam_syslog(pamh, LOG_DEBUG, "Opened '%s' for reading.", tfa_filename);

    // get the seed
    // and the email
    
    
    fclose(tfa_file); // later
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    return pam_sm_acct_mgmt(pamh, flags, argc, argv);
}
