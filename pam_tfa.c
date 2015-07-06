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

#include <curl/curl.h>

#define TFA_CONFIG "/.tfa_config"
#define EMAIL_BUFSIZ 2048
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define MODULE_NAME "pam_tfa"

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>

#include "util.h"

//// global per-instance
char emailToAddr[256], emailFromAddr[256], emailServer[256],
    emailPort[256], emailUser[256], emailPass[256], failPolicy[256];

int debug = 0;

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
    {"password", emailPass, sizeof(emailPass)},
    {"fail", failPolicy, sizeof(failPolicy)}
};

//// Send the email
char MailPayload[EMAIL_BUFSIZ] = {0};

static void clearParams(void)
{
    size_t iparam;
    for(iparam = 0; iparam < sizeof(file_params) / sizeof(file_params[0]); ++iparam)
    {
        memset(file_params[iparam].output_variable, 0,
               file_params[iparam].length_of_output);
    }

    memset(MailPayload, 0, sizeof(MailPayload));
}


static char *request_random(pam_handle_t *pamh, int echocode, const char *prompt)
{
    //const struct pam_message msg = { .msg_style = echocode,
    //                                 .msg = prompt };
    //const struct pam_message *msgs = &msg;

    //struct pam_response *resp = NULL;
    char *resp;
    //int retval = converse(pamh, 1, &msgs, &resp);
    (void) pam_prompt(pamh, echocode, &resp, "%s", prompt);
    //int retval = misc_conv(1, &msgs, &resp, NULL);

    if( resp == NULL )
    {
        static char result = 0;
        resp = &result;
    }
    
    return resp;
}

//// Base64 routines


struct upload_status
{
    size_t bytes_read;
};

static size_t publish_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
    struct upload_status *upload_ctx = (struct upload_status *)userp;
    const char *data;
    
    if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
        return 0;
    }
    
    data = &MailPayload[upload_ctx->bytes_read];
    
    if(data) {
        size_t len = MIN(strlen(data), size);
        memcpy(ptr, data, len);
        upload_ctx->bytes_read += len;
        
        return len;
    }
    
    return 0;
}

static int publish_email(pam_handle_t *pamh, const char *currentUser, const char *code)
{
    struct upload_status upload_ctx;
    CURL *curl;
    CURLcode res = CURLE_OK;
    struct curl_slist *recipients = NULL;
    char emailServerURL[290] = {0};
    struct tm curTm;
    time_t start = time(0);

    if( !strlen(emailToAddr) || !strlen(emailFromAddr) ||
        !strlen(emailServer) || !strlen(emailPort) ||
        !strlen(emailUser)   || !strlen(emailPass) )
    {
        pam_syslog(pamh, LOG_ERR, "Failed for missing tfa_config element.");
        return -1;
    }

    gmtime_r(&start, &curTm);

    strcpy(MailPayload, "Date: ");
    strftime(MailPayload+strlen(MailPayload), 32, "%A, %d-%b-%Y %H:%M:%S", &curTm);
    strcat(MailPayload, "\r\nTo: ");
    strcat(MailPayload, emailToAddr);
    strcat(MailPayload, "\r\nFrom: ");
    strcat(MailPayload, emailFromAddr);
    strcat(MailPayload, "\r\nSubject: Attempted Log-in\r\n\r\n");
    strcat(MailPayload, "Your account name '");
    strcat(MailPayload, currentUser);
    strcat(MailPayload, "' authorization code "
           "\r\nCHECK: ");
    strcat(MailPayload, code);
    strcat(MailPayload, "\r\n\r\n");

    upload_ctx.bytes_read = 0;

    curl = curl_easy_init();
    if(!curl)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to allocate 'curl' object");
        return -2;
    }
    strcpy(emailServerURL, "smtp://");
    strcat(emailServerURL, emailServer);
    strcat(emailServerURL, ":");
    strcat(emailServerURL, emailPort);

    if(debug) pam_syslog(pamh, LOG_DEBUG, "cURL SMTP: [%s]", emailServerURL);

    /* This is the URL for your mailserver */ 
    curl_easy_setopt(curl, CURLOPT_URL, emailServerURL);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, emailFromAddr);

    curl_easy_setopt(curl, CURLOPT_USERNAME, emailUser);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, emailPass);
    
    recipients = curl_slist_append(recipients, emailToAddr);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, publish_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

    res = curl_easy_perform(curl);

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    
    if( res != CURLE_OK )
    {
        pam_syslog(pamh, LOG_ERR, "Unsuccessful transfer of mail: %s",
                   curl_easy_strerror(res));
        return -3;
    }
    
    return 0;
}

#ifdef ENABLE_OTP
//// Google TOTP HMAC SHA1
static void hmac_sha1(const unsigned char *secret, size_t secret_len,
                      const unsigned char *input, size_t input_len,
                      unsigned char *result, size_t result_size)
{
    SHA1_INFO context;
    // The scope on this is required here, because we may assign secret to
    // point to this if secret_len > 64
    unsigned char tmp_internal_hash[64];

    // temp length
    int i;

    if( secret_length > 64 )
    {
        sha1_init(&context);
        sha1_update(&context, secret, secret_len);
        sha1_final(&context, tmp_internal_hash);
        secret_len = SHA1_DIGEST_LENGTH;
    }
    else
    {
        memcpy(tmp_internal_hash, secret, secret_len);
    }

    for(i = 0; i < secret_len; ++i)
    {
        tmp_internal_hash[i] ^= 0x36; 
    }

    memset(tmp_internal_hash + secret_len, 0x36, 64 - secret_len);
}
#endif

static void release_pwbuf_structs(struct passwd *pwbuf)
{
    release_str( pwbuf->pw_shell );
    release_str( pwbuf->pw_dir );
    release_str( pwbuf->pw_gecos );
    release_str( pwbuf->pw_passwd );
    release_str( pwbuf->pw_name );
}

//// the following is the main entrypoint

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                int argc, const char **argv)
{
    int opt_in = 1, i;
    struct passwd pwbuf, *findUser = &pwbuf;
    const char *currentUser;
    char randBufAscii[16] = {0};
    uid_t oldUID;
    gid_t oldGID;
    char *CHAP, *RESP;
    
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
        clearParams();
        return PAM_SYSTEM_ERR;
    }

    if(debug) pam_syslog(pamh, LOG_DEBUG, "TwoFactor for %s", currentUser);

    // gett pwentry
    
    if( getPwEntryByName(currentUser, findUser) != 0 )
    {
        if( debug )
        {
            pam_syslog(pamh, LOG_DEBUG, "Error while using getpwent");
        }
        clearParams();
        return PAM_SYSTEM_ERR;
    }

    /// now we have the correct user - allocate strlen pwdir, strlen tfa_config and 1 terminating null byte
    tfa_filename = (char*)malloc(strlen(findUser->pw_dir)+strlen(TFA_CONFIG)+1);
    if( !tfa_filename )
    {
        pam_syslog(pamh, LOG_ERR, "Unable to alloc memory");
        clearParams();
        return PAM_SYSTEM_ERR;
    }

    *tfa_filename = 0; // set first byte to nil for favorable str* fn interaction

    // this should be okay, we used pw_dir to make the dest long
    // HOWEVER, we should probably figure out a 'safe' mechanism
    strcpy(tfa_filename, findUser->pw_dir);
    strcat(tfa_filename, TFA_CONFIG);
    
    ///
    if(0 != stat(tfa_filename, &tfa_stat) )
    {
        release_pwbuf_structs(findUser);
        if( opt_in )
        {
            pam_syslog(pamh, LOG_WARNING, "User '%s' not opted in for file '%s', allowing",
                       currentUser, tfa_filename);
            free(tfa_filename);
            clearParams();
            return PAM_SUCCESS;
        }
        
        //@todo: is it safe to print this name this way? I guess so since
        // the root user would have set this up... still... shiver?
        pam_syslog(pamh, LOG_ERR, "Unable to stat '%s'", tfa_filename);
        free(tfa_filename);
        clearParams();
        return PAM_SYSTEM_ERR;
    }
    
    if( tfa_stat.st_mode & (S_IRWXG | S_IRWXO) )
    {
        pam_syslog(pamh, LOG_ERR, "G/O are allowed to manipulate the secret seed on '%s'.", tfa_filename);
        request_random(pamh, PAM_ERROR_MSG, "G/O permissions on ~/.tfa_config are incorrect.");
        free(tfa_filename);
        // explicit denial here
        clearParams();
        return PAM_PERM_DENIED;
    }

    oldUID = setfsuid(findUser->pw_uid);
    oldGID = setfsgid(findUser->pw_gid);

    release_pwbuf_structs(findUser); // give it up!
    
    tfa_file = fopen(tfa_filename, "r");
    if( tfa_file == NULL )
    {
        pam_syslog(pamh, LOG_ERR, "Unable to open '%s'", tfa_filename);
        free(tfa_filename);

        setfsgid(oldGID); setfsuid(oldUID);
        clearParams();

        if( !opt_in )
            return PAM_PERM_DENIED; // if we can stat but can't open for reading
        // there is some kind of hack afoot - explicit deny
        return PAM_SUCCESS;
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
                setfsgid(oldGID); setfsuid(oldUID);
                clearParams();
                return PAM_SYSTEM_ERR;
            }
            ++iws;
            while(line[iws] == ' ' || line[iws] == '\t') ++iws;
            if(iws == sizeof(line))
            {
                pam_syslog(pamh, LOG_ERR, "Invalid format for '%s'",
                           file_params[iparam].param_name);
                fclose(tfa_file);
                setfsgid(oldGID); setfsuid(oldUID);
                clearParams();
                return PAM_SYSTEM_ERR;
            }
            strncpy(file_params[iparam].output_variable,
                    line+iws, MIN(file_params[iparam].length_of_output,
                                  sizeof(line)-(iws)));
            file_params[iparam].output_variable[file_params[iparam].length_of_output-1] = 0;
            
            iws = 0;
            while( file_params[iparam].output_variable[iws] != ' ' &&
                   file_params[iparam].output_variable[iws] != '\t' &&
                   file_params[iparam].output_variable[iws] != '\r' &&
                   file_params[iparam].output_variable[iws] != '\n' ) iws++;
            file_params[iparam].output_variable[iws] = 0; // nuke any
                                                          // trailing whitespace
        }

        if(!found)
        {
            pam_syslog(pamh, LOG_WARNING, "Unknown element '%s' is being ignored.", line+iws);
        }
    }
    fclose(tfa_file); // later
    memset(line, 0, sizeof(line));
    
    if( debug )
    {
        pam_syslog(pamh, LOG_DEBUG, "Email to: %s", emailToAddr);
        pam_syslog(pamh, LOG_DEBUG, "Email from: %s", emailFromAddr);
        pam_syslog(pamh, LOG_DEBUG, "Email server: %s", emailServer);
        pam_syslog(pamh, LOG_DEBUG, "Email port: %s", emailPort);
        pam_syslog(pamh, LOG_DEBUG, "Email username: %s", emailUser);
    }

    // get the random data as acii
    snprintf(randBufAscii, sizeof(randBufAscii), "%08x", getRandomInt32(pamh));

    CHAP = base64_encode(randBufAscii, strlen(randBufAscii));
    *(CHAP+8) = 0;
    
    if( publish_email(pamh, currentUser, CHAP) < 0 )
    {
        
        pam_syslog(pamh, LOG_ERR, "Unable to send email!!");
        free(CHAP);
        setfsgid(oldGID); setfsuid(oldUID);

        if( !strcmp(failPolicy, "pass") )
        {
            clearParams();
            return PAM_SUCCESS;
        }
        clearParams();
        return PAM_PERM_DENIED;
    }

    if(debug) pam_syslog(pamh, LOG_DEBUG, "Sent email... awaiting response");
    
    //
    RESP = request_random(pamh, PAM_PROMPT_ECHO_ON, "Challenge: ");
    
    if(debug) pam_syslog(pamh, LOG_DEBUG, "Response '%s' received, comparing with '%s'", RESP, CHAP);
    
    i = strcmp(RESP, CHAP);
    free(CHAP);
    free(RESP);
    setfsgid(oldGID); setfsuid(oldUID);
    clearParams();

    if( i )
    {
        //fputs("Failed - try again.", stdout);
        return PAM_PERM_DENIED;
    }
    
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    return pam_sm_acct_mgmt(pamh, flags, argc, argv);
}
