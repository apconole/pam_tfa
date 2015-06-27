#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

const struct pam_conv conv =
    {
        misc_conv,
        NULL
    };

int main(int argc, char *argv[])
{
    int retval = PAM_SYSTEM_ERR;
    pam_handle_t *pamh = NULL;
    
    if( argc > 1 )
        retval = pam_start("testtfa", argv[1], &conv, &pamh);
    
    if( retval == PAM_SUCCESS )
        retval = pam_authenticate(pamh, 0);

    if( retval == PAM_SUCCESS )
        return 0;
    return -1;
}
