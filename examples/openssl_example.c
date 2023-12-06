#include <stdio.h>
#include <stdlib.h>

#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/err.h>

int main(void)
{
    /*
    OSSL_PROVIDER *legacy;
    OSSL_PROVIDER *deflt;

    // Load Multiple providers into the default (NULL) library context
    legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (legacy == NULL) {
        printf("Failed to load Legacy provider\n");
        exit(EXIT_FAILURE);
    }
    deflt = OSSL_PROVIDER_load(NULL, "default");
    if (deflt == NULL) {
        printf("Failed to load Default provider\n");
        OSSL_PROVIDER_unload(legacy);
        exit(EXIT_FAILURE);
    }
    OSSL_PROVIDER_unload(legacy);
    OSSL_PROVIDER_unload(deflt);
    */

    // Rest of application

	OSSL_PROVIDER *prov = NULL;
	const char *build = NULL;
	OSSL_PARAM request[] = {
	    { "buildinfo", OSSL_PARAM_UTF8_PTR, &build, 0, 0 },
	    { NULL, 0, NULL, 0, 0 }
	};

	if ((prov = OSSL_PROVIDER_load(NULL, "libwolfprov")) != NULL
	    && OSSL_PROVIDER_get_params(prov, request))
	    printf("Provider 'libwolfprov' buildinfo: %s\n", build);
	else
	    ERR_print_errors_fp(stderr);

    if (OSSL_PROVIDER_self_test(prov) == 0)
        printf("Provider selftest failed\n");
    else
        printf("Provider selftest passed\n");

    OSSL_PROVIDER_unload(prov);
    exit(EXIT_SUCCESS);
}
