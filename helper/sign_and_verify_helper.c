#include "../header/sign_and_verify_header.h"

/* Create an HMAC key */
int make_keys(EVP_PKEY** skey, unsigned char * key)
{
	const char hn[] = "SHA256";
    /* HMAC key */
    unsigned char hkey[EVP_MAX_MD_SIZE];
    
    int result = -1;
    
    if(!skey)
        return -1;
    
    if(*skey != NULL) {
        EVP_PKEY_free(*skey);
        *skey = NULL;
    }
    
    do
    {
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int size = EVP_MD_size(md);
        assert(size >= 16);
        if(!(size >= 16)) {
            printf("EVP_MD_size failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(size <= sizeof(hkey));
        if(!(size <= sizeof(hkey))) {
            printf("EVP_MD_size is too large\n");
            break; /* failed */
        }
        
        /* Generate unsigned chars */
        int rc = RAND_bytes(hkey, size);
        assert(rc == 1);
        if(rc != 1) {
            printf("RAND_unsigned chars failed, error 0x%lx\n", ERR_get_error());
            break;
        }
        
        memcpy(key, hkey, size);
        
        *skey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hkey, size);
    
        assert(*skey != NULL);
        if(*skey == NULL) {
            printf("EVP_PKEY_new_mac_key failed, error 0x%lx\n", ERR_get_error());
            break;
        }
        
        result = 0;
        
    } while(0);
    
    OPENSSL_cleanse(hkey, sizeof(hkey));
    
    /* Convert to 0/1 result */
    return !!result;
}

int sign_it(const unsigned char* msg, size_t mlen, unsigned char** sig, size_t* slen, EVP_PKEY* pkey)
{
	const char hn[] = "SHA256";
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !pkey) {
        assert(0);
        return -1;
    }
    
    if(*sig)
        OPENSSL_free(*sig);
    
    *sig = NULL;
    *slen = 0;
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(req > 0);
        if(!(req > 0)) {
            printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if(*sig == NULL) {
            printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }
        
        assert(req == *slen);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    /* Convert to 0/1 result */
    return !!result;
}

int verify_it(const unsigned char* msg, size_t mlen, const unsigned char* sig, size_t slen, EVP_PKEY* pkey)
{
	const char hn[] = "SHA256";
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !slen || !pkey) {
        assert(0);
        return -1;
    }

    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        unsigned char buff[EVP_MAX_MD_SIZE];
        size_t size = sizeof(buff);
        
        rc = EVP_DigestSignFinal(ctx, buff, &size);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(size > 0);
        if(!(size > 0)) {
            printf("EVP_DigestSignFinal failed (2)\n");
            break; /* failed */
        }
        
        const size_t m = (slen < size ? slen : size);

        result = !!CRYPTO_memcmp(sig, buff, m);
        
        OPENSSL_cleanse(buff, sizeof(buff));
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    /* Convert to 0/1 result */
    return !!result;
}

int sign_msg_using_hmac(char * msg, unsigned char * hkey, unsigned char * signature) {
	OpenSSL_add_all_algorithms();

    /* Sign HMAC keys */
    EVP_PKEY *skey = NULL;
    
    int rc = make_keys(&skey, hkey);
    
    assert(rc == 0);
    if(rc != 0)
        exit(1);
    
    assert(skey != NULL);
    if(skey == NULL)
        exit(1);
    
    unsigned char* sig = NULL;
    size_t slen = 0;

    /* Using the skey or signing key */
    rc = sign_it((const unsigned char *)msg, sizeof(msg), &sig, &slen, skey);
    assert(rc == 0);
    if(rc == 0) {
        //printf("Created signature\n");
    } else {
        printf("Failed to create signature, return code %d\n", rc);
        exit(1); /* Should cleanup here */
    }

    if(sig)
        OPENSSL_free(sig);
    
    if(skey)
        EVP_PKEY_free(skey);

    return slen;
}

int verify_msg_using_hmac(unsigned char* msg, size_t mlen, unsigned char* sig, size_t slen,unsigned char * hkey) {
	
	OpenSSL_add_all_algorithms();

	EVP_PKEY *vkey = NULL;

	vkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hkey, 32);
	
	int rc = verify_it((const unsigned char *)msg, sizeof(msg), sig, slen, vkey);

	if(vkey)
        EVP_PKEY_free(vkey);

    return rc;
}