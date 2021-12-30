/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <uadk/wd.h>
#include "uadk.h"
#include "uadk_async.h"
#include "uadk_cipher.h"
#include "uadk_aead.h"
#ifdef KAE
#include "v1/uadk_v1.h"
#endif

#define UADK_CMD_ENABLE_CIPHER_ENV	ENGINE_CMD_BASE
#define UADK_CMD_ENABLE_AEAD_ENV	(ENGINE_CMD_BASE + 1)
#define UADK_CMD_ENABLE_DIGEST_ENV	(ENGINE_CMD_BASE + 2)
#define UADK_CMD_ENABLE_RSA_ENV		(ENGINE_CMD_BASE + 3)
#define UADK_CMD_ENABLE_DH_ENV		(ENGINE_CMD_BASE + 4)
#define UADK_CMD_ENABLE_ECC_ENV		(ENGINE_CMD_BASE + 5)

/* Constants used when creating the ENGINE */
const char *engine_uadk_id = "uadk_engine";
static const char *engine_uadk_name = "uadk hardware engine support";

static int uadk_cipher;
static int uadk_digest;
static int uadk_rsa;
static int uadk_dh;
static int uadk_ecc;

#ifdef KAE
static int uadk_cipher_nosva;
static int uadk_digest_nosva;
static int uadk_rsa_nosva;
static int uadk_dh_nosva;
#endif

static const ENGINE_CMD_DEFN g_uadk_cmd_defns[] = {
	{
		UADK_CMD_ENABLE_CIPHER_ENV,
		"UADK_CMD_ENABLE_CIPHER_ENV",
		"Enable or Disable cipher engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_AEAD_ENV,
                "UADK_CMD_ENABLE_AEAD_ENV",
                "Enable or Disable aead engine environment variable.",
                ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_DIGEST_ENV,
		"UADK_CMD_ENABLE_DIGEST_ENV",
		"Enable or Disable digest engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_RSA_ENV,
		"UADK_CMD_ENABLE_RSA_ENV",
		"Enable or Disable rsa engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_DH_ENV,
		"UADK_CMD_ENABLE_DH_ENV",
		"Enable or Disable dh engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		UADK_CMD_ENABLE_ECC_ENV,
		"UADK_CMD_ENABLE_ECC_ENV",
		"Enable or Disable ecc engine environment variable.",
		ENGINE_CMD_FLAG_NUMERIC
	},
	{
		0, NULL, NULL, 0
	}
};

__attribute__((constructor))
static void uadk_constructor(void)
{
}

__attribute__((destructor))
static void uadk_destructor(void)
{
}

struct uadk_alg_env_enabled {
	const char *alg_name;
	__u8 env_enabled;
};

static struct uadk_alg_env_enabled uadk_env_enabled[] = {
	{ "cipher", 0 },
	{ "aead",   0 },
	{ "digest", 0 },
	{ "rsa", 0 },
	{ "dh", 0 },
	{ "ecc", 0 }
};

int uadk_cipher_nids_920[] = {
        NID_aes_128_cbc,
        NID_aes_192_cbc,
        NID_aes_256_cbc,
        NID_aes_128_ecb,
        NID_aes_192_ecb,
        NID_aes_256_ecb,
        NID_aes_128_xts,
        NID_aes_256_xts,
        NID_sm4_cbc,
        NID_des_ede3_cbc,
        NID_des_ede3_ecb,
        NID_aes_128_gcm,
        NID_aes_192_gcm,
        NID_aes_256_gcm
};

int uadk_cipher_nids_930[] = {
        NID_aes_128_cbc,
        NID_aes_192_cbc,
        NID_aes_256_cbc,
        NID_aes_128_ctr,
        NID_aes_192_ctr,
        NID_aes_256_ctr,
        NID_aes_128_ecb,
        NID_aes_192_ecb,
        NID_aes_256_ecb,
        NID_aes_128_xts,
        NID_aes_256_xts,
        NID_sm4_cbc,
        NID_sm4_ecb,
        NID_des_ede3_cbc,
        NID_des_ede3_ecb,
        NID_aes_128_cfb128,
        NID_aes_192_cfb128,
        NID_aes_256_cfb128,
        NID_aes_128_ofb128,
        NID_aes_192_ofb128,
        NID_aes_256_ofb128,
        NID_sm4_cfb128,
        NID_sm4_ofb128,
        NID_sm4_ctr,
        NID_aes_128_gcm,
        NID_aes_192_gcm,
        NID_aes_256_gcm       
};

static cipher_info c_info[] = {
        {NID_aes_128_cbc, NULL},
        {NID_aes_192_cbc, NULL},
        {NID_aes_256_cbc, NULL},
        {NID_aes_128_ctr, NULL},
        {NID_aes_192_ctr, NULL},
        {NID_aes_256_ctr, NULL},
        {NID_aes_128_ecb, NULL},
        {NID_aes_192_ecb, NULL},
        {NID_aes_256_ecb, NULL},
        {NID_aes_128_xts, NULL},
        {NID_aes_256_xts, NULL},
        {NID_sm4_cbc, NULL},
        {NID_sm4_ecb, NULL},
        {NID_des_ede3_cbc, NULL},
        {NID_des_ede3_ecb, NULL},
        {NID_aes_128_cfb128, NULL},
        {NID_aes_192_cfb128, NULL},
        {NID_aes_256_cfb128, NULL},
        {NID_aes_128_ofb128, NULL},
        {NID_aes_192_ofb128, NULL},
        {NID_aes_256_ofb128, NULL},
        {NID_sm4_cfb128, NULL},
        {NID_sm4_ofb128, NULL},
        {NID_sm4_ctr, NULL},
        {NID_aes_128_gcm, NULL},
        {NID_aes_192_gcm, NULL},
        {NID_aes_256_gcm, NULL}
};

static const unsigned int num_cc = (sizeof(c_info) / sizeof(c_info[0])); 

int uadk_e_is_env_enabled(const char *alg_name)
{
	int len = ARRAY_SIZE(uadk_env_enabled);
	int i = 0;

	while (i < len) {
		if (uadk_env_enabled[i].alg_name == alg_name)
			return uadk_env_enabled[i].env_enabled;
		i++;
	}
	return 0;
}

static void uadk_e_set_env_enabled(const char *alg_name, __u8 value)
{
	int len = ARRAY_SIZE(uadk_env_enabled);
	int i = 0;

	while (i < len) {
		if (uadk_env_enabled[i].alg_name == alg_name) {
			uadk_env_enabled[i].env_enabled = value;
			return;
		}
		i++;
	}
}

int uadk_e_set_env(const char *var_name, int numa_id)
{
	char env_string[ENV_STRING_LEN] = {0};
	const char *var_s;
	int ret;

	var_s = secure_getenv(var_name);
	if (!var_s || !strlen(var_s)) {
		/* uadk will request ctxs from device on specified numa node */
		ret = snprintf(env_string, ENV_STRING_LEN, "%s%d%s%d",
			       "sync:2@", numa_id,
			       ",async:2@", numa_id);
		if (ret < 0)
			return ret;

		ret = setenv(var_name, env_string, 1);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int uadk_engine_ctrl(ENGINE *e, int cmd, long i,
			    void *p, void (*f) (void))
{
	(void)p;
	(void)f;

	if (!e) {
		fprintf(stderr, "Null Engine\n");
		return 0;
	}

	switch (cmd) {
	case UADK_CMD_ENABLE_CIPHER_ENV:
		uadk_e_set_env_enabled("cipher", i);
		break;
	case UADK_CMD_ENABLE_AEAD_ENV:
		uadk_e_set_env_enabled("aead", i);
		break;
	case UADK_CMD_ENABLE_DIGEST_ENV:
		uadk_e_set_env_enabled("digest", i);
		break;
	case UADK_CMD_ENABLE_RSA_ENV:
		uadk_e_set_env_enabled("rsa", i);
		break;
	case UADK_CMD_ENABLE_DH_ENV:
		uadk_e_set_env_enabled("dh", i);
		break;
	case UADK_CMD_ENABLE_ECC_ENV:
		uadk_e_set_env_enabled("ecc", i);
		break;
	default:
		return 0;
	}

	return 1;
}

static int uadk_destroy(ENGINE *e)
{
#ifdef KAE
	if (uadk_cipher_nosva)
		sec_ciphers_free_ciphers();
	if (uadk_digest_nosva)
		sec_digests_free_methods();
	if (uadk_rsa_nosva)
		hpre_destroy();
	if (uadk_dh_nosva)
		hpre_dh_destroy();
#endif

        if (uadk_cipher) {
                uadk_e_destroy_cipher(c_info, num_cc);
                uadk_e_destroy_aead(c_info, num_cc);
        }
	if (uadk_digest)
	        uadk_e_destroy_digest();
	if (uadk_rsa)
	        uadk_e_destroy_rsa();
	if (uadk_ecc)
	        uadk_e_destroy_ecc();
	if (uadk_dh)
	        uadk_e_destroy_dh();
	return 1;
}


static int uadk_init(ENGINE *e)
{
	return 1;
}

static int uadk_finish(ENGINE *e)
{
	return 1;
}

static void engine_init_child_at_fork_handler(void)
{
	async_module_init();
}

#ifdef KAE
static void bind_fn_kae_alg(ENGINE *e)
{
	struct uacce_dev *dev;

	dev = wd_get_accel_dev("cipher");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			cipher_module_init();
			if (!ENGINE_set_ciphers(e, sec_engine_ciphers))
				fprintf(stderr, "uadk bind cipher failed\n");
			else
				uadk_cipher_nosva = 1;
		}
		free(dev);
	}

	dev = wd_get_accel_dev("digest");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			digest_module_init();
			if (!ENGINE_set_digests(e, sec_engine_digests))
				fprintf(stderr, "uadk bind digest failed\n");
			else
				uadk_digest_nosva = 1;
		}
		free(dev);
	}

	dev = wd_get_accel_dev("rsa");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			hpre_module_init();
			if (!ENGINE_set_RSA(e, hpre_get_rsa_methods()))
				fprintf(stderr, "uadk bind rsa failed\n");
			else
				uadk_rsa_nosva = 1;
		}
		free(dev);
	}

	dev = wd_get_accel_dev("dh");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			hpre_module_dh_init();
			if (!ENGINE_set_DH(e, hpre_get_dh_methods()))
				fprintf(stderr, "uadk bind dh failed\n");
			else
				uadk_dh_nosva = 1;
		}
		free(dev);
	}
}
#endif

void uadk_e_create_ciphers(int index)
{
        switch(c_info[index].nid) {
	    case NID_aes_128_gcm:
	    case NID_aes_192_gcm:
	    case NID_aes_256_gcm:
                        c_info[index].cipher = (EVP_CIPHER *)uadk_create_gcm_cipher_meth(c_info[index].nid);
                break;
	    case NID_aes_128_cbc:
	    case NID_aes_192_cbc:
	    case NID_aes_256_cbc:
	    case NID_aes_128_ctr:
	    case NID_aes_192_ctr:
	    case NID_aes_256_ctr:
	    case NID_aes_128_ecb:
	    case NID_aes_192_ecb:
	    case NID_aes_256_ecb:
	    case NID_aes_128_xts:
	    case NID_aes_256_xts:
	    case NID_sm4_cbc:
	    case NID_sm4_ecb:
	    case NID_des_ede3_cbc:
	    case NID_des_ede3_ecb:
	    case NID_aes_128_cfb128:
	    case NID_aes_192_cfb128:
	    case NID_aes_256_cfb128:
	    case NID_aes_128_ofb128:
	    case NID_aes_192_ofb128:
	    case NID_aes_256_ofb128:
	    case NID_sm4_cfb128:
	    case NID_sm4_ofb128:
	    case NID_sm4_ctr:
                        c_info[index].cipher = (EVP_CIPHER *)uadk_create_cipher_meth(c_info[index].nid);
                break;
            default:
                       break;
       }
}

static int uadk_e_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
        int i, platform;
        struct uacce_dev *dev;
        if(unlikely((nids == NULL) && ((cipher == NULL) || (nid < 0)))) {
                if(cipher != NULL)
                        *cipher = NULL;
                return 0;
        }

        dev = wd_get_accel_dev("cipher");
        if (!strcmp(dev->api, "hisi_qm_v2"))
                platform = KUNPENG920;
        else
                platform = KUNPENG930;

        if (cipher == NULL) {
                 if (platform == KUNPENG920) {
                         *nids = uadk_cipher_nids_920;
                         return (sizeof(uadk_cipher_nids_920) / sizeof(uadk_cipher_nids_920[0]));
                 } else {
                         *nids = uadk_cipher_nids_930;
                         return (sizeof(uadk_cipher_nids_930) / sizeof(uadk_cipher_nids_930[0]));
                 }
        }

        for(i = 0; i < num_cc; i++) {
                if(nid == c_info[i].nid) {
                        if(c_info[i].cipher == NULL)
                        {
                                uadk_e_create_ciphers(i);
                        }
                        *cipher = c_info[i].cipher;
                        return 1;
                }
        }
        *cipher = NULL;
        return 0;
}

static void bind_fn_uadk_alg(ENGINE *e)
{
	struct uacce_dev *dev;

	dev = wd_get_accel_dev("cipher");
	if (dev) {
		if (!ENGINE_set_ciphers(e, uadk_e_ciphers))
			fprintf(stderr, "uadk bind cipher failed\n");
		else
			uadk_cipher = 1;
		free(dev);
	}

	dev = wd_get_accel_dev("digest");
	if (dev) {
		if (!uadk_e_bind_digest(e))
			fprintf(stderr, "uadk bind digest failed\n");
		else
			uadk_digest = 1;
		free(dev);
	}

	dev = wd_get_accel_dev("rsa");
	if (dev) {
		if (!uadk_e_bind_rsa(e))
			fprintf(stderr, "uadk bind rsa failed\n");
		else
			uadk_rsa = 1;
		free(dev);
	}

	dev = wd_get_accel_dev("dh");
	if (dev) {
		if (!uadk_e_bind_dh(e))
			fprintf(stderr, "uadk bind dh failed\n");
		else
			uadk_dh = 1;
		free(dev);
	}

	if (!uadk_e_bind_ecc(e))
		fprintf(stderr, "uadk bind ecc failed\n");
	else
		uadk_ecc = 1;
}

/*
 * This stuff is needed if this ENGINE is being
 * compiled into a self-contained shared-library.
 */
static int bind_fn(ENGINE *e, const char *id)
{
	int ret;

	if (!ENGINE_set_id(e, engine_uadk_id) ||
	    !ENGINE_set_destroy_function(e, uadk_destroy) ||
	    !ENGINE_set_init_function(e, uadk_init) ||
	    !ENGINE_set_finish_function(e, uadk_finish) ||
	    !ENGINE_set_name(e, engine_uadk_name)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}

#ifdef KAE
	bind_fn_kae_alg(e);

	if (uadk_cipher_nosva || uadk_digest_nosva || uadk_rsa_nosva ||
	    uadk_dh_nosva) {
		async_module_init_v1();
		pthread_atfork(NULL, NULL, engine_init_child_at_fork_handler_v1);
		goto set_ctrl_cmd;
	}
#endif
	async_module_init();
	pthread_atfork(NULL, NULL, engine_init_child_at_fork_handler);

	bind_fn_uadk_alg(e);

#ifdef KAE
set_ctrl_cmd:
#endif
	ret = ENGINE_set_ctrl_function(e, uadk_engine_ctrl);
	if (ret != 1) {
		fprintf(stderr, "failed to set ctrl function\n");
		return 0;
	}

	ret = ENGINE_set_cmd_defns(e, g_uadk_cmd_defns);
	if (ret != 1) {
		fprintf(stderr, "failed to set defns\n");
		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
