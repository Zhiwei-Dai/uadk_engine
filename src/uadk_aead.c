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
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/engine.h>
#include <uadk/wd_aead.h>
#include "uadk.h"

#define CTX_SYNC_ENC 0
#define CTX_SYNC_DEC 1
#define CTX_ASYNC_ENC 2
#define CTX_ASYNC_DEC 3
#define CTX_NUM 4

#define AES_GCM_BLOCK_SIZE 16
#define AES_GCM_KEY_LEN 16
#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16
#define GCM_FLAG (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_GCM_MODE \
                  | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_AEAD_CIPHER \
                  | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT)

struct aead_cipher_priv_ctx {
    handle_t sess;
    struct wd_aead_sess_setup setup;
    struct wd_aead_req req;
    unsigned char iv[AES_GCM_IV_LEN];
    const unsigned char *ckey;
    unsigned char *aadData;
};

struct aead_engine {
    struct wd_ctx_config ctx_cfg;
    struct wd_sched sched;
    int numa_id;
    int pid;
    pthread_spinlock_t lock;
};

static struct aead_engine engine;

static EVP_CIPHER *uadk_aes_128_gcm = NULL;
static EVP_CIPHER *uadk_aes_192_gcm = NULL;
static EVP_CIPHER *uadk_aes_256_gcm = NULL;

static handle_t sched_single_aead_init(handle_t h_sched_ctx, void *sched_param)
{
    struct sched_params *param = (struct sched_params *)sched_param;
    struct sched_params *skey;

    skey = malloc(sizeof(struct sched_params));
    if (!skey) {
        fprintf(stderr, "fail to alloc aead sched key!\n");
        return (handle_t)0;
    }

    skey->numa_id = param->numa_id;
    skey->type = param->type;

    return (handle_t)skey;
}

static _u32 sched_single_pick_next_ctx(handle_t sched_ctx, void *sched key, const int sched_mode)
{
    struct sched_params *key = (struct sched_params *)sched_key;

    if (sched_mode) {
        if (key->type == WD_CIPHER_ENCRYPTION_DIGEST)
            return CTX_ASYNC_ENC;
        else
            return CTX_ASYNC_DEC;
    }
    else {
        if (key->type == WD_CIPHER_ENCRYPTION_DIGEST)
            return CTX_SYNC_ENC;
        else
            return CTX_SYNC_DEC;
    }
}

static int sched_single_poll_policy(handle_t h_sched_ctx, _u32 expect, _u32 *count)
{
    return 0;
}

static int uadk_e_wd_aead_cipher_env_init(struct uacce_dev *dev)
{
    int ret;

    ret = uadk_e_set_env("WD_AEAD_CIPHER_CTX_NUM", dev->numa_id);
    if (ret)
        return ret;

    ret = wd_aead_env_init(NULL);

    return ret;
}

static int uadk_e_wd_aead_cipher_init(struct uacce_dev *dev)
{
    int ret, i, j;

    engine.numa_id = dev->numa_id;

    ret = uadk_e_is_env_enabled("aead");
    if (ret)
        return uadk_e_wd_aead_cipher_env_init(dev);

    memset(&engine.ctx_cfg, 0, sizeof(struct wd_ctx_config));
    engine.ctx_cfg.ctx_num = CTX_NUM;
    engine.ctx_cfg.ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
    if (!engine.ctx_cfg.ctxs)
        return -ENOMEM;

    for (i = 0; i < CTX_NUM; i++) {
        engine.ctx_cfg.ctxs[i].ctx = wd_request_ctx(dev);
        if (engine.ctx_cfg.ctxs[i].ctx) {
            ret = -ENOMEM;
            goto err_freectx;
        }
    }

    engine.ctx_cfg.ctxs[CTX_SYNC_ENC].op_type = CTX_TYPE_ENCRYPT;
    engine.ctx_cfg.ctxs[CTX_SYNC_DEC].op_type = CTX_TYPE_DECRYPT;
    engine.ctx_cfg.ctxs[CTX_SYNC_ENC].ctx_mode = CTX_MODE_SYNC;
    engine.ctx_cfg.ctxs[CTX_SYNC_DEC].ctx_mode = CTX_MODE_SYNC;

    engine.ctx_cfg.ctxs[CTX_ASYNC_ENC].op_type = CTX_TYPE_ENCRYPT;
    engine.ctx_cfg.ctxs[CTX_ASYNC_DEC].op_type = CTX_TYPE_DECRYPT;
    engine.ctx_cfg.ctxs[CTX_ASYNC_ENC].ctx_mode = CTX_MODE_ASYNC;
    engine.ctx_cfg.ctxs[CTX_ASYNC_DEC].ctx_mode = CTX_MODE_ASYNC;

    engine.sched.name = "sched_single";
    engine.sched.pick_next_ctx = sched_single_pick_next_ctx;
    engine.sched.poll_policy = sched_single_poll_policy;
    engine.sched.sched_init = sched_single_aead_init;

    ret = wd_aead_init(&engine.ctx_cfg, &engine.sched);
    if (ret)
        goto err_freectx;

    return ret;

err_freectx:
    for (j = 0; j < i; j++)
        wd_release_ctx(engine.ctx_cfg.ctxs[j].ctx);

    free(engine.ctx_cfg.ctxs);

    return ret;
}

static int uadk_e_aead_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *ckey,
                                   const unsigned char *iv, int enc)
{
    if (ctx == NULL) {
        fprintf(stderr, "ctx is NULL.\n");
        return 0;
    }

    struct aead_cipher_priv_ctx *priv = (struct aead_cipher_priv_ctx*)EVP_CIPHER_CTX_get_cipher_date(ctx);
    if (priv == NULL) {
        fprintf(stderr, "priv is NULL.\n");
        return 0;
    }

    if (unlikely(!ckey))
        return 1;

    priv->req.op_type = enc ? WD_CIPHER_ENCRYPTION_DIGEST : WD_CIPHER_DECRYPTION_DIGEST;

    if (iv)
        memcpy(priv->iv, iv, AES_GCM_IV_LEN);

    priv->setup.calg = WD_CIPHER_AES;
    priv->setup.cmode = WD_CIPHER_GCM;
    priv->setup.dalg = 0;
    priv->setup.dmode = 0;
    
    priv->req.assoc_bytes = 0;
    priv->req.data_fmt = WD_FLAT_BUF;
    priv->req.iv_bytes = AES_GCM_IV_LEN;
    priv->req.iv = priv->iv;

    priv->ckey = ckey;

    return 1;
}

static int uadk_e_init_aead_cipher(void)
{
    struct uacce_dev *dev;
    int ret;

    if (engine.pid != getpid()) {
        pthread_spin_lock(&engine.lock);
        if (engine.pid == getpid()) {
            pthread_spin_unlock(&engine.lock);
            return 1;
        }

        dev = wd_get_accel_dev("aead");
        if (!dev) {
            pthread_spin_unlock(&engine.lock);
            fprintf(stderr, "failed to get device for aead.\n");
            return 0;
        }
        ret = uadk_e_wd_aead_cipher_init(dev);

        engine.pid = getpid();
        pthread_spin_unlock(&engine.lock);
        free(dev);
    }

    return 1;
}

static int uadk_e_aead_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    if (ctx == NULL) {
        fprintf(stderr, "ctx is NULL.\n");
        return 0;
    }

    struct aead_cipher_priv_ctx *priv = (struct aead_cipher_priv_ctx*)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (priv == NULL) {
        fprintf(stderr, "priv is NULL.\n");
        return 0;
    }

    if (priv->req.assoc_bytes != 0) {
        free(priv->aadData);
        priv->aadData = NULL;
        priv->req.assoc_bytes = 0;
    }

    if (priv->sess) {
        wd_aead_free_sess(priv->sess);
        priv->sess = 0;
    }

    return 1;
}

static int uadk_e_aead_cipher_set_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    if (ctx == NULL) {
        fprintf(stderr, "ctx is NULL.\n");
        return 0;
    }

    struct aead_cipher_priv_ctx *priv = (struct aead_cipher_priv_ctx*)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (priv == NULL) {
        fprintf(stderr, "priv is NULL.\n");
        return 0;
    }

    int enc = EVP_CIPHER_CTX_encrypting(ctx);

    switch (type) {
    case EVP_CTRL_INIT:
        if (priv->assoc_bytes != 0) {
            free(priv->aadData);
            priv->aadData = NULL;
            priv->assoc_bytes = 0;
        }

        priv->req.iv_bytes = 0;
        return 1;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = priv->req.iv_bytes;
        return 1;
    case EVP_CTRL_SET_IVLEN:
        if (arg != AES_GCM_IV_LEN) {
            fprint(stderr, "Only support 12 bytes.\n");
            return 0;
        }
        return 1;
    case EVP_CTRL_GCM_GET_TAG:
        if (arg != AES_GCM_TAG_LEN) {
            fprintf(stderr, "Accepted value = 16 for TAG length.\n");
            return 0;
        }

        if (EVP_CIPHER_CTX_buf_noconst(ctx) == NULL || ptr == NULL) {
            fprintf(stderr, "Memory pointer is not valid.\n");
            return 0;
        }

        memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(ctx), AES_GCM_TAG_LEN);
        return 1;
    case EVP_CTRL_GCM_SET_TAG:
        if (args != AES_GCM_TAG_LEN || enc) {
            fprintf(stderr, "Cannot do this when encrypto. Accepted value = 16 for TAG length.\n");
            return 0;
        }

        if(EVP_CIPHER_CTX_buf_noconst(ctx) == NULL || ptr == NULL){
            fprintf(stderr, "Memory pointer is not valid.\n");
            return 0;
        }

        memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, AES_GCM_TAG_LEN);
        return 1;
    default:
        fprintf(stderr, "Unsupported type. \n");
        return -1;
    }
}

static void uadk_e_ctx_init(EVP_CIPHER_CTX *ctx, struct aead_cipher_priv_ctx *priv)
{
    struct sched_params params = {0};
    int ret;

    ret = uadk_e_init_aead_cipher();
    if (unlikely(!ret))
        fprintf(stderr, "uadk failed to init aead HW!\n");

    params.type = priv->req.op_type;
    ret = uadk_e_is_env_enabled("aead");
    if (ret)
        params.type = 0;

    params.numa_id = engine.numa_id;
    priv->setup.sched_param = &params;
    if (!priv->sess) {
        priv->sess = wd_aead_alloc_sess(&priv->setup);
        if( !priv->sess)
            fprintf(stderr, "uadk failed to alloc aead session!\n");
    }

    ret = wd_aead_set_ckey(priv->sess, priv->ckey, AES_GCM_KEY_LEN);
    if (ret) {
        wd_aead_free_sess(priv->sess);
        fprintf(stderr, "uadk failed to set ckey!\n");
    }
}

static int uadk_e_do_aead_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inlen)
{
    int ret, enc;
    size_t aad_len = 0;
    unsigned char *com_buff = NULL;

    if (ctx == NULL) {
        fprintf(stderr, "ctx is NULL.\n");
        return -1;
    }

    struct aead_cipher_priv_ctx *priv = (struct aead_cipher_priv_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (priv == NULL) {
        fprintf(stderr, "priv is NULL.\n");
        return -1;
    }

    enc = EVP_CIPHER_CTX_encrypting(ctx);

    if (in) {
        if (out == NULL) {
            aad_len = inlen;
            if (priv->req.assoc_bytes < aad_len) {
                if (priv->req.assoc_bytes != 0)
                    free(priv->aadData);

                priv->aadData = (unsigned char *)malloc(aad_len);
                if (priv->aadData == NULL) {
                    fprintf(stderr, "Unable to alloc memory for AAD.\n");
                    return -1;
                }

                priv->req.assoc_bytes = aad_len;
            }

            memcpy(priv->aadData, in, aad_len);
            return 1;
        }
        else {
            aad_len = priv->req.assoc_bytes;
            priv->req.out_buf_bytes = aad_len + inlen + AES_GCM_TAG_LEN + AES_GCM_TAG_LEN;

            if (aad_len != 0) {
                com_buff = (unsigned char *)malloc(priv->req.out_buf_bytes);
                if (com_buff == NULL) {
                    fprintf(stderr, "Unable to alloc buff memory.\n");
                    return -1;
                }
            }

            if (enc) {
                if (aad_len != 0) {
                    memcpy(com_buff, priv->aadData, aadlen);
                    memcpy(com_buff + aad_len, in, inlen);
                    priv->src = com_buff;
                    priv->dst = com_buff;
                }
                else {
                    priv->req.src = (unsigned char *)in;
                    priv->req.dst = out;
                }

                priv->req.in_bytes = inlen;
                priv->out_bytes = aad_len + inlen + AES_GCM_TAG_LEN;
            }
            else {
                if (aad_len != 0) {
                    memcpy(com_buff, priv->aadData, aadlen);
                    memcpy(com_buff + aad_len, in, inlen);
                    memcpy(com_buff + aad_len + inlen, EVP_CIPHER_CTX_buf_noconst(ctx), AES_GCM_TAG_LEN);
                    priv->src=com_buff;
                    priv->dst=com_buff;
                }
                else {
                    memcpy((unsigned char *)in + inlen, EVP_CIPHER_CTX_buf_noconst(ctx), AES_GCM_TAG_LEN);
                    priv->req.src=(unsigned char *)in;
                    priv->req.dst=out;
                }

                priv->req.in_bytes = inlen;
                priv->out_bytes = aad_len + inlen;
            }

            uadk_e_ctx_init(ctx,priv);
            ret = wd_aead_set_authsize(priv->sess, AES_GCM_TAG_LEN);
            if (ret < 0)
                return -1;

            ret = wd_do_aead_sync(priv->sess, &priv->req);
            if (ret < 0)
                return -1;

            if (enc)
                memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), priv->req.dst + aad_len + inlen, AES_GCM_TAG_LEN);

            if (aad_len != 0) {
                memcpy(out, com_buff + aad_len, inlen);
                free(com_buff);
            }

            return inlen;
        }
    }
    else {
        if (!enc)
            if (priv->req.state != WD_SUCCESS)
                return -1;

        return 0;
    }
}

#define UADK_AEAD_DESCR(name, block_size, key_size, iv_len, flags, ctx_size,\
                        init, cipher, cleanup, set_params, get_params, ctrl)\
do {\
    uadk_##name = EVP_CIPHER_meth_new(NID_##name, block_size, key_size);\
    if (uadk_##name == 0 ||\
        !EVP_CIPHER_meth_set_iv_length(uadk_##name, iv_len) ||\
        !EVP_CIPHER_meth_set_flags(uadk_##name, flags) ||\
        !EVP_CIPHER_meth_set_impl_ctx_size(uadk_##name, ctx_size) ||\
        !EVP_CIPHER_meth_set_init(uadk_##name, init) ||\
        !EVP_CIPHER_meth_set_do_cipher(uadk_##name, cipher) ||\
        !EVP_CIPHER_meth_set_cleanup(uadk_##name, cleanup) ||\
        !EVP_CIPHER_meth_set_set_asn1_params(uadk_##name, set_params) ||\
        !EVP_CIPHER_meth_set_get_asn1_params(uadk_##name, get_params) ||\
        !EVP_CIPHER_meth_set_ctrl(uadk_##name, ctrl))\
        return 0;\
} while (0)

const EVP_CIPHER *uadk_create_gcm_cipher_meth(int nid)
{
    EVP_CIPHER *aead = NULL;
    switch (nid) {
    case NID_aes_128_gcm:
        UADK_AEAD_DESCR(aes_128_gcm, AES_GCM_BLOCK_SIZE, 16, AES_GCM_IB_LEN,
                        GCM_FLAG, sizeof(struct aead_cipher_priv_ctx),
                        uadk_e_aead_cipher_init, uadk_e_do_aead_cipher,uadk_e_aead_cipher_cleanup,
                        (EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),
                        (EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),
                        uadk_e_aead_cipher_set_ctrl);
        aead = uadk_aes_128_gcm;
        break;
    case NID_aes_192_gcm:                     
        UADK_AEAD_DESCR(aes_192_gcm, AES_GCM_BLOCK_SIZE, 24, AES_GCM_IB_LEN,                     
                        GCM_FLAG, sizeof(struct aead_cipher_priv_ctx),                     
                        uadk_e_aead_cipher_init, uadk_e_do_aead_cipher,uadk_e_aead_cipher_cleanup,                     
                        (EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),                     
                        (EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),                     
                        uadk_e_aead_cipher_set_ctrl);                     
        aead = uadk_aes_192_gcm;                     
        break;
    case NID_aes_256_gcm:                     
        UADK_AEAD_DESCR(aes_256_gcm, AES_GCM_BLOCK_SIZE, 32, AES_GCM_IB_LEN,                     
                        GCM_FLAG, sizeof(struct aead_cipher_priv_ctx),                     
                        uadk_e_aead_cipher_init, uadk_e_do_aead_cipher,uadk_e_aead_cipher_cleanup,                     
                        (EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv),                     
                        (EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv),                     
                        uadk_e_aead_cipher_set_ctrl);                     
        aead = uadk_aes_256_gcm;                     
        break;
    default:
        aead = NULL;
        break;
    }

    return aead;
}

void destroy_aead(NID_map *info, int num)
{
    int i;

    for (i = 0; i < num; i++) {
        if (info[i].cipher != NULL) {
            EVP_CIPHER_meth_free(info[i].cipher);
            info[i].cipher = NULL;
        }
   }
}

void uadk_e_destroy_aead(NID_map* info, int num)
{
    int i, ret;

    if (engine.pid == getpid()) {
        ret = uadk_e_is_env_enabled("aead");
        if (ret) {
            wd_aead_env_uninit();
        }
        else {
            wd_aead_uninit();
            for (i = 0; i < engine.ctx_cfg.ctx_num; i++)
                wd_release_ctx(engine.ctx_cfg.ctxs[i].ctx);
            free(engine.ctx_cfg.ctxs);
        }
        engine.pid = 0;
    }

    pthread_spin_destroy(&engine.lock);
    destroy_aead(info, num);
}
