#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "freebsd_helper.h"
#include "sbl_helper.h"
#include "pfs_helper.h"
#include "rif_helper.h"
#include "ccp_helper.h"

extern void* (*real_memcpy)(void* dst, const void* src, size_t len) PAYLOAD_BSS;
extern void* (*real_memcmp)(const void *b1, const void *b2, size_t len) PAYLOAD_BSS;
extern void* (*real_memset)(void *s, int c, size_t n) PAYLOAD_BSS;
extern int (*real_sx_xlock)(struct sx *sx, int opts) PAYLOAD_BSS;
extern int (*real_sx_xunlock)(struct sx *sx) PAYLOAD_BSS;
extern int (*real_fpu_kern_enter)(struct thread *td, struct fpu_kern_ctx *ctx, uint32_t flags) PAYLOAD_BSS;
extern int (*real_fpu_kern_leave)(struct thread *td, struct fpu_kern_ctx *ctx) PAYLOAD_BSS;
extern void (*real_Sha256Hmac)(uint8_t hash[0x20], const uint8_t* data, size_t data_size, const uint8_t* key, int key_size) PAYLOAD_BSS;
extern int (*real_AesCbcCfb128Decrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_BSS;
extern int (*real_RsaesPkcs1v15Dec2048CRT)(struct rsa_buffer* out, struct rsa_buffer* in, struct rsa_key* key) PAYLOAD_BSS;
extern int (*real_sceSblPfsKeymgrGenEKpfsForGDGPAC)(struct pfs_key_blob* key_blob) PAYLOAD_BSS;
extern int (*real_sceSblPfsSetKey)(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_BSS;
extern int (*real_sceSblServiceCryptAsync)(struct ccp_req* request) PAYLOAD_BSS;
extern int (*real_sceSblKeymgrSmCallfunc)(union keymgr_payload* payload) PAYLOAD_BSS;

extern struct sbl_map_list_entry** sbl_driver_mapped_pages PAYLOAD_BSS;
extern struct sbl_key_rbtree_entry** sbl_keymgr_key_rbtree PAYLOAD_BSS;
extern void* fpu_ctx PAYLOAD_BSS;

extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl(struct pfs_key_blob* key_blob) PAYLOAD_CODE;
extern int my_sceSblPfsSetKey_pfs_sbl_init(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_CODE;
extern int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) PAYLOAD_CODE;

extern struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS] PAYLOAD_BSS;
extern struct sx s_fake_keys_lock PAYLOAD_BSS;

static const uint8_t s_ypkg_p[0x80] PAYLOAD_RDATA =
{
  0x2D, 0xE8, 0xB4, 0x65, 0xBE, 0x05, 0x78, 0x6A, 0x89, 0x31, 0xC9, 0x5A, 0x44, 0xDE, 0x50, 0xC1,
  0xC7, 0xFD, 0x9D, 0x3E, 0x21, 0x42, 0x17, 0x40, 0x79, 0xF9, 0xC9, 0x41, 0xC1, 0xFC, 0xD7, 0x0F,
  0x34, 0x76, 0xA3, 0xE2, 0xC0, 0x1B, 0x5A, 0x20, 0x0F, 0xAF, 0x2F, 0x52, 0xCD, 0x83, 0x34, 0x72,
  0xAF, 0xB3, 0x12, 0x33, 0x21, 0x2C, 0x20, 0xB0, 0xC6, 0xA0, 0x2D, 0xB1, 0x59, 0xE3, 0xA7, 0xB0,
  0x4E, 0x1C, 0x4C, 0x5B, 0x5F, 0x10, 0x9A, 0x50, 0x18, 0xCC, 0x86, 0x79, 0x25, 0xFF, 0x10, 0x02,
  0x8F, 0x90, 0x03, 0xA9, 0x37, 0xBA, 0xF2, 0x1C, 0x13, 0xCC, 0x09, 0x45, 0x15, 0xB8, 0x55, 0x74,
  0x0A, 0x28, 0x24, 0x04, 0xD1, 0x19, 0xAB, 0xB3, 0xCA, 0x44, 0xB6, 0xF8, 0x3D, 0xB1, 0x2A, 0x72,
  0x88, 0x35, 0xE4, 0x86, 0x6B, 0x55, 0x47, 0x08, 0x25, 0x16, 0xAB, 0x69, 0x1D, 0xBF, 0xF6, 0xFE,
};

static const uint8_t s_ypkg_q[0x80] PAYLOAD_RDATA =
{
  0x23, 0x80, 0x77, 0x84, 0x4D, 0x6F, 0x9B, 0x24, 0x51, 0xFE, 0x2A, 0x6B, 0x28, 0x80, 0xA1, 0x9E,
  0xBD, 0x6D, 0x18, 0xCA, 0x8D, 0x7D, 0x9E, 0x79, 0x5A, 0xE0, 0xB8, 0xEB, 0xD1, 0x3D, 0xF3, 0xD9,
  0x02, 0x90, 0x2A, 0xA7, 0xB5, 0x7E, 0x9A, 0xA2, 0xD7, 0x2F, 0x21, 0xA8, 0x50, 0x7D, 0x8C, 0xA1,
  0x91, 0x2F, 0xBF, 0x97, 0xBE, 0x92, 0xC2, 0xC1, 0x0D, 0x8C, 0x0C, 0x1F, 0xDE, 0x31, 0x35, 0x15,
  0x39, 0x90, 0xCC, 0x97, 0x47, 0x2E, 0x7F, 0x09, 0xE9, 0xC3, 0x9C, 0xCE, 0x91, 0xB2, 0xC8, 0x58,
  0x76, 0xE8, 0x70, 0x1D, 0x72, 0x5F, 0x4A, 0xE6, 0xAA, 0x36, 0x22, 0x94, 0xC6, 0x52, 0x90, 0xB3,
  0x9F, 0x9B, 0xF0, 0xEF, 0x57, 0x8E, 0x53, 0xC3, 0xE3, 0x30, 0xC9, 0xD7, 0xB0, 0x3A, 0x0C, 0x79,
  0x1B, 0x97, 0xA8, 0xD4, 0x81, 0x22, 0xD2, 0xB0, 0x82, 0x62, 0x7D, 0x00, 0x58, 0x47, 0x9E, 0xC7,
};

static const uint8_t s_ypkg_dmp1[0x80] PAYLOAD_RDATA =
{
  0x25, 0x54, 0xDB, 0xFD, 0x86, 0x45, 0x97, 0x9A, 0x1E, 0x17, 0xF0, 0xE3, 0xA5, 0x92, 0x0F, 0x12,
  0x2A, 0x5C, 0x4C, 0xA6, 0xA5, 0xCF, 0x7F, 0xE8, 0x5B, 0xF3, 0x65, 0x1A, 0xC8, 0xCF, 0x9B, 0xB9,
  0x2A, 0xC9, 0x90, 0x5D, 0xD4, 0x08, 0xCF, 0xF6, 0x03, 0x5A, 0x5A, 0xFC, 0x9E, 0xB6, 0xDB, 0x11,
  0xED, 0xE2, 0x3D, 0x62, 0xC1, 0xFC, 0x88, 0x5D, 0x97, 0xAC, 0x31, 0x2D, 0xC3, 0x15, 0xAD, 0x70,
  0x05, 0xBE, 0xA0, 0x5A, 0xE6, 0x34, 0x9C, 0x44, 0x78, 0x2B, 0xE5, 0xFE, 0x38, 0x56, 0xD4, 0x68,
  0x83, 0x13, 0xA4, 0xE6, 0xFA, 0xD2, 0x9C, 0xAB, 0xAC, 0x89, 0x5F, 0x10, 0x8F, 0x75, 0x6F, 0x04,
  0xBC, 0xAE, 0xB9, 0xBC, 0xB7, 0x1D, 0x42, 0xFA, 0x4E, 0x94, 0x1F, 0xB4, 0x0A, 0x27, 0x9C, 0x6B,
  0xAB, 0xC7, 0xD2, 0xEB, 0x27, 0x42, 0x52, 0x29, 0x41, 0xC8, 0x25, 0x40, 0x54, 0xE0, 0x48, 0x6D,
};

static const uint8_t s_ypkg_dmq1[0x80] PAYLOAD_RDATA =
{
  0x4D, 0x35, 0x67, 0x38, 0xBC, 0x90, 0x3E, 0x3B, 0xAA, 0x6C, 0xBC, 0xF2, 0xEB, 0x9E, 0x45, 0xD2,
  0x09, 0x2F, 0xCA, 0x3A, 0x9C, 0x02, 0x36, 0xAD, 0x2E, 0xC1, 0xB1, 0xB2, 0x6D, 0x7C, 0x1F, 0x6B,
  0xA1, 0x8F, 0x62, 0x20, 0x8C, 0xD6, 0x6C, 0x36, 0xD6, 0x5A, 0x54, 0x9E, 0x30, 0xA9, 0xA8, 0x25,
  0x3D, 0x94, 0x12, 0x3E, 0x0D, 0x16, 0x1B, 0xF0, 0x86, 0x42, 0x72, 0xE0, 0xD6, 0x9C, 0x39, 0x68,
  0xDB, 0x11, 0x80, 0x96, 0x18, 0x2B, 0x71, 0x41, 0x48, 0x78, 0xE8, 0x17, 0x8B, 0x7D, 0x00, 0x1F,
  0x16, 0x68, 0xD2, 0x75, 0x97, 0xB5, 0xE0, 0xF2, 0x6D, 0x0C, 0x75, 0xAC, 0x16, 0xD9, 0xD5, 0xB1,
  0xB5, 0x8B, 0xE8, 0xD0, 0xBF, 0xA7, 0x1F, 0x61, 0x5B, 0x08, 0xF8, 0x68, 0xE7, 0xF0, 0xD1, 0xBC,
  0x39, 0x60, 0xBF, 0x55, 0x9C, 0x7C, 0x20, 0x30, 0xE8, 0x50, 0x28, 0x44, 0x02, 0xCE, 0x51, 0x2A,
};

static const uint8_t s_ypkg_iqmp[0x80] PAYLOAD_RDATA =
{
  0xF5, 0x73, 0xB8, 0x7E, 0x5C, 0x98, 0x7C, 0x87, 0x67, 0xF1, 0xDA, 0xAE, 0xA0, 0xF9, 0x4B, 0xAB,
  0x77, 0xD8, 0xCE, 0x64, 0x6A, 0xC1, 0x4F, 0xA6, 0x9B, 0xB9, 0xAA, 0xCC, 0x76, 0x09, 0xA4, 0x3F,
  0xB9, 0xFA, 0xF5, 0x62, 0x84, 0x0A, 0xB8, 0x49, 0x02, 0xDF, 0x9E, 0xC4, 0x1A, 0x37, 0xD3, 0x56,
  0x0D, 0xA4, 0x6E, 0x15, 0x07, 0x15, 0xA0, 0x8D, 0x97, 0x9D, 0x92, 0x20, 0x43, 0x52, 0xC3, 0xB2,
  0xFD, 0xF7, 0xD3, 0xF3, 0x69, 0xA2, 0x28, 0x4F, 0x62, 0x6F, 0x80, 0x40, 0x5F, 0x3B, 0x80, 0x1E,
  0x5E, 0x38, 0x0D, 0x8B, 0x56, 0xA8, 0x56, 0x58, 0xD8, 0xD9, 0x6F, 0xEA, 0x12, 0x2A, 0x40, 0x16,
  0xC1, 0xED, 0x3D, 0x27, 0x16, 0xA0, 0x63, 0x97, 0x61, 0x39, 0x55, 0xCC, 0x8A, 0x05, 0xFA, 0x08,
  0x28, 0xFD, 0x55, 0x56, 0x31, 0x94, 0x65, 0x05, 0xE7, 0xD3, 0x57, 0x6C, 0x0D, 0x1C, 0x67, 0x0B,
};

static const uint8_t rif_debug_key[0x10] PAYLOAD_RDATA = 
{
  0x96, 0xC2, 0x26, 0x8D, 0x69, 0x26, 0x1C, 0x8B, 0x1E, 0x3B, 0x6B, 0xFF, 0x2F, 0xE0, 0x4E, 0x12
};

// we mark our key using some pattern that we can check later
static const uint8_t s_fake_key_seed[0x10] PAYLOAD_RDATA =
{
  0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45,
};

PAYLOAD_CODE static inline struct fake_key_desc* get_free_fake_key_slot(void)
{
  struct fake_key_desc* slot = NULL;
  size_t i;

  real_sx_xlock(&s_fake_keys_lock, 0);
  {
    for (i = 0; i < _countof(s_fake_keys); ++i)
    {
      if (!s_fake_keys[i].occupied)
      {
        s_fake_keys[i].occupied = 1;
        slot = s_fake_keys + i;
        break;
      }
    }
  }
  real_sx_xunlock(&s_fake_keys_lock);

  return slot;
}

PAYLOAD_CODE static inline struct sbl_key_rbtree_entry* sceSblKeymgrGetKey(unsigned int handle)
{
  struct sbl_key_rbtree_entry* entry = *sbl_keymgr_key_rbtree;

  while (entry)
  {
    if (entry->handle < handle)
      entry = entry->right;
    else if (entry->handle > handle)
      entry = entry->left;
    else if (entry->handle == handle)
      return entry;
  }

  return NULL;
}

PAYLOAD_CODE static inline struct fake_key_desc* is_fake_pfs_key(uint8_t* key)
{
  struct fake_key_desc* slot = NULL;
  size_t i;

  real_sx_xlock(&s_fake_keys_lock, 0);
  {
    for (i = 0; i < _countof(s_fake_keys); ++i)
    {
      if (!s_fake_keys[i].occupied)
        continue;

      if (real_memcmp(s_fake_keys[i].key, key, sizeof(s_fake_keys[i].key)) == 0)
      {
        slot = s_fake_keys + i;
        break;
      }
    }
  }
  real_sx_xunlock(&s_fake_keys_lock);

  return slot;
}

// a common function to generate a final key for PFS
PAYLOAD_CODE static inline void pfs_gen_crypto_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], unsigned int index, uint8_t key[PFS_FINAL_KEY_SIZE])
{
  struct thread* td = curthread();
  struct fake_key_d d;

  real_memset(&d, 0, sizeof(d));
  {
    d.index = index;
    real_memcpy(d.seed, seed, PFS_SEED_SIZE);
  }

  real_fpu_kern_enter(td, fpu_ctx, 0);
  {
    real_Sha256Hmac(key, (uint8_t *)&d, sizeof(d), ekpfs, EKPFS_SIZE);
  }
  real_fpu_kern_leave(td, fpu_ctx);
}

// an encryption key generator based on EKPFS and PFS header seed
PAYLOAD_CODE static inline void pfs_generate_enc_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], uint8_t key[PFS_FINAL_KEY_SIZE])
{
  pfs_gen_crypto_key(ekpfs, seed, 1, key);
}

// asigning key generator based on EKPFS and PFS header seed
PAYLOAD_CODE static inline void pfs_generate_sign_key(uint8_t* ekpfs, uint8_t seed[PFS_SEED_SIZE], uint8_t key[PFS_FINAL_KEY_SIZE])
{
  pfs_gen_crypto_key(ekpfs, seed, 2, key);
}

PAYLOAD_CODE static inline int npdrm_decrypt_debug_rif(unsigned int type, uint8_t* data)
{
  struct thread* td = curthread();
  int ret;

  real_fpu_kern_enter(td, fpu_ctx, 0);
  {
    // decrypt fake rif manually using a key from publishing tools 
    ret = real_AesCbcCfb128Decrypt(data + RIF_DIGEST_SIZE, data + RIF_DIGEST_SIZE, RIF_DATA_SIZE, rif_debug_key, sizeof(rif_debug_key) * 8, data);
    if (ret)
      ret = SCE_SBL_ERROR_NPDRM_ENOTSUP;
  }
  real_fpu_kern_leave(td, fpu_ctx);

  return ret;
}

PAYLOAD_CODE static inline struct sbl_map_list_entry* sceSblDriverFindMappedPageListByGpuVa(vm_offset_t gpu_va)
{
  struct sbl_map_list_entry* entry;
  if (!gpu_va)
  {
    return NULL;
  }
  entry = *sbl_driver_mapped_pages;
  while (entry)
  {
    if (entry->gpu_va == gpu_va)
    {
      return entry;
    }
    entry = entry->next;
  }
  return NULL;
}

PAYLOAD_CODE static inline vm_offset_t sceSblDriverGpuVaToCpuVa(vm_offset_t gpu_va, size_t* num_page_groups)
{
  struct sbl_map_list_entry* entry = sceSblDriverFindMappedPageListByGpuVa(gpu_va);
  if (!entry)
  {
    return 0;
  }
  if (num_page_groups)
  {
    *num_page_groups = entry->num_page_groups;
  }
  return entry->cpu_va;
}

PAYLOAD_CODE static inline int ccp_msg_populate_key(unsigned int key_handle, uint8_t* key, int reverse)
{
  struct sbl_key_rbtree_entry* key_entry;
  uint8_t* in_key;
  int i;
  int status = 0;

  // searching for a key entry 
  key_entry = sceSblKeymgrGetKey(key_handle);

  if (key_entry)
  {
    // we have found one, now checking if it's our key 
    if (real_memcmp(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(key_entry->desc.pfs.seed)) == 0)
    {
      // currently we have a crypto request that use a key slot which should be already in CCP, but because we
      // did everything manually, we don't have this key slot, so we need to remove using of key slot and place
      // a plain key here 
      in_key = key_entry->desc.pfs.key;
      if (reverse)
      { // reverse bytes of a key if it's needed 
        for (i = 0; i < 0x20; ++i)
          key[0x20 - i - 1] = in_key[i];
      } 
      else 
      { // copy a key as is 
        real_memcpy(key, in_key, 0x20);
      }
      status = 1;
    }
  }
  return status;
}

PAYLOAD_CODE static inline int ccp_msg_populate_key_if_needed(struct ccp_msg* msg)
{
  unsigned int cmd = msg->op.common.cmd; 
  unsigned int type = CCP_OP(cmd);
  uint8_t* buf;
  int status = 0;

  // skip messages that use plain keys and key slots 
  if (!(cmd & CCP_USE_KEY_HANDLE))
    goto skip;

  buf = (uint8_t*)&msg->op;

  // we only need to handle xts/hmac crypto operations 
  switch (type)
  {
    case CCP_OP_XTS:
      status = ccp_msg_populate_key(*(uint32_t*)(buf + 0x28), buf + 0x28, 1); // xts key have a reversed byte order 
      break;
    case CCP_OP_HMAC:
      status = ccp_msg_populate_key(*(uint32_t*)(buf + 0x40), buf + 0x40, 0); // hmac key have a normal byte order 
      break;
    default:
      goto skip;
  }

  // if key was successfully populated, then remove the flag which tells CCP to use a key slot 
  if (status)
    msg->op.common.cmd &= ~CCP_USE_KEY_HANDLE;

skip:
  return status;
}

PAYLOAD_CODE int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload)
{
  // it's SM request, thus we have the GPU address here, so we need to convert it to the CPU address
  union keymgr_request* request = (union keymgr_request*)sceSblDriverGpuVaToCpuVa(payload->data, NULL);
  int ret;

  // try to decrypt rif normally 
  ret = real_sceSblKeymgrSmCallfunc(payload);

  // and if it fails then we check if it's fake rif and try to decrypt it by ourselves 
  if ((ret != 0 || payload->status != 0) && request)
  {
    if (request->decrypt_rif.type == 0x200)
    { // fake?
      ret = npdrm_decrypt_debug_rif(request->decrypt_rif.type, request->decrypt_rif.data);
      payload->status = ret;
      ret = 0;
    }
  }
  return ret;
}

PAYLOAD_CODE int my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl(struct pfs_key_blob* blob)
{
  struct thread* td = curthread();

  struct rsa_buffer in_data;
  struct rsa_buffer out_data;
  struct rsa_key key;
  uint8_t dec_data[EEKPFS_SIZE];
  struct fake_key_desc* fake_key_slot;
  int ret;

  // try to decrypt EEKPFS normally 
  ret = real_sceSblPfsKeymgrGenEKpfsForGDGPAC(blob);

  if (ret)
  {
    // if this key is for debug/fake content, we could try to decrypt it manually 
    if (!blob->finalized)
    {
      real_memset(&in_data, 0, sizeof(in_data));
      {
        in_data.ptr = blob->eekpfs;
        in_data.size = sizeof(blob->eekpfs);
      }

      real_memset(&out_data, 0, sizeof(out_data));
      {
        out_data.ptr = dec_data;
        out_data.size = sizeof(dec_data);
      }

      real_memset(&key, 0, sizeof(key));
      {
        // here we feed a custom key to the algorithm 
        key.p = (uint8_t*)s_ypkg_p;
        key.q = (uint8_t*)s_ypkg_q;
        key.dmp1 = (uint8_t*)s_ypkg_dmp1;
        key.dmq1 = (uint8_t*)s_ypkg_dmq1;
        key.iqmp = (uint8_t*)s_ypkg_iqmp;
      }

      real_fpu_kern_enter(td, fpu_ctx, 0);
      {
        ret = real_RsaesPkcs1v15Dec2048CRT(&out_data, &in_data, &key);
      }
      real_fpu_kern_leave(td, fpu_ctx);

      if (ret == 0)
      { // got EKPFS key? 
        real_memcpy(blob->ekpfs, dec_data, sizeof(blob->ekpfs));

        // add it to our key list 
        fake_key_slot = get_free_fake_key_slot();
        if (fake_key_slot)
          real_memcpy(fake_key_slot->key, blob->ekpfs, sizeof(fake_key_slot->key));
      }
    }
  }
  return ret;
}

PAYLOAD_CODE int my_sceSblPfsSetKey_pfs_sbl_init(unsigned int* ekh, unsigned int* skh, uint8_t* key, uint8_t* iv, int mode, int unused, uint8_t disc_flag)
{
  struct sbl_key_rbtree_entry* key_entry;
  int is_fake_key;
  int ret;

  ret = real_sceSblPfsSetKey(ekh, skh, key, iv, mode, unused, disc_flag);

  // check if it's a key that we have decrypted manually 
  is_fake_key = is_fake_pfs_key(key) != NULL;

  key_entry = sceSblKeymgrGetKey(*ekh); // find a corresponding key entry 
  if (key_entry)
  {
    if (is_fake_key)
    {
      // generate an encryption key 
      pfs_generate_enc_key(key, iv, key_entry->desc.pfs.key);
      real_memcpy(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(s_fake_key_seed));
    }
  }
  key_entry = sceSblKeymgrGetKey(*skh); // find a corresponding key entry 
  if (key_entry)
  {
    if (is_fake_key)
    {
      // generate a signing key
      pfs_generate_sign_key(key, iv, key_entry->desc.pfs.key);
      real_memcpy(key_entry->desc.pfs.seed, s_fake_key_seed, sizeof(s_fake_key_seed));
    }
  }
  return ret;
}

PAYLOAD_CODE int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request)
{
  struct ccp_msg* msg;
  int ret;

  TAILQ_FOREACH(msg, &request->msgs, next){
    // handle each message in crypto request 
    ccp_msg_populate_key_if_needed(msg);
  }

  // run a crypto function normally 
  ret = real_sceSblServiceCryptAsync(request);

  return ret;
}

PAYLOAD_CODE int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload)
{
  uint64_t buf_gpu_va = payload->data;

  // it's SM request, thus we have the GPU address here, so we need to convert it to the CPU address 
  union keymgr_request* request = (union keymgr_request*)sceSblDriverGpuVaToCpuVa(buf_gpu_va, NULL);
  union keymgr_response* response = (union keymgr_response*)request;
  int orig_ret, ret;

  // try to decrypt rif normally
  ret = orig_ret = real_sceSblKeymgrSmCallfunc(payload);

  // and if it fails then we check if it's fake rif and try to decrypt it by ourselves
  if ((ret != 0 || payload->status != 0) && request)
  {
    if (request->decrypt_entire_rif.rif.format != 2)
    { // not fake?
      ret = orig_ret;
      goto err;
    }

    ret = npdrm_decrypt_debug_rif(request->decrypt_entire_rif.rif.format, request->decrypt_entire_rif.rif.digest);

    if (ret)
    {
      ret = orig_ret;
      goto err;
    }

    /* XXX: sorry, i'm lazy to refactor this crappy code :D basically, we're copying decrypted data to proper place,
       consult with kernel code if offsets needs to be changed */
    real_memcpy(response->decrypt_entire_rif.raw, request->decrypt_entire_rif.rif.digest, sizeof(request->decrypt_entire_rif.rif.digest) + sizeof(request->decrypt_entire_rif.rif.data));

    real_memset(response->decrypt_entire_rif.raw + 
                sizeof(request->decrypt_entire_rif.rif.digest) +
                sizeof(request->decrypt_entire_rif.rif.data), 
                0,
                sizeof(response->decrypt_entire_rif.raw) - 
                (sizeof(request->decrypt_entire_rif.rif.digest) + 
                sizeof(request->decrypt_entire_rif.rif.data)));

    payload->status = ret;
    ret = 0;
  }

err:
  return ret;
}
