#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "freebsd_helper.h"
#include "elf_helper.h"
#include "self_helper.h"
#include "sbl_helper.h"
#include "pfs_helper.h"
#include "rif_helper.h"
#include "ccp_helper.h"

void* (*real_malloc)(unsigned long size, void* type, int flags) PAYLOAD_BSS;
void (*real_free)(void* addr, void* type) PAYLOAD_BSS;
void* (*real_memcpy)(void* dst, const void* src, size_t len) PAYLOAD_BSS;
void* (*real_memcmp)(const void *b1, const void *b2, size_t len) PAYLOAD_BSS;
void* (*real_memset)(void *s, int c, size_t n) PAYLOAD_BSS;
int (*real_sx_xlock)(struct sx *sx, int opts) PAYLOAD_BSS;
int (*real_sx_xunlock)(struct sx *sx) PAYLOAD_BSS;
int (*real_fpu_kern_enter)(struct thread *td, struct fpu_kern_ctx *ctx, uint32_t flags) PAYLOAD_BSS;
int (*real_fpu_kern_leave)(struct thread *td, struct fpu_kern_ctx *ctx) PAYLOAD_BSS;
void (*real_Sha256Hmac)(uint8_t hash[0x20], const uint8_t* data, size_t data_size, const uint8_t* key, int key_size) PAYLOAD_BSS;
int (*real_AesCbcCfb128Decrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_BSS;
int (*real_RsaesPkcs1v15Dec2048CRT)(struct rsa_buffer* out, struct rsa_buffer* in, struct rsa_key* key) PAYLOAD_BSS;
void* (*real_eventhandler_register)(void* list, const char* name, void* func, void* arg, int priority) PAYLOAD_BSS;
void  (*real_sx_init_flags)(struct sx *sx, const char *description, int opts) PAYLOAD_BSS;
void  (*real_sx_destroy)(struct sx *sx) PAYLOAD_BSS;
void (*real_sceSblAuthMgrSmStart)(void**) PAYLOAD_BSS;
int (*real_sceSblServiceMailbox)(unsigned long service_id, uint8_t request[SBL_MSG_SERVICE_MAILBOX_MAX_SIZE], void* response) PAYLOAD_BSS;
int (*real_sceSblAuthMgrGetSelfInfo)(struct self_context* ctx, struct self_ex_info** info) PAYLOAD_BSS;
int (*real_sceSblAuthMgrIsLoadable2)(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_BSS;
int (*real_sceSblAuthMgrVerifyHeader)(struct self_context* ctx) PAYLOAD_BSS;
int (*real_sceSblPfsKeymgrGenEKpfsForGDGPAC)(struct pfs_key_blob* key_blob) PAYLOAD_BSS;
int (*real_sceSblPfsSetKey)(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_BSS;
int (*real_sceSblServiceCryptAsync)(struct ccp_req* request) PAYLOAD_BSS;
int (*real_sceSblKeymgrSmCallfunc)(union keymgr_payload* payload) PAYLOAD_BSS;

void* M_TEMP PAYLOAD_BSS;
void* fpu_ctx PAYLOAD_BSS;
uint8_t* mini_syscore_self_binary PAYLOAD_BSS;
struct sbl_map_list_entry** sbl_driver_mapped_pages PAYLOAD_BSS;
struct sbl_key_rbtree_entry** sbl_keymgr_key_rbtree PAYLOAD_BSS;

extern int my_sceSblAuthMgrIsLoadable2(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_CODE;
extern int my_sceSblAuthMgrVerifyHeader(struct self_context* ctx) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl(struct pfs_key_blob* key_blob) PAYLOAD_CODE;
extern int my_sceSblPfsSetKey_pfs_sbl_init(uint32_t* ekh, uint32_t* skh, uint8_t* key, uint8_t* iv, int type, int unused, uint8_t is_disc) PAYLOAD_CODE;
extern int my_sceSblServiceCryptAsync_pfs_crypto(struct ccp_req* request) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) PAYLOAD_CODE;

extern struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS] PAYLOAD_BSS;
extern struct sx s_fake_keys_lock PAYLOAD_BSS;

struct real_info
{
  const size_t kernel_offset;
  const void* payload_target;
};

struct disp_info
{
  const size_t call_offset;
  const void* payload_target;
};

struct real_info real_infos[] PAYLOAD_DATA =
{
  { 0x3F7750, &real_malloc },
  { 0x3F7930, &real_free },
  { 0x14A6B0, &real_memcpy },
  { 0x242A60, &real_memcmp },
  { 0x302BD0, &real_memset },
  { 0x38FA30, &real_sx_xlock },
  { 0x38FBC0, &real_sx_xunlock },
  { 0x059580, &real_fpu_kern_enter },
  { 0x059680, &real_fpu_kern_leave },
  { 0x2D5C50, &real_Sha256Hmac },
  { 0x17A6F0, &real_AesCbcCfb128Decrypt },
  { 0x3EF200, &real_RsaesPkcs1v15Dec2048CRT },
  { 0x3C97F0, &real_eventhandler_register },
  { 0x38F900, &real_sx_init_flags },
  { 0x38F970, &real_sx_destroy },
  { 0x622020, &real_sceSblAuthMgrSmStart },
  { 0x60CA10, &real_sceSblServiceCryptAsync },
  { 0x6146C0, &real_sceSblServiceMailbox },
  { 0x606E00, &real_sceSblPfsSetKey },
  { 0x60E680, &real_sceSblKeymgrSmCallfunc },
  { 0x625C50, &real_sceSblAuthMgrIsLoadable2 },
  { 0x625CB0, &real_sceSblAuthMgrVerifyHeader },
  { 0x626490, &real_sceSblAuthMgrGetSelfInfo },
  { 0x60F000, &real_sceSblPfsKeymgrGenEKpfsForGDGPAC },

  { 0x1993B30, &M_TEMP },
  { 0x251CCC0, &fpu_ctx },
  { 0x1471468, &mini_syscore_self_binary },
  { 0x2519DD0, &sbl_driver_mapped_pages },
  { 0x2534DE0, &sbl_keymgr_key_rbtree },

  { 0, NULL },
};

struct disp_info disp_infos[] PAYLOAD_DATA =
{
  // Fself
  { 0x61F24F, &my_sceSblAuthMgrIsLoadable2 },
  { 0x61F976, &my_sceSblAuthMgrVerifyHeader },
  { 0x620599, &my_sceSblAuthMgrVerifyHeader },
  { 0x6238BA, &my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox },
  { 0x6244E1, &my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox },

  // Fpkg 
  { 0x62DF00, &my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif },
  { 0x62ECDE, &my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new },
  { 0x607045, &my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl  },
  { 0x6070E1, &my_sceSblPfsKeymgrGenEKpfsForGDGPAC_sceSblPfsKeymgrIoctl },
  { 0x69DB4A, &my_sceSblPfsSetKey_pfs_sbl_init },
  { 0x69DBD8, &my_sceSblPfsSetKey_pfs_sbl_init },
  { 0x69DDE4, &my_sceSblServiceCryptAsync_pfs_crypto },
  { 0x69E28C, &my_sceSblServiceCryptAsync_pfs_crypto },
  { 0x69E4E8, &my_sceSblServiceCryptAsync_pfs_crypto },
  { 0x69E85D, &my_sceSblServiceCryptAsync_pfs_crypto },
  { 0x69EC7E, &my_sceSblServiceCryptAsync_pfs_crypto },
  { 0x69EF0D, &my_sceSblServiceCryptAsync_pfs_crypto },
  { 0x69F252, &my_sceSblServiceCryptAsync_pfs_crypto },

  { 0, 0 },
};

struct fake_key_desc s_fake_keys[MAX_FAKE_KEYS] PAYLOAD_BSS;
struct sx s_fake_keys_lock PAYLOAD_BSS;

PAYLOAD_CODE void debug_pfs_cleanup(void* arg)
{
  real_sx_destroy(&s_fake_keys_lock);
}

// initialization, etc

PAYLOAD_CODE void my_entrypoint()
{
  real_sx_init_flags(&s_fake_keys_lock, "fake_keys_lock", 0);
  real_eventhandler_register(NULL, "shutdown_pre_sync", &debug_pfs_cleanup, NULL, 0);
}

struct
{
  uint64_t signature;
  struct real_info* real_infos;
  struct disp_info* disp_infos;
  void* entrypoint;
}
payload_header PAYLOAD_HEADER =
{
  0x5041594C4F414430ull,
  real_infos,
  disp_infos,
  &my_entrypoint,
};

int _start()
{
  return 0;
}
