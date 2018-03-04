#ifndef __PFS_HELPER_H
#define __PFS_HELPER_H

#define EKPFS_SIZE 0x20
#define EEKPFS_SIZE 0x100
#define PFS_SEED_SIZE 0x10
#define PFS_FINAL_KEY_SIZE 0x20
#define SIZEOF_PFS_KEY_BLOB 0x158
#define CONTENT_KEY_SEED_SIZE 0x10
#define SELF_KEY_SEED_SIZE 0x10
#define EEKC_SIZE 0x20
#define MAX_FAKE_KEYS 32
#define SIZEOF_RSA_KEY 0x48

struct fake_key_desc
{
  uint8_t key[0x20];
  int occupied;
};

struct fake_key_d
{
  uint32_t index;
  uint8_t seed[PFS_SEED_SIZE];
};

struct ekc
{
  uint8_t content_key_seed[CONTENT_KEY_SEED_SIZE];
  uint8_t self_key_seed[SELF_KEY_SEED_SIZE];
};

struct pfs_key_blob
{
  uint8_t ekpfs[EKPFS_SIZE];
  uint8_t eekpfs[EEKPFS_SIZE];
  struct ekc eekc;
  uint32_t key_ver;
  uint32_t pubkey_ver;
  uint32_t type;
  uint32_t finalized;
  uint32_t is_disc;
  uint32_t pad;
};

typedef struct pfs_key_blob pfs_key_blob_t;

TYPE_CHECK_SIZE(pfs_key_blob_t, SIZEOF_PFS_KEY_BLOB);

struct rsa_buffer
{
  uint8_t* ptr;
  size_t size;
};

#endif
