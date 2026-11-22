/*
 * Copyright (c) 2026 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef PUF_VAULT_H__
#define PUF_VAULT_H__

#include <stddef.h>
#include <stdint.h>

/*
 * Fixed .noinit vault at the end of the powered TF-M RAM, immediately below
 * the reserved PUF bank. The crypto partition's built-in-key loader reads this
 * address directly; keep the layout in sync with docs/ram_keys.md.
 */
#define PUF_VAULT_ADDR 0x2000BC00UL
#define PUF_VAULT_SIZE 0x00000400U
#define PUF_VAULT_MAGIC 0x52414D5641554C54ULL
#define PUF_SLOT_VALID_MAGIC 0x534B4559UL

#define PUF_SERVER_SLOTS 8U
#define PUF_SERVER_KEY_BYTES 32U
#define PUF_SERVER_CMAC_BYTES 16U
#define PUF_RAM_HUK_BYTES 32U
#define PUF_PUF_SECRET_BYTES 40U
#define PUF_KCV_BYTES 8U

#define PUF_FLAG_ENROLLED (1U << 0)
#define PUF_FLAG_RECONSTRUCTED_OK (1U << 1)
#define PUF_FLAG_STABLE (1U << 2)
#define PUF_FLAG_WARM_CACHED (1U << 3)
#define PUF_FLAG_TAMPER_DETECTED (1U << 7)
#define PUF_FLAG_KEYS_ZEROED (1U << 4)

typedef struct {
	uint32_t valid_magic;
	uint16_t key_type;
	uint16_t key_bits;
	uint32_t alg;
	uint32_t usage;
	uint32_t key_version;
	uint8_t key_bytes[PUF_SERVER_KEY_BYTES];
	uint8_t cmac_tag[PUF_SERVER_CMAC_BYTES];
} __attribute__((packed)) noinit_ram_key_slot_t;

typedef struct {
	uint64_t vault_magic;
	uint32_t boot_epoch;
	uint32_t last_puf_off_rtc_ticks;
	uint8_t ram_huk[PUF_RAM_HUK_BYTES];
	uint32_t ram_huk_crc32;
	uint8_t puf_state_flags;
	uint8_t boot_retry_count;
	uint16_t last_raw_ber_bit_flips;
	uint16_t last_canary_flips;
	uint16_t last_hamming_weight_permille;
	uint8_t last_max_bch_block_flips;
	/* Transient between the platform decoder and the loader; zeroized once
	 * the RAM HUK is committed. */
	uint8_t puf_secret[PUF_PUF_SECRET_BYTES];
	uint8_t puf_secret_valid;
	/* KCV of the header this HUK was derived for; rejects a stale vault. */
	uint8_t kcv[PUF_KCV_BYTES];
	uint8_t reserved[6];
	noinit_ram_key_slot_t server_keys[PUF_SERVER_SLOTS];
} __attribute__((aligned(8))) tfm_noinit_vault_t;

_Static_assert(sizeof(noinit_ram_key_slot_t) == 68, "server key slot ABI");
_Static_assert(sizeof(tfm_noinit_vault_t) <= PUF_VAULT_SIZE, "vault fits");

static inline uint32_t puf_crc32(const void *data, size_t len)
{
	const uint8_t *bytes = (const uint8_t *)data;
	uint32_t crc = 0xFFFFFFFFUL;

	while (len-- > 0U) {
		crc ^= *bytes++;
		for (uint32_t bit = 0; bit < 8U; bit++) {
			crc = (crc >> 1) ^ (0xEDB88320UL & (0U - (crc & 1U)));
		}
	}

	return ~crc;
}

static inline int puf_vault_ram_huk_valid(const tfm_noinit_vault_t *vault)
{
	uint32_t nonzero = 0U;

	if (vault->vault_magic != PUF_VAULT_MAGIC ||
	    (vault->puf_state_flags & PUF_FLAG_STABLE) == 0U ||
	    (vault->puf_state_flags & (PUF_FLAG_TAMPER_DETECTED | PUF_FLAG_KEYS_ZEROED)) != 0U ||
	    vault->ram_huk_crc32 != puf_crc32(vault->ram_huk, PUF_RAM_HUK_BYTES)) {
		return 0;
	}
	for (uint32_t i = 0; i < PUF_RAM_HUK_BYTES; i++) {
		nonzero |= vault->ram_huk[i];
	}
	return nonzero != 0U;
}

#endif /* PUF_VAULT_H__ */
