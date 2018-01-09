/*
 * Helper function for dealing with post-quantum preshared keys
 *
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "state.h"
#include "packet.h"

extern bool ikev2_find_ppk(struct state *st, const chunk_t **ppk,
				const chunk_t **ppk_id, char **fn);
extern bool create_ppk_id_payload(const chunk_t *ppk_id, struct ppk_id_payload *payl);
extern chunk_t create_unified_ppk_id(struct ppk_id_payload *payl);
extern bool extract_ppk_id(pb_stream *pbs, struct ppk_id_payload *payl);
extern const chunk_t *ikev2_find_ppk_by_id(const chunk_t *ppk_id, char **fn);
extern bool ikev2_update_dynamic_ppk(char *fn);
extern PK11SymKey *clone_key(PK11SymKey *key);
extern stf_status ikev2_calc_no_ppk_auth(struct connection *c, struct state *st,
			unsigned char *id_hash, chunk_t *no_ppk_auth);
extern bool ppk_recalculate(const chunk_t *ppk, const struct prf_desc *prf,
				PK11SymKey **sk_d,
				PK11SymKey **sk_pi,
				PK11SymKey **sk_pr);

extern void revert_to_no_ppk_keys(PK11SymKey *sk_d, PK11SymKey *sk_pi,
		PK11SymKey *sk_pr, PK11SymKey *sk_d_no_ppk,
		PK11SymKey *sk_pi_no_ppk, PK11SymKey *sk_pr_no_ppk);
