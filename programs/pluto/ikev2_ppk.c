/*
 * Helper function for dealing with post-quantum preshared keys
 *
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include <libreswan.h>

#include "lswlog.h"

#include "defs.h"

#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "keys.h" /* needs state.h */
#include "demux.h"
#include "packet.h"
#include "ikev2_prf.h"

#include "ike_alg.h"
#include "crypt_symkey.h"
#include "pluto_crypt.h"
#include "ikev2.h"
#include "ikev2_ppk.h"

bool ikev2_find_ppk(struct state *st, const chunk_t **ppk_m, const chunk_t **ppk_id_m, char **fn)
{
	const struct connection *c = st->st_connection;
	const chunk_t *ppk = get_ppk(c, ppk_id_m, fn);

	if (ppk != NULL) {
		*ppk_m = ppk;
		return TRUE;
	} else {
		return FALSE;
	}
}

/* used by initiator, to properly construct struct
 * from chunk_t we got from .secrets */
bool create_ppk_id_payload(const chunk_t *ppk_id, struct ppk_id_payload *payl)
{
	payl->type = PPK_ID_FIXED;	/* currently we support only this type */
	payl->ppk_id = ppk_id;
	return TRUE;
}

/* used by initiator to make chunk_t from ppk_id payload
 * for sending it in PPK_ID Notify Payload over the wire */
chunk_t create_unified_ppk_id(struct ppk_id_payload *payl)
{
	u_char type = PPK_ID_FIXED;	/* PPK_ID_FIXED */
	u_int i;
	const chunk_t *ppk_id = payl->ppk_id;

	chunk_t unified =  alloc_chunk(ppk_id->len + 1, "Unified PPK_ID");
	*unified.ptr = type;
	for (i = 1; i < ppk_id->len + 1; i++) {
		*(unified.ptr + i) = *((ppk_id->ptr) + (i - 1));
	}
	return unified;
}

/* used by responder, for extracting PPK_ID from IKEv2 Notify
 * PPK_ID Payload, we store PPK_ID and it's type in payl */
bool extract_ppk_id(pb_stream *pbs, struct ppk_id_payload *payl)
{
	size_t len = pbs_left(pbs);
	u_char dst[PPK_ID_MAXLEN];
	int idtype;
	chunk_t ppk_id;

	if (len > PPK_ID_MAXLEN) {
		loglog(RC_LOG_SERIOUS, "PPK ID length is too big");
		return FALSE;
	}
	if (len <= 1) {
		loglog(RC_LOG_SERIOUS, "PPK ID data must be at least 1 byte (received %zd bytes including ppk type byte)",
			len);
		return FALSE;
	}

	if (!in_raw(dst, len, pbs, "Unified PPK_ID Payload")) {
		loglog(RC_LOG_SERIOUS, "PPK ID data could not be read");
		return FALSE;
	}

	DBG(DBG_CONTROL, DBG_log("received PPK_ID type: %s",
		enum_name(&ikev2_ppk_id_names, dst[0])));

	idtype = (int)dst[0];
	switch (idtype) {
	case PPK_ID_FIXED:
		DBG(DBG_CONTROL, DBG_log("PPK_ID of type PPK_ID_FIXED."));
		break;

	case PPK_ID_OPAQUE:
	default:
		loglog(RC_LOG_SERIOUS, "PPK_ID type %d(%s) not supported",
			idtype, enum_name(&ikev2_ppk_id_names, idtype));
		return FALSE;
	}

	/* clone ppk id data without ppk id type byte */
	clonetochunk(ppk_id, dst + 1, len - 1, "PPK_ID data");
	payl->ppk_id = &ppk_id;
	DBG(DBG_CONTROL, DBG_dump_chunk("Extracted PPK_ID", *payl->ppk_id));

	return TRUE;
}

const chunk_t *ikev2_find_ppk_by_id(const chunk_t *ppk_id, char **fn)
{
	return get_ppk_by_id(ppk_id, fn);
}

bool ikev2_update_dynamic_ppk(char *fn)
{
	return update_dynamic_ppk(fn);
}

PK11SymKey *clone_key(PK11SymKey *key)
{
	return key_from_symkey_bytes(key, 0, sizeof_symkey(key));
}

stf_status ikev2_calc_no_ppk_auth(struct connection *c, struct state *st, unsigned char *id_hash, chunk_t *no_ppk_auth)
{
	enum keyword_authby authby = c->spd.this.authby;
	switch (authby) {
	case AUTH_RSASIG:
		/* TODO */
		break;
	case AUTH_PSK:
		if (ikev2_create_psk_auth(AUTH_PSK, st, id_hash, NULL, TRUE, no_ppk_auth))
			return STF_OK;
		break;
	default:
		break;
	}
	return STF_INTERNAL_ERROR;
}

void ppk_recalculate(const chunk_t *ppk, const struct prf_desc *prf_desc, PK11SymKey **sk_d, PK11SymKey **sk_pi, PK11SymKey **sk_pr)
{
	PK11SymKey *new_sk_pi, *new_sk_pr, *new_sk_d;
	PK11SymKey *ppk_key = symkey_from_chunk("PPK Keying material", DBG_CRYPT, *ppk);

	DBG(DBG_PRIVATE, DBG_log("Starting to recalculate SK_d, SK_pi, SK_pr");
			 DBG_dump_chunk("PPK:", *ppk));

	new_sk_d = ikev2_prfplus(prf_desc, ppk_key, *sk_d, prf_desc->prf_key_size);
	release_symkey(__func__, "sk_d", sk_d);
	*sk_d = new_sk_d;

	new_sk_pi = ikev2_prfplus(prf_desc, ppk_key, *sk_pi, prf_desc->prf_key_size);
	release_symkey(__func__, "sk_pi", sk_pi);
	*sk_pi = new_sk_pi;

	new_sk_pr = ikev2_prfplus(prf_desc, ppk_key, *sk_pr, prf_desc->prf_key_size);
	release_symkey(__func__, "sk_pr", sk_pr);
	*sk_pr = new_sk_pr;

	if (DBGP(DBG_PRIVATE)) {
		/* declaring chunks for dumping them beneath */
		chunk_t chunk_sk_d = chunk_from_symkey("chunk_SK_d", DBG_CRYPT, *sk_d);
		chunk_t chunk_sk_pi = chunk_from_symkey("chunk_SK_pi", DBG_CRYPT, *sk_pi);
		chunk_t chunk_sk_pr = chunk_from_symkey("chunk_SK_pr", DBG_CRYPT, *sk_pr);

		DBG(DBG_PRIVATE,
		    DBG_log("Finished recalculating SK_d, SK_pi, SK_pr");
		    DBG_log("ppk_recalculate pointers: SK_d-key@%p, SK_pi-key@%p, SK_pr-key@%p",
			     *sk_d, *sk_pi, *sk_pr);
		    DBG_dump_chunk("new SK_d", chunk_sk_d);
		    DBG_dump_chunk("new SK_pi", chunk_sk_pi);
		    DBG_dump_chunk("new SK_pr", chunk_sk_pr));

		freeanychunk(chunk_sk_d);
		freeanychunk(chunk_sk_pi);
		freeanychunk(chunk_sk_pr);
	}

}

void revert_to_no_ppk_keys(PK11SymKey *sk_d, PK11SymKey *sk_pi,
		 	   PK11SymKey *sk_pr, PK11SymKey *sk_d_no_ppk,
			   PK11SymKey *sk_pi_no_ppk, PK11SymKey *sk_pr_no_ppk)
{
	DBG(DBG_CONTROL, DBG_log("I'm going to release recalculated keys and replace them with old (no_ppk) ones."));
	release_symkey(__func__, "sk_d", &sk_d);
	release_symkey(__func__, "sk_pi", &sk_pi);
	release_symkey(__func__, "sk_pr", &sk_pr);

	sk_d = sk_d_no_ppk;
	sk_pi = sk_pi_no_ppk;
	sk_pr = sk_pr_no_ppk;
}
