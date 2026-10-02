/* Copyright r2ai - 2023-2026 - pancake */

#include "r2ai.h"
// TODO: move into r2/libr/util/json.c

static void emit(PJ *pj, const RJson *j) {
	const RJson *c;
	switch (j->type) {
	case R_JSON_STRING:
		pj_s (pj, j->str_value);
		break;
	case R_JSON_INTEGER:
		if (j->num.dbl_value < 0) {
			pj_N (pj, j->num.s_value);
		} else {
			pj_n (pj, j->num.u_value);
		}
		break;
	case R_JSON_DOUBLE:
		pj_d (pj, j->num.dbl_value);
		break;
	case R_JSON_BOOLEAN:
		pj_b (pj, j->num.u_value);
		break;
	case R_JSON_NULL:
		pj_null (pj);
		break;
	case R_JSON_OBJECT:
		pj_o (pj);
		for (c = j->children.first; c; c = c->next) {
			if (c->key) {
				pj_k (pj, c->key);
				emit (pj, c);
			}
		}
		pj_end (pj);
		break;
	case R_JSON_ARRAY:
		pj_a (pj);
		for (c = j->children.first; c; c = c->next) {
			emit (pj, c);
		}
		pj_end (pj);
		break;
	}
}

R_API char *r_json_to_string(const RJson *json) {
	if (!json) {
		return NULL;
	}
	PJ *pj = pj_new ();
	emit (pj, json);
	return pj_drain (pj);
}
