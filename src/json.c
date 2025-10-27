#include "r2ai.h"
// TODO: move into r2/libr/util/json.c
//
// Helper function to convert RJson to PJ without draining
R_API PJ *r_json_to_pj(const RJson *json, PJ *existing_pj) {
	if (!json) {
		return existing_pj;
	}

	PJ *pj = existing_pj? existing_pj: pj_new ();
	if (!pj) {
		return NULL;
	}

	switch (json->type) {
	case R_JSON_STRING:
		pj_s (pj, json->str_value);
		break;
	case R_JSON_INTEGER:
		pj_n (pj, json->num.u_value);
		break;
	case R_JSON_DOUBLE:
		pj_d (pj, json->num.dbl_value);
		break;
	case R_JSON_BOOLEAN:
		pj_b (pj, json->num.u_value);
		break;
	case R_JSON_NULL:
		pj_null (pj);
		break;
	case R_JSON_OBJECT:
		if (!existing_pj) {
			pj_o (pj);
		}
		// Handle object's properties
		const RJson *prop = json->children.first;
		while (prop) {
			if (prop->key) {
				switch (prop->type) {
				case R_JSON_STRING:
					pj_ks (pj, prop->key, prop->str_value);
					break;
				case R_JSON_INTEGER:
					pj_kn (pj, prop->key, prop->num.u_value);
					break;
				case R_JSON_DOUBLE:
					pj_kd (pj, prop->key, prop->num.dbl_value);
					break;
				case R_JSON_BOOLEAN:
					pj_kb (pj, prop->key, prop->num.u_value);
					break;
				case R_JSON_NULL:
					pj_knull (pj, prop->key);
					break;
				case R_JSON_OBJECT:
					pj_ko (pj, prop->key);
					if (!r_json_to_pj (prop, pj)) {
						if (!existing_pj) {
							pj_free (pj);
						}
						return NULL;
					}
					pj_end (pj);
					break;
				case R_JSON_ARRAY:
					pj_ka (pj, prop->key);
					if (!r_json_to_pj (prop, pj)) {
						if (!existing_pj) {
							pj_free (pj);
						}
						return NULL;
					}
					pj_end (pj);
					break;
				default:
					break;
				}
			}
			prop = prop->next;
		}
		if (!existing_pj) {
			pj_end (pj);
		}
		break;
	case R_JSON_ARRAY:
		if (!existing_pj) {
			pj_a (pj);
		}
		// Handle array items
		const RJson *item = json->children.first;
		while (item) {
			switch (item->type) {
			case R_JSON_STRING:
				pj_s (pj, item->str_value);
				break;
			case R_JSON_INTEGER:
				pj_n (pj, item->num.u_value);
				break;
			case R_JSON_DOUBLE:
				pj_d (pj, item->num.dbl_value);
				break;
			case R_JSON_BOOLEAN:
				pj_b (pj, item->num.u_value);
				break;
			case R_JSON_NULL:
				pj_null (pj);
				break;
			case R_JSON_OBJECT:
				pj_o (pj);
				if (!r_json_to_pj (item, pj)) {
					if (!existing_pj) {
						pj_free (pj);
					}
					return NULL;
				}
				pj_end (pj);
				break;
			case R_JSON_ARRAY:
				pj_a (pj);
				if (!r_json_to_pj (item, pj)) {
					if (!existing_pj) {
						pj_free (pj);
					}
					return NULL;
				}
				pj_end (pj);
				break;
			default:
				break;
			}
			item = item->next;
		}
		if (!existing_pj) {
			pj_end (pj);
		}
		break;
	default:
		if (!existing_pj) {
			pj_free (pj);
		}
		return NULL;
	}

	return pj;
}

// Helper function to clone RJson to string
R_API char *r_json_to_string(const RJson *json) {
	PJ *pj = r_json_to_pj (json, NULL);
	return pj? pj_drain (pj): NULL;
}
