/* r2ai - Copyright 2024 pancake */

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <math.h>

#include "r_vdb.h"

#define DO_NORM 0

/*=============================
 * Vector Utility
 *=============================*/

Vector vector_new(int dim) {
	Vector v;
	v.dim = dim;
	v.data = (float *)calloc(dim, sizeof(float));
	return v;
}

void vector_free(Vector *v) {
	if (v->data) {
		free(v->data);
		v->data = NULL;
	}
	v->dim = 0;
}

void vector_norm(Vector *v) {
	if (v->dim <= 0) {
		return;
	}
	float norm_sq = 0.0f;
	for (int i = 0; i < v->dim; i++) {
		norm_sq += v->data[i] * v->data[i];
	}
	if (norm_sq == 0.0f) {
		// zero vector, handle as needed
		return;
	}
	float norm = sqrtf(norm_sq);
	for (int i = 0; i < v->dim; i++) {
		v->data[i] /= norm;
	}
}

/* We typically use squared Euclidean distance for k-d trees (no sqrt). */
float squared_distance(const Vector *a, const Vector *b) {
	if (a->dim != b->dim) {
		return 1e30f; // dimension mismatch
	}
	float dist = 0.0f;
	for (int i = 0; i < a->dim; i++) {
		float diff = a->data[i] - b->data[i];
		dist += diff * diff;
	}
	return dist;
}

/*=============================
 * KDNode Utility
 *=============================*/

KDNode *create_kdnode(const Vector *v, const char *text, int split_dim) {
	KDNode *node = (KDNode *)malloc (sizeof (KDNode));
	node->point.dim = v->dim;
	node->point.data = (float *)malloc (sizeof (float) * v->dim);
	memcpy (node->point.data, v->data, sizeof (float) * v->dim);
	node->text = text ? strdup (text) : NULL;
	node->split_dim = split_dim;
	node->left = NULL;
	node->right = NULL;
	return node;
}

static void kdnode_free(KDNode *node) {
	if (!node) {
		return;
	}
	kdnode_free (node->left);
	kdnode_free (node->right);
	if (node->text) {
		free (node->text);
		node->text = NULL;
	}
	vector_free (&node->point);
	free (node);
}

/*=============================
 * RVDB / KD-Tree
 *=============================*/

RVDB *r_vdb_new(int dim) {
	RVDB *db = (RVDB *)malloc (sizeof (RVDB));
	db->root = NULL;
	db->dimension = dim;
	db->size = 0;
	return db;
}

void r_vdb_free(RVDB *db) {
	if (db) {
		kdnode_free (db->root);
		free (db);
	}
}

/* Recursive KD-tree insertion */
KDNode *kd_insert_recursive(KDNode *node, const Vector *v, const char *text, int depth, int dimension) {
	if (node == NULL) {
		int split_dim = depth % dimension;
		return create_kdnode (v, text, split_dim);
	}

	int axis = node->split_dim;
	if (v->data[axis] < node->point.data[axis]) {
		node->left = kd_insert_recursive (node->left, v, text, depth + 1, dimension);
	} else {
		node->right = kd_insert_recursive (node->right, v, text, depth + 1, dimension);
	}
	return node;
}

#include "vdb_embed.inc.c"

void r_vdb_insert(RVDB *db, const char *text) {
	if (!db || !text) {
		return;
	}
	float *embedding = (float *)calloc (db->dimension, sizeof(float));
	compute_embedding (text, embedding, db->dimension, DO_NORM);

	Vector v;
	v.dim = db->dimension;
	v.data = embedding;
	vector_norm(&v);

	db->root = kd_insert_recursive (db->root, &v, text, 0, db->dimension);
	db->size++;

	free(embedding);
}

/*=============================
 * K-NN Search Data Structures
 *=============================*/


static RVDBResultSet *create_knn_result_set(int capacity) {
	RVDBResultSet *rs = (RVDBResultSet *)malloc(sizeof(RVDBResultSet));
	rs->results = (RVDBResult *)malloc(sizeof(RVDBResult) * capacity);
	rs->capacity = capacity;
	rs->size = 0;
	return rs;
}

void r_vdb_result_free(RVDBResultSet *rs) {
	if (rs) {
		free (rs->results);
		free (rs);
	}
}

/* Swap helper */
static void swap_knn(RVDBResult *a, RVDBResult *b) {
	RVDBResult tmp = *a;
	*a = *b;
	*b = tmp;
}

/* Heapify up (max-heap) */
static void heapify_up(RVDBResultSet *rs, int idx) {
	while (idx > 0) {
		int parent = (idx - 1) / 2;
		if (rs->results[idx].dist_sq > rs->results[parent].dist_sq) {
			swap_knn(&rs->results[idx], &rs->results[parent]);
			idx = parent;
		} else {
			break;
		}
	}
}

/* Heapify down (max-heap) */
static void heapify_down(RVDBResultSet *rs, int idx) {
	while (1) {
		int left = 2 * idx + 1;
		int right = 2 * idx + 2;
		int largest = idx;

		if (left < rs->size && rs->results[left].dist_sq > rs->results[largest].dist_sq) {
			largest = left;
		}
		if (right < rs->size && rs->results[right].dist_sq > rs->results[largest].dist_sq) {
			largest = right;
		}
		if (largest == idx) {
			break;
		}
		swap_knn (&rs->results[idx], &rs->results[largest]);
		idx = largest;
	}
}

/* Insert a new candidate into the result set.
 * If there's room, add it; if at capacity, compare with root (worst) and replace if better. */
static void knn_insert_result(RVDBResultSet *rs, KDNode *node, float dist_sq) {
	if (rs->size < rs->capacity) {
		int idx = rs->size;
		rs->results[idx].node = node;
		rs->results[idx].dist_sq = dist_sq;
		rs->size++;
		heapify_up (rs, idx);
	} else {
		/* If new distance < root distance => pop root & insert new */
		if (dist_sq < rs->results[0].dist_sq) {
			rs->results[0].node = node;
			rs->results[0].dist_sq = dist_sq;
			heapify_down (rs, 0);
		}
	}
}

/* The largest distance in the set is at rs->results[0] if size > 0 */
static float knn_worst_dist(const RVDBResultSet *rs) {
	if (rs->size == 0) {
		return 1e30f;
	}
	return rs->results[0].dist_sq;
}

/* Optional final sort in ascending order by dist_sq. */
static int compare_knn_result(const void *a, const void *b) {
	const float d1 = ((RVDBResult *)a)->dist_sq;
	const float d2 = ((RVDBResult *)b)->dist_sq;
	if (d1 < d2) {
		return -1;
	}
	if (d1 > d2) {
		return 1;
	}
	return 0;
}

/*=============================
 * K-NN Search
 *=============================*/

/* Recursive k-NN search in the kd-tree */
static void kd_search_knn_recursive(KDNode *node, const Vector *query, RVDBResultSet *rs, int depth, int dim) {
	if (!node) return;

	/* 1. Insert the current node into the result set. */
	float dist_sq = squared_distance (query, &node->point);
	knn_insert_result (rs, node, dist_sq);

	/* 2. Check which side of the split to search first. */
	int axis = node->split_dim;
	float diff = query->data[axis] - node->point.data[axis];

	KDNode *first = (diff < 0) ? node->left : node->right;
	KDNode *second = (diff < 0) ? node->right : node->left;

	/* 3. Search the primary subtree. */
	kd_search_knn_recursive (first, query, rs, depth + 1, dim);

	/* 4. Possibly search the other subtree if it could contain closer points. */
	float diff_sq = diff * diff;
	float worst = knn_worst_dist (rs);
	if (diff_sq < worst) {
		kd_search_knn_recursive (second, query, rs, depth + 1, dim);
	}
}

/*
 * Find the k nearest neighbors to the embedding computed from `query_data`.
 * Returns a RVDBResultSet that must be freed by the caller.
 */
RVDBResultSet *r_vdb_query_embedding(RVDB *db, const float *query_data, int k) {
	if (!db || db->size == 0 || k <= 0) {
		return NULL;
	}

	Vector query_vec = vector_new (db->dimension);
	for (int i = 0; i < db->dimension; i++) {
		query_vec.data[i] = query_data[i];
	}
	vector_norm (&query_vec);

	RVDBResultSet *rs = create_knn_result_set (k);
	kd_search_knn_recursive (db->root, &query_vec, rs, 0, db->dimension);

	/* (Optional) Sort results in ascending order of dist_sq. */
	qsort (rs->results, rs->size, sizeof(RVDBResult), compare_knn_result);

	vector_free (&query_vec);
	return rs;
}

RVDBResultSet *r_vdb_query(RVDB *db, const char *text, int k) {
	float *query_embedding = (float *)calloc (db->dimension, sizeof (float));
	compute_embedding (text, query_embedding, db->dimension, DO_NORM);
	vector_norm (&(Vector){.data=query_embedding, .dim=db->dimension});
#if 0
	printf ("%f %f %f %f\n",
			query_embedding[0],
			query_embedding[1],
			query_embedding[2],
			query_embedding[3]);
	printf ("%f %f %f %f\n",
			query_embedding[4],
			query_embedding[5],
			query_embedding[6],
			query_embedding[7]);
#endif
	RVDBResultSet *res = r_vdb_query_embedding (db, query_embedding, k);
	free (query_embedding);
	return res;
}

#if 0
int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <query text>\n", argv[0]);
		return 1;
	}

	const char *query_text = argv[1];

	int DIM = 8;
	RVDB *db = r_vdb_new (DIM);

#if 0
	r_vdb_insert (db, "my favourite music is acid techno");
#endif

	const int K = 5;
	RVDBResultSet *rs = r_vdb_query (db, query_text, K);

	if (rs) {
		printf("Query: \"%s\"\n", query_text);
		printf("Found up to %d neighbors (actual found: %d).\n", K, rs->size);
		for (int i = 0; i < rs->size; i++) {
			RVDBResult *r = &rs->results[i];
			KDNode *n = r->node;
			float dist_sq = r->dist_sq;
			float cos_sim = 1.0f - (dist_sq * 0.5f); // for normalized vectors
			printf("%2d) dist_sq=%.4f cos_sim=%.4f text=\"%s\"\n",
					i+1, dist_sq, cos_sim, (n->text ? n->text : "(null)"));
		}
		r_vdb_result_free (rs);
	} else {
		printf("No results found (DB empty or error).\n");
	}

	r_vdb_free (db);
	return 0;
}
#endif
