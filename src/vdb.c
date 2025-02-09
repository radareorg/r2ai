/* r2ai - MIT - Copyright 2024-2025 pancake */

#include <r_util.h>
#include "r_vdb.h"

/*-------------------------------
  Vector Utility Functions
  -------------------------------*/
static Vector vector_new(int dim) {
	Vector v;
	v.dim = dim;
	v.data = (float *)calloc(dim, sizeof(float));
	return v;
}

static void vector_free(Vector *v) {
	if (v) {
		free (v->data);
		v->dim = 0;
	}
}

/*-------------------------------
  Distance Function
  (Using Squared Euclidean Distance)
  For two unit vectors: dist^2 = 2 - 2 * (dot product)
  -------------------------------*/
static float squared_distance(const Vector *a, const Vector *b) {
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

/*-------------------------------
  KDNode Utility Functions
  -------------------------------*/
static KDNode *create_kdnode(const Vector *v, const char *text, int split_dim) {
	KDNode *node = (KDNode *)malloc(sizeof(KDNode));
	node->point.dim = v->dim;
	node->point.data = (float *)malloc(sizeof(float) * v->dim);
	memcpy(node->point.data, v->data, sizeof(float) * v->dim);
	node->text = text ? strdup(text) : NULL;
	node->split_dim = split_dim;
	node->left = NULL;
	node->right = NULL;
	return node;
}

static void kdnode_free(KDNode *node) {
	if (!node) {
		return;
	}
	kdnode_free(node->left);
	kdnode_free(node->right);
	if (node->text) {
		free(node->text);
		node->text = NULL;
	}
	vector_free(&node->point);
	free(node);
}

RVdb *r_vdb_new(int dim) {
	RVdb *db = (RVdb *)malloc(sizeof(RVdb));
	db->root = NULL;
	db->dimension = dim;
	db->tokens = r_list_newf (token_free);
	db->size = 0;
	return db;
}

void r_vdb_free(RVdb *db) {
	if (db) {
		r_list_free (db->tokens);
		kdnode_free (db->root);
		free(db);
	}
}

/* Recursive KD-tree insertion */
static KDNode *kd_insert_recursive(KDNode *node, const Vector *v, const char *text, int depth, int dimension) {
	if (node == NULL) {
		int split_dim = depth % dimension;
		return create_kdnode(v, text, split_dim);
	}
	int axis = node->split_dim;
	if (v->data[axis] < node->point.data[axis]) {
		node->left = kd_insert_recursive(node->left, v, text, depth + 1, dimension);
	} else {
		node->right = kd_insert_recursive(node->right, v, text, depth + 1, dimension);
	}
	return node;
}

#include "vdb_embed.inc.c"

void r_vdb_insert(RVdb *db, const char *text) {
	if (!db || !text) {
		return;
	}
	float *embedding = (float *)calloc (db->dimension, sizeof(float));
	// New call: pass the db pointer so TF-IDF stats are updated.
	compute_embedding (db, text, embedding, db->dimension);
	Vector v;
	v.dim = db->dimension;
	v.data = embedding;
	db->root = kd_insert_recursive (db->root, &v, text, 0, db->dimension);
	db->size++;
	free(embedding);
}

// K-NN Search Data Structures and Helpers
static RVdbResultSet *create_knn_result_set(int capacity) {
	RVdbResultSet *rs = (RVdbResultSet *)malloc(sizeof(RVdbResultSet));
	rs->results = (RVdbResult *)malloc(sizeof(RVdbResult) * capacity);
	rs->capacity = capacity;
	rs->size = 0;
	return rs;
}

void r_vdb_result_free(RVdbResultSet *rs) {
	if (rs) {
		free(rs->results);
		free(rs);
	}
}

/* Swap helper */
static void swap_knn(RVdbResult *a, RVdbResult *b) {
	RVdbResult tmp = *a;
	*a = *b;
	*b = tmp;
}

/* Heapify up (max-heap) */
static void heapify_up(RVdbResultSet *rs, int idx) {
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
static void heapify_down(RVdbResultSet *rs, int idx) {
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
		swap_knn(&rs->results[idx], &rs->results[largest]);
		idx = largest;
	}
}

/* Insert a new candidate into the result set. */
static void knn_insert_result(RVdbResultSet *rs, KDNode *node, float dist_sq) {
	if (rs->size < rs->capacity) {
		int idx = rs->size;
		rs->results[idx].node = node;
		rs->results[idx].dist_sq = dist_sq;
		rs->size++;
		heapify_up(rs, idx);
	} else {
		if (dist_sq < rs->results[0].dist_sq) {
			rs->results[0].node = node;
			rs->results[0].dist_sq = dist_sq;
			heapify_down(rs, 0);
		}
	}
}

/* The largest distance in the set (for max-heap) is at rs->results[0] */
static float knn_worst_dist(const RVdbResultSet *rs) {
	if (rs->size == 0) {
		return 1e30f;
	}
	return rs->results[0].dist_sq;
}

static int compare_knn_result(const void *a, const void *b) {
	const float d1 = ((RVdbResult *)a)->dist_sq;
	const float d2 = ((RVdbResult *)b)->dist_sq;
	if (d1 < d2) {
		return -1;
	}
	if (d1 > d2) {
		return 1;
	}
	return 0;
}

/* K-NN Search (using squared Euclidean distance) */
void kd_search_knn_recursive(KDNode *node, const Vector *query, RVdbResultSet *rs, int depth, int dim) {
	if (!node) {
		return;
	}
	float dist_sq = squared_distance(query, &node->point);
	knn_insert_result(rs, node, dist_sq);

	int axis = node->split_dim;
	float diff = query->data[axis] - node->point.data[axis];
	KDNode *first = (diff < 0) ? node->left : node->right;
	KDNode *second = (diff < 0) ? node->right : node->left;

	kd_search_knn_recursive (first, query, rs, depth + 1, dim);

	float diff_sq = diff * diff;
	float worst = knn_worst_dist(rs);
	if (diff_sq < worst) {
		kd_search_knn_recursive(second, query, rs, depth + 1, dim);
	}
}

/*
 * Find the k nearest neighbors to the embedding computed from `query_data`.
 * Returns a RVdbResultSet that must be freed by the caller.
 */
RVdbResultSet *r_vdb_query_embedding(RVdb *db, const float *query_data, int k) {
	if (!db || db->size == 0 || k <= 0) {
		return NULL;
	}
	Vector query_vec = vector_new (db->dimension);
	for (int i = 0; i < db->dimension; i++) {
		query_vec.data[i] = query_data[i];
	}
	// query_vec is already normalized by compute_embedding()
	RVdbResultSet *rs = create_knn_result_set(k);
	kd_search_knn_recursive (db->root, &query_vec, rs, 0, db->dimension);
	/* Optional: sort the result set in ascending order of distance */
	qsort (rs->results, rs->size, sizeof(RVdbResult), compare_knn_result);
	vector_free (&query_vec);
	return rs;
}

RVdbResultSet *r_vdb_query(RVdb *db, const char *text, int k) {
	float *query_embedding = (float *)calloc (db->dimension, sizeof(float));
	compute_embedding (db, text, query_embedding, db->dimension);
	// No extra normalization is needed.
	RVdbResultSet *res = r_vdb_query_embedding (db, query_embedding, k);
	free (query_embedding);
	return res;
}
