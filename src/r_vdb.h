#ifndef R_VDB_H
#define R_VDB_H 1

/* Vector of floats with `dim` dimensions */
typedef struct {
	float *data;
	int dim;
} Vector;

/* KD-node that stores a Vector and associated text */
typedef struct KDNode {
	Vector point;
	char *text;
	struct KDNode *left;
	struct KDNode *right;
	int split_dim;
} KDNode;

/* A k-d tree "database" */
typedef struct token_df {
	char *token;
	int df; // count
	struct token_df *next;
} token_df;

typedef struct {
	char *token;
	int count;
	float df;
} RVdbToken;

static inline void token_free(void *p) {
	if (p) {
		RVdbToken *t = (RVdbToken *)p;
		free (t->token);
		free (t);
	}
}

typedef struct {
	KDNode *root;
	int dimension;
	int size;
	RList *tokens; // global tokens count
	int total_docs;       // initialize to 0
	// token_df *df_table;   // initialize to NULL
} RVdb;

/* Each k-NN result: pointer to KDNode + distance (squared). */
typedef struct {
	KDNode *node;
	float dist_sq;
} RVdbResult;

/*
 * A max-heap of up to k results, sorted by dist_sq DESC.
 * That way, the root is the *worst* (largest) distance in the set,
 * making it easy to pop it when we find a better (smaller-dist) candidate.
 */
typedef struct {
	RVdbResult *results;
	int capacity;
	int size;
} RVdbResultSet;

RVdb *r_vdb_new(int dim);
void r_vdb_insert(RVdb *db, const char *text); // add_document
// expose api to add_token
RVdbResultSet *r_vdb_query(RVdb *db, const char *text, int k);
void r_vdb_free(RVdb *db);
void r_vdb_result_free(RVdbResultSet *rs);

#endif
