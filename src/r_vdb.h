#ifndef R_VDB_H
#define R_VDB_H 1

/* Vector of floats with `dim` dimensions */
typedef struct {
	float *data; 
	int    dim;  
} Vector;

/* KD-node that stores a Vector and associated text */
typedef struct KDNode {
	Vector         point;      
	char          *text;       
	struct KDNode *left;       
	struct KDNode *right;      
	int split_dim;  
} KDNode;

/* A k-d tree "database" */
typedef struct token_df {
    char *token;
    int df;
    struct token_df *next;
} token_df;

typedef struct RVDB {
    KDNode *root;
    int dimension;
    int size;
    int total_docs;       // initialize to 0
    token_df *df_table;   // initialize to NULL
} RVDB;
/* Each k-NN result: pointer to KDNode + distance (squared). */
typedef struct {
	KDNode *node;
	float   dist_sq;
} RVDBResult;

/* 
 * A max-heap of up to k results, sorted by dist_sq DESC.
 * That way, the root is the *worst* (largest) distance in the set,
 * making it easy to pop it when we find a better (smaller-dist) candidate.
 */
typedef struct {
	RVDBResult *results;
	int        capacity;  
	int        size;      
} RVDBResultSet;

RVDB *r_vdb_new(int dim);
void r_vdb_insert(RVDB *db, const char *text);
RVDBResultSet *r_vdb_query(RVDB *db, const char *text, int k);
void r_vdb_free(RVDB *db);
void r_vdb_result_free(RVDBResultSet *rs);

#endif
