/**
 * Vector Database Implementation
 * Follows the logic of the original C implementation in r2ai
 * No external dependencies, works with pure strings and native TS/JS
 */
// Token representation
interface Token {
  token: string;
  count: number;
  df: number;
}

// KD-Tree Node
interface KDNodeData {
  point: Float32Array;
  text: string;
  left: KDNodeData | null;
  right: KDNodeData | null;
  splitDim: number;
}

// Result for K-Nearest Neighbors
interface KNNResult {
  node: KDNodeData;
  distanceSq: number;
}

class VectorDB {
  // Core database structures
  private dimension: number;
  private root: KDNodeData | null = null;
  private tokens: Token[] = [];
  private totalDocs: number = 0;
  private size: number = 0;

  constructor(dimension: number) {
    this.dimension = dimension;
  }

  // Validate token (similar to C implementation)
  private isValidToken(token: string): boolean {
    const invalidTokens = ["pancake", "author", "radare2"];
    return !invalidTokens.includes(token);
  }

  // Find a token in the global token list
  private findToken(tokens: Token[], token: string): Token | undefined {
    return tokens.find((t) => t.token === token);
  }

  // Compute embedding using TF-IDF approach
  private computeEmbedding(text: string): Float32Array {
    // Zero the embedding vector
    const embedding = new Float32Array(this.dimension);

    // Tokenize and normalize
    const tokens = text
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, " ")
      .split(/\s+/)
      .filter((token) => token.length > 0);

    // Local document token frequency
    const docTokens: Token[] = [];
    for (const token of tokens) {
      const existingToken = this.findToken(docTokens, token);
      if (existingToken) {
        existingToken.count++;
      } else {
        docTokens.push({ token, count: 1, df: 0 });
      }
    }

    // Increment total documents
    this.totalDocs++;

    // Update global document frequencies
    for (const docToken of docTokens) {
      const globalToken = this.findToken(this.tokens, docToken.token);
      if (globalToken) {
        if (this.isValidToken(docToken.token)) {
          globalToken.count++;
          globalToken.df += 1;
        }
      } else {
        this.tokens.push({ ...docToken, df: 1 });
      }
    }

    // Compute TF-IDF and update embedding
    for (const docToken of docTokens) {
      // Compute term frequency
      const tf = 1 + Math.log(docToken.count);

      // Find global token to get document frequency
      const globalToken = this.findToken(this.tokens, docToken.token);
      const dfValue = globalToken ? globalToken.df : 1;

      // Compute inverse document frequency
      const idf = Math.log((this.totalDocs + 1) / (dfValue + 1)) + 1;

      // Compute weight
      const weight = tf * idf;

      // Hash-based index assignment
      const hash = this.simpleHash(docToken.token);
      const index = hash % this.dimension;

      // Add weighted value to embedding
      embedding[index] += weight;
    }

    // L2 Normalize the embedding
    return this.normalizeVector(embedding);
  }

  // Simple string hash function
  private simpleHash(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  // Normalize vector to unit length
  private normalizeVector(vec: Float32Array): Float32Array {
    const normSq = vec.reduce((sum, val) => sum + val * val, 0);
    if (normSq > 0) {
      const norm = Math.sqrt(normSq);
      return vec.map((val) => val / norm);
    }
    return vec;
  }

  // Compute squared Euclidean distance
  private squaredDistance(a: Float32Array, b: Float32Array): number {
    if (a.length !== b.length) return Number.MAX_VALUE;
    return a.reduce((sum, val, i) => sum + Math.pow(val - b[i], 2), 0);
  }

  // Recursive KD-Tree insertion
  private insertRecursive(
    node: KDNodeData | null,
    point: Float32Array,
    text: string,
    depth: number,
  ): KDNodeData {
    if (!node) {
      const splitDim = depth % this.dimension;
      return {
        point,
        text,
        left: null,
        right: null,
        splitDim,
      };
    }

    const axis = node.splitDim;
    if (point[axis] < node.point[axis]) {
      node.left = this.insertRecursive(node.left, point, text, depth + 1);
    } else {
      node.right = this.insertRecursive(node.right, point, text, depth + 1);
    }

    return node;
  }

  // Insert a document into the vector database
  insert(text: string): void {
    if (!text) return;

    // Compute embedding
    const embedding = this.computeEmbedding(text);

    // Insert into KD-Tree
    this.root = this.insertRecursive(this.root, embedding, text, 0);
    this.size++;
  }

  // K-Nearest Neighbors search
  query(text: string, k: number): string[] {
    if (!text) return [];
    if (!this.root) return [];

    // Compute query embedding
    const queryEmbedding = this.computeEmbedding(text);

    // Initialize result set
    const results: KNNResult[] = [];

    // Recursive KNN search
    const searchRecursive = (
      node: KDNodeData | null,
      query: Float32Array,
      depth: number,
    ) => {
      if (!node) return;

      // Compute distance and potentially insert into results
      const distSq = this.squaredDistance(query, node.point);

      if (results.length < k) {
        results.push({ node, distanceSq: distSq });
        // Maintain max-heap property
        results.sort((a, b) => b.distanceSq - a.distanceSq);
      } else if (distSq < results[0].distanceSq) {
        results[0] = { node, distanceSq: distSq };
        results.sort((a, b) => b.distanceSq - a.distanceSq);
      }

      // Decide which subtree to search first
      const axis = node.splitDim;
      const diff = query[axis] - node.point[axis];
      const first = diff < 0 ? node.left : node.right;
      const second = diff < 0 ? node.right : node.left;

      // Recursively search
      searchRecursive(first, query, depth + 1);

      // Potentially search the other subtree
      if (results.length < k || diff * diff < results[0].distanceSq) {
        searchRecursive(second, query, depth + 1);
      }
    };

    // Perform the search
    searchRecursive(this.root, queryEmbedding, 0);

    // Sort results and return texts
    return results
      .sort((a, b) => a.distanceSq - b.distanceSq)
      .map((result) => result.node.text);
  }

  // Get total number of documents
  getSize(): number {
    return this.size;
  }
}

/*
// Example usage
function main() {
  // Create a vector database with 64-dimensional embeddings
  const db = new VectorDB(64);

  // Insert some sample documents
  db.insert("The quick brown fox jumps over the lazy dog");
  db.insert("A quick brown fox is very quick");
  db.insert("The author of radare2 is name / named pancake");
  db.insert("The lazy dog sleeps all day");

  // Query for similar documents
  const results = db.query("who is the author of radare2?", 2);
  // const results = db.query("quick brown animal", 2);
  console.log("Similar documents:", results);
}

// Uncomment to run
main();

*/
export default VectorDB;
