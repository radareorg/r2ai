import Foundation

// Token representation
struct Token {
    var token: String
    var count: Int
    var df: Int
}

// KD-Tree Node
class KDNodeData {
    let point: [Float]
    let text: String
    var left: KDNodeData?
    var right: KDNodeData?
    let splitDim: Int
    
    init(point: [Float], text: String, left: KDNodeData? = nil, right: KDNodeData? = nil, splitDim: Int) {
        self.point = point
        self.text = text
        self.left = left
        self.right = right
        self.splitDim = splitDim
    }
}

// Result for K-Nearest Neighbors
struct KNNResult {
    let node: KDNodeData
    let distanceSq: Float
}

class VectorDB {
    // Core database structures
    private let dimension: Int
    private var root: KDNodeData?
    private var tokens: [Token] = []
    private var totalDocs: Int = 0
    private var size: Int = 0
    
    init(dimension: Int) {
        self.dimension = dimension
    }
    
    // Validate token (similar to C implementation)
    private func isValidToken(_ token: String) -> Bool {
        let invalidTokens = ["pancake", "author", "radare2"]
        return !invalidTokens.contains(token)
    }
    
    // Find a token in the token list
    private func findToken(_ tokens: [Token], _ token: String) -> Token? {
        return tokens.first { $0.token == token }
    }
    
    // Compute embedding using TF-IDF approach
    private func computeEmbedding(_ text: String) -> [Float] {
        // Zero the embedding vector
        var embedding = [Float](repeating: 0.0, count: dimension)
        
        // Tokenize and normalize
        let words = text
            .lowercased()
            .replacingOccurrences(of: "[^a-z0-9\\s]", with: " ", options: .regularExpression)
            .split(separator: " ")
            .map { String($0) }
            .filter { !$0.isEmpty }
        
        // Local document token frequency
        var docTokens: [Token] = []
        for token in words {
            if let existingToken = findToken(docTokens, token) {
                let index = docTokens.firstIndex { $0.token == token }!
                docTokens[index].count += 1
            } else {
                docTokens.append(Token(token: token, count: 1, df: 0))
            }
        }
        
        // Increment total documents
        totalDocs += 1
        
        // Update global document frequencies
        for docToken in docTokens {
            if let globalToken = findToken(self.tokens, docToken.token) {
                if isValidToken(docToken.token) {
                    let index = self.tokens.firstIndex { $0.token == docToken.token }!
                    self.tokens[index].count += 1
                    self.tokens[index].df += 1
                }
            } else {
                self.tokens.append(Token(token: docToken.token, count: docToken.count, df: 1))
            }
        }
        
        // Compute TF-IDF and update embedding
        for docToken in docTokens {
            // Compute term frequency
            let tf = 1 + log(Float(docToken.count))
            
            // Find global token to get document frequency
            let dfValue = findToken(self.tokens, docToken.token)?.df ?? 1
            
            // Compute inverse document frequency
            let idf = log(Float(totalDocs + 1) / Float(dfValue + 1)) + 1
            
            // Compute weight
            let weight = tf * idf
            
            // Hash-based index assignment
            let hash = simpleHash(docToken.token)
            let index = hash % dimension
            
            // Add weighted value to embedding
            embedding[index] += weight
        }
        
        // L2 Normalize the embedding
        return normalizeVector(embedding)
    }
    
    // Simple string hash function
    private func simpleHash(_ str: String) -> Int {
        var hash = 0
        for char in str.unicodeScalars {
            hash = ((hash << 5) - hash) + Int(char.value)
            hash = hash & hash // Convert to 32-bit integer
        }
        return abs(hash)
    }
    
    // Normalize vector to unit length
    private func normalizeVector(_ vec: [Float]) -> [Float] {
        let normSq = vec.reduce(0) { $0 + $1 * $1 }
        if normSq > 0 {
            let norm = sqrt(normSq)
            return vec.map { $0 / norm }
        }
        return vec
    }
    
    // Compute squared Euclidean distance
    private func squaredDistance(_ a: [Float], _ b: [Float]) -> Float {
        guard a.count == b.count else { return Float.greatestFiniteMagnitude }
        return zip(a, b).reduce(0) { $0 + pow($1.0 - $1.1, 2) }
    }
    
    // Recursive KD-Tree insertion
    private func insertRecursive(_ node: KDNodeData?, point: [Float], text: String, depth: Int) -> KDNodeData {
        guard let currentNode = node else {
            return KDNodeData(point: point, text: text, splitDim: depth % dimension)
        }
        
        let axis = currentNode.splitDim
        if point[axis] < currentNode.point[axis] {
            currentNode.left = insertRecursive(currentNode.left, point: point, text: text, depth: depth + 1)
        } else {
            currentNode.right = insertRecursive(currentNode.right, point: point, text: text, depth: depth + 1)
        }
        
        return currentNode
    }
    
    // Insert a document into the vector database
    func insert(_ text: String) {
        guard !text.isEmpty else { return }
        
        // Compute embedding
        let embedding = computeEmbedding(text)
        
        // Insert into KD-Tree
        root = insertRecursive(root, point: embedding, text: text, depth: 0)
        size += 1
    }
    
    // K-Nearest Neighbors search
    func query(_ text: String, k: Int) -> [String] {
        guard !text.isEmpty, root != nil else { return [] }
        
        // Compute query embedding
        let queryEmbedding = computeEmbedding(text)
        
        // Initialize result set
        var results: [KNNResult] = []
        
        // Recursive KNN search
        func searchRecursive(_ node: KDNodeData?, query: [Float], depth: Int) {
            guard let node = node else { return }
            
            // Compute distance and potentially insert into results
            let distSq = squaredDistance(query, node.point)
            
            if results.count < k {
                results.append(KNNResult(node: node, distanceSq: distSq))
                // Maintain max-heap property
                results.sort { $0.distanceSq > $1.distanceSq }
            } else if distSq < results[0].distanceSq {
                results[0] = KNNResult(node: node, distanceSq: distSq)
                results.sort { $0.distanceSq > $1.distanceSq }
            }
            
            // Decide which subtree to search first
            let axis = node.splitDim
            let diff = query[axis] - node.point[axis]
            let first = diff < 0 ? node.left : node.right
            let second = diff < 0 ? node.right : node.left
            
            // Recursively search
            searchRecursive(first, query: query, depth: depth + 1)
            
            // Potentially search the other subtree
            if results.count < k || diff * diff < results[0].distanceSq {
                searchRecursive(second, query: query, depth: depth + 1)
            }
        }
        
        // Perform the search
        searchRecursive(root, query: queryEmbedding, depth: 0)
        
        // Sort results and return texts
        return results
            .sorted { $0.distanceSq < $1.distanceSq }
            .map { $0.node.text }
    }
    
    // Get total number of documents
    func getSize() -> Int {
        return size
    }
}

// Example usage
func main() {
    // Create a vector database with 64-dimensional embeddings
    let db = VectorDB(dimension: 64)
    
    // Insert some sample documents
    db.insert("The quick brown fox jumps over the lazy dog")
    db.insert("A quick brown fox is very quick")
    db.insert("The author of radare2 is name / named pancake")
    db.insert("The lazy dog sleeps all day")
    
    // Query for similar documents
    let results = db.query("who is the author of radare2?", k: 2)
    print("Similar documents:", results)
}

// Run example
main()
