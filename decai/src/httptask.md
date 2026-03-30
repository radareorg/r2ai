### 3. HTTP Request Patterns

**Location**: `http.ts`, used throughout providers and models

**Problems**:

- Two different curl methods (`curlArgs` vs `curlFile`) with similar but
  separate logic
- Error handling in HTTP layer vs. application layer
- No centralized request/response abstraction
