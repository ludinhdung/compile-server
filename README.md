# Code Compiler API

A Node.js API for compiling and executing code in sandboxed Docker containers with enhanced security.

## Deployment

### Requirements
- Docker
- Docker Compose (recommended)

### Using Docker Compose (Recommended)
1. Clone the repository
2. Run the following command:
```bash
docker-compose up -d
```

### Using Docker directly
1. Clone the repository
2. Build the Docker image:
```bash
docker build -t code-compiler -f DockerFile .
```
3. Run the container:
```bash
docker run -d --name code-compiler \
  -p 3000:3000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /tmp:/tmp \
  --restart unless-stopped \
  code-compiler
```

### Important Notes
- The application requires access to the Docker socket (`/var/run/docker.sock`) to create containers for code execution
- The `/tmp` directory is mounted to allow for temporary file operations

## Supported Languages

- **Python**: Python 3.9
- **JavaScript**: Node.js 18
- **Java**: OpenJDK 11

## API Endpoints

### 1. `/api/compile`

Compiles and executes code with security checks.

**Request Body:**
```json
{
  "language": "python",
  "code": "print('Hello, World!')"
}
```

**Response:**
```json
{
  "success": true,
  "output": "Hello, World!",
  "error": null,
  "truncated": false
}
```

### 2. `/api/languages`

Lists supported languages and configurations.

### 3. `/api/health`

Checks if the API is healthy.

## Security Features

The API includes several security measures to protect against malicious code:

1. **Code Scanning**: Detects and blocks potentially harmful patterns such as:
   - Infinite loops (`while(true)`, `for(;;)`, etc.)
   - File system operations
   - Process execution
   - System access
   - Network access
   - Unsafe eval

2. **Resource Limits**:
   - Memory: 256MB per container
   - CPU: 50% of a CPU core
   - Execution time: 5 seconds
   - Output size: 100KB
   - Maximum code size: 64KB

3. **Container Isolation**:
   - Read-only filesystem
   - No network access
   - Process limits
   - Privilege restrictions

4. **Monitoring**:
   - Automatic killing of containers exceeding limits
   - CPU usage monitoring to detect infinite loops
   - Output truncation for excessive output

## Sample Code for Languages

### Python
```python
print("Hello, World!")
```

### Java
```java
public class Main {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

### JavaScript
```javascript
console.log("Hello, World!");
```

## Testing with Postman

Import the `postman_samples.json` file into Postman to test the API.

## Implementation Notes

- All executions are sandboxed in Docker containers with strict resource limits
- Security checks run before code execution to prevent harmful code from running
- Container security is enforced using Docker's security options
- Output is monitored and truncated if it exceeds limits #   c o m p i l e - s e r v e r 
 
