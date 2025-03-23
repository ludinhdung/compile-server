const express = require('express');
const Docker = require('dockerode');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const { PassThrough } = require('stream');

const app = express();
const docker = new Docker();

const cors = require('cors');
app.use(cors());

const languageConfigs = {
    java: {
        image: 'openjdk:11',
        sourceFileName: 'Main.java',
        programFileName: 'Main',
        workingDir: '/work',
        commandTemplate: ['javac', '$SOURCE'],
        executeCommandTemplate: ['java', '-cp', '/work', 'Main'],
        timeout: 5000,
        memory: 256 * 1024 * 1024,
        cpuQuota: 50000,
        maxOutputSize: 1024 * 100,
    },
    javascript: {
        image: 'node:18',
        sourceFileName: 'main.js',
        programFileName: 'main.js',
        workingDir: '/work',
        commandTemplate: [], 
        executeCommandTemplate: ['node', '--max-old-space-size=200', '--max-http-header-size=8192', '--no-warnings', '$SOURCE'],
        timeout: 5000,
        memory: 256 * 1024 * 1024,
        cpuQuota: 50000,
        maxOutputSize: 1024 * 100,
    },
    python: {
        image: 'python:3.9',
        sourceFileName: 'main.py',
        programFileName: 'main.py',
        workingDir: '/work',
        commandTemplate: ['python', '-m', 'py_compile', '$SOURCE'],
        executeCommandTemplate: ['python', '-u', '$SOURCE'],
        timeout: 5000,
        memory: 256 * 1024 * 1024,
        cpuQuota: 50000,
        maxOutputSize: 1024 * 100,
    }
};

app.use(express.json());

function getStream(container, maxOutputSize = 1024 * 100) {
    return new Promise((resolve, reject) => {
        const stdoutChunks = [];
        const stderrChunks = [];
        let totalOutputSize = 0;
        let outputLimitExceeded = false;

        container.attach({ stream: true, stdout: true, stderr: true }, (err, stream) => {
            if (err) return reject(err);

            const stdout = new PassThrough();
            const stderr = new PassThrough();

            container.modem.demuxStream(stream, stdout, stderr);

            stdout.on('data', (chunk) => {
                if (totalOutputSize + chunk.length <= maxOutputSize) {
                    stdoutChunks.push(chunk);
                    totalOutputSize += chunk.length;
                } else if (!outputLimitExceeded) {
                    const truncationMessage = Buffer.from('\n[Output truncated due to size limit]');
                    stdoutChunks.push(truncationMessage);
                    outputLimitExceeded = true;
                    
                    try {
                        container.kill().catch(e => console.error('Failed to kill container:', e));
                    } catch (e) {
                        console.error('Error killing container on output limit exceeded:', e);
                    }
                }
            });

            stderr.on('data', (chunk) => {
                if (totalOutputSize + chunk.length <= maxOutputSize) {
                    stderrChunks.push(chunk);
                    totalOutputSize += chunk.length;
                } else if (!outputLimitExceeded) {
                    const truncationMessage = Buffer.from('\n[Error output truncated due to size limit]');
                    stderrChunks.push(truncationMessage);
                    outputLimitExceeded = true;
                }
            });

            stream.on('end', () => {
                resolve({
                    stdout: Buffer.concat(stdoutChunks).toString(),
                    stderr: Buffer.concat(stderrChunks).toString(),
                    truncated: outputLimitExceeded
                });
            });

            stream.on('error', reject);
        });
    });
}

async function pullImage(imageName) {
    console.log(`Pulling image ${imageName}...`);
    return new Promise((resolve, reject) => {
        docker.pull(imageName, (err, stream) => {
            if (err) return reject(err);

            docker.modem.followProgress(stream, (err, output) => {
                if (err) return reject(err);
                console.log(`Image ${imageName} pulled successfully`);
                resolve();
            });
        });
    });
}

async function runCompileContainer(language, hostWorkingDir, sourceFileName, programFileName) {
    const config = languageConfigs[language];
    const workingDir = config.workingDir;
    const containerSourceFilePath = path.posix.join(workingDir, sourceFileName);
    const containerProgramFilePath = path.posix.join(workingDir, programFileName);

    const command = config.commandTemplate.map(cmd =>
        cmd === '$SOURCE' ? containerSourceFilePath :
            cmd === '$PROGRAM' ? containerProgramFilePath : cmd
    );

    console.log(`Creating container for ${language} with command:`, command);

    const container = await docker.createContainer({
        Image: config.image,
        WorkingDir: workingDir,
        Cmd: command,
        AttachStdout: true,
        AttachStderr: true,
        HostConfig: {
            Binds: [`${hostWorkingDir}:${workingDir}`],
            Resources: { Memory: config.memory, CpuQuota: config.cpuQuota },
            NetworkMode: 'none',
        },
        Tty: false
    });

    try {
        await container.start();
        const logs = await getStream(container);
        const executionTimeout = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Compilation timed out')), config.timeout)
        );

        const containerData = await Promise.race([container.wait(), executionTimeout]);

        return {
            statusCode: containerData.StatusCode,
            stdout: logs.stdout,
            stderr: logs.stderr,
            programFilePath: path.join(hostWorkingDir, programFileName)
        };
    } catch (error) {
        console.error(`Error in container execution for ${language}:`, error);
        throw error;
    } finally {
        await container.remove({ force: true }).catch(() => { });
    }
}

// Add code scanner to check for potentially dangerous code
async function scanForDangerousCode(language, code) {
    const dangers = [];
    
    // Common dangerous patterns across languages
    const dangerousPatterns = {
        all: [
            { pattern: /while\s*\(\s*true\s*\)/g, message: "Infinite loop detected (while(true))" },
            { pattern: /for\s*\(\s*;\s*;\s*\)/g, message: "Infinite loop detected (for(;;))" },
            { pattern: /while\s*\(\s*1\s*\)/g, message: "Infinite loop detected (while(1))" },
        ],
        javascript: [
            { pattern: /process\.exit/g, message: "Process termination attempt detected" },
            { pattern: /require\s*\(\s*['"](?:fs|child_process|http|net|os|path|crypto)['"]|import\s+.*from\s+['"](?:fs|child_process|http|net|os|path|crypto)['"]/g, message: "Attempt to import restricted modules" },
            { pattern: /eval\s*\(/g, message: "Potentially unsafe eval() usage detected" },
            { pattern: /setTimeout\s*\(\s*.*,\s*(?:999999|[0-9]{7,})\s*\)/g, message: "Very long timeout detected" },
        ],
        python: [
            { pattern: /import\s+(?:os|sys|subprocess|shutil|socket|urllib|requests|pty)/g, message: "Attempt to import restricted modules" },
            { pattern: /open\s*\(/g, message: "File operations are restricted" },
            { pattern: /exec\s*\(/g, message: "Potentially unsafe exec() usage detected" },
            { pattern: /eval\s*\(/g, message: "Potentially unsafe eval() usage detected" },
        ],
        java: [
            { pattern: /Runtime\.getRuntime\(\)/g, message: "Runtime access is restricted" },
            { pattern: /ProcessBuilder|Process/g, message: "Process execution is restricted" },
            { pattern: /System\.exit/g, message: "System exit attempt detected" },
            { pattern: /\.readLine|FileReader|FileInputStream|FileOutputStream/g, message: "File operations are restricted" },
        ]
    };
    
    // Check common patterns for all languages
    dangerousPatterns.all.forEach(({pattern, message}) => {
        if (pattern.test(code)) {
            dangers.push(message);
        }
    });
    
    // Check language-specific patterns
    if (dangerousPatterns[language]) {
        dangerousPatterns[language].forEach(({pattern, message}) => {
            if (pattern.test(code)) {
                dangers.push(message);
            }
        });
    }
    
    return dangers;
}

// Create source file with size limits
async function createSourceFile(hostWorkingDir, sourceFileName, content) {
    // Check file size limits
    const MAX_CODE_SIZE = 64 * 1024; // 64KB max code size
    if (content.length > MAX_CODE_SIZE) {
        throw new Error(`Code size exceeds the maximum allowed size of ${MAX_CODE_SIZE / 1024}KB`);
    }
    
    // Ensure the directory exists
    try {
        await fs.mkdir(hostWorkingDir, { recursive: true });
    } catch (err) {
        console.error(`Error creating directory ${hostWorkingDir}:`, err);
    }

    const sourceFilePath = path.join(hostWorkingDir, sourceFileName);
    console.log(`Creating source file at ${sourceFilePath}`);

    try {
        await fs.writeFile(sourceFilePath, content);

        // Verify file was created and show its content for debugging
        const stats = await fs.stat(sourceFilePath);
        console.log(`File created: ${sourceFilePath}, size: ${stats.size} bytes`);

        const fileContent = await fs.readFile(sourceFilePath, 'utf8');
        console.log(`File content (first 100 chars): ${fileContent.substring(0, 100)}...`);

        return sourceFilePath;
    } catch (err) {
        console.error(`Error writing to file ${sourceFilePath}:`, err);
        throw err;
    }
}

// Compile code with additional security checks
async function compileCode(language, content) {
    if (!languageConfigs[language]) {
        throw new Error(`Unsupported language: ${language}`);
    }

    // Scan for potentially dangerous code
    const dangers = await scanForDangerousCode(language, content);
    if (dangers.length > 0) {
        return {
            success: false,
            stdout: '',
            stderr: `Security check failed:\n${dangers.join('\n')}`,
            warnings: dangers
        };
    }

    const uniqueId = uuidv4().substring(0, 8);
    const hostWorkingDir = path.join(os.tmpdir(), `compile-${uniqueId}`);
    console.log(`Created working directory: ${hostWorkingDir}`);

    const config = languageConfigs[language];

    try {
        const sourceFilePath = await createSourceFile(
            hostWorkingDir,
            config.sourceFileName,
            content
        );

        if (language === 'python') {
            return {
                success: true,
                programFilePath: sourceFilePath,
                stdout: '',
                stderr: ''
            };
        }

        const compileResult = await runCompileContainer(
            language,
            hostWorkingDir,
            config.sourceFileName,
            config.programFileName
        );

        if (compileResult.statusCode !== 0) {
            console.log(`Compilation failed with status code ${compileResult.statusCode}`);
            console.log(`STDERR: ${compileResult.stderr}`);
            console.log(`STDOUT: ${compileResult.stdout}`);

            return {
                success: false,
                stdout: compileResult.stdout,
                stderr: compileResult.stderr
            };
        }

        console.log(`Compilation succeeded. Program file: ${compileResult.programFilePath}`);
        return {
            success: true,
            programFilePath: compileResult.programFilePath,
            stdout: compileResult.stdout,
            stderr: compileResult.stderr
        };
    } catch (error) {
        console.error('Error during compilation:', error);
        try {
            await fs.rm(hostWorkingDir, { recursive: true, force: true });
        } catch (cleanupError) {
            console.error('Failed to clean up working directory:', cleanupError);
        }
        throw error;
    }
}

// Run compiled program with additional security
async function runProgram(language, programFilePath) {
    const config = languageConfigs[language];
    const hostWorkingDir = path.dirname(programFilePath);
    const programFileName = path.basename(programFilePath);

    const command = config.executeCommandTemplate.map(cmd =>
        cmd === '$SOURCE' ? path.posix.join(config.workingDir, config.sourceFileName) :
            cmd === '$PROGRAM' ? path.posix.join(config.workingDir, programFileName) : 
            cmd === '$PROGRAM_PATH' ? path.posix.join(config.workingDir, programFileName) : cmd
    );

    console.log(`Running program with command:`, command);

    const container = await docker.createContainer({
        Image: config.image,
        WorkingDir: config.workingDir,
        Cmd: command,
        AttachStdout: true,
        AttachStderr: true,
        HostConfig: {
            Binds: [`${hostWorkingDir}:${config.workingDir}`],
            Resources: { 
                Memory: config.memory, 
                CpuQuota: config.cpuQuota,
                PidsLimit: 50,  // Limit number of processes
            },
            NetworkMode: 'none',  // No network access
            ReadonlyRootfs: true, // Read-only filesystem
            SecurityOpt: ['no-new-privileges'],  // Prevent privilege escalation
        },
        Tty: false
    });

    // Set a shorter kill timeout
    const killTimeout = setTimeout(() => {
        console.log('Force killing container due to execution timeout');
        try {
            container.kill().catch(e => console.error('Failed to force kill container:', e));
        } catch (e) {
            console.error('Error force killing container:', e);
        }
    }, config.timeout + 1000); // Extra 1s grace period

    try {
        await container.start();
        
        // Start a monitoring process
        const monitorInterval = setInterval(async () => {
            try {
                const stats = await container.stats({ stream: false });
                const cpuUsage = stats.cpu_stats.cpu_usage.total_usage;
                const memUsage = stats.memory_stats.usage;
                
                console.log(`Container stats - CPU: ${cpuUsage}, Memory: ${memUsage}`);
                
                // If CPU is pegged at nearly 100% for extended time, it might be an infinite loop
                if (cpuUsage > 0.95 * config.cpuQuota) {
                    console.log('High CPU usage detected, possible infinite loop');
                }
            } catch (e) {
                // Container might have already exited
                clearInterval(monitorInterval);
            }
        }, 1000);
        
        const logs = await getStream(container, config.maxOutputSize);
        const executionTimeout = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Execution timed out')), config.timeout)
        );

        const containerData = await Promise.race([container.wait(), executionTimeout]);
        
        // Clean up monitoring
        clearInterval(monitorInterval);
        clearTimeout(killTimeout);

        return {
            statusCode: containerData.StatusCode,
            stdout: logs.stdout,
            stderr: logs.stderr,
            truncated: logs.truncated
        };
    } catch (error) {
        clearTimeout(killTimeout);
        console.error('Error running program:', error);
        
        if (error.message.includes('timed out')) {
            return {
                statusCode: 124, // SIGTERM timeout status code
                stdout: '',
                stderr: 'Execution timed out. Your code may contain an infinite loop.',
                truncated: false
            };
        }
        
        throw error;
    } finally {
        await container.remove({ force: true }).catch(() => { });
    }
}

// Initialize by pulling images
async function initializeImages() {
    for (const language of Object.keys(languageConfigs)) {
        try {
            await pullImage(languageConfigs[language].image);
        } catch (error) {
            console.error(`Failed to pull image for ${language}:`, error);
        }
    }
}

initializeImages().catch(console.error);

app.post('/api/compile', async (req, res) => {
    try {
        const { language, code } = req.body;

        if (!language || !code) {
            return res.status(400).json({ error: 'Both language and code are required' });
        }

        const lang = language.toLowerCase();
        if (!languageConfigs[lang]) {
            return res.status(400).json({ 
                error: `Unsupported language: ${language}. Supported languages are: java, javascript, python` 
            });
        }

        // Check code length directly here too
        if (code.length > 64 * 1024) {
            return res.status(400).json({
                success: false,
                output: null,
                error: `Code size exceeds the maximum allowed size of 64KB`
            });
        }

        console.log(`Processing ${language} compilation request`);

        const compileResult = await compileCode(lang, code);

        // If there are warnings but compilation succeeded, include them in response
        if (compileResult.warnings && compileResult.warnings.length > 0) {
            return res.json({
                success: false,
                output: null,
                error: compileResult.stderWr || compileResult.stdout,
                warnings: compileResult.warnings
            });
        }

        if (!compileResult.success) {
            return res.json({
                success: false,
                output: null,
                error: compileResult.stderr || compileResult.stdout
            });
        }

        const runResult = await runProgram(lang, compileResult.programFilePath);

        const hostWorkingDir = path.dirname(compileResult.programFilePath);
        await fs.rm(hostWorkingDir, { recursive: true, force: true }).catch(err => {
            console.error('Failed to clean up working directory:', err);
        });

        if (runResult.statusCode !== 0) {
            return res.json({
                success: false,
                output: runResult.stdout,
                error: runResult.stderr,
                truncated: runResult.truncated
            });
        }

        return res.json({
            success: true,
            output: runResult.stdout,
            error: null,
            truncated: runResult.truncated
        });
    } catch (error) {
        console.error('Error handling compilation request:', error);
        return res.status(500).json({
            success: false,
            output: null,
            error: `Server error: ${error.message}`
        });
    }
});

app.get('/api/health', async (req, res) => {
    try {
        await docker.ping();
        res.json({ status: 'healthy', docker: true });
    } catch (error) {
        res.status(500).json({ status: 'unhealthy', error: error.message, docker: false });
    }
});

app.get('/api/languages', (req, res) => {
    const languages = {};
    
    for (const [lang, config] of Object.entries(languageConfigs)) {
        languages[lang] = {
            sourceFileExtension: path.extname(config.sourceFileName),
            timeout: config.timeout,
            memory: config.memory / (1024 * 1024), // Convert to MB for readability
            cpuQuota: config.cpuQuota
        };
    }
    
    res.json({
        languages,
        count: Object.keys(languages).length
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Code compilation API server running on port ${PORT}`);
});

module.exports = app;