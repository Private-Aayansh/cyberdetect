// Cyber Detect - Standalone JavaScript Application
// Advanced Security Log Analysis Platform

// Global State Management
const AppState = {
    theme: localStorage.getItem('cyberdetect-theme') || 'light',
    selectedFile: null,
    allResults: [],
    scanResults: {},
    isScanning: {},
    dynamicAnalyses: [],
    currentView: 'overview',
    filters: {
        attackType: '',
        statusCode: '',
        ip: '',
        dateRange: '',
        severity: '',
        search: '',
        method: ''
    },
    aiConfig: {
        provider: 'gemini',
        apiKey: '',
        customEndpoint: ''
    },
    parsedEntries: []
};

// Attack Types Configuration
const ATTACK_TYPES = [
    {
        name: 'SQL Injection',
        description: 'Attempts to inject malicious SQL code into database queries',
        severity: 'high',
        color: '#DC2626',
        endpoint: 'sql-injection'
    },
    {
        name: 'Path Traversal',
        description: 'Attempts to access files outside the web root directory',
        severity: 'high',
        color: '#EA580C',
        endpoint: 'path-traversal'
    },
    {
        name: 'Bot Detection',
        description: 'Automated bot and crawler activity detection',
        severity: 'medium',
        color: '#CA8A04',
        endpoint: 'bots'
    },
    {
        name: 'LFI/RFI Attacks',
        description: 'Local and Remote File Inclusion attack attempts',
        severity: 'high',
        color: '#DC2626',
        endpoint: 'lfi-rfi'
    },
    {
        name: 'WordPress Probes',
        description: 'WordPress-specific vulnerability scanning attempts',
        severity: 'medium',
        color: '#7C3AED',
        endpoint: 'wp-probe'
    },
    {
        name: 'Brute Force',
        description: 'Password brute force and credential stuffing attacks',
        severity: 'high',
        color: '#B91C1C',
        endpoint: 'brute-force'
    },
    {
        name: 'HTTP Errors',
        description: 'Suspicious HTTP error patterns and responses',
        severity: 'low',
        color: '#059669',
        endpoint: 'errors'
    },
    {
        name: 'Internal IP Access',
        description: 'Unauthorized access attempts to internal IP ranges',
        severity: 'medium',
        color: '#0284C7',
        endpoint: 'internal-ip'
    }
];

// LLM Providers Configuration
const LLM_PROVIDERS = [
    {
        id: 'gemini',
        name: 'Google Gemini',
        description: 'Google\'s Gemini AI model',
        requiresApiKey: true,
        apiKeyLink: 'https://makersuite.google.com/app/apikey'
    },
    {
        id: 'openai',
        name: 'OpenAI GPT',
        description: 'OpenAI\'s GPT models',
        requiresApiKey: true,
        apiKeyLink: 'https://platform.openai.com/api-keys'
    },
    {
        id: 'anthropic',
        name: 'Anthropic Claude',
        description: 'Anthropic\'s Claude models',
        requiresApiKey: true,
        apiKeyLink: 'https://console.anthropic.com/account/keys'
    },
    {
        id: 'aipipe',
        name: 'AIPipe',
        description: 'AIPipe.org API service',
        requiresApiKey: true,
        customEndpoint: true,
        defaultEndpoint: 'https://aipipe.org/openrouter/v1/chat/completions',
        apiKeyLink: 'https://aipipe.org/'
    },
    {
        id: 'custom',
        name: 'Custom Endpoint',
        description: 'Custom OpenAI-compatible API endpoint',
        requiresApiKey: true,
        customEndpoint: true
    }
];

// Utility Functions
const Utils = {
    // Generate unique ID
    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    },

    // Format file size
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Format date
    formatDate(dateString) {
        return new Date(dateString).toLocaleString();
    },

    // Debounce function
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Download file
    downloadFile(content, filename, contentType) {
        const blob = new Blob([content], { type: contentType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    },

    // Copy to clipboard
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            return false;
        }
    },

    // Escape HTML
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// Toast Notification System
const Toast = {
    container: null,

    init() {
        this.container = document.getElementById('toast-container');
    },

    show(message, type = 'info', duration = 5000) {
        const toast = document.createElement('div');
        toast.className = `toast ${type} text-white p-4 rounded-lg shadow-lg flex items-center space-x-3 min-w-80 max-w-md animate-slide-in`;
        
        const icon = this.getIcon(type);
        toast.innerHTML = `
            <i class="${icon} flex-shrink-0"></i>
            <p class="flex-1 text-sm font-medium">${Utils.escapeHtml(message)}</p>
            <button class="toast-close p-1 hover:bg-white/20 rounded transition-colors">
                <i class="fas fa-times text-sm"></i>
            </button>
        `;

        // Add close functionality
        toast.querySelector('.toast-close').addEventListener('click', () => {
            this.remove(toast);
        });

        this.container.appendChild(toast);

        // Auto remove after duration
        if (duration > 0) {
            setTimeout(() => {
                this.remove(toast);
            }, duration);
        }

        return toast;
    },

    getIcon(type) {
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-times-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };
        return icons[type] || icons.info;
    },

    remove(toast) {
        if (toast && toast.parentNode) {
            toast.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }
    },

    success(message, duration) {
        return this.show(message, 'success', duration);
    },

    error(message, duration) {
        return this.show(message, 'error', duration);
    },

    warning(message, duration) {
        return this.show(message, 'warning', duration);
    },

    info(message, duration) {
        return this.show(message, 'info', duration);
    }
};

// Theme Management
const ThemeManager = {
    init() {
        this.applyTheme(AppState.theme);
        this.bindEvents();
    },

    applyTheme(theme) {
        AppState.theme = theme;
        localStorage.setItem('cyberdetect-theme', theme);
        
        if (theme === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    },

    toggle() {
        const newTheme = AppState.theme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
    },

    bindEvents() {
        document.getElementById('theme-toggle').addEventListener('click', () => {
            this.toggle();
        });
    }
};

// Log Parser
const LogParser = {
    parseLogFile(content) {
        const lines = content.split('\n');
        const parsed = [];
        
        // Apache/Nginx combined log format pattern
        const logPattern = /(?<ip>\S+) - - \[(?<timestamp>.*?)\] "(?<method>\S+) (?<path>\S+) (?<protocol>[^"]+)" (?<status>\d{3}) (?<bytes>\S+) "(?<referrer>[^"]*)" "(?<user_agent>[^"]*)" (?<host>\S+) (?<server_ip>\S+)/;

        for (const line of lines) {
            const match = line.match(logPattern);
            if (match && match.groups) {
                parsed.push({
                    ip: match.groups.ip,
                    timestamp: this.parseTimestamp(match.groups.timestamp),
                    method: match.groups.method,
                    path: match.groups.path,
                    protocol: match.groups.protocol,
                    status: match.groups.status,
                    bytes: match.groups.bytes,
                    referrer: match.groups.referrer,
                    user_agent: match.groups.user_agent,
                    host: match.groups.host,
                    server_ip: match.groups.server_ip
                });
            }
        }

        return parsed;
    },

    parseTimestamp(timestamp) {
        try {
            // Parse common log format timestamp: DD/MMM/YYYY:HH:MM:SS TIMEZONE
            const match = timestamp.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})/);
            if (!match) {
                return timestamp;
            }
            
            const [, day, monthName, year, hour, minute, second, timezone] = match;
            
            // Convert month name to number
            const monthMap = {
                'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
            };
            
            const month = monthMap[monthName];
            if (!month) {
                return timestamp;
            }
            
            // Create ISO format string
            const isoString = `${year}-${month}-${day}T${hour}:${minute}:${second}${timezone}`;
            
            // Validate the date
            const date = new Date(isoString);
            if (isNaN(date.getTime())) {
                return timestamp;
            }
            
            return date.toISOString();
        } catch {
            return timestamp;
        }
    }
};

// Security Detectors
const SecurityDetectors = {
    // SQL Injection Detector
    detectSqlInjection(entries) {
        const patterns = [
            // Union-based injections
            "union\\s+(all\\s+)?select",
            "select\\s+.*\\s+from",
            "select\\s+\\*",
            
            // Boolean-based blind injections
            "(and|or)\\s+\\d+\\s*[=<>!]+\\s*\\d+",
            "(and|or)\\s+['\"]?[a-z]+['\"]?\\s*[=<>!]+\\s*['\"]?[a-z]+['\"]?",
            "(and|or)\\s+\\d+\\s*(and|or)\\s+\\d+",
            
            // Time-based blind injections
            "(sleep|waitfor|delay)\\s*\\(\\s*\\d+\\s*\\)",
            "benchmark\\s*\\(\\s*\\d+",
            "pg_sleep\\s*\\(\\s*\\d+\\s*\\)",
            
            // Error-based injections
            "(convert|cast|char)\\s*\\(",
            "concat\\s*\\(",
            "group_concat\\s*\\(",
            "having\\s+\\d+\\s*[=<>!]+\\s*\\d+",
            
            // Authentication bypass
            "(admin|user|login)['\"]?\\s*(=|like)\\s*['\"]?\\s*(or|and)",
            "['\"]\\s*(or|and)\\s*['\"]?[^'\"]*['\"]?\\s*(=|like)",
            "['\"]\\s*(or|and)\\s*\\d+\\s*[=<>!]+\\s*\\d+",
            
            // SQL commands and functions
            "(drop|delete|truncate|insert|update)\\s+(table|from|into)",
            "(exec|execute|sp_|xp_)\\w*",
            "(information_schema|sys\\.|mysql\\.|pg_)",
            "(load_file|into\\s+outfile|dumpfile)",
            
            // Comment patterns
            "(--|#|\\*/|\\*\\*)",
            "/\\*.*\\*/",
            
            // Special characters and encodings
            "(%27|%22|%2d%2d|%23)",
            "(0x[0-9a-f]+)",
            "(char\\s*\\(\\s*\\d+)"
        ];
        
        const sqliRegex = new RegExp(
            patterns.map(pattern => `(${pattern})`).join('|'),
            'gim'
        );
        
        const suspicious = entries.filter(entry => {
            if (!entry.path) return false;
            const decodedPath = decodeURIComponent(entry.path);
            return sqliRegex.test(decodedPath);
        });
        
        return suspicious.map(entry => ({
            ...entry,
            suspicion_reason: 'SQL injection pattern detected',
            attack_type: 'SQL Injection'
        }));
    },

    // Path Traversal Detector
    detectPathTraversal(entries) {
        const suspicious = entries.filter(entry => {
            const path = entry.path;
            if (!path) return false;

            // Check for path traversal patterns
            const hasTraversalPattern = new RegExp('(\\.\\./|%2e%2e%2f|%2e%2f|%2f\\.\\.|/\\.{2})', 'i').test(path);
            
            // Check for excessive directory depth
            const hasExcessiveDepth = (path.match(/\//g) || []).length > 15;
            
            return hasTraversalPattern || hasExcessiveDepth;
        });

        return suspicious.map(entry => ({
            ...entry,
            suspicion_reason: 'Path traversal pattern detected',
            attack_type: 'Path Traversal'
        }));
    },

    // Bot Detection
    detectBots(entries) {
        const CRAWLERS = [
            'googlebot', 'bingbot', 'baiduspider', 'yandexbot',
            'duckduckbot', 'slurp', 'facebookexternalhit', 'twitterbot',
            'applebot', 'linkedinbot', 'petalbot', 'semrushbot'
        ];

        const CLIENT_LIBS = [
            'curl', 'wget', 'httpclient', 'python-requests', 'aiohttp',
            'okhttp', 'java/', 'libwww-perl', 'go-http-client', 'restsharp',
            'scrapy', 'httpie'
        ];

        function classifyUserAgent(ua) {
            const userAgent = ua.toLowerCase();
            
            if (CRAWLERS.some(crawler => userAgent.includes(crawler))) {
                return "Crawler Bot";
            }
            
            if (CLIENT_LIBS.some(lib => userAgent.includes(lib))) {
                return "Client Library Bot";
            }
            
            if (userAgent.trim() === '' || userAgent.length < 10 || !userAgent.includes('mozilla')) {
                return "Suspicious User-Agent";
            }
            
            return null;
        }

        const bots = entries.filter(entry => {
            const botType = classifyUserAgent(entry.user_agent);
            return botType !== null;
        });

        return bots.map(entry => ({
            ...entry,
            suspicion_reason: classifyUserAgent(entry.user_agent) || 'Bot detected',
            attack_type: 'Bot Detection'
        }));
    },

    // LFI/RFI Detector
    detectLfiRfi(entries) {
        const pattern = /(etc\/passwd|proc\/self\/environ|input_file=|data:text)/i;

        const suspicious = entries.filter(entry => {
            return pattern.test(entry.path);
        });

        return suspicious.map(entry => ({
            ...entry,
            suspicion_reason: 'LFI/RFI pattern detected',
            attack_type: 'LFI/RFI Attacks'
        }));
    },

    // WordPress Probe Detector
    detectWpProbe(entries) {
        const pattern = /(\.php|\/wp-|xmlrpc\.php|\?author=|\?p=)/i;

        const suspicious = entries.filter(entry => {
            return pattern.test(entry.path);
        });

        return suspicious.map(entry => ({
            ...entry,
            suspicion_reason: 'WordPress probe detected',
            attack_type: 'WordPress Probes'
        }));
    },

    // Brute Force Detector
    detectBruteForce(entries) {
        const loginPattern = /(login|admin|signin|wp-login\.php)/i;
        const badStatuses = ['401', '403', '429'];

        const suspicious = entries.filter(entry => {
            return loginPattern.test(entry.path) && badStatuses.includes(entry.status);
        });

        return suspicious.map(entry => ({
            ...entry,
            suspicion_reason: 'Brute force attempt detected',
            attack_type: 'Brute Force'
        }));
    },

    // HTTP Error Detector
    detectErrors(entries) {
        const badStatuses = ['403', '404', '406', '500', '502'];

        const errors = entries.filter(entry => {
            return badStatuses.includes(entry.status);
        });

        return errors.map(entry => ({
            ...entry,
            suspicion_reason: `HTTP error status: ${entry.status}`,
            attack_type: 'HTTP Errors'
        }));
    },

    // Internal IP Detector
    detectInternalIp(entries) {
        const internal = entries.filter(entry => {
            const ip = entry.ip;
            return ip.startsWith('192.168.') ||
                   ip.startsWith('10.') ||
                   ip.startsWith('127.') ||
                   ip.startsWith('172.');
        });

        return internal.map(entry => ({
            ...entry,
            suspicion_reason: 'Internal IP address detected',
            attack_type: 'Internal IP Access'
        }));
    },

    // Get detector by endpoint
    getDetector(endpoint) {
        const detectorMap = {
            'sql-injection': this.detectSqlInjection,
            'path-traversal': this.detectPathTraversal,
            'bots': this.detectBots,
            'lfi-rfi': this.detectLfiRfi,
            'wp-probe': this.detectWpProbe,
            'brute-force': this.detectBruteForce,
            'errors': this.detectErrors,
            'internal-ip': this.detectInternalIp
        };
        return detectorMap[endpoint];
    }
};

// LLM Service for AI Analysis
const LLMService = {
    async makeGeminiRequest(prompt, apiKey, options = {}) {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                contents: [{
                    parts: [{
                        text: prompt
                    }]
                }],
                generationConfig: {
                    temperature: options.temperature || 0.7,
                    topK: 40,
                    topP: 0.95,
                    maxOutputTokens: options.maxTokens || 2048,
                },
                safetySettings: [
                    {
                        category: "HARM_CATEGORY_HARASSMENT",
                        threshold: "BLOCK_MEDIUM_AND_ABOVE"
                    },
                    {
                        category: "HARM_CATEGORY_HATE_SPEECH",
                        threshold: "BLOCK_MEDIUM_AND_ABOVE"
                    },
                    {
                        category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        threshold: "BLOCK_MEDIUM_AND_ABOVE"
                    },
                    {
                        category: "HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold: "BLOCK_MEDIUM_AND_ABOVE"
                    }
                ]
            })
        });

        if (!response.ok) {
            throw new Error(`Gemini API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        if (!data.candidates || data.candidates.length === 0) {
            throw new Error('No response from Gemini API');
        }

        return {
            text: data.candidates[0].content.parts[0].text,
            usage: data.usageMetadata ? {
                promptTokens: data.usageMetadata.promptTokenCount,
                completionTokens: data.usageMetadata.candidatesTokenCount,
                totalTokens: data.usageMetadata.totalTokenCount,
            } : undefined,
        };
    },

    async makeOpenAIRequest(prompt, apiKey, options = {}, endpoint) {
        const baseUrl = endpoint || 'https://api.openai.com/v1';
        const response = await fetch(`${baseUrl}/chat/completions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
            },
            body: JSON.stringify({
                model: 'gpt-3.5-turbo',
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                max_tokens: options.maxTokens || 2048,
                temperature: options.temperature || 0.7,
            })
        });

        if (!response.ok) {
            throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        if (!data.choices || data.choices.length === 0) {
            throw new Error('No response from OpenAI API');
        }

        return {
            text: data.choices[0].message.content,
            usage: data.usage ? {
                promptTokens: data.usage.prompt_tokens,
                completionTokens: data.usage.completion_tokens,
                totalTokens: data.usage.total_tokens,
            } : undefined,
        };
    },

    async makeAnthropicRequest(prompt, apiKey, options = {}) {
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify({
                model: 'claude-3-sonnet-20240229',
                max_tokens: options.maxTokens || 2048,
                temperature: options.temperature || 0.7,
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ]
            })
        });

        if (!response.ok) {
            throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        if (!data.content || data.content.length === 0) {
            throw new Error('No response from Anthropic API');
        }

        return {
            text: data.content[0].text,
            usage: data.usage ? {
                promptTokens: data.usage.input_tokens,
                completionTokens: data.usage.output_tokens,
                totalTokens: data.usage.input_tokens + data.usage.output_tokens,
            } : undefined,
        };
    },

    async makeAIPipeRequest(prompt, apiKey, options = {}) {
        const aipipeEndpoint = 'https://aipipe.org/openrouter/v1/chat/completions';
        
        const response = await fetch(aipipeEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
            },
            body: JSON.stringify({
                model: 'openai/gpt-4o-mini',
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                max_tokens: options.maxTokens || 2048,
                temperature: options.temperature || 0.7,
            })
        });

        if (!response.ok) {
            throw new Error(`AIPipe API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        
        // Handle different response formats
        let text = '';
        if (data.choices && data.choices.length > 0) {
            text = data.choices[0].message?.content || data.choices[0].text || '';
        } else if (data.response) {
            text = data.response;
        } else if (data.text) {
            text = data.text;
        } else {
            throw new Error('Unexpected response format from AIPipe API');
        }

        return {
            text,
            usage: data.usage ? {
                promptTokens: data.usage.prompt_tokens,
                completionTokens: data.usage.completion_tokens,
                totalTokens: data.usage.total_tokens,
            } : undefined,
        };
    },

    async generateResponse(providerId, prompt, apiKey, endpoint, options = {}) {
        const requestOptions = {
            prompt,
            maxTokens: options.maxTokens || 2048,
            temperature: options.temperature || 0.7,
        };

        switch (providerId) {
            case 'gemini':
                return this.makeGeminiRequest(prompt, apiKey, requestOptions);
            
            case 'openai':
                return this.makeOpenAIRequest(prompt, apiKey, requestOptions);
            
            case 'anthropic':
                return this.makeAnthropicRequest(prompt, apiKey, requestOptions);
            
            case 'aipipe':
                return this.makeAIPipeRequest(prompt, apiKey, requestOptions);
            
            case 'custom':
                if (!endpoint) {
                    throw new Error('Custom endpoint URL is required');
                }
                return this.makeOpenAIRequest(prompt, apiKey, requestOptions, endpoint);
            
            default:
                throw new Error(`Unsupported LLM provider: ${providerId}`);
        }
    }
};

// File Processing Service
const FileProcessor = {
    async processFile(file) {
        if (file.name.endsWith('.zip')) {
            return await this.processZipFile(file);
        } else if (file.name.endsWith('.gz')) {
            return await this.processGzFile(file);
        } else {
            return await this.processTextFile(file);
        }
    },

    async processZipFile(file) {
        try {
            const zip = await JSZip.loadAsync(file);
            const firstFile = Object.keys(zip.files)[0];
            if (firstFile) {
                const decompressedFile = zip.file(firstFile);
                if (decompressedFile) {
                    const content = await decompressedFile.async('text');
                    return {
                        name: decompressedFile.name,
                        content: content,
                        size: content.length
                    };
                }
            }
            throw new Error('No files found in ZIP archive');
        } catch (error) {
            throw new Error('Failed to extract ZIP file: ' + error.message);
        }
    },

    async processGzFile(file) {
        try {
            const arrayBuffer = await file.arrayBuffer();
            const compressedData = new Uint8Array(arrayBuffer);
            const decompressedData = pako.inflate(compressedData);
            const content = new TextDecoder().decode(decompressedData);
            const newFileName = file.name.replace(/\.gz$/, '');
            
            return {
                name: newFileName,
                content: content,
                size: content.length
            };
        } catch (error) {
            throw new Error('Failed to decompress GZ file: ' + error.message);
        }
    },

    async processTextFile(file) {
        try {
            const content = await file.text();
            return {
                name: file.name,
                content: content,
                size: content.length
            };
        } catch (error) {
            throw new Error('Failed to read text file: ' + error.message);
        }
    }
};

// Analysis Service
const AnalysisService = {
    async analyzeWithDetector(detectorEndpoint) {
        if (!AppState.parsedEntries.length) {
            throw new Error('No log data loaded');
        }

        const detector = SecurityDetectors.getDetector(detectorEndpoint);
        if (!detector) {
            throw new Error(`Unknown detector: ${detectorEndpoint}`);
        }

        const results = detector.call(SecurityDetectors, AppState.parsedEntries);
        
        // Convert to ProcessedLogEntry format
        const processedResults = results.map(entry => ({
            ip: entry.ip,
            timestamp: entry.timestamp,
            method: entry.method,
            path: entry.path,
            protocol: entry.protocol,
            status: parseInt(entry.status, 10),
            bytes: parseInt(entry.bytes === '-' ? '0' : entry.bytes, 10),
            referrer: entry.referrer,
            user_agent: entry.user_agent,
            host: entry.host,
            server_ip: entry.server_ip,
            suspicion_reason: entry.suspicion_reason || '',
            attack_type: entry.attack_type || 'Unknown'
        }));

        return processedResults;
    },

    async runAllAnalyses() {
        const results = {};
        
        for (const attackType of ATTACK_TYPES) {
            try {
                AppState.isScanning[attackType.name] = true;
                UI.updateScanButton(attackType.name, true);
                
                const analysisResults = await this.analyzeWithDetector(attackType.endpoint);
                results[attackType.name] = analysisResults;
                
                AppState.scanResults[attackType.name] = analysisResults;
                AppState.allResults = AppState.allResults.filter(r => r.attack_type !== attackType.name);
                AppState.allResults.push(...analysisResults);
                
                UI.updateAttackCard(attackType.name, analysisResults.length, false, true);
                
                Toast.success(`${attackType.name}: ${analysisResults.length} threats found`);
            } catch (error) {
                console.error(`Analysis failed for ${attackType.name}:`, error);
                Toast.error(`Failed to analyze ${attackType.name}`);
            } finally {
                AppState.isScanning[attackType.name] = false;
                UI.updateScanButton(attackType.name, false);
            }
        }
        
        UI.updateExportButtons();
        UI.updateDashboard();
        
        return results;
    },

    async createDynamicAnalysis(description) {
        const config = AppState.aiConfig;
        
        if (!this.canAnalyze(config)) {
            throw new Error('Please configure your AI provider settings');
        }

        const prompt = `
You are a cybersecurity expert. I need you to generate JavaScript code that analyzes web server log entries to detect specific security threats.

User Request: "${description}"

Please generate a JavaScript function that:
1. Takes an array of parsed log entries as input
2. Analyzes each entry to detect the specific threat described
3. Returns an array of suspicious entries with a suspicion_reason field

Each log entry has this structure:
{
  ip: string,
  timestamp: string,
  method: string,
  path: string,
  protocol: string,
  status: string,
  bytes: string,
  referrer: string,
  user_agent: string,
  host: string,
  server_ip: string
}

Requirements:
- Return ONLY the JavaScript function code, no explanations
- Function should be named 'detectThreats'
- Function should take 'entries' parameter (array of log entries)
- Return array of entries that match the threat pattern
- Add 'suspicion_reason' field to each returned entry explaining why it's suspicious
- Use regex patterns, string matching, and logical conditions as appropriate
- Be specific and accurate in detection logic
- Handle edge cases and avoid false positives

Example format:
function detectThreats(entries) {
  return entries.filter(entry => {
    // Your detection logic here
    if (/* condition */) {
      entry.suspicion_reason = "Reason for suspicion";
      return true;
    }
    return false;
  });
}
`;

        try {
            const response = await LLMService.generateResponse(
                config.provider,
                prompt,
                config.apiKey,
                config.customEndpoint,
                {
                    temperature: 0.3,
                    maxTokens: 1024,
                }
            );

            // Extract the function code from the response
            let functionCode = response.text.trim();
            
            // Clean up the response - remove markdown code blocks if present
            functionCode = functionCode.replace(/^```javascript\s*\n?/i, '');
            functionCode = functionCode.replace(/^```js\s*\n?/i, '');
            functionCode = functionCode.replace(/^```\s*\n?/i, '');
            functionCode = functionCode.replace(/\n?```\s*$/i, '');
            functionCode = functionCode.trim();
            
            // Validate that we have a function
            if (!functionCode.includes('function detectThreats')) {
                throw new Error('Generated code does not contain the required detectThreats function');
            }

            // Create a unique ID for this analysis
            const id = `dynamic-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            
            // Generate a name from the description
            const name = this.generateAnalysisName(description);

            const analysis = {
                id,
                name,
                description,
                functionCode,
                createdAt: new Date().toISOString(),
            };

            // Store the analysis
            AppState.dynamicAnalyses.push(analysis);

            return analysis;
        } catch (error) {
            console.error('Dynamic analysis creation failed:', error);
            throw new Error(`Failed to create analysis: ${error.message}`);
        }
    },

    async runDynamicAnalysis(analysisId) {
        const analysis = AppState.dynamicAnalyses.find(a => a.id === analysisId);
        if (!analysis) {
            throw new Error('Analysis not found');
        }

        if (!AppState.parsedEntries.length) {
            throw new Error('No log data loaded');
        }

        try {
            // Create a safe execution environment
            const safeEval = new Function('entries', `
                ${analysis.functionCode}
                return detectThreats(entries);
            `);

            // Execute the generated function
            const results = safeEval(AppState.parsedEntries);

            // Validate results
            if (!Array.isArray(results)) {
                throw new Error('Analysis function must return an array');
            }

            // Convert to ProcessedLogEntry format
            return results.map(entry => ({
                ip: entry.ip,
                timestamp: entry.timestamp,
                method: entry.method,
                path: entry.path,
                protocol: entry.protocol,
                status: parseInt(entry.status, 10),
                bytes: parseInt(entry.bytes === '-' ? '0' : entry.bytes, 10),
                referrer: entry.referrer,
                user_agent: entry.user_agent,
                host: entry.host,
                server_ip: entry.server_ip,
                suspicion_reason: entry.suspicion_reason || 'Custom analysis match',
                attack_type: analysis.name,
            }));
        } catch (error) {
            console.error('Analysis execution failed:', error);
            throw new Error(`Failed to execute analysis: ${error.message}`);
        }
    },

    generateAnalysisName(description) {
        // Extract key terms and create a concise name
        const words = description.toLowerCase()
            .replace(/[^\w\s]/g, ' ')
            .split(/\s+/)
            .filter(word => word.length > 2)
            .filter(word => !['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use'].includes(word));

        // Take first few meaningful words and capitalize
        const nameWords = words.slice(0, 3).map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        );

        return nameWords.join(' ') + ' Analysis';
    },

    canAnalyze(config) {
        const provider = LLM_PROVIDERS.find(p => p.id === config.provider);
        if (!provider) return false;

        // Check if API key is required and provided
        if (provider.requiresApiKey && !config.apiKey.trim()) {
            return false;
        }

        // Check if custom endpoint is required and provided (except for aipipe)
        if (provider.customEndpoint && config.provider === 'custom' && !config.customEndpoint?.trim()) {
            return false;
        }

        return true;
    }
};

// Report Generation Service
const ReportService = {
    async generateReport(allResults, summary, datasetUrl, fileName, config) {
        if (!this.canGenerateReport(config)) {
            throw new Error('Invalid report configuration');
        }

        const reportData = this.prepareReportData(allResults, summary, fileName, datasetUrl);
        const prompt = this.buildReportPrompt(reportData);

        try {
            const response = await LLMService.generateResponse(
                config.provider,
                prompt,
                config.apiKey,
                config.customEndpoint,
                {
                    temperature: 0.3,
                    maxTokens: 4000,
                }
            );

            // Clean up the response to remove markdown code block fences
            let cleanedText = response.text.trim();
            
            // Remove markdown code block delimiters if present
            cleanedText = cleanedText.replace(/^```markdown\s*\n?/i, '');
            cleanedText = cleanedText.replace(/^```\s*\n?/i, '');
            cleanedText = cleanedText.replace(/\n?```\s*$/i, '');
            
            // Remove any leading/trailing whitespace after cleanup
            cleanedText = cleanedText.trim();
            
            return cleanedText;
        } catch (error) {
            console.error('Report generation failed:', error);
            throw new Error(`Failed to generate report: ${error.message}`);
        }
    },

    prepareReportData(allResults, summary, fileName, datasetUrl) {
        // Get top attack types
        const topAttackTypes = Object.entries(summary.attackTypeCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 10);

        // Get recent attacks (last 24 hours if timestamps are available)
        const now = new Date();
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const recentAttacks = allResults.filter(entry => {
            const entryDate = new Date(entry.timestamp);
            return entryDate >= oneDayAgo;
        });

        // Get most targeted paths
        const pathCounts = {};
        allResults.forEach(entry => {
            pathCounts[entry.path] = (pathCounts[entry.path] || 0) + 1;
        });
        const topPaths = Object.entries(pathCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 10);

        // Get attack methods distribution
        const methodCounts = {};
        allResults.forEach(entry => {
            methodCounts[entry.method] = (methodCounts[entry.method] || 0) + 1;
        });

        return {
            fileName: fileName || 'Unknown',
            datasetUrl: datasetUrl || 'Unknown',
            totalThreats: summary.totalThreats,
            uniqueAttackers: summary.topAttackers.length,
            analysisDate: new Date().toISOString(),
            topAttackTypes,
            topAttackers: summary.topAttackers.slice(0, 10),
            recentAttacks: recentAttacks.length,
            topPaths,
            methodCounts: Object.entries(methodCounts).sort(([, a], [, b]) => b - a),
            statusCodeDistribution: summary.statusCodeDistribution,
            timelineData: summary.timelineData,
            criticalFindings: this.identifyCriticalFindings(allResults, summary),
        };
    },

    identifyCriticalFindings(allResults, summary) {
        const findings = [];

        // High-severity attack types with significant activity
        const highSeverityTypes = ['SQL Injection', 'Path Traversal', 'LFI/RFI Attacks', 'Brute Force'];
        highSeverityTypes.forEach(type => {
            const count = summary.attackTypeCounts[type] || 0;
            if (count > 10) {
                findings.push({
                    severity: 'HIGH',
                    type,
                    count,
                    description: `Significant ${type.toLowerCase()} activity detected`
                });
            }
        });

        // Top attackers with high activity
        summary.topAttackers.slice(0, 3).forEach(attacker => {
            if (attacker.count > 50) {
                findings.push({
                    severity: 'HIGH',
                    type: 'Persistent Attacker',
                    count: attacker.count,
                    description: `IP ${attacker.ip} shows persistent attack behavior`
                });
            }
        });

        // High error rates
        const errorCodes = ['403', '404', '500', '502'];
        const totalErrors = errorCodes.reduce((sum, code) => sum + (summary.statusCodeDistribution[code] || 0), 0);
        if (totalErrors > allResults.length * 0.3) {
            findings.push({
                severity: 'MEDIUM',
                type: 'High Error Rate',
                count: totalErrors,
                description: 'Unusually high number of HTTP errors detected'
            });
        }

        return findings;
    },

    buildReportPrompt(data) {
        return `
You are a cybersecurity analyst. Generate a comprehensive security analysis report in Markdown format based on the following log analysis data:

**Analysis Overview:**
- File: ${data.fileName}
- Dataset: ${data.datasetUrl}
- Analysis Date: ${new Date(data.analysisDate).toLocaleString()}
- Total Threats Detected: ${data.totalThreats}
- Unique Attackers: ${data.uniqueAttackers}
- Recent Activity (24h): ${data.recentAttacks} threats

**Attack Type Distribution:**
${data.topAttackTypes.map(([type, count]) => `- ${type}: ${count} incidents`).join('\n')}

**Top Attackers:**
${data.topAttackers.map((attacker) => `- ${attacker.ip}: ${attacker.count} attempts`).join('\n')}

**Most Targeted Paths:**
${data.topPaths.map(([path, count]) => `- ${path}: ${count} requests`).join('\n')}

**HTTP Methods:**
${data.methodCounts.map(([method, count]) => `- ${method}: ${count} requests`).join('\n')}

**Status Code Distribution:**
${Object.entries(data.statusCodeDistribution).map(([code, count]) => `- ${code}: ${count} responses`).join('\n')}

**Critical Findings:**
${data.criticalFindings.map((finding) => `- [${finding.severity}] ${finding.description} (${finding.count} incidents)`).join('\n')}

Please generate a professional security analysis report in Markdown format that includes:

1. **Executive Summary** - High-level overview of security posture and key findings
2. **Threat Landscape Analysis** - Detailed analysis of attack types and patterns
3. **Attacker Profile Analysis** - Analysis of attacker behavior and origins
4. **Vulnerability Assessment** - Most targeted areas and potential vulnerabilities
5. **Risk Assessment** - Risk levels and potential impact
6. **Recommendations** - Specific actionable security recommendations
7. **Incident Response** - Immediate actions needed
8. **Monitoring and Prevention** - Long-term security improvements

Use proper Markdown formatting with headers, bullet points, tables where appropriate, and emphasis for important findings. Be specific, professional, and actionable in your recommendations.
`;
    },

    canGenerateReport(config) {
        if (!config.provider || !config.apiKey.trim()) {
            return false;
        }
        return true;
    }
};

// UI Management
const UI = {
    init() {
        this.bindEvents();
        this.initializeViews();
        this.updateAIProviderLinks();
    },

    bindEvents() {
        // Navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const view = e.currentTarget.dataset.view;
                this.switchView(view);
            });
        });

        // File upload
        const fileInput = document.getElementById('file-input');
        const fileUploadArea = document.getElementById('file-upload-area');

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFileSelect(e.target.files[0]);
            }
        });

        // Drag and drop
        fileUploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileUploadArea.classList.add('file-upload-drag');
        });

        fileUploadArea.addEventListener('dragleave', (e) => {
            e.preventDefault();
            fileUploadArea.classList.remove('file-upload-drag');
        });

        fileUploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            fileUploadArea.classList.remove('file-upload-drag');
            
            const files = Array.from(e.dataTransfer.files);
            if (files.length > 0) {
                this.handleFileSelect(files[0]);
            }
        });

        // Demo dataset
        document.getElementById('load-demo-btn').addEventListener('click', () => {
            this.loadDemoDataset();
        });

        // Run all scans
        document.getElementById('run-all-btn').addEventListener('click', () => {
            this.runAllScans();
        });

        // Export buttons
        document.getElementById('export-csv-btn').addEventListener('click', () => {
            this.exportData('csv');
        });

        document.getElementById('export-json-btn').addEventListener('click', () => {
            this.exportData('json');
        });

        document.getElementById('generate-report-btn').addEventListener('click', () => {
            this.openReportModal();
        });

        // AI Configuration
        document.getElementById('ai-config-toggle').addEventListener('click', () => {
            this.toggleAIConfig();
        });

        document.getElementById('ai-provider-select').addEventListener('change', (e) => {
            AppState.aiConfig.provider = e.target.value;
            this.updateAIProviderLinks();
            this.updateCustomEndpointVisibility();
            this.updateAIWarning();
        });

        document.getElementById('ai-api-key').addEventListener('input', (e) => {
            AppState.aiConfig.apiKey = e.target.value;
            this.updateAIWarning();
        });

        document.getElementById('custom-endpoint').addEventListener('input', (e) => {
            AppState.aiConfig.customEndpoint = e.target.value;
            this.updateAIWarning();
        });

        // Dynamic Analysis
        document.getElementById('dynamic-analysis-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.createDynamicAnalysis();
        });

        // Example prompts
        document.querySelectorAll('.example-prompt').forEach(button => {
            button.addEventListener('click', (e) => {
                const prompt = e.currentTarget.dataset.prompt;
                document.getElementById('analysis-description').value = prompt;
            });
        });

        // Modal events
        this.bindModalEvents();
    },

    bindModalEvents() {
        // Details Modal
        document.getElementById('close-modal').addEventListener('click', () => {
            this.closeModal('details-modal');
        });

        // Function Modal
        document.getElementById('close-function-modal').addEventListener('click', () => {
            this.closeModal('function-modal');
        });

        document.getElementById('close-function-modal-footer').addEventListener('click', () => {
            this.closeModal('function-modal');
        });

        document.getElementById('copy-function-btn').addEventListener('click', () => {
            this.copyFunctionCode();
        });

        // Report Modal
        document.getElementById('close-report-modal').addEventListener('click', () => {
            this.closeModal('report-modal');
        });

        document.getElementById('report-config-toggle').addEventListener('click', () => {
            this.toggleReportConfig();
        });

        document.getElementById('generate-report-final-btn').addEventListener('click', () => {
            this.generateReport();
        });

        // Report provider configuration
        document.getElementById('report-ai-provider-select').addEventListener('change', (e) => {
            this.updateReportProviderConfig(e.target.value);
        });

        // Report tabs
        document.getElementById('report-tab-preview').addEventListener('click', () => {
            this.switchReportTab('preview');
        });

        document.getElementById('report-tab-markdown').addEventListener('click', () => {
            this.switchReportTab('markdown');
        });

        // Report actions
        document.getElementById('copy-report-btn').addEventListener('click', () => {
            this.copyReport();
        });

        document.getElementById('download-md-btn').addEventListener('click', () => {
            this.downloadReport('md');
        });

        document.getElementById('download-html-btn').addEventListener('click', () => {
            this.downloadReport('html');
        });

        // Close modals on backdrop click
        document.querySelectorAll('.fixed.inset-0').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.add('hidden');
                }
            });
        });
    },

    initializeViews() {
        this.switchView('overview');
    },

    switchView(viewName) {
        // Update navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-view="${viewName}"]`).classList.add('active');

        // Update content
        document.querySelectorAll('.view-content').forEach(view => {
            view.classList.remove('active');
        });
        document.getElementById(`${viewName}-view`).classList.add('active');

        AppState.currentView = viewName;

        // Update view-specific content
        if (viewName === 'dashboard') {
            this.updateDashboard();
        } else if (viewName === 'data') {
            this.updateDataTable();
        }
    },

    async handleFileSelect(file) {
        try {
            AppState.selectedFile = file;
            
            // Show file info
            document.getElementById('file-name').textContent = file.name;
            document.getElementById('file-size').textContent = Utils.formatFileSize(file.size);
            document.getElementById('selected-file-info').classList.remove('hidden');
            
            // Process file
            const processedFile = await FileProcessor.processFile(file);
            
            // Parse log content
            AppState.parsedEntries = LogParser.parseLogFile(processedFile.content);
            
            // Clear previous results
            AppState.allResults = [];
            AppState.scanResults = {};
            
            // Show attack types section
            document.getElementById('attack-types-section').classList.remove('hidden');
            
            // Generate attack cards
            this.generateAttackCards();
            
            Toast.success(`File "${file.name}" loaded successfully. Found ${AppState.parsedEntries.length} log entries.`);
        } catch (error) {
            console.error('File processing failed:', error);
            Toast.error(`Failed to process file: ${error.message}`);
        }
    },

    async loadDemoDataset() {
        const loadBtn = document.getElementById('load-demo-btn');
        const originalContent = loadBtn.innerHTML;
        
        try {
            loadBtn.innerHTML = '<div class="spinner mr-2"></div><span>Loading...</span>';
            loadBtn.disabled = true;
            
            Toast.info('Downloading demo dataset...');
            
            // Fetch the demo file
            const response = await fetch('https://raw.githubusercontent.com/Yadav-Aayansh/gramener-datasets/refs/heads/add-server-logs/server_logs.zip');
            
            if (!response.ok) {
                throw new Error(`Failed to fetch demo dataset: ${response.statusText}`);
            }
            
            const blob = await response.blob();
            const file = new File([blob], 'server_logs.zip', { type: 'application/zip' });
            
            await this.handleFileSelect(file);
        } catch (error) {
            console.error('Failed to load demo dataset:', error);
            Toast.error(`Failed to load demo dataset: ${error.message}`);
        } finally {
            loadBtn.innerHTML = originalContent;
            loadBtn.disabled = false;
        }
    },

    generateAttackCards() {
        const grid = document.getElementById('attack-cards-grid');
        grid.innerHTML = '';

        ATTACK_TYPES.forEach(attackType => {
            const card = this.createAttackCard(attackType);
            grid.appendChild(card);
        });
    },

    createAttackCard(attackType) {
        const card = document.createElement('div');
        card.className = 'attack-card bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-200 hover:-translate-y-1 border border-gray-200 dark:border-gray-700 flex flex-col h-full';
        card.dataset.attackType = attackType.name;

        const severityClass = `severity-${attackType.severity}`;
        const iconClass = this.getSeverityIcon(attackType.severity);

        card.innerHTML = `
            <div class="flex items-start justify-between mb-4">
                <div class="flex items-center space-x-3">
                    <div class="p-2 rounded-lg" style="background-color: ${attackType.color}20">
                        <i class="${iconClass}" style="color: ${attackType.color}"></i>
                    </div>
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                            ${attackType.name}
                        </h3>
                        <span class="${severityClass} inline-block px-2 py-1 rounded-full text-xs font-medium">
                            ${attackType.severity.toUpperCase()}
                        </span>
                    </div>
                </div>
                <div class="text-right">
                    <div class="threat-count text-2xl font-bold text-gray-900 dark:text-white">
                        0
                    </div>
                    <div class="text-xs text-gray-500 dark:text-gray-400">
                        instances
                    </div>
                </div>
            </div>

            <p class="text-sm text-gray-600 dark:text-gray-300 mb-4">
                ${attackType.description}
            </p>

            <div class="space-y-2 mt-auto">
                <button class="scan-btn w-full flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors">
                    <i class="fas fa-play"></i>
                    <span>Scan</span>
                </button>
                
                <button class="view-results-btn w-full flex items-center justify-center space-x-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors hidden">
                    <i class="fas fa-eye"></i>
                    <span>View Results (<span class="result-count">0</span>)</span>
                </button>
                
                <button class="view-function-btn w-full flex items-center justify-center space-x-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors">
                    <i class="fas fa-code"></i>
                    <span>View Function</span>
                </button>
            </div>
        `;

        // Bind events
        const scanBtn = card.querySelector('.scan-btn');
        const viewResultsBtn = card.querySelector('.view-results-btn');
        const viewFunctionBtn = card.querySelector('.view-function-btn');

        scanBtn.addEventListener('click', () => {
            this.runSingleScan(attackType);
        });

        viewResultsBtn.addEventListener('click', () => {
            this.viewAttackResults(attackType.name);
        });

        viewFunctionBtn.addEventListener('click', () => {
            this.viewAttackFunction(attackType.name);
        });

        return card;
    },

    getSeverityIcon(severity) {
        const icons = {
            high: 'fas fa-exclamation-triangle',
            medium: 'fas fa-shield-alt',
            low: 'fas fa-info-circle'
        };
        return icons[severity] || icons.medium;
    },

    async runSingleScan(attackType) {
        if (!AppState.parsedEntries.length) {
            Toast.error('Please load a log file first');
            return;
        }

        AppState.isScanning[attackType.name] = true;
        this.updateScanButton(attackType.name, true);

        try {
            const results = await AnalysisService.analyzeWithDetector(attackType.endpoint);
            
            AppState.scanResults[attackType.name] = results;
            
            // Update all results
            AppState.allResults = AppState.allResults.filter(r => r.attack_type !== attackType.name);
            AppState.allResults.push(...results);
            
            this.updateAttackCard(attackType.name, results.length, false, true);
            this.updateExportButtons();
            
            Toast.success(`${attackType.name} scan completed: ${results.length} threats found`);
        } catch (error) {
            console.error('Scan failed:', error);
            Toast.error(`Failed to scan for ${attackType.name}`);
        } finally {
            AppState.isScanning[attackType.name] = false;
            this.updateScanButton(attackType.name, false);
        }
    },

    async runAllScans() {
        if (!AppState.parsedEntries.length) {
            Toast.error('Please load a log file first');
            return;
        }

        const runAllBtn = document.getElementById('run-all-btn');
        const originalContent = runAllBtn.innerHTML;
        
        runAllBtn.innerHTML = '<div class="spinner mr-2"></div><span>Running Scans...</span>';
        runAllBtn.disabled = true;

        Toast.info('Starting comprehensive security scan...');
        
        try {
            await AnalysisService.runAllAnalyses();
            
            const totalThreats = AppState.allResults.length;
            Toast.success(`Comprehensive scan completed! Found ${totalThreats} total threats across ${ATTACK_TYPES.length} attack types`);
        } catch (error) {
            console.error('Batch scan failed:', error);
            Toast.error('Failed to complete all scans');
        } finally {
            runAllBtn.innerHTML = originalContent;
            runAllBtn.disabled = false;
        }
    },

    updateScanButton(attackType, isLoading) {
        const card = document.querySelector(`[data-attack-type="${attackType}"]`);
        if (!card) return;

        const scanBtn = card.querySelector('.scan-btn');
        if (isLoading) {
            scanBtn.innerHTML = '<div class="spinner mr-2"></div><span>Scanning...</span>';
            scanBtn.disabled = true;
        } else {
            const hasResults = AppState.scanResults[attackType]?.length > 0;
            scanBtn.innerHTML = hasResults ? 
                '<i class="fas fa-check-circle mr-2"></i><span>Rescan</span>' :
                '<i class="fas fa-play mr-2"></i><span>Scan</span>';
            scanBtn.disabled = false;
        }
    },

    updateAttackCard(attackType, count, isLoading, hasResults) {
        const card = document.querySelector(`[data-attack-type="${attackType}"]`);
        if (!card) return;

        const threatCount = card.querySelector('.threat-count');
        const viewResultsBtn = card.querySelector('.view-results-btn');
        const resultCount = card.querySelector('.result-count');

        threatCount.textContent = isLoading ? '...' : count.toLocaleString();
        
        if (hasResults && count > 0) {
            viewResultsBtn.classList.remove('hidden');
            resultCount.textContent = count;
        } else {
            viewResultsBtn.classList.add('hidden');
        }
    },

    updateExportButtons() {
        const exportButtons = document.getElementById('export-buttons');
        if (AppState.allResults.length > 0) {
            exportButtons.classList.remove('hidden');
        } else {
            exportButtons.classList.add('hidden');
        }
    },

    viewAttackResults(attackType) {
        const results = AppState.scanResults[attackType] || [];
        this.openDetailsModal(attackType, results);
    },

    viewAttackFunction(attackType) {
        // Check if it's a custom analysis
        const customAnalysis = AppState.dynamicAnalyses.find(a => a.name === attackType);
        if (customAnalysis) {
            this.openFunctionModal(
                customAnalysis.name,
                customAnalysis.functionCode,
                customAnalysis.description,
                true
            );
        } else {
            // It's a built-in detector
            const builtInFunction = this.getBuiltInDetectorCode(attackType);
            if (builtInFunction) {
                this.openFunctionModal(
                    builtInFunction.name,
                    builtInFunction.code,
                    builtInFunction.description,
                    false
                );
            }
        }
    },

    getBuiltInDetectorCode(attackType) {
        const detectorMap = {
            'SQL Injection': {
                name: 'SQL Injection Detector',
                description: 'Advanced SQL injection detection using pattern matching for union-based, boolean-based, time-based, and error-based attacks.',
                code: `function detectSqlInjection(entries) {
  const patterns = [
    // Union-based injections
    "union\\\\s+(all\\\\s+)?select",
    "select\\\\s+.*\\\\s+from",
    "select\\\\s+\\\\*",
    
    // Boolean-based blind injections
    "(and|or)\\\\s+\\\\d+\\\\s*[=<>!]+\\\\s*\\\\d+",
    "(and|or)\\\\s+['\\\\\\\"]?[a-z]+['\\\\\\\"]?\\\\s*[=<>!]+\\\\s*['\\\\\\\"]?[a-z]+['\\\\\\\"]?",
    "(and|or)\\\\s+\\\\d+\\\\s*(and|or)\\\\s+\\\\d+",
    
    // Time-based blind injections
    "(sleep|waitfor|delay)\\\\s*\\\\(\\\\s*\\\\d+\\\\s*\\\\)",
    "benchmark\\\\s*\\\\(\\\\s*\\\\d+",
    "pg_sleep\\\\s*\\\\(\\\\s*\\\\d+\\\\s*\\\\)",
    
    // Error-based injections
    "(convert|cast|char)\\\\s*\\\\(",
    "concat\\\\s*\\\\(",
    "group_concat\\\\s*\\\\(",
    "having\\\\s+\\\\d+\\\\s*[=<>!]+\\\\s*\\\\d+",
    
    // Authentication bypass
    "(admin|user|login)['\\\\\\\"]?\\\\s*(=|like)\\\\s*['\\\\\\\"]?\\\\s*(or|and)",
    "['\\\\\\\"]\\\\s*(or|and)\\\\s*['\\\\\\\"]?[^'\\\\\\\\"]*['\\\\\\\"]?\\\\s*(=|like)",
    "['\\\\\\\"]\\\\s*(or|and)\\\\s*\\\\d+\\\\s*[=<>!]+\\\\s*\\\\d+",
    
    // SQL commands and functions
    "(drop|delete|truncate|insert|update)\\\\s+(table|from|into)",
    "(exec|execute|sp_|xp_)\\\\w*",
    "(information_schema|sys\\\\.|mysql\\\\.|pg_)",
    "(load_file|into\\\\s+outfile|dumpfile)",
    
    // Comment patterns
    "(--|#|\\\\*/|\\\\*\\\\*)",
    "/\\\\*.*\\\\*/",
    
    // Special characters and encodings
    "(%27|%22|%2d%2d|%23)",
    "(0x[0-9a-f]+)",
    "(char\\\\s*\\\\(\\\\s*\\\\d+)",
  ];
  
  const sqliRegex = new RegExp(
    patterns.map(pattern => \`(\${pattern})\`).join('|'),
    'gim'
  );
  
  const suspicious = entries.filter(entry => {
    if (!entry.path) return false;
    const decodedPath = decodeURIComponent(entry.path);
    return sqliRegex.test(decodedPath);
  });
  
  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'SQL injection pattern detected'
  }));
}`
            },
            'Path Traversal': {
                name: 'Path Traversal Detector',
                description: 'Detects directory traversal attempts and excessive path depth patterns.',
                code: `function detectPathTraversal(entries) {
  const suspicious = entries.filter(entry => {
    const path = entry.path;
    if (!path) return false;

    // Check for path traversal patterns
    const hasTraversalPattern = new RegExp('(\\\\.\\\\./|%2e%2e%2f|%2e%2f|%2f\\\\.\\\\.|/\\\\.{2})', 'i').test(path);
    
    // Check for excessive directory depth
    const hasExcessiveDepth = (path.match(/\\//g) || []).length > 15;
    
    return hasTraversalPattern || hasExcessiveDepth;
  });

  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'Path traversal pattern detected'
  }));
}`
            },
            'Bot Detection': {
                name: 'Bot Detection Function',
                description: 'Identifies automated bots, crawlers, and suspicious user agents.',
                code: `function detectBots(entries) {
  const CRAWLERS = [
    'googlebot', 'bingbot', 'baiduspider', 'yandexbot',
    'duckduckbot', 'slurp', 'facebookexternalhit', 'twitterbot',
    'applebot', 'linkedinbot', 'petalbot', 'semrushbot'
  ];

  const CLIENT_LIBS = [
    'curl', 'wget', 'httpclient', 'python-requests', 'aiohttp',
    'okhttp', 'java/', 'libwww-perl', 'go-http-client', 'restsharp',
    'scrapy', 'httpie'
  ];

  function classifyUserAgent(ua) {
    const userAgent = ua.toLowerCase();
    
    if (CRAWLERS.some(crawler => userAgent.includes(crawler))) {
      return "Crawler Bot";
    }
    
    if (CLIENT_LIBS.some(lib => userAgent.includes(lib))) {
      return "Client Library Bot";
    }
    
    if (userAgent.trim() === '' || userAgent.length < 10 || !userAgent.includes('mozilla')) {
      return "Suspicious User-Agent";
    }
    
    return null;
  }

  const bots = entries.filter(entry => {
    const botType = classifyUserAgent(entry.user_agent);
    return botType !== null;
  });

  return bots.map(entry => ({
    ...entry,
    suspicion_reason: classifyUserAgent(entry.user_agent) || 'Bot detected'
  }));
}`
            },
            'LFI/RFI Attacks': {
                name: 'LFI/RFI Attack Detector',
                description: 'Detects Local File Inclusion and Remote File Inclusion attack patterns.',
                code: `function detectLfiRfi(entries) {
  const pattern = /(etc\\/passwd|proc\\/self\\/environ|input_file=|data:text)/i;

  const suspicious = entries.filter(entry => {
    return pattern.test(entry.path);
  });

  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'LFI/RFI pattern detected'
  }));
}`
            },
            'WordPress Probes': {
                name: 'WordPress Probe Detector',
                description: 'Identifies WordPress-specific vulnerability scanning and probing attempts.',
                code: `function detectWpProbe(entries) {
  const pattern = /(\\.php|\\/wp-|xmlrpc\\.php|\\?author=|\\?p=)/i;

  const suspicious = entries.filter(entry => {
    return pattern.test(entry.path);
  });

  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'WordPress probe detected'
  }));
}`
            },
            'Brute Force': {
                name: 'Brute Force Attack Detector',
                description: 'Detects brute force login attempts and credential stuffing attacks.',
                code: `function detectBruteForce(entries) {
  const loginPattern = /(login|admin|signin|wp-login\\.php)/i;
  const badStatuses = ['401', '403', '429'];

  const suspicious = entries.filter(entry => {
    return loginPattern.test(entry.path) && badStatuses.includes(entry.status);
  });

  return suspicious.map(entry => ({
    ...entry,
    suspicion_reason: 'Brute force attempt detected'
  }));
}`
            },
            'HTTP Errors': {
                name: 'HTTP Error Detector',
                description: 'Identifies suspicious HTTP error patterns and responses.',
                code: `function detectErrors(entries) {
  const badStatuses = ['403', '404', '406', '500', '502'];

  const errors = entries.filter(entry => {
    return badStatuses.includes(entry.status);
  });

  return errors.map(entry => ({
    ...entry,
    suspicion_reason: \`HTTP error status: \${entry.status}\`
  }));
}`
            },
            'Internal IP Access': {
                name: 'Internal IP Access Detector',
                description: 'Detects access attempts from internal IP address ranges.',
                code: `function detectInternalIp(entries) {
  const internal = entries.filter(entry => {
    const ip = entry.ip;
    return ip.startsWith('192.168.') ||
           ip.startsWith('10.') ||
           ip.startsWith('127.') ||
           ip.startsWith('172.');
  });

  return internal.map(entry => ({
    ...entry,
    suspicion_reason: 'Internal IP address detected'
  }));
}`
            }
        };

        return detectorMap[attackType] || null;
    },

    toggleAIConfig() {
        const panel = document.getElementById('ai-config-panel');
        panel.classList.toggle('hidden');
    },

    updateAIProviderLinks() {
        const provider = LLM_PROVIDERS.find(p => p.id === AppState.aiConfig.provider);
        if (provider && provider.apiKeyLink) {
            document.getElementById('api-key-link').href = provider.apiKeyLink;
        }
    },

    updateCustomEndpointVisibility() {
        const provider = LLM_PROVIDERS.find(p => p.id === AppState.aiConfig.provider);
        const customEndpointDiv = document.getElementById('custom-endpoint-div');
        
        if (provider && provider.customEndpoint) {
            customEndpointDiv.classList.remove('hidden');
        } else {
            customEndpointDiv.classList.add('hidden');
        }
    },

    updateAIWarning() {
        const warning = document.getElementById('ai-warning');
        const canAnalyze = AnalysisService.canAnalyze(AppState.aiConfig);
        
        if (canAnalyze) {
            warning.classList.add('hidden');
        } else {
            warning.classList.remove('hidden');
        }
    },

    async createDynamicAnalysis() {
        const description = document.getElementById('analysis-description').value.trim();
        if (!description) {
            Toast.error('Please enter an analysis description');
            return;
        }

        if (!AnalysisService.canAnalyze(AppState.aiConfig)) {
            Toast.error('Please configure your AI provider settings');
            return;
        }

        if (!AppState.parsedEntries.length) {
            Toast.error('Please load a log file first');
            return;
        }

        const createBtn = document.getElementById('create-analysis-btn');
        const originalContent = createBtn.innerHTML;
        
        createBtn.innerHTML = '<div class="spinner mr-2"></div><span>Creating Analysis...</span>';
        createBtn.disabled = true;

        try {
            const analysis = await AnalysisService.createDynamicAnalysis(description);
            
            // Clear the form
            document.getElementById('analysis-description').value = '';
            
            // Show custom analysis results section
            document.getElementById('custom-analysis-results').classList.remove('hidden');
            
            // Add the custom analysis card
            this.addCustomAnalysisCard(analysis);
            
            Toast.success(`Custom analysis "${analysis.name}" created successfully`);
        } catch (error) {
            console.error('AI analysis failed:', error);
            Toast.error(`Failed to create analysis: ${error.message}`);
        } finally {
            createBtn.innerHTML = originalContent;
            createBtn.disabled = false;
        }
    },

    addCustomAnalysisCard(analysis) {
        const grid = document.getElementById('custom-cards-grid');
        const card = this.createCustomAnalysisCard(analysis);
        grid.appendChild(card);
    },

    createCustomAnalysisCard(analysis) {
        const card = document.createElement('div');
        card.className = 'attack-card bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-200 hover:-translate-y-1 border border-gray-200 dark:border-gray-700 flex flex-col h-full';
        card.dataset.attackType = analysis.name;

        card.innerHTML = `
            <div class="flex items-start justify-between mb-4">
                <div class="flex items-center space-x-3">
                    <div class="p-2 rounded-lg bg-purple-100 dark:bg-purple-900/20">
                        <i class="fas fa-magic text-purple-600 dark:text-purple-400"></i>
                    </div>
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                            ${analysis.name}
                        </h3>
                        <span class="severity-medium inline-block px-2 py-1 rounded-full text-xs font-medium">
                            CUSTOM
                        </span>
                    </div>
                </div>
                <div class="text-right">
                    <div class="threat-count text-2xl font-bold text-gray-900 dark:text-white">
                        0
                    </div>
                    <div class="text-xs text-gray-500 dark:text-gray-400">
                        instances
                    </div>
                </div>
            </div>

            <p class="text-sm text-gray-600 dark:text-gray-300 mb-4">
                ${analysis.description}
            </p>

            <div class="space-y-2 mt-auto">
                <button class="scan-btn w-full flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors">
                    <i class="fas fa-play"></i>
                    <span>Scan</span>
                </button>
                
                <button class="view-results-btn w-full flex items-center justify-center space-x-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors hidden">
                    <i class="fas fa-eye"></i>
                    <span>View Results (<span class="result-count">0</span>)</span>
                </button>
                
                <button class="view-function-btn w-full flex items-center justify-center space-x-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors">
                    <i class="fas fa-code"></i>
                    <span>View Function</span>
                </button>
            </div>
        `;

        // Bind events
        const scanBtn = card.querySelector('.scan-btn');
        const viewResultsBtn = card.querySelector('.view-results-btn');
        const viewFunctionBtn = card.querySelector('.view-function-btn');

        scanBtn.addEventListener('click', () => {
            this.runCustomAnalysis(analysis);
        });

        viewResultsBtn.addEventListener('click', () => {
            this.viewAttackResults(analysis.name);
        });

        viewFunctionBtn.addEventListener('click', () => {
            this.openFunctionModal(
                analysis.name,
                analysis.functionCode,
                analysis.description,
                true
            );
        });

        return card;
    },

    async runCustomAnalysis(analysis) {
        if (!AppState.parsedEntries.length) {
            Toast.error('Please load a log file first');
            return;
        }

        AppState.isScanning[analysis.name] = true;
        this.updateScanButton(analysis.name, true);

        try {
            const results = await AnalysisService.runDynamicAnalysis(analysis.id);
            
            AppState.scanResults[analysis.name] = results;
            
            // Update all results
            AppState.allResults = AppState.allResults.filter(r => r.attack_type !== analysis.name);
            AppState.allResults.push(...results);
            
            this.updateAttackCard(analysis.name, results.length, false, true);
            this.updateExportButtons();
            
            Toast.success(`${analysis.name} completed: ${results.length} threats found`);
        } catch (error) {
            console.error('Custom analysis failed:', error);
            Toast.error(`Failed to run analysis: ${error.message}`);
        } finally {
            AppState.isScanning[analysis.name] = false;
            this.updateScanButton(analysis.name, false);
        }
    },

    openDetailsModal(attackType, results) {
        const modal = document.getElementById('details-modal');
        const title = document.getElementById('modal-title');
        const content = document.getElementById('modal-content');

        title.textContent = `${attackType} - Detailed Results`;
        content.innerHTML = this.generateDataTable(results);

        modal.classList.remove('hidden');
    },

    openFunctionModal(title, code, description, isCustom) {
        const modal = document.getElementById('function-modal');
        const modalTitle = document.getElementById('function-modal-title');
        const modalSubtitle = document.getElementById('function-modal-subtitle');
        const functionDescription = document.getElementById('function-description');
        const functionDescriptionText = document.getElementById('function-description-text');
        const functionCode = document.getElementById('function-code');
        const functionLinesCount = document.getElementById('function-lines-count');
        const functionFooterText = document.getElementById('function-footer-text');

        modalTitle.textContent = `${title} - Detection Function`;
        modalSubtitle.textContent = isCustom ? 'AI-Generated Custom Analysis Function' : 'Built-in Security Detection Function';

        if (description) {
            functionDescription.classList.remove('hidden');
            functionDescriptionText.textContent = description;
        } else {
            functionDescription.classList.add('hidden');
        }

        functionCode.querySelector('code').textContent = code;
        functionLinesCount.textContent = `${code.split('\n').length} lines`;

        functionFooterText.textContent = isCustom ? 
            'This function was generated by AI based on your custom analysis requirements.' :
            'This is a built-in detection function that analyzes log entries for security threats.';

        modal.classList.remove('hidden');
    },

    async copyFunctionCode() {
        const code = document.getElementById('function-code').querySelector('code').textContent;
        const success = await Utils.copyToClipboard(code);
        
        const btn = document.getElementById('copy-function-btn');
        const originalContent = btn.innerHTML;
        
        if (success) {
            btn.innerHTML = '<i class="fas fa-check mr-1"></i><span>Copied!</span>';
            setTimeout(() => {
                btn.innerHTML = originalContent;
            }, 2000);
        } else {
            Toast.error('Failed to copy to clipboard');
        }
    },

    closeModal(modalId) {
        document.getElementById(modalId).classList.add('hidden');
    },

    exportData(format) {
        if (AppState.allResults.length === 0) {
            Toast.error('No data to export');
            return;
        }

        try {
            const timestamp = new Date().toISOString().split('T')[0];
            const filename = `log-analysis-${timestamp}.${format}`;
            
            if (format === 'csv') {
                const csvContent = this.exportToCSV(AppState.allResults);
                Utils.downloadFile(csvContent, filename, 'text/csv');
            } else {
                const jsonContent = this.exportToJSON(AppState.allResults);
                Utils.downloadFile(jsonContent, filename, 'application/json');
            }
            
            Toast.success(`Data exported as ${format.toUpperCase()}`);
        } catch (error) {
            Toast.error('Failed to export data');
        }
    },

    exportToCSV(data) {
        const headers = [
            'IP',
            'Timestamp',
            'Method',
            'Path',
            'Protocol',
            'Status',
            'Bytes',
            'Referrer',
            'User Agent',
            'Host',
            'Server IP',
            'Suspicion Reason',
            'Attack Type'
        ];

        const csvContent = [
            headers.join(','),
            ...data.map(row => [
                row.ip,
                row.timestamp,
                row.method,
                `"${row.path.replace(/"/g, '""')}"`,
                row.protocol,
                row.status,
                row.bytes,
                `"${row.referrer.replace(/"/g, '""')}"`,
                `"${row.user_agent.replace(/"/g, '""')}"`,
                row.host,
                row.server_ip,
                `"${row.suspicion_reason.replace(/"/g, '""')}"`,
                row.attack_type
            ].join(','))
        ].join('\n');

        return csvContent;
    },

    exportToJSON(data) {
        return JSON.stringify(data, null, 2);
    },

    generateDataTable(data) {
        if (!data || data.length === 0) {
            return '<p class="text-center text-gray-500 dark:text-gray-400 py-8">No data available</p>';
        }

        const table = document.createElement('div');
        table.className = 'overflow-x-auto';
        
        table.innerHTML = `
            <table class="data-table w-full">
                <thead class="bg-gray-50 dark:bg-gray-700">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">IP Address</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Timestamp</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Method</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Path</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Suspicion Reason</th>
                    </tr>
                </thead>
                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    ${data.map(entry => `
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-white">${Utils.escapeHtml(entry.ip)}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">${Utils.formatDate(entry.timestamp)}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                                <span class="method-${entry.method.toLowerCase()} px-2 py-1 rounded-full text-xs font-medium">
                                    ${Utils.escapeHtml(entry.method)}
                                </span>
                            </td>
                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-white max-w-xs">
                                <div class="truncate" title="${Utils.escapeHtml(entry.path)}">
                                    ${Utils.escapeHtml(entry.path)}
                                </div>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                                <span class="status-${Math.floor(entry.status / 100)}xx px-2 py-1 rounded-full text-xs font-medium">
                                    ${entry.status}
                                </span>
                            </td>
                            <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-300 max-w-xs">
                                <div class="truncate" title="${Utils.escapeHtml(entry.suspicion_reason)}">
                                    ${Utils.escapeHtml(entry.suspicion_reason)}
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        return table.outerHTML;
    },

    updateDashboard() {
        if (AppState.allResults.length === 0) {
            document.getElementById('dashboard-loading').classList.remove('hidden');
            document.getElementById('dashboard-content').classList.add('hidden');
            return;
        }

        document.getElementById('dashboard-loading').classList.add('hidden');
        document.getElementById('dashboard-content').classList.remove('hidden');

        const summary = this.calculateSummary();
        this.renderDashboard(summary);
    },

    calculateSummary() {
        const attackTypeCounts = {};
        const ipCounts = {};
        const statusCounts = {};
        const timelineCounts = {};

        AppState.allResults.forEach(entry => {
            // Attack type counts
            attackTypeCounts[entry.attack_type] = (attackTypeCounts[entry.attack_type] || 0) + 1;
            
            // IP counts
            ipCounts[entry.ip] = (ipCounts[entry.ip] || 0) + 1;
            
            // Status code counts
            statusCounts[entry.status.toString()] = (statusCounts[entry.status.toString()] || 0) + 1;
            
            // Timeline data (by date)
            const date = new Date(entry.timestamp).toDateString();
            timelineCounts[date] = (timelineCounts[date] || 0) + 1;
        });

        const topAttackers = Object.entries(ipCounts)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 20)
            .map(([ip, count]) => ({ ip, count }));

        const timelineData = Object.entries(timelineCounts)
            .sort(([a], [b]) => new Date(a).getTime() - new Date(b).getTime())
            .map(([date, count]) => ({ date, count }));

        return {
            totalThreats: AppState.allResults.length,
            attackTypeCounts,
            topAttackers,
            statusCodeDistribution: statusCounts,
            timelineData,
        };
    },

    renderDashboard(summary) {
        const content = document.getElementById('dashboard-content');
        
        content.innerHTML = `
            <!-- Summary Cards -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
                <div class="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-600 dark:text-gray-300">Total Threats</p>
                            <p class="text-3xl font-bold text-gray-900 dark:text-white">${summary.totalThreats.toLocaleString()}</p>
                        </div>
                        <div class="p-3 bg-red-100 dark:bg-red-900/20 rounded-lg">
                            <i class="fas fa-exclamation-triangle text-red-600 dark:text-red-400 text-xl"></i>
                        </div>
                    </div>
                </div>

                <div class="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-600 dark:text-gray-300">Unique IPs</p>
                            <p class="text-3xl font-bold text-gray-900 dark:text-white">${summary.topAttackers.length.toLocaleString()}</p>
                        </div>
                        <div class="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                            <i class="fas fa-network-wired text-blue-600 dark:text-blue-400 text-xl"></i>
                        </div>
                    </div>
                </div>

                <div class="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-600 dark:text-gray-300">Attack Types</p>
                            <p class="text-3xl font-bold text-gray-900 dark:text-white">
                                ${Object.keys(summary.attackTypeCounts).length}
                            </p>
                        </div>
                        <div class="p-3 bg-green-100 dark:bg-green-900/20 rounded-lg">
                            <i class="fas fa-shield-alt text-green-600 dark:text-green-400 text-xl"></i>
                        </div>
                    </div>
                </div>

                <div class="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-sm font-medium text-gray-600 dark:text-gray-300">Top Attacker</p>
                            <p class="text-lg font-bold text-gray-900 dark:text-white">
                                ${summary.topAttackers[0]?.ip || 'N/A'}
                            </p>
                            <p class="text-sm text-gray-500 dark:text-gray-400">
                                ${summary.topAttackers[0]?.count || 0} attempts
                            </p>
                        </div>
                        <div class="p-3 bg-yellow-100 dark:bg-yellow-900/20 rounded-lg">
                            <i class="fas fa-user-secret text-yellow-600 dark:text-yellow-400 text-xl"></i>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Charts -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <!-- Attack Types Chart -->
                <div class="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Attack Types Distribution</h3>
                    <div class="chart-container">
                        <canvas id="attack-types-chart"></canvas>
                    </div>
                </div>

                <!-- Status Codes Chart -->
                <div class="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">HTTP Status Codes</h3>
                    <div class="chart-container">
                        <canvas id="status-codes-chart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Timeline Chart -->
            ${summary.timelineData.length > 0 ? `
            <div class="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700 mb-6">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Attack Timeline</h3>
                <div class="chart-container">
                    <canvas id="timeline-chart"></canvas>
                </div>
            </div>
            ` : ''}

            <!-- Top Attackers -->
            <div class="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg border border-gray-200 dark:border-gray-700">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top Attackers</h3>
                <div class="space-y-3">
                    ${summary.topAttackers.slice(0, 10).map((attacker, index) => `
                        <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                            <div class="flex items-center space-x-3">
                                <div class="w-8 h-8 bg-red-100 dark:bg-red-900/20 rounded-full flex items-center justify-center">
                                    <span class="text-sm font-medium text-red-600 dark:text-red-400">#${index + 1}</span>
                                </div>
                                <div>
                                    <p class="font-mono text-sm text-gray-900 dark:text-white">${attacker.ip}</p>
                                </div>
                            </div>
                            <div class="text-right">
                                <p class="text-lg font-semibold text-gray-900 dark:text-white">${attacker.count}</p>
                                <p class="text-xs text-gray-500 dark:text-gray-400">attempts</p>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        // Render charts
        setTimeout(() => {
            this.renderCharts(summary);
        }, 100);
    },

    renderCharts(summary) {
        // Attack Types Chart
        const attackTypesCtx = document.getElementById('attack-types-chart');
        if (attackTypesCtx) {
            const attackTypesData = ATTACK_TYPES.map(type => ({
                name: type.name,
                count: summary.attackTypeCounts[type.name] || 0,
                color: type.color,
            }));

            new Chart(attackTypesCtx, {
                type: 'bar',
                data: {
                    labels: attackTypesData.map(d => d.name),
                    datasets: [{
                        label: 'Threats',
                        data: attackTypesData.map(d => d.count),
                        backgroundColor: attackTypesData.map(d => d.color + '80'),
                        borderColor: attackTypesData.map(d => d.color),
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: AppState.theme === 'dark' ? '#374151' : '#E5E7EB'
                            },
                            ticks: {
                                color: AppState.theme === 'dark' ? '#9CA3AF' : '#6B7280'
                            }
                        },
                        x: {
                            grid: {
                                color: AppState.theme === 'dark' ? '#374151' : '#E5E7EB'
                            },
                            ticks: {
                                color: AppState.theme === 'dark' ? '#9CA3AF' : '#6B7280',
                                maxRotation: 45
                            }
                        }
                    }
                }
            });
        }

        // Status Codes Chart
        const statusCodesCtx = document.getElementById('status-codes-chart');
        if (statusCodesCtx) {
            const statusCodesData = Object.entries(summary.statusCodeDistribution).map(([code, count]) => ({
                name: code,
                count
            }));

            const colors = ['#DC2626', '#EA580C', '#CA8A04', '#059669', '#0284C7', '#7C3AED', '#BE185D', '#0F766E'];

            new Chart(statusCodesCtx, {
                type: 'doughnut',
                data: {
                    labels: statusCodesData.map(d => d.name),
                    datasets: [{
                        data: statusCodesData.map(d => d.count),
                        backgroundColor: colors.slice(0, statusCodesData.length),
                        borderWidth: 2,
                        borderColor: AppState.theme === 'dark' ? '#1F2937' : '#FFFFFF'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: AppState.theme === 'dark' ? '#D1D5DB' : '#374151',
                                padding: 20
                            }
                        }
                    }
                }
            });
        }

        // Timeline Chart
        const timelineCtx = document.getElementById('timeline-chart');
        if (timelineCtx && summary.timelineData.length > 0) {
            new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: summary.timelineData.map(d => d.date),
                    datasets: [{
                        label: 'Threats',
                        data: summary.timelineData.map(d => d.count),
                        borderColor: '#3B82F6',
                        backgroundColor: '#3B82F680',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: AppState.theme === 'dark' ? '#374151' : '#E5E7EB'
                            },
                            ticks: {
                                color: AppState.theme === 'dark' ? '#9CA3AF' : '#6B7280'
                            }
                        },
                        x: {
                            grid: {
                                color: AppState.theme === 'dark' ? '#374151' : '#E5E7EB'
                            },
                            ticks: {
                                color: AppState.theme === 'dark' ? '#9CA3AF' : '#6B7280'
                            }
                        }
                    }
                }
            });
        }
    },

    updateDataTable() {
        const container = document.getElementById('data-table-container');
        
        if (AppState.allResults.length === 0) {
            container.innerHTML = `
                <div class="bg-white dark:bg-gray-800 rounded-xl p-8 text-center">
                    <i class="fas fa-database text-4xl text-gray-400 mb-4"></i>
                    <p class="text-gray-600 dark:text-gray-300">No data available. Please run some scans first.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden">
                <div class="p-4 border-b border-gray-200 dark:border-gray-700">
                    <div class="flex items-center justify-between">
                        <div>
                            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                                Security Threats (${AppState.allResults.length.toLocaleString()})
                            </h3>
                            <p class="text-sm text-gray-600 dark:text-gray-300">
                                All detected security threats from log analysis
                            </p>
                        </div>
                    </div>
                </div>
                ${this.generateDataTable(AppState.allResults)}
            </div>
        `;
    },

    // Report Modal Functions
    openReportModal() {
        if (AppState.allResults.length === 0) {
            Toast.error('No analysis data available to generate report');
            return;
        }

        const modal = document.getElementById('report-modal');
        
        // Reset modal state
        document.getElementById('report-generation-interface').classList.remove('hidden');
        document.getElementById('report-display').classList.add('hidden');
        
        // Update provider configuration
        this.updateReportProviderConfig(AppState.aiConfig.provider);
        document.getElementById('report-ai-provider-select').value = AppState.aiConfig.provider;
        document.getElementById('report-ai-api-key').value = AppState.aiConfig.apiKey;
        document.getElementById('report-custom-endpoint').value = AppState.aiConfig.customEndpoint;
        
        // Update warning
        this.updateReportWarning();
        
        modal.classList.remove('hidden');
    },

    toggleReportConfig() {
        const panel = document.getElementById('report-config-panel');
        panel.classList.toggle('hidden');
    },

    updateReportProviderConfig(providerId) {
        const provider = LLM_PROVIDERS.find(p => p.id === providerId);
        const customEndpointDiv = document.getElementById('report-custom-endpoint-div');
        const apiKeyLink = document.getElementById('report-api-key-link');
        
        if (provider) {
            if (provider.customEndpoint) {
                customEndpointDiv.classList.remove('hidden');
            } else {
                customEndpointDiv.classList.add('hidden');
            }
            
            if (provider.apiKeyLink) {
                apiKeyLink.href = provider.apiKeyLink;
            }
        }
        
        // Update AI config
        AppState.aiConfig.provider = providerId;
        this.updateReportWarning();
    },

    updateReportWarning() {
        const warning = document.getElementById('report-warning');
        const generateBtn = document.getElementById('generate-report-final-btn');
        const canGenerate = ReportService.canGenerateReport({
            provider: document.getElementById('report-ai-provider-select').value,
            apiKey: document.getElementById('report-ai-api-key').value,
            customEndpoint: document.getElementById('report-custom-endpoint').value
        });
        
        if (canGenerate) {
            warning.classList.add('hidden');
            generateBtn.disabled = false;
        } else {
            warning.classList.remove('hidden');
            generateBtn.disabled = true;
        }
    },

    async generateReport() {
        const config = {
            provider: document.getElementById('report-ai-provider-select').value,
            apiKey: document.getElementById('report-ai-api-key').value,
            customEndpoint: document.getElementById('report-custom-endpoint').value
        };

        if (!ReportService.canGenerateReport(config)) {
            Toast.error('Please configure your AI provider settings');
            return;
        }

        const generateBtn = document.getElementById('generate-report-final-btn');
        const originalContent = generateBtn.innerHTML;
        
        generateBtn.innerHTML = '<div class="spinner mr-2"></div><span>Generating Report...</span>';
        generateBtn.disabled = true;

        try {
            const summary = this.calculateSummary();
            const markdown = await ReportService.generateReport(
                AppState.allResults,
                summary,
                'https://raw.githubusercontent.com/Yadav-Aayansh/gramener-datasets/add-server-logs/server_logs.zip',
                AppState.selectedFile?.name,
                config
            );
            
            this.displayReport(markdown);
            Toast.success('Security report generated successfully');
        } catch (error) {
            console.error('Report generation failed:', error);
            Toast.error(`Failed to generate report: ${error.message}`);
        } finally {
            generateBtn.innerHTML = originalContent;
            generateBtn.disabled = false;
        }
    },

    displayReport(markdown) {
        // Hide generation interface and show report display
        document.getElementById('report-generation-interface').classList.add('hidden');
        document.getElementById('report-display').classList.remove('hidden');
        
        // Set markdown content
        document.getElementById('report-markdown-content').textContent = markdown;
        
        // Render preview
        const previewDiv = document.getElementById('report-preview');
        previewDiv.innerHTML = marked.parse(markdown);
        previewDiv.className = 'report-content prose prose-lg max-w-none dark:prose-invert overflow-y-auto h-full p-6';
        
        // Show preview tab by default
        this.switchReportTab('preview');
    },

    switchReportTab(tab) {
        // Update tab buttons
        document.querySelectorAll('.report-tab').forEach(btn => {
            btn.classList.remove('active');
        });
        document.getElementById(`report-tab-${tab}`).classList.add('active');
        
        // Update content
        if (tab === 'preview') {
            document.getElementById('report-preview').classList.remove('hidden');
            document.getElementById('report-markdown').classList.add('hidden');
        } else {
            document.getElementById('report-preview').classList.add('hidden');
            document.getElementById('report-markdown').classList.remove('hidden');
        }
    },

    async copyReport() {
        const markdown = document.getElementById('report-markdown-content').textContent;
        const success = await Utils.copyToClipboard(markdown);
        
        const btn = document.getElementById('copy-report-btn');
        const originalContent = btn.innerHTML;
        
        if (success) {
            btn.innerHTML = '<i class="fas fa-check mr-1"></i><span>Copied!</span>';
            setTimeout(() => {
                btn.innerHTML = originalContent;
            }, 2000);
        } else {
            Toast.error('Failed to copy to clipboard');
        }
    },

    downloadReport(format) {
        const markdown = document.getElementById('report-markdown-content').textContent;
        const timestamp = new Date().toISOString().split('T')[0];
        
        if (format === 'md') {
            Utils.downloadFile(markdown, `security-report-${timestamp}.md`, 'text/markdown');
        } else if (format === 'html') {
            const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: #fff;
        }
        h1 { color: #1a202c; border-bottom: 3px solid #3182ce; padding-bottom: 0.5rem; }
        h2 { color: #2d3748; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; margin-top: 2rem; }
        h3 { color: #4a5568; margin-top: 1.5rem; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { border: 1px solid #e2e8f0; padding: 0.75rem; text-align: left; }
        th { background: #f7fafc; font-weight: 600; }
        code { background: #f1f5f9; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-family: 'Monaco', 'Consolas', monospace; }
        pre { background: #1a202c; color: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
        blockquote { border-left: 4px solid #3182ce; padding-left: 1rem; margin: 1rem 0; background: #f8fafc; }
        .severity-high { color: #e53e3e; background: #fed7d7; padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
        .severity-medium { color: #dd6b20; background: #feebc8; padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
        .severity-low { color: #38a169; background: #c6f6d5; padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
        @media print {
            body { padding: 1rem; }
            h1, h2 { page-break-after: avoid; }
        }
    </style>
</head>
<body>
    ${marked.parse(markdown)}
</body>
</html>`;
            Utils.downloadFile(htmlContent, `security-report-${timestamp}.html`, 'text/html');
        }
    }
};

// Application Initialization
document.addEventListener('DOMContentLoaded', () => {
    // Initialize all components
    Toast.init();
    ThemeManager.init();
    UI.init();
    
    // Update AI provider configuration on change
    document.getElementById('report-ai-provider-select').addEventListener('change', (e) => {
        UI.updateReportProviderConfig(e.target.value);
    });
    
    document.getElementById('report-ai-api-key').addEventListener('input', () => {
        UI.updateReportWarning();
    });
    
    document.getElementById('report-custom-endpoint').addEventListener('input', () => {
        UI.updateReportWarning();
    });
    
    console.log('🛡️ Cyber Detect - Advanced Security Log Analysis Platform');
    console.log('Application initialized successfully');
});

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    Toast.error('An unexpected error occurred. Please check the console for details.');
});

// Global unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    Toast.error('An unexpected error occurred. Please check the console for details.');
});