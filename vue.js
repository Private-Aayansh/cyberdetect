const { createApp } = Vue;

// Attack types configuration - exact same as original
const attackTypes = [
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

// LLM Providers configuration
const llmProviders = [
    {
        id: "gemini",
        name: "Google Gemini",
        description: "Google's Gemini AI model",
        requiresApiKey: true,
        apiKeyLink: "https://makersuite.google.com/app/apikey"
    },
    {
        id: "openai",
        name: "OpenAI GPT",
        description: "OpenAI's GPT models",
        requiresApiKey: true,
        apiKeyLink: "https://platform.openai.com/api-keys"
    },
    {
        id: "anthropic",
        name: "Anthropic Claude",
        description: "Anthropic's Claude models",
        requiresApiKey: true,
        apiKeyLink: "https://console.anthropic.com/account/keys"
    },
    {
        id: "aipipe",
        name: "AIPipe",
        description: "AIPipe.org API service",
        requiresApiKey: true,
        customEndpoint: true,
        defaultEndpoint: "https://aipipe.org/openrouter/v1/chat/completions",
        apiKeyLink: "https://aipipe.org/"
    },
    {
        id: "custom",
        name: "Custom Endpoint",
        description: "Custom OpenAI-compatible API endpoint",
        requiresApiKey: true,
        customEndpoint: true
    }
];

// Detection functions - corrected to match script.js exactly
const detectionFunctions = {
    'sql-injection': {
        name: 'SQL Injection',
        description: 'Detects SQL injection attempts in URLs and parameters',
        code: `function detectSQLInjection(logEntry) {
    const sqlPatterns = [
        /('|(\\%27))|(;|(\\%3B))/i,
        /(union|select|insert|update|delete|drop|create|alter|exec|execute)/i,
        /(\\\\|\\%5C)|(\\"|\\%22)/i,
        /(or|and)\\s*(=|like|in)/i,
        /\\b(script|javascript|vbscript|onload|onerror|onclick)\\b/i,
        /\\b(alert|confirm|prompt)\\s*\\(/i,
        /<script[^>]*>.*?<\\/script>/i
    ];
    
    const url = logEntry.url || '';
    const userAgent = logEntry.userAgent || '';
    const referer = logEntry.referer || '';
    
    return sqlPatterns.some(pattern => 
        pattern.test(url) || pattern.test(userAgent) || pattern.test(referer)
    );
}`,
        detect: function(logEntry) {
            const sqlPatterns = [
                /('|(\%27))|(;|(\%3B))/i,
                /(union|select|insert|update|delete|drop|create|alter|exec|execute)/i,
                /(\\|%5C)|("|%22)/i,
                /(or|and)\s*(=|like|in)/i,
                /\b(script|javascript|vbscript|onload|onerror|onclick)\b/i,
                /\b(alert|confirm|prompt)\s*\(/i,
                /<script[^>]*>.*?<\/script>/i
            ];
            
            const url = logEntry.url || '';
            const userAgent = logEntry.userAgent || '';
            const referer = logEntry.referer || '';
            
            return sqlPatterns.some(pattern => 
                pattern.test(url) || pattern.test(userAgent) || pattern.test(referer)
            );
        }
    },
    'path-traversal': {
        name: 'Path Traversal',
        description: 'Detects directory traversal and path manipulation attempts',
        code: `function detectPathTraversal(logEntry) {
    const pathPatterns = [
        /\\.\\.\\/|\\.\\.\\\\/i,
        /\\%2e\\%2e\\%2f|\\%2e\\%2e\\%5c/i,
        /\\%252e\\%252e\\%252f/i,
        /\\/etc\\/passwd|\\/etc\\/shadow|\\/etc\\/hosts/i,
        /\\/windows\\/system32|\\/winnt/i,
        /\\.\\.\\\\|\\.\\.\\//i,
        /\\/proc\\/|\\/sys\\/|\\/dev\\//i,
        /\\%00/i
    ];
    
    const url = logEntry.url || '';
    const userAgent = logEntry.userAgent || '';
    
    return pathPatterns.some(pattern => 
        pattern.test(url) || pattern.test(userAgent)
    );
}`,
        detect: function(logEntry) {
            const pathPatterns = [
                /\.\.\//i,
                /\.\.\\/i,
                /%2e%2e%2f|%2e%2e%5c/i,
                /%252e%252e%252f/i,
                /\/etc\/passwd|\/etc\/shadow|\/etc\/hosts/i,
                /\/windows\/system32|\/winnt/i,
                /\.\.\\/i,
                /\/proc\/|\/sys\/|\/dev\//i,
                /%00/i
            ];
            
            const url = logEntry.url || '';
            const userAgent = logEntry.userAgent || '';
            
            return pathPatterns.some(pattern => 
                pattern.test(url) || pattern.test(userAgent)
            );
        }
    },
    'bots': {
        name: 'Bot Detection',
        description: 'Identifies automated bot and crawler activity',
        code: `function detectBots(logEntry) {
    const botPatterns = [
        /bot|crawler|spider|scraper|scan/i,
        /curl|wget|python|java|go-http|libwww/i,
        /automated|script|tool|monitor/i,
        /nikto|nmap|sqlmap|burp|zap/i,
        /masscan|nessus|openvas|acunetix/i
    ];
    
    const userAgent = logEntry.userAgent || '';
    const url = logEntry.url || '';
    
    // Check for bot user agents
    const isBotUserAgent = botPatterns.some(pattern => pattern.test(userAgent));
    
    // Check for suspicious request patterns
    const suspiciousPatterns = [
        /\\/robots\\.txt/i,
        /\\/sitemap\\.xml/i,
        /\\/wp-admin/i,
        /\\/admin/i,
        /\\/phpmyadmin/i,
        /\\/test/i,
        /\\/backup/i
    ];
    
    const isSuspiciousRequest = suspiciousPatterns.some(pattern => pattern.test(url));
    
    // Check for rapid requests (simplified)
    const hasEmptyUserAgent = !userAgent || userAgent.trim() === '' || userAgent === '-';
    
    return isBotUserAgent || isSuspiciousRequest || hasEmptyUserAgent;
}`,
        detect: function(logEntry) {
            const botPatterns = [
                /bot|crawler|spider|scraper|scan/i,
                /curl|wget|python|java|go-http|libwww/i,
                /automated|script|tool|monitor/i,
                /nikto|nmap|sqlmap|burp|zap/i,
                /masscan|nessus|openvas|acunetix/i
            ];
            
            const userAgent = logEntry.userAgent || '';
            const url = logEntry.url || '';
            
            const isBotUserAgent = botPatterns.some(pattern => pattern.test(userAgent));
            
            const suspiciousPatterns = [
                /\/robots\.txt/i,
                /\/sitemap\.xml/i,
                /\/wp-admin/i,
                /\/admin/i,
                /\/phpmyadmin/i,
                /\/test/i,
                /\/backup/i
            ];
            
            const isSuspiciousRequest = suspiciousPatterns.some(pattern => pattern.test(url));
            const hasEmptyUserAgent = !userAgent || userAgent.trim() === '' || userAgent === '-';
            
            return isBotUserAgent || isSuspiciousRequest || hasEmptyUserAgent;
        }
    },
    'lfi-rfi': {
        name: 'LFI/RFI Attacks',
        description: 'Detects Local and Remote File Inclusion attempts',
        code: `function detectLFIRFI(logEntry) {
    const lfiPatterns = [
        /\\?.*file=|\\?.*page=|\\?.*include=|\\?.*path=/i,
        /php:\\/\\/|data:\\/\\/|expect:\\/\\/|zip:\\/\\//i,
        /\\/proc\\/self\\/environ|\\/proc\\/version/i,
        /\\/var\\/log|\\/var\\/mail/i,
        /\\.\\.\\//i,
        /\\%00/i,
        /file:\\/\\/\\/|file:\\/\\/localhost/i
    ];
    
    const rfiPatterns = [
        /\\?.*url=http|\\?.*file=http|\\?.*include=http/i,
        /\\?.*path=http|\\?.*page=http/i,
        /http:\\/\\/.*\\.(txt|php|asp|jsp)/i,
        /https:\\/\\/.*\\.(txt|php|asp|jsp)/i
    ];
    
    const url = logEntry.url || '';
    const userAgent = logEntry.userAgent || '';
    
    const isLFI = lfiPatterns.some(pattern => pattern.test(url) || pattern.test(userAgent));
    const isRFI = rfiPatterns.some(pattern => pattern.test(url) || pattern.test(userAgent));
    
    return isLFI || isRFI;
}`,
        detect: function(logEntry) {
            const lfiPatterns = [
                /\?.*file=|\?.*page=|\?.*include=|\?.*path=/i,
                /php:\/\/|data:\/\/|expect:\/\/|zip:\/\//i,
                /\/proc\/self\/environ|\/proc\/version/i,
                /\/var\/log|\/var\/mail/i,
                /\.\.\//i,
                /%00/i,
                /file:\/\/\/|file:\/\/localhost/i
            ];
            
            const rfiPatterns = [
                /\?.*url=http|\?.*file=http|\?.*include=http/i,
                /\?.*path=http|\?.*page=http/i,
                /http:\/\/.*\.(txt|php|asp|jsp)/i,
                /https:\/\/.*\.(txt|php|asp|jsp)/i
            ];
            
            const url = logEntry.url || '';
            const userAgent = logEntry.userAgent || '';
            
            const isLFI = lfiPatterns.some(pattern => pattern.test(url) || pattern.test(userAgent));
            const isRFI = rfiPatterns.some(pattern => pattern.test(url) || pattern.test(userAgent));
            
            return isLFI || isRFI;
        }
    },
    'wp-probe': {
        name: 'WordPress Probes',
        description: 'Detects WordPress-specific vulnerability scanning',
        code: `function detectWordPressProbes(logEntry) {
    const wpPatterns = [
        /\\/wp-admin|\\/wp-login|\\/wp-content|\\/wp-includes/i,
        /\\/wp-config|\\/wp-settings|\\/wp-load/i,
        /\\/xmlrpc\\.php|\\/wp-cron\\.php/i,
        /\\/wp-json|\\/wp-api/i,
        /wp-|wordpress/i,
        /\\/plugins\\/|\\/themes\\//i,
        /\\/uploads\\/|\\/wp-content\\/uploads/i
    ];
    
    const url = logEntry.url || '';
    const userAgent = logEntry.userAgent || '';
    const referer = logEntry.referer || '';
    
    return wpPatterns.some(pattern => 
        pattern.test(url) || pattern.test(userAgent) || pattern.test(referer)
    );
}`,
        detect: function(logEntry) {
            const wpPatterns = [
                /\/wp-admin|\/wp-login|\/wp-content|\/wp-includes/i,
                /\/wp-config|\/wp-settings|\/wp-load/i,
                /\/xmlrpc\.php|\/wp-cron\.php/i,
                /\/wp-json|\/wp-api/i,
                /wp-|wordpress/i,
                /\/plugins\/|\/themes\//i,
                /\/uploads\/|\/wp-content\/uploads/i
            ];
            
            const url = logEntry.url || '';
            const userAgent = logEntry.userAgent || '';
            const referer = logEntry.referer || '';
            
            return wpPatterns.some(pattern => 
                pattern.test(url) || pattern.test(userAgent) || pattern.test(referer)
            );
        }
    },
    'brute-force': {
        name: 'Brute Force',
        description: 'Detects brute force and credential stuffing attacks',
        code: `function detectBruteForce(logEntry) {
    const bruteForcePatterns = [
        /\\/login|\\/signin|\\/auth|\\/authenticate/i,
        /\\/admin|\\/administrator|\\/wp-admin/i,
        /password|passwd|pwd|credential/i,
        /username|user|email|account/i,
        /\\/api\\/auth|\\/oauth/i
    ];
    
    const url = logEntry.url || '';
    const method = logEntry.method || '';
    const status = parseInt(logEntry.status) || 0;
    const userAgent = logEntry.userAgent || '';
    
    // Check for login-related URLs
    const isLoginAttempt = bruteForcePatterns.some(pattern => pattern.test(url));
    
    // Check for POST requests to login endpoints with failed status
    const isFailedLogin = method === 'POST' && (status === 401 || status === 403 || status === 422);
    
    // Check for suspicious user agents
    const suspiciousUA = /curl|wget|python|script/i.test(userAgent);
    
    return (isLoginAttempt && isFailedLogin) || (isLoginAttempt && suspiciousUA);
}`,
        detect: function(logEntry) {
            const bruteForcePatterns = [
                /\/login|\/signin|\/auth|\/authenticate/i,
                /\/admin|\/administrator|\/wp-admin/i,
                /password|passwd|pwd|credential/i,
                /username|user|email|account/i,
                /\/api\/auth|\/oauth/i
            ];
            
            const url = logEntry.url || '';
            const method = logEntry.method || '';
            const status = parseInt(logEntry.status) || 0;
            const userAgent = logEntry.userAgent || '';
            
            const isLoginAttempt = bruteForcePatterns.some(pattern => pattern.test(url));
            const isFailedLogin = method === 'POST' && (status === 401 || status === 403 || status === 422);
            const suspiciousUA = /curl|wget|python|script/i.test(userAgent);
            
            return (isLoginAttempt && isFailedLogin) || (isLoginAttempt && suspiciousUA);
        }
    },
    'errors': {
        name: 'HTTP Errors',
        description: 'Detects suspicious HTTP error patterns',
        code: `function detectHTTPErrors(logEntry) {
    const status = parseInt(logEntry.status) || 0;
    const url = logEntry.url || '';
    const method = logEntry.method || '';
    
    // Focus on 4xx and 5xx errors
    const isError = status >= 400;
    
    // Check for suspicious error patterns
    const suspiciousPatterns = [
        /\\.php|\\.asp|\\.jsp|\\.cgi/i,
        /admin|config|backup|test|debug|dev/i,
        /\\.env|\\.git|\\.svn|\\.htaccess/i,
        /database|db|sql|mysql/i,
        /upload|file|document/i
    ];
    
    const isSuspiciousUrl = suspiciousPatterns.some(pattern => pattern.test(url));
    
    // High-value error codes
    const criticalErrors = [403, 404, 500, 502, 503];
    const isCriticalError = criticalErrors.includes(status);
    
    return isError && (isSuspiciousUrl || isCriticalError);
}`,
        detect: function(logEntry) {
            const status = parseInt(logEntry.status) || 0;
            const url = logEntry.url || '';
            const method = logEntry.method || '';
            
            const isError = status >= 400;
            
            const suspiciousPatterns = [
                /\.php|\.asp|\.jsp|\.cgi/i,
                /admin|config|backup|test|debug|dev/i,
                /\.env|\.git|\.svn|\.htaccess/i,
                /database|db|sql|mysql/i,
                /upload|file|document/i
            ];
            
            const isSuspiciousUrl = suspiciousPatterns.some(pattern => pattern.test(url));
            const criticalErrors = [403, 404, 500, 502, 503];
            const isCriticalError = criticalErrors.includes(status);
            
            return isError && (isSuspiciousUrl || isCriticalError);
        }
    },
    'internal-ip': {
        name: 'Internal IP Access',
        description: 'Detects unauthorized access attempts to internal IP ranges',
        code: `function detectInternalIPAccess(logEntry) {
    const ip = logEntry.ip || '';
    const url = logEntry.url || '';
    const referer = logEntry.referer || '';
    
    // Check for internal IP patterns in URL or referer
    const internalIPPatterns = [
        /192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\./,
        /127\\.0\\.0\\.1|localhost/i,
        /0\\.0\\.0\\.0|255\\.255\\.255\\.255/,
        /\\b(?:192\\.168|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01]))\\./
    ];
    
    // Check for attempts to access internal resources
    const internalResourcePatterns = [
        /\\/internal|\\/private|\\/admin|\\/management/i,
        /\\/config|\\/settings|\\/env|\\/environment/i,
        /\\/status|\\/health|\\/metrics|\\/debug/i,
        /\\/api\\/internal|\\/api\\/private/i,
        /localhost|127\\.0\\.0\\.1/i
    ];
    
    const hasInternalIP = internalIPPatterns.some(pattern => 
        pattern.test(ip) || pattern.test(url) || pattern.test(referer)
    );
    
    const accessesInternalResource = internalResourcePatterns.some(pattern => 
        pattern.test(url) || pattern.test(referer)
    );
    
    return hasInternalIP || accessesInternalResource;
}`,
        detect: function(logEntry) {
            const ip = logEntry.ip || '';
            const url = logEntry.url || '';
            const referer = logEntry.referer || '';
            
            const internalIPPatterns = [
                /192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\./,
                /127\.0\.0\.1|localhost/i,
                /0\.0\.0\.0|255\.255\.255\.255/,
                /\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\./
            ];
            
            const internalResourcePatterns = [
                /\/internal|\/private|\/admin|\/management/i,
                /\/config|\/settings|\/env|\/environment/i,
                /\/status|\/health|\/metrics|\/debug/i,
                /\/api\/internal|\/api\/private/i,
                /localhost|127\.0\.0\.1/i
            ];
            
            const hasInternalIP = internalIPPatterns.some(pattern => 
                pattern.test(ip) || pattern.test(url) || pattern.test(referer)
            );
            
            const accessesInternalResource = internalResourcePatterns.some(pattern => 
                pattern.test(url) || pattern.test(referer)
            );
            
            return hasInternalIP || accessesInternalResource;
        }
    }
};

createApp({
    data() {
        return {
            activeView: 'overview',
            attackTypes: attackTypes,
            logData: [],
            analysisResults: [],
            customAnalysisResults: [],
            selectedFile: null,
            isDragging: false,
            isLoading: false,
            isScanning: false,
            scanningTypes: [],
            toasts: [],
            showFunctionModal: false,
            showResultModal: false,
            showReportModal: false,
            currentFunction: null,
            currentResult: null,
            isDarkMode: false,
            
            // AI Configuration
            aiProvider: 'gemini',
            aiApiKey: '',
            customEndpoint: '',
            showAiConfig: false,
            
            // Report Generation
            reportContent: '',
            reportMarkdown: '',
            showReportConfig: false,
            reportTab: 'preview',
            isGeneratingReport: false,
            
            // Data Table Filtering
            dataFilters: {
                searchTerm: '',
                selectedMethods: [],
                selectedStatuses: [],
                selectedIPs: [],
                dateRange: { start: '', end: '' }
            },
            availableFilters: {
                methods: [],
                statuses: [],
                ips: []
            }
        };
    },
    computed: {
        filteredLogData() {
            let filtered = [...this.logData];
            
            if (this.dataFilters.searchTerm) {
                const term = this.dataFilters.searchTerm.toLowerCase();
                filtered = filtered.filter(entry => 
                    (entry.url || '').toLowerCase().includes(term) ||
                    (entry.ip || '').toLowerCase().includes(term) ||
                    (entry.userAgent || '').toLowerCase().includes(term)
                );
            }
            
            if (this.dataFilters.selectedMethods.length > 0) {
                filtered = filtered.filter(entry => 
                    this.dataFilters.selectedMethods.includes(entry.method)
                );
            }
            
            if (this.dataFilters.selectedStatuses.length > 0) {
                filtered = filtered.filter(entry => 
                    this.dataFilters.selectedStatuses.includes(entry.status)
                );
            }
            
            if (this.dataFilters.selectedIPs.length > 0) {
                filtered = filtered.filter(entry => 
                    this.dataFilters.selectedIPs.includes(entry.ip)
                );
            }
            
            return filtered;
        },
        
        currentProvider() {
            return llmProviders.find(p => p.id === this.aiProvider);
        }
    },
    mounted() {
        this.initializeTheme();
        this.loadAiConfig();
    },
    methods: {
        initializeTheme() {
            const savedTheme = localStorage.getItem('cyberdetect-theme');
            const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            
            this.isDarkMode = savedTheme ? savedTheme === 'dark' : prefersDark;
            this.applyTheme();
        },
        
        toggleTheme() {
            this.isDarkMode = !this.isDarkMode;
            this.applyTheme();
            localStorage.setItem('cyberdetect-theme', this.isDarkMode ? 'dark' : 'light');
        },
        
        applyTheme() {
            if (this.isDarkMode) {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
        },
        
        loadAiConfig() {
            const saved = localStorage.getItem('cyberdetect-ai-config');
            if (saved) {
                try {
                    const config = JSON.parse(saved);
                    this.aiProvider = config.provider || 'gemini';
                    this.aiApiKey = config.apiKey || '';
                    this.customEndpoint = config.customEndpoint || '';
                } catch (e) {
                    console.error('Failed to load AI config:', e);
                }
            }
        },
        
        saveAiConfig() {
            const config = {
                provider: this.aiProvider,
                apiKey: this.aiApiKey,
                customEndpoint: this.customEndpoint
            };
            localStorage.setItem('cyberdetect-ai-config', JSON.stringify(config));
        },
        
        showToast(message, type = 'info') {
            const toast = {
                id: Date.now(),
                message,
                type
            };
            this.toasts.push(toast);
            
            setTimeout(() => {
                const index = this.toasts.findIndex(t => t.id === toast.id);
                if (index > -1) {
                    this.toasts.splice(index, 1);
                }
            }, 5000);
        },
        
        getToastIcon(type) {
            const icons = {
                success: 'fas fa-check-circle',
                error: 'fas fa-exclamation-circle',
                warning: 'fas fa-exclamation-triangle',
                info: 'fas fa-info-circle'
            };
            return icons[type] || icons.info;
        },
        
        getSeverityClass(severity) {
            const classes = {
                high: 'severity-high',
                medium: 'severity-medium',
                low: 'severity-low'
            };
            return classes[severity] || classes.low;
        },
        
        formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },
        
        async loadDemoDataset() {
            this.isLoading = true;
            this.showToast('Loading demo dataset...', 'info');
            
            try {
                const response = await fetch('https://raw.githubusercontent.com/Yadav-Aayansh/gramener-datasets/add-server-logs/server_logs.zip');
                if (!response.ok) throw new Error('Failed to fetch demo dataset');
                
                const arrayBuffer = await response.arrayBuffer();
                await this.processZipFile(arrayBuffer);
                
                this.showToast('Demo dataset loaded successfully!', 'success');
            } catch (error) {
                console.error('Error loading demo dataset:', error);
                this.showToast('Failed to load demo dataset: ' + error.message, 'error');
            } finally {
                this.isLoading = false;
            }
        },
        
        handleFileDrop(event) {
            event.preventDefault();
            this.isDragging = false;
            
            const files = event.dataTransfer.files;
            if (files.length > 0) {
                this.handleFile(files[0]);
            }
        },
        
        handleFileSelect(event) {
            const file = event.target.files[0];
            if (file) {
                this.handleFile(file);
            }
        },
        
        async handleFile(file) {
            this.selectedFile = file;
            this.isLoading = true;
            this.showToast('Processing log file...', 'info');
            
            try {
                let content;
                
                if (file.name.endsWith('.zip')) {
                    const arrayBuffer = await file.arrayBuffer();
                    await this.processZipFile(arrayBuffer);
                    return;
                } else if (file.name.endsWith('.gz')) {
                    const arrayBuffer = await file.arrayBuffer();
                    const decompressed = pako.inflate(new Uint8Array(arrayBuffer), { to: 'string' });
                    content = decompressed;
                } else {
                    content = await file.text();
                }
                
                await this.processLogData(content);
                this.showToast('Log file processed successfully!', 'success');
            } catch (error) {
                console.error('Error processing file:', error);
                this.showToast('Failed to process file: ' + error.message, 'error');
            } finally {
                this.isLoading = false;
            }
        },
        
        async processZipFile(arrayBuffer) {
            const zip = new JSZip();
            const zipContent = await zip.loadAsync(arrayBuffer);
            
            // Find all potential log files
            const logFiles = Object.keys(zipContent.files).filter(name => {
                const file = zipContent.files[name];
                return !file.dir && (
                    name.endsWith('.log') || 
                    name.endsWith('.txt') ||
                    name.includes('log') ||
                    name.includes('access') ||
                    name.includes('error')
                );
            });
            
            if (logFiles.length === 0) {
                throw new Error('No log files found in the ZIP archive');
            }
            
            // Use the first log file found
            const firstLogFile = logFiles[0];
            const content = await zipContent.files[firstLogFile].async('text');
            
            this.showToast(`Found ${logFiles.length} log file(s), processing: ${firstLogFile}`, 'info');
            await this.processLogData(content);
        },
        
        async processLogData(content) {
            const lines = content.split('\n').filter(line => line.trim());
            this.logData = [];
            
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;
                
                const logEntry = this.parseLogLine(line);
                if (logEntry) {
                    logEntry.id = i;
                    this.logData.push(logEntry);
                }
            }
            
            this.updateAvailableFilters();
            this.showToast(`Processed ${this.logData.length} log entries`, 'success');
        },
        
        parseLogLine(line) {
            // Apache Common Log Format parser - enhanced
            const apacheRegex = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?/;
            const match = line.match(apacheRegex);
            
            if (match) {
                return {
                    ip: match[1],
                    timestamp: match[2],
                    method: match[3],
                    url: match[4],
                    status: match[5],
                    size: match[6] === '-' ? 0 : parseInt(match[6]),
                    referer: match[7] || '',
                    userAgent: match[8] || '',
                    raw: line
                };
            }
            
            // Try alternative formats
            const nginxRegex = /^(\S+) - - \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) (\S+) "([^"]*)" "([^"]*)"/;
            const nginxMatch = line.match(nginxRegex);
            
            if (nginxMatch) {
                return {
                    ip: nginxMatch[1],
                    timestamp: nginxMatch[2],
                    method: nginxMatch[3],
                    url: nginxMatch[4],
                    status: nginxMatch[5],
                    size: nginxMatch[6] === '-' ? 0 : parseInt(nginxMatch[6]),
                    referer: nginxMatch[7] || '',
                    userAgent: nginxMatch[8] || '',
                    raw: line
                };
            }
            
            return null;
        },
        
        updateAvailableFilters() {
            const methods = [...new Set(this.logData.map(entry => entry.method).filter(Boolean))];
            const statuses = [...new Set(this.logData.map(entry => entry.status).filter(Boolean))];
            const ips = [...new Set(this.logData.map(entry => entry.ip).filter(Boolean))].slice(0, 50); // Limit IPs
            
            this.availableFilters = {
                methods: methods.sort(),
                statuses: statuses.sort(),
                ips: ips.sort()
            };
        },
        
        async runAllScans() {
            if (this.logData.length === 0) {
                this.showToast('Please load log data first', 'warning');
                return;
            }
            
            this.isScanning = true;
            this.showToast('Running all security scans...', 'info');
            
            for (const attackType of this.attackTypes) {
                await this.runScan(attackType, false);
            }
            
            this.isScanning = false;
            this.showToast('All scans completed!', 'success');
        },
        
        async runScan(attackType, showToast = true) {
            if (this.logData.length === 0) {
                this.showToast('Please load log data first', 'warning');
                return;
            }
            
            this.scanningTypes.push(attackType.endpoint);
            
            if (showToast) {
                this.showToast(`Running ${attackType.name} scan...`, 'info');
            }
            
            try {
                // Simulate processing time
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                const detectionFunction = detectionFunctions[attackType.endpoint];
                if (!detectionFunction) {
                    throw new Error(`Detection function not found for ${attackType.endpoint}`);
                }
                
                const threats = [];
                
                for (const logEntry of this.logData) {
                    if (detectionFunction.detect(logEntry)) {
                        threats.push(logEntry);
                    }
                }
                
                // Update or add analysis result
                const existingIndex = this.analysisResults.findIndex(r => r.type === attackType.endpoint);
                const result = {
                    type: attackType.endpoint,
                    name: attackType.name,
                    color: attackType.color,
                    severity: attackType.severity,
                    description: attackType.description,
                    threats: threats,
                    timestamp: new Date().toISOString()
                };
                
                if (existingIndex >= 0) {
                    this.analysisResults[existingIndex] = result;
                } else {
                    this.analysisResults.push(result);
                }
                
                if (showToast) {
                    this.showToast(`${attackType.name} scan completed: ${threats.length} threats found`, 'success');
                }
            } catch (error) {
                console.error('Error running scan:', error);
                if (showToast) {
                    this.showToast(`Failed to run ${attackType.name} scan: ${error.message}`, 'error');
                }
            } finally {
                const index = this.scanningTypes.indexOf(attackType.endpoint);
                if (index > -1) {
                    this.scanningTypes.splice(index, 1);
                }
            }
        },
        
        viewFunction(attackType) {
            const detectionFunction = detectionFunctions[attackType.endpoint];
            if (detectionFunction) {
                this.currentFunction = detectionFunction;
                this.showFunctionModal = true;
            }
        },
        
        closeFunctionModal() {
            this.showFunctionModal = false;
            this.currentFunction = null;
        },
        
        viewResult(attackType) {
            const result = this.getAnalysisResult(attackType.endpoint);
            if (result) {
                this.currentResult = result;
                this.showResultModal = true;
            }
        },
        
        closeResultModal() {
            this.showResultModal = false;
            this.currentResult = null;
        },
        
        getAnalysisResult(endpoint) {
            return this.analysisResults.find(r => r.type === endpoint);
        },
        
        // AI Analysis Methods
        async createCustomAnalysis(description) {
            if (!this.aiApiKey) {
                this.showToast('Please configure your AI API key first', 'warning');
                return;
            }
            
            if (!description.trim()) {
                this.showToast('Please provide a description for the analysis', 'warning');
                return;
            }
            
            this.showToast('Creating custom analysis...', 'info');
            
            try {
                const prompt = this.buildAnalysisPrompt(description);
                const functionCode = await this.callAI(prompt);
                
                // Parse and execute the generated function
                const customFunction = this.parseGeneratedFunction(functionCode, description);
                
                // Run the analysis
                const threats = [];
                for (const logEntry of this.logData) {
                    if (customFunction.detect(logEntry)) {
                        threats.push(logEntry);
                    }
                }
                
                const result = {
                    type: 'custom-' + Date.now(),
                    name: customFunction.name,
                    color: '#8B5CF6',
                    severity: 'medium',
                    description: description,
                    threats: threats,
                    timestamp: new Date().toISOString(),
                    isCustom: true,
                    code: functionCode
                };
                
                this.customAnalysisResults.push(result);
                this.showToast(`Custom analysis completed: ${threats.length} threats found`, 'success');
                
            } catch (error) {
                console.error('Error creating custom analysis:', error);
                this.showToast('Failed to create custom analysis: ' + error.message, 'error');
            }
        },
        
        buildAnalysisPrompt(description) {
            return `Create a JavaScript function to detect security threats in web server logs based on this description: "${description}"

The function should:
1. Take a logEntry object with properties: ip, timestamp, method, url, status, size, referer, userAgent, raw
2. Return true if the log entry matches the threat pattern, false otherwise
3. Use appropriate regex patterns and logic to detect the specified threats
4. Be efficient and accurate

Example log entry structure:
{
  ip: "192.168.1.1",
  timestamp: "10/Oct/2000:13:55:36 -0700",
  method: "GET",
  url: "/apache_pb.gif",
  status: "200",
  size: 2326,
  referer: "http://www.example.com/start.html",
  userAgent: "Mozilla/4.08 [en] (Win98; I ;Nav)",
  raw: "192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326 \"http://www.example.com/start.html\" \"Mozilla/4.08 [en] (Win98; I ;Nav)\""
}

Return only the JavaScript function code, no explanations:`;
        },
        
        async callAI(prompt) {
            const provider = this.currentProvider;
            let endpoint, headers, body;
            
            switch (provider.id) {
                case 'gemini':
                    endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${this.aiApiKey}`;
                    headers = { 'Content-Type': 'application/json' };
                    body = {
                        contents: [{ parts: [{ text: prompt }] }],
                        generationConfig: { temperature: 0.1, maxOutputTokens: 2048 }
                    };
                    break;
                    
                case 'openai':
                    endpoint = 'https://api.openai.com/v1/chat/completions';
                    headers = {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.aiApiKey}`
                    };
                    body = {
                        model: 'gpt-3.5-turbo',
                        messages: [{ role: 'user', content: prompt }],
                        temperature: 0.1,
                        max_tokens: 2048
                    };
                    break;
                    
                case 'anthropic':
                    endpoint = 'https://api.anthropic.com/v1/messages';
                    headers = {
                        'Content-Type': 'application/json',
                        'x-api-key': this.aiApiKey,
                        'anthropic-version': '2023-06-01'
                    };
                    body = {
                        model: 'claude-3-sonnet-20240229',
                        max_tokens: 2048,
                        messages: [{ role: 'user', content: prompt }]
                    };
                    break;
                    
                case 'aipipe':
                case 'custom':
                    endpoint = this.customEndpoint || provider.defaultEndpoint;
                    headers = {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.aiApiKey}`
                    };
                    body = {
                        model: 'gpt-3.5-turbo',
                        messages: [{ role: 'user', content: prompt }],
                        temperature: 0.1,
                        max_tokens: 2048
                    };
                    break;
            }
            
            const response = await fetch(endpoint, {
                method: 'POST',
                headers,
                body: JSON.stringify(body)
            });
            
            if (!response.ok) {
                throw new Error(`AI API request failed: ${response.status} ${response.statusText}`);
            }
            
            const data = await response.json();
            
            // Extract response based on provider
            switch (provider.id) {
                case 'gemini':
                    return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
                case 'openai':
                case 'aipipe':
                case 'custom':
                    return data.choices?.[0]?.message?.content || '';
                case 'anthropic':
                    return data.content?.[0]?.text || '';
                default:
                    throw new Error('Unknown AI provider response format');
            }
        },
        
        parseGeneratedFunction(code, description) {
            try {
                // Extract function from code
                const functionMatch = code.match(/function\s+\w+\s*\([^)]*\)\s*\{[\s\S]*\}/);
                if (!functionMatch) {
                    throw new Error('No valid function found in generated code');
                }
                
                const functionCode = functionMatch[0];
                
                // Create a safe function
                const func = new Function('logEntry', `
                    ${functionCode}
                    return ${functionCode.match(/function\s+(\w+)/)[1]}(logEntry);
                `);
                
                return {
                    name: `Custom: ${description.substring(0, 50)}${description.length > 50 ? '...' : ''}`,
                    description: description,
                    code: functionCode,
                    detect: func
                };
            } catch (error) {
                throw new Error('Failed to parse generated function: ' + error.message);
            }
        },
        
        // Report Generation Methods
        async generateReport() {
            if (this.analysisResults.length === 0 && this.customAnalysisResults.length === 0) {
                this.showToast('No analysis results available for report generation', 'warning');
                return;
            }
            
            this.showReportModal = true;
            
            if (!this.aiApiKey) {
                return; // Show config panel
            }
            
            this.isGeneratingReport = true;
            
            try {
                const reportPrompt = this.buildReportPrompt();
                const reportContent = await this.callAI(reportPrompt);
                
                this.reportMarkdown = reportContent;
                this.reportContent = marked.parse(reportContent);
                
                this.showToast('Security report generated successfully!', 'success');
            } catch (error) {
                console.error('Error generating report:', error);
                this.showToast('Failed to generate report: ' + error.message, 'error');
            } finally {
                this.isGeneratingReport = false;
            }
        },
        
        buildReportPrompt() {
            const allResults = [...this.analysisResults, ...this.customAnalysisResults];
            const totalThreats = allResults.reduce((sum, result) => sum + result.threats.length, 0);
            
            let prompt = `Generate a comprehensive cybersecurity analysis report based on the following log analysis results:

**Analysis Summary:**
- Total log entries analyzed: ${this.logData.length}
- Total security threats detected: ${totalThreats}
- Analysis types performed: ${allResults.length}

**Detailed Results:**
`;
            
            for (const result of allResults) {
                prompt += `
**${result.name}** (${result.severity} severity)
- Description: ${result.description}
- Threats detected: ${result.threats.length}
- Sample threats: ${result.threats.slice(0, 3).map(t => `${t.ip} - ${t.method} ${t.url} (${t.status})`).join(', ')}
`;
            }
            
            prompt += `
Please create a professional security report in Markdown format that includes:

1. **Executive Summary** - High-level overview of security posture
2. **Threat Analysis** - Detailed breakdown of each threat type
3. **Risk Assessment** - Severity levels and potential impact
4. **Recommendations** - Specific actionable security measures
5. **Technical Details** - Key findings and patterns
6. **Conclusion** - Overall security assessment and next steps

Use proper Markdown formatting with headers, tables, lists, and emphasis. Make it suitable for both technical and executive audiences.`;
            
            return prompt;
        },
        
        closeReportModal() {
            this.showReportModal = false;
            this.reportContent = '';
            this.reportMarkdown = '';
        },
        
        copyReport() {
            const content = this.reportTab === 'preview' ? this.reportMarkdown : this.reportMarkdown;
            navigator.clipboard.writeText(content).then(() => {
                this.showToast('Report copied to clipboard!', 'success');
            });
        },
        
        downloadMarkdown() {
            const blob = new Blob([this.reportMarkdown], { type: 'text/markdown' });
            saveAs(blob, 'security-analysis-report.md');
        },
        
        downloadHTML() {
            const html = `<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .severity-high { color: #dc2626; font-weight: bold; }
        .severity-medium { color: #ea580c; font-weight: bold; }
        .severity-low { color: #059669; font-weight: bold; }
    </style>
</head>
<body>
${this.reportContent}
</body>
</html>`;
            const blob = new Blob([html], { type: 'text/html' });
            saveAs(blob, 'security-analysis-report.html');
        },
        
        exportCSV() {
            if (this.analysisResults.length === 0) {
                this.showToast('No analysis results to export', 'warning');
                return;
            }
            
            let csvContent = 'Attack Type,Timestamp,IP Address,Method,URL,Status Code,User Agent\n';
            
            for (const result of [...this.analysisResults, ...this.customAnalysisResults]) {
                for (const threat of result.threats) {
                    const row = [
                        result.name,
                        threat.timestamp,
                        threat.ip,
                        threat.method,
                        threat.url.replace(/"/g, '""'),
                        threat.status,
                        (threat.userAgent || '').replace(/"/g, '""')
                    ];
                    csvContent += '"' + row.join('","') + '"\n';
                }
            }
            
            const blob = new Blob([csvContent], { type: 'text/csv' });
            saveAs(blob, 'security-analysis-results.csv');
            this.showToast('CSV exported successfully!', 'success');
        },
        
        exportJSON() {
            if (this.analysisResults.length === 0) {
                this.showToast('No analysis results to export', 'warning');
                return;
            }
            
            const exportData = {
                exportDate: new Date().toISOString(),
                totalLogEntries: this.logData.length,
                analysisResults: [...this.analysisResults, ...this.customAnalysisResults].map(result => ({
                    attackType: result.name,
                    endpoint: result.type,
                    severity: result.severity,
                    description: result.description,
                    threatsFound: result.threats.length,
                    threats: result.threats,
                    isCustom: result.isCustom || false
                }))
            };
            
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            saveAs(blob, 'security-analysis-results.json');
            this.showToast('JSON exported successfully!', 'success');
        },
        
        // Filter methods
        toggleMethodFilter(method) {
            const index = this.dataFilters.selectedMethods.indexOf(method);
            if (index > -1) {
                this.dataFilters.selectedMethods.splice(index, 1);
            } else {
                this.dataFilters.selectedMethods.push(method);
            }
        },
        
        toggleStatusFilter(status) {
            const index = this.dataFilters.selectedStatuses.indexOf(status);
            if (index > -1) {
                this.dataFilters.selectedStatuses.splice(index, 1);
            } else {
                this.dataFilters.selectedStatuses.push(status);
            }
        },
        
        toggleIPFilter(ip) {
            const index = this.dataFilters.selectedIPs.indexOf(ip);
            if (index > -1) {
                this.dataFilters.selectedIPs.splice(index, 1);
            } else {
                this.dataFilters.selectedIPs.push(ip);
            }
        },
        
        clearFilters() {
            this.dataFilters = {
                searchTerm: '',
                selectedMethods: [],
                selectedStatuses: [],
                selectedIPs: [],
                dateRange: { start: '', end: '' }
            };
        },
        
        getMethodClass(method) {
            const classes = {
                'GET': 'method-get',
                'POST': 'method-post',
                'PUT': 'method-put',
                'DELETE': 'method-delete'
            };
            return classes[method] || 'method-get';
        },
        
        getStatusClass(status) {
            const code = parseInt(status);
            if (code >= 200 && code < 300) return 'status-2xx';
            if (code >= 300 && code < 400) return 'status-3xx';
            if (code >= 400 && code < 500) return 'status-4xx';
            if (code >= 500) return 'status-5xx';
            return 'status-2xx';
        }
    }
}).mount('#app');