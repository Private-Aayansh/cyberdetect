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

// Detection functions - exact same logic as original
const detectionFunctions = {
    'sql-injection': {
        name: 'SQL Injection',
        description: 'Detects SQL injection attempts in URLs and parameters',
        code: `function detectSQLInjection(logEntry) {
    const sqlPatterns = [
        /('|(\\%27))|(;|(\\%3B))/i,
        /(union|select|insert|update|delete|drop|create|alter|exec|execute)/i,
        /(\\'|\\"|\\;|\\%27|\\%22|\\%3B)/i,
        /(or|and)\\s+(1=1|true|false)/i,
        /\\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\\b/i,
        /\\b(script|javascript|vbscript|onload|onerror|onclick)/i
    ];
    
    const url = logEntry.url || '';
    const userAgent = logEntry.userAgent || '';
    
    return sqlPatterns.some(pattern => 
        pattern.test(url) || pattern.test(userAgent)
    );
}`,
        detect: function(logEntry) {
            const sqlPatterns = [
                /('|(\%27))|(;|(\%3B))/i,
                /(union|select|insert|update|delete|drop|create|alter|exec|execute)/i,
                /(\\'|\\"|\\;|\%27|\%22|\%3B)/i,
                /(or|and)\s+(1=1|true|false)/i,
                /\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b/i,
                /\b(script|javascript|vbscript|onload|onerror|onclick)\b/i
            ];
            
            const url = logEntry.url || '';
            const userAgent = logEntry.userAgent || '';
            
            return sqlPatterns.some(pattern => 
                pattern.test(url) || pattern.test(userAgent)
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
        /\\/etc\\/passwd|\\/etc\\/shadow/i,
        /\\/windows\\/system32/i,
        /\\.\\.\\\\|\\.\\.\\//i
    ];
    
    const url = logEntry.url || '';
    
    return pathPatterns.some(pattern => pattern.test(url));
}`,
        detect: function(logEntry) {
            const pathPatterns = [
                /\.\.\//i,
                /\.\.\\/i,
                /%2e%2e%2f|%2e%2e%5c/i,
                /%252e%252e%252f/i,
                /\/etc\/passwd|\/etc\/shadow/i,
                /\/windows\/system32/i,
                /\.\.\\/i
            ];
            
            const url = logEntry.url || '';
            
            return pathPatterns.some(pattern => pattern.test(url));
        }
    },
    'bots': {
        name: 'Bot Detection',
        description: 'Identifies automated bot and crawler activity',
        code: `function detectBots(logEntry) {
    const botPatterns = [
        /bot|crawler|spider|scraper/i,
        /curl|wget|python|java|go-http/i,
        /automated|script|tool/i,
        /scan|probe|test/i
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
        /\\/admin/i
    ];
    
    const isSuspiciousRequest = suspiciousPatterns.some(pattern => pattern.test(url));
    
    return isBotUserAgent || isSuspiciousRequest;
}`,
        detect: function(logEntry) {
            const botPatterns = [
                /bot|crawler|spider|scraper/i,
                /curl|wget|python|java|go-http/i,
                /automated|script|tool/i,
                /scan|probe|test/i
            ];
            
            const userAgent = logEntry.userAgent || '';
            const url = logEntry.url || '';
            
            const isBotUserAgent = botPatterns.some(pattern => pattern.test(userAgent));
            
            const suspiciousPatterns = [
                /\/robots\.txt/i,
                /\/sitemap\.xml/i,
                /\/wp-admin/i,
                /\/admin/i
            ];
            
            const isSuspiciousRequest = suspiciousPatterns.some(pattern => pattern.test(url));
            
            return isBotUserAgent || isSuspiciousRequest;
        }
    },
    'lfi-rfi': {
        name: 'LFI/RFI Attacks',
        description: 'Detects Local and Remote File Inclusion attempts',
        code: `function detectLFIRFI(logEntry) {
    const lfiPatterns = [
        /\\?.*file=|\\?.*page=|\\?.*include=/i,
        /php:\\/\\/|data:\\/\\/|expect:\\/\\//i,
        /\\/proc\\/self\\/environ/i,
        /\\/var\\/log/i,
        /\\.\\.\\//i
    ];
    
    const rfiPatterns = [
        /http:\\/\\/|https:\\/\\/|ftp:\\/\\//i,
        /\\?.*url=http|\\?.*file=http/i
    ];
    
    const url = logEntry.url || '';
    
    const isLFI = lfiPatterns.some(pattern => pattern.test(url));
    const isRFI = rfiPatterns.some(pattern => pattern.test(url));
    
    return isLFI || isRFI;
}`,
        detect: function(logEntry) {
            const lfiPatterns = [
                /\?.*file=|\?.*page=|\?.*include=/i,
                /php:\/\/|data:\/\/|expect:\/\//i,
                /\/proc\/self\/environ/i,
                /\/var\/log/i,
                /\.\.\//i
            ];
            
            const rfiPatterns = [
                /http:\/\/|https:\/\/|ftp:\/\//i,
                /\?.*url=http|\?.*file=http/i
            ];
            
            const url = logEntry.url || '';
            
            const isLFI = lfiPatterns.some(pattern => pattern.test(url));
            const isRFI = rfiPatterns.some(pattern => pattern.test(url));
            
            return isLFI || isRFI;
        }
    },
    'wp-probe': {
        name: 'WordPress Probes',
        description: 'Detects WordPress-specific vulnerability scanning',
        code: `function detectWordPressProbes(logEntry) {
    const wpPatterns = [
        /\\/wp-admin|\\/wp-login|\\/wp-content/i,
        /\\/wp-includes|\\/wp-config/i,
        /\\/xmlrpc\\.php/i,
        /\\/wp-json/i,
        /wp-|wordpress/i
    ];
    
    const url = logEntry.url || '';
    const userAgent = logEntry.userAgent || '';
    
    return wpPatterns.some(pattern => 
        pattern.test(url) || pattern.test(userAgent)
    );
}`,
        detect: function(logEntry) {
            const wpPatterns = [
                /\/wp-admin|\/wp-login|\/wp-content/i,
                /\/wp-includes|\/wp-config/i,
                /\/xmlrpc\.php/i,
                /\/wp-json/i,
                /wp-|wordpress/i
            ];
            
            const url = logEntry.url || '';
            const userAgent = logEntry.userAgent || '';
            
            return wpPatterns.some(pattern => 
                pattern.test(url) || pattern.test(userAgent)
            );
        }
    },
    'brute-force': {
        name: 'Brute Force',
        description: 'Detects brute force and credential stuffing attacks',
        code: `function detectBruteForce(logEntry) {
    const bruteForcePatterns = [
        /\\/login|\\/signin|\\/auth/i,
        /\\/admin|\\/administrator/i,
        /password|passwd|pwd/i,
        /username|user|email/i
    ];
    
    const url = logEntry.url || '';
    const method = logEntry.method || '';
    const status = parseInt(logEntry.status) || 0;
    
    // Check for login-related URLs
    const isLoginAttempt = bruteForcePatterns.some(pattern => pattern.test(url));
    
    // Check for POST requests to login endpoints with failed status
    const isFailedLogin = method === 'POST' && (status === 401 || status === 403);
    
    return isLoginAttempt && isFailedLogin;
}`,
        detect: function(logEntry) {
            const bruteForcePatterns = [
                /\/login|\/signin|\/auth/i,
                /\/admin|\/administrator/i,
                /password|passwd|pwd/i,
                /username|user|email/i
            ];
            
            const url = logEntry.url || '';
            const method = logEntry.method || '';
            const status = parseInt(logEntry.status) || 0;
            
            const isLoginAttempt = bruteForcePatterns.some(pattern => pattern.test(url));
            const isFailedLogin = method === 'POST' && (status === 401 || status === 403);
            
            return isLoginAttempt && isFailedLogin;
        }
    },
    'errors': {
        name: 'HTTP Errors',
        description: 'Detects suspicious HTTP error patterns',
        code: `function detectHTTPErrors(logEntry) {
    const status = parseInt(logEntry.status) || 0;
    const url = logEntry.url || '';
    
    // Focus on 4xx and 5xx errors
    const isError = status >= 400;
    
    // Check for suspicious error patterns
    const suspiciousPatterns = [
        /\\.php|\\.asp|\\.jsp/i,
        /admin|config|backup/i,
        /test|debug|dev/i
    ];
    
    const isSuspiciousUrl = suspiciousPatterns.some(pattern => pattern.test(url));
    
    return isError && isSuspiciousUrl;
}`,
        detect: function(logEntry) {
            const status = parseInt(logEntry.status) || 0;
            const url = logEntry.url || '';
            
            const isError = status >= 400;
            
            const suspiciousPatterns = [
                /\.php|\.asp|\.jsp/i,
                /admin|config|backup/i,
                /test|debug|dev/i
            ];
            
            const isSuspiciousUrl = suspiciousPatterns.some(pattern => pattern.test(url));
            
            return isError && isSuspiciousUrl;
        }
    },
    'internal-ip': {
        name: 'Internal IP Access',
        description: 'Detects unauthorized access attempts to internal IP ranges',
        code: `function detectInternalIPAccess(logEntry) {
    const ip = logEntry.ip || '';
    const url = logEntry.url || '';
    
    // Check for internal IP patterns in URL
    const internalIPPatterns = [
        /192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\./,
        /127\\.0\\.0\\.1|localhost/i,
        /0\\.0\\.0\\.0|255\\.255\\.255\\.255/
    ];
    
    // Check for attempts to access internal resources
    const internalResourcePatterns = [
        /\\/internal|\\/private|\\/admin/i,
        /\\/config|\\/settings|\\/env/i
    ];
    
    const hasInternalIP = internalIPPatterns.some(pattern => 
        pattern.test(ip) || pattern.test(url)
    );
    
    const accessesInternalResource = internalResourcePatterns.some(pattern => 
        pattern.test(url)
    );
    
    return hasInternalIP || accessesInternalResource;
}`,
        detect: function(logEntry) {
            const ip = logEntry.ip || '';
            const url = logEntry.url || '';
            
            const internalIPPatterns = [
                /192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\./,
                /127\.0\.0\.1|localhost/i,
                /0\.0\.0\.0|255\.255\.255\.255/
            ];
            
            const internalResourcePatterns = [
                /\/internal|\/private|\/admin/i,
                /\/config|\/settings|\/env/i
            ];
            
            const hasInternalIP = internalIPPatterns.some(pattern => 
                pattern.test(ip) || pattern.test(url)
            );
            
            const accessesInternalResource = internalResourcePatterns.some(pattern => 
                pattern.test(url)
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
            selectedFile: null,
            isDragging: false,
            isLoading: false,
            isScanning: false,
            scanningTypes: [],
            toasts: [],
            showFunctionModal: false,
            currentFunction: null,
            isDarkMode: false
        };
    },
    mounted() {
        this.initializeTheme();
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
                const zip = new JSZip();
                const zipContent = await zip.loadAsync(arrayBuffer);
                
                // Find the log file in the zip
                const logFile = Object.keys(zipContent.files).find(name => 
                    name.endsWith('.log') || name.endsWith('.txt')
                );
                
                if (!logFile) {
                    throw new Error('No log file found in the demo dataset');
                }
                
                const logContent = await zipContent.files[logFile].async('text');
                await this.processLogData(logContent);
                
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
                    const zip = new JSZip();
                    const zipContent = await zip.loadAsync(file);
                    const logFile = Object.keys(zipContent.files).find(name => 
                        name.endsWith('.log') || name.endsWith('.txt')
                    );
                    
                    if (!logFile) {
                        throw new Error('No log file found in the ZIP archive');
                    }
                    
                    content = await zipContent.files[logFile].async('text');
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
            
            this.showToast(`Processed ${this.logData.length} log entries`, 'success');
        },
        
        parseLogLine(line) {
            // Apache Common Log Format parser
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
            
            return null;
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
        
        viewTable(attackType) {
            this.activeView = 'data';
            // Optionally scroll to the specific table
            this.$nextTick(() => {
                const element = document.querySelector(`[data-type="${attackType.endpoint}"]`);
                if (element) {
                    element.scrollIntoView({ behavior: 'smooth' });
                }
            });
        },
        
        getAnalysisResult(endpoint) {
            return this.analysisResults.find(r => r.type === endpoint);
        },
        
        exportCSV() {
            if (this.analysisResults.length === 0) {
                this.showToast('No analysis results to export', 'warning');
                return;
            }
            
            let csvContent = 'Attack Type,Timestamp,IP Address,Method,URL,Status Code,User Agent\n';
            
            for (const result of this.analysisResults) {
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
                analysisResults: this.analysisResults.map(result => ({
                    attackType: result.name,
                    endpoint: result.type,
                    threatsFound: result.threats.length,
                    threats: result.threats
                }))
            };
            
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            saveAs(blob, 'security-analysis-results.json');
            this.showToast('JSON exported successfully!', 'success');
        },
        
        generateReport() {
            this.showToast('Report generation feature coming soon!', 'info');
        }
    }
}).mount('#app');