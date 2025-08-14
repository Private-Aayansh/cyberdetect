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
        
        // Modal state
        const modalTitle = ref('');
        const modalContent = ref('');
        
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
            // Simulate parsing log data
            const sampleLogEntries = [
                '192.168.1.100 - - [10/Oct/2023:13:55:36 +0000] "GET /admin/login.php HTTP/1.1" 200 1234',
                '10.0.0.50 - - [10/Oct/2023:13:56:12 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 404 567',
                '172.16.0.25 - - [10/Oct/2023:13:57:45 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 890'
            ];
            
            logData.value = sampleLogEntries.map((entry, index) => ({
                id: index + 1,
                raw: entry,
                timestamp: new Date(),
                ip: entry.split(' ')[0],
                method: entry.match(/"(\w+)/)?.[1] || 'GET',
                path: entry.match(/"[A-Z]+ ([^"]+)/)?.[1] || '/',
                status: parseInt(entry.match(/"\s+(\d+)/)?.[1]) || 200
            }));
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
                    
                    // Simulate random results
                    const count = Math.floor(Math.random() * 50);
                    analysisResults.value[attackType.endpoint] = {
                        count,
                        details: generateMockDetails(attackType, count)
                    };
                }
                
                showToast('Security analysis completed', 'success');
            } catch (error) {
                showToast('Analysis failed', 'error');
            } finally {
                isAnalyzing.value = false;
            }
        };
        
        const runSingleScan = async (attackType) => {
            if (!selectedFile.value) {
                showToast('Please upload a log file first', 'warning');
                return;
            }
            
            try {
                // Simulate single scan
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                const count = Math.floor(Math.random() * 25);
                analysisResults.value[attackType.endpoint] = {
                    count,
                    details: generateMockDetails(attackType, count)
                };
                
                showToast(`${attackType.name} scan completed`, 'success');
                
                // Show details modal
                showAnalysisDetails(attackType);
            } catch (error) {
                showToast('Scan failed', 'error');
            }
        };
        
        const generateMockDetails = (attackType, count) => {
            const details = [];
            for (let i = 0; i < Math.min(count, 10); i++) {
                details.push({
                    id: i + 1,
                    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                    ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
                    path: `/suspicious/path/${i}`,
                    method: 'GET',
                    status: 200 + Math.floor(Math.random() * 400),
                    description: `${attackType.name} attempt detected`
                });
            }
            return details;
        };
        
        const showAnalysisDetails = (attackType) => {
            const result = analysisResults.value[attackType.endpoint];
            if (!result) return;
            
            modalTitle.value = `${attackType.name} - Analysis Details`;
            modalContent.value = `
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
                    </div>
                    
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Detections</h3>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                <thead class="bg-gray-50 dark:bg-gray-700">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">IP Address</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Path</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Status</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Time</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                    ${result.details.map(detail => `
                                        <tr>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">${detail.ip}</td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">${detail.path}</td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">${detail.status}</td>
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
        
        const closeDetailsModal = () => {
            showDetailsModal.value = false;
            modalTitle.value = '';
            modalContent.value = '';
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
                    details: []
                };
                
                customAnalysisResults.value.push(customAnalysis);
                customAnalysisDescription.value = '';
                
                showToast('Custom analysis created successfully', 'success');
            } catch (error) {
                showToast('Failed to create custom analysis', 'error');
            } finally {
                isCreatingAnalysis.value = false;
            }
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
                    </div>
                </div>
            `;
            showDetailsModal.value = true;
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
        
        const exportCSV = () => {
            if (!hasAnalysisResults.value) {
                showToast('No analysis results to export', 'warning');
                return;
            }
            
            // Simulate CSV export
            const csvData = 'Attack Type,Severity,Count,Description\n' +
                attackTypes.filter(type => analysisResults.value[type.endpoint]?.count > 0)
                    .map(type => `"${type.name}","${type.severity}","${analysisResults.value[type.endpoint].count}","${type.description}"`)
                    .join('\n');
            
            const blob = new Blob([csvData], { type: 'text/csv' });
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
            
            showToast('Report generation feature would be implemented here', 'info');
        };
        
        // Initialize theme on mount
        onMounted(() => {
            const savedTheme = localStorage.getItem('cyberdetect-vue-theme');
            if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                isDarkMode.value = true;
            }
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
            selectedFile,
            logData,
            analysisResults,
            customAnalysisResults,
            aiConfig,
            customAnalysisDescription,
            modalTitle,
            modalContent,
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
            
            // Methods
            showToast,
            removeToast,
            getToastIcon,
            toggleTheme,
            formatFileSize,
            getSeverityClass,
            handleDrop,
            handleFileSelect,
            handleFile,
            loadDemo,
            runAllScans,
            runSingleScan,
            showAnalysisDetails,
            closeDetailsModal,
            createCustomAnalysis,
            viewCustomAnalysisDetails,
            updateApiKeyLink,
            exportCSV,
            exportJSON,
            generateReport,
            handleDragEnter,
            handleDragLeave
        };
    }
}).mount('#app');