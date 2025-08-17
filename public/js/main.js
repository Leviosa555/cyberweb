class CyberScanApp {
    constructor() {
        this.initializeElements();
        this.initializeEventListeners();
        this.scanCount = parseInt(localStorage.getItem('scanCount') || '0');
        this.updateScanCount();
    }

    initializeElements() {
        this.form = document.getElementById('urlAnalyzerForm');
        this.urlInput = document.getElementById('urlInput');
        this.scanButton = document.getElementById('scanButton');
        this.resultsSection = document.getElementById('resultsSection');
        this.scanProgress = document.getElementById('scanProgress');
        this.scanResults = document.getElementById('scanResults');
        this.scanStatus = document.getElementById('scanStatus');
        this.progressFill = document.getElementById('progressFill');
        this.progressPercentage = document.getElementById('progressPercentage');
        this.scanCountElement = document.getElementById('scanCount');
    }

    initializeEventListeners() {
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleScan();
        });

        this.urlInput.addEventListener('input', () => {
            this.validateInput();
        });
    }

    validateInput() {
        const url = this.urlInput.value.trim();
        const isValid = this.isValidUrl(url);
        
        this.scanButton.disabled = !isValid;
        
        if (url && !isValid) {
            this.urlInput.style.borderColor = 'var(--danger-cyber)';
        } else if (isValid) {
            this.urlInput.style.borderColor = 'var(--border-cyber)';
        } else {
            this.urlInput.style.borderColor = 'var(--border-primary)';
        }
        
        return isValid;
    }

    isValidUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch {
            return false;
        }
    }

    async handleScan() {
        if (!this.validateInput()) return;
        
        const url = this.urlInput.value.trim();
        
        try {
            this.startScan(url);
            const results = await this.performScan(url);
            this.displayResults(results);
            this.updateScanCount();
        } catch (error) {
            this.showError(error.message || 'Scan failed. Please try again.');
        }
    }

    startScan(url) {
        this.resultsSection.style.display = 'block';
        this.scanProgress.style.display = 'block';
        this.scanResults.style.display = 'none';
        
        this.resultsSection.scrollIntoView({ behavior: 'smooth' });
        
        this.scanButton.disabled = true;
        this.scanButton.innerHTML = `
            <span class="btn-content">
                <i class="fas fa-spinner fa-spin"></i>
                <span class="btn-text">SCANNING...</span>
            </span>
        `;
        
        this.animateProgress();
    }

    animateProgress() {
        let progress = 0;
        const steps = [
            'Analyzing URL structure...',
            'Checking security databases...',
            'Performing threat analysis...',
            'Gathering intelligence data...',
            'Calculating security score...'
        ];
        
        let currentStep = 0;
        
        const updateProgress = () => {
            if (currentStep < steps.length) {
                this.scanStatus.textContent = steps[currentStep];
                progress += 20;
                this.progressFill.style.width = `${progress}%`;
                this.progressPercentage.textContent = `${progress}%`;
                currentStep++;
                setTimeout(updateProgress, 800 + Math.random() * 600);
            } else {
                this.progressFill.style.width = '100%';
                this.progressPercentage.textContent = '100%';
                this.scanStatus.textContent = 'Analysis complete!';
            }
        };
        
        setTimeout(updateProgress, 500);
    }

    async performScan(url) {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || `HTTP ${response.status}`);
        }

        const results = await response.json();
        
        // Wait for progress animation to complete
        await new Promise(resolve => setTimeout(resolve, 4000));
        
        return results.data;
    }

    displayResults(results) {
        setTimeout(() => {
            this.scanProgress.style.display = 'none';
            this.scanResults.style.display = 'block';
            
            this.populateResults(results);
            
            this.scanButton.disabled = false;
            this.scanButton.innerHTML = `
                <span class="btn-content">
                    <i class="fas fa-radar-chart"></i>
                    <span class="btn-text">SCAN URL</span>
                </span>
            `;
        }, 1000);
    }

    populateResults(results) {
        // Update timestamp
        document.getElementById('scanTimestamp').textContent = 
            `Scan completed: ${new Date(results.timestamp).toLocaleString()}`;
        
        // Update security score
        this.animateSecurityScore(results.securityScore);
        
        // Update threat summary
        document.getElementById('cleanEngines').textContent = results.summary.cleanResults;
        document.getElementById('suspiciousEngines').textContent = results.summary.suspiciousResults;
        document.getElementById('maliciousEngines').textContent = results.summary.maliciousResults;
        
        // Populate security engines
        this.populateSecurityEngines(results.engines);
        
        // Generate and populate recommendations
        this.populateRecommendations(results);
    }

    animateSecurityScore(score) {
        const scoreElement = document.getElementById('securityScore');
        let currentScore = 0;
        const increment = score / 50;
        
        const countUp = () => {
            currentScore += increment;
            if (currentScore < score) {
                scoreElement.textContent = Math.round(currentScore);
                requestAnimationFrame(countUp);
            } else {
                scoreElement.textContent = score;
            }
        };
        
        // Change color based on score
        let color = '#00ff41'; // Green
        if (score < 70) color = '#ffaa00'; // Orange
        if (score < 50) color = '#ff0040'; // Red
        
        scoreElement.style.color = color;
        scoreElement.style.textShadow = `0 0 20px ${color}`;
        
        setTimeout(countUp, 500);
    }

    populateSecurityEngines(engines) {
        const content = document.getElementById('securityEnginesContent');
        
        content.innerHTML = Object.entries(engines).map(([engineName, result]) => {
            const engineDisplayName = this.getEngineDisplayName(engineName);
            const status = result.status === 'completed' ? result.data.threatLevel : 'error';
            const statusClass = status === 'clean' ? 'safe' : status === 'suspicious' ? 'warning' : status === 'malicious' ? 'danger' : 'warning';
            const statusIcon = status === 'clean' ? 'fa-check-circle' : status === 'suspicious' ? 'fa-exclamation-triangle' : status === 'malicious' ? 'fa-times-circle' : 'fa-question-circle';
            
            return `
                <div class="engine-item">
                    <span class="engine-name">${engineDisplayName}</span>
                    <span class="status-indicator status-${statusClass}">
                        <i class="fas ${statusIcon}"></i>
                        ${status.toUpperCase()}
                    </span>
                </div>
            `;
        }).join('');
    }

    populateRecommendations(results) {
        const content = document.getElementById('recommendationsContent');
        const recommendations = this.generateRecommendations(results);
        
        content.innerHTML = recommendations.map(rec => `
            <div class="recommendation-item" style="margin-bottom: 1rem; padding: 1rem; background: var(--bg-secondary); border-radius: 8px; border-left: 4px solid ${rec.color};">
                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                    <i class="fas ${rec.icon}" style="color: ${rec.color};"></i>
                    <strong style="color: ${rec.color};">${rec.title}</strong>
                </div>
                <div style="color: var(--text-secondary); font-size: 0.9rem;">
                    ${rec.description}
                </div>
            </div>
        `).join('');
    }

    generateRecommendations(results) {
        const recommendations = [];
        
        if (results.overallThreatLevel === 'high') {
            recommendations.push({
                type: 'critical',
                title: 'CRITICAL: Malicious Content Detected',
                description: 'Multiple security engines have identified this URL as malicious. Do not visit this site and avoid sharing it.',
                icon: 'fa-skull-crossbones',
                color: '#ff0040'
            });
        } else if (results.overallThreatLevel === 'medium') {
            recommendations.push({
                type: 'warning',
                title: 'WARNING: Suspicious Activity',
                description: 'Some security engines have flagged potential issues. Exercise extreme caution when visiting this site.',
                icon: 'fa-exclamation-triangle',
                color: '#ffaa00'
            });
        } else if (results.securityScore > 85) {
            recommendations.push({
                type: 'safe',
                title: 'Site Appears Safe',
                description: 'No threats detected by security engines. The site appears legitimate and safe to visit.',
                icon: 'fa-check-circle',
                color: '#00ff41'
            });
        }
        
        // Additional recommendations based on specific engines
        if (results.engines.googleSafeBrowsing?.data?.threatLevel === 'malicious') {
            recommendations.push({
                type: 'critical',
                title: 'Google Safe Browsing Alert',
                description: 'This URL is flagged by Google Safe Browsing as unsafe. Avoid visiting this site.',
                icon: 'fa-shield-slash',
                color: '#ff0040'
            });
        }
        
        if (results.engines.virusTotal?.data?.positives > 0) {
            recommendations.push({
                type: 'warning',
                title: 'Antivirus Detection',
                description: `${results.engines.virusTotal.data.positives} out of ${results.engines.virusTotal.data.total} antivirus engines flagged this URL.`,
                icon: 'fa-virus',
                color: '#ffaa00'
            });
        }
        
        if (results.securityScore < 50) {
            recommendations.push({
                type: 'danger',
                title: 'Low Security Score',
                description: 'This URL has a very low security score indicating high risk. Consider avoiding this site.',
                icon: 'fa-exclamation-circle',
                color: '#ff0040'
            });
        }
        
        return recommendations;
    }

    getEngineDisplayName(engineName) {
        const names = {
            googleSafeBrowsing: 'Google Safe Browsing',
            virusTotal: 'VirusTotal',
            urlScan: 'URLScan.io',
            abuseIPDB: 'AbuseIPDB',
            ipQualityScore: 'IPQualityScore'
        };
        return names[engineName] || engineName;
    }

    updateScanCount() {
        this.scanCount++;
        this.scanCountElement.textContent = this.scanCount;
        localStorage.setItem('scanCount', this.scanCount.toString());
    }

    showError(message) {
        this.scanProgress.style.display = 'none';
        this.scanResults.innerHTML = `
            <div class="cyber-card error-card">
                <div class="error-content" style="text-align: center; padding: 2rem;">
                    <div class="error-icon" style="font-size: 3rem; color: var(--danger-cyber); margin-bottom: 1rem;">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <h3 style="color: var(--danger-cyber); margin-bottom: 1rem;">Scan Failed</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 2rem;">${message}</p>
                    <button class="cyber-btn" onclick="location.reload()" style="margin: 0 auto;">
                        <span class="btn-content">
                            <i class="fas fa-redo"></i>
                            <span class="btn-text">Try Again</span>
                        </span>
                    </button>
                </div>
            </div>
        `;
        this.scanResults.style.display = 'block';
        
        this.scanButton.disabled = false;
        this.scanButton.innerHTML = `
            <span class="btn-content">
                <i class="fas fa-radar-chart"></i>
                <span class="btn-text">SCAN URL</span>
            </span>
        `;
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.cyberScanApp = new CyberScanApp();
});
