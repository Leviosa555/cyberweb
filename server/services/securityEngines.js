const axios = require('axios');
const crypto = require('crypto');

class SecurityEngineManager {
    constructor() {
        this.engines = new Map();
        this.initializeEngines();
    }

    initializeEngines() {
        this.engines.set('googleSafeBrowsing', new GoogleSafeBrowsingEngine());
        this.engines.set('virusTotal', new VirusTotalEngine());
        this.engines.set('urlScan', new URLScanEngine());
        this.engines.set('abuseIPDB', new AbuseIPDBEngine());
        this.engines.set('ipQualityScore', new IPQualityScoreEngine());
    }
    
    async scanURL(url, options = {}) {
        const results = {
            url,
            timestamp: new Date().toISOString(),
            engines: {},
            summary: {
                totalEngines: 0,
                cleanResults: 0,
                suspiciousResults: 0,
                maliciousResults: 0,
                unavailableResults: 0
            }
        };

        const enginePromises = Array.from(this.engines.entries()).map(
            ([name, engine]) => this.scanWithEngine(name, engine, url, options)
        );

        const engineResults = await Promise.allSettled(enginePromises);

        engineResults.forEach((result, index) => {
            const engineName = Array.from(this.engines.keys())[index];
            results.engines[engineName] = this.processEngineResult(result);
            this.updateSummary(results.summary, results.engines[engineName]);
        });

        results.overallThreatLevel = this.calculateOverallThreatLevel(results.summary);
        results.securityScore = this.calculateSecurityScore(results.summary, results.engines);
        
        return results;
    }

    async scanWithEngine(name, engine, url, options) {
        try {
            const result = await engine.scan(url, options);
            return { engine: name, ...result };
        } catch (error) {
            console.error(`Engine ${name} failed:`, error.message);
            throw error;
        }
    }

    processEngineResult(result) {
        if (result.status === 'fulfilled') {
            return {
                status: 'completed',
                data: result.value,
                timestamp: new Date().toISOString()
            };
        } else {
            return {
                status: 'error',
                error: result.reason?.message || 'Engine unavailable',
                timestamp: new Date().toISOString()
            };
        }
    }

    updateSummary(summary, engineResult) {
        summary.totalEngines++;
        
        if (engineResult.status === 'completed') {
            switch (engineResult.data.threatLevel) {
                case 'clean':
                    summary.cleanResults++;
                    break;
                case 'suspicious':
                    summary.suspiciousResults++;
                    break;
                case 'malicious':
                    summary.maliciousResults++;
                    break;
                default:
                    summary.unavailableResults++;
            }
        } else {
            summary.unavailableResults++;
        }
    }

    calculateOverallThreatLevel(summary) {
        if (summary.maliciousResults > 0) return 'high';
        if (summary.suspiciousResults > 0) return 'medium';
        if (summary.cleanResults > 0) return 'low';
        return 'unknown';
    }

    calculateSecurityScore(summary, engines) {
        let score = 100;
        const totalActive = summary.totalEngines - summary.unavailableResults;
        
        if (totalActive === 0) return 0;
        
        const suspiciousRatio = summary.suspiciousResults / totalActive;
        const maliciousRatio = summary.maliciousResults / totalActive;
        
        score -= (suspiciousRatio * 30);
        score -= (maliciousRatio * 60);
        
        if (engines.googleSafeBrowsing?.data?.threatLevel === 'malicious') score -= 15;
        if (engines.virusTotal?.data?.positives > 5) score -= 20;
        
        return Math.max(0, Math.round(score));
    }
}

// Google Safe Browsing Engine Implementation
class GoogleSafeBrowsingEngine {
    async scan(url) {
        const requestBody = {
            client: {
                clientId: "cyberscan-analyzer",
                clientVersion: "1.0.0"
            },
            threatInfo: {
                threatTypes: [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };

        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_API_KEY}`,
            requestBody,
            { timeout: 10000 }
        );

        const threats = response.data.matches || [];
        
        return {
            engine: 'Google Safe Browsing',
            threatLevel: threats.length > 0 ? 'malicious' : 'clean',
            threats: threats.map(threat => ({
                type: threat.threatType,
                platform: threat.platformType
            })),
            lastUpdated: new Date().toISOString(),
            details: {
                threatsFound: threats.length,
                coverage: 'Global web threat database'
            }
        };
    }
}

// VirusTotal Engine Implementation
class VirusTotalEngine {
    async scan(url) {
        const response = await axios.post(
            'https://www.virustotal.com/vtapi/v2/url/report',
            `apikey=${process.env.VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(url)}`,
            {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                timeout: 15000
            }
        );

        const data = response.data;
        
        if (data.response_code === 1) {
            const positives = data.positives || 0;
            const total = data.total || 0;
            
            let threatLevel = 'clean';
            if (positives > 0) {
                threatLevel = positives > 5 ? 'malicious' : 'suspicious';
            }
            
            return {
                engine: 'VirusTotal',
                threatLevel,
                positives,
                total,
                scanDate: data.scan_date,
                permalink: data.permalink,
                details: {
                    detectionRatio: `${positives}/${total}`,
                    engines: total,
                    lastScan: data.scan_date
                }
            };
        } else {
            return {
                engine: 'VirusTotal',
                threatLevel: 'clean',
                positives: 0,
                total: 0,
                status: 'not_found',
                details: {
                    message: 'URL not in database'
                }
            };
        }
    }
}

// URLScan.io Engine Implementation
class URLScanEngine {
    async scan(url) {
        try {
            const submitResponse = await axios.post(
                'https://urlscan.io/api/v1/scan/',
                { url, visibility: 'public' },
                {
                    headers: {
                        'API-Key': process.env.URLSCAN_API_KEY,
                        'Content-Type': 'application/json'
                    },
                    timeout: 10000
                }
            );

            const scanId = submitResponse.data.uuid;
            
            return {
                engine: 'URLScan.io',
                threatLevel: 'clean',
                scanId,
                status: 'queued',
                details: {
                    message: 'Scan submitted successfully',
                    scanId
                }
            };
        } catch (error) {
            return {
                engine: 'URLScan.io',
                threatLevel: 'clean',
                status: 'error',
                details: {
                    error: error.message
                }
            };
        }
    }
}

// AbuseIPDB Engine Implementation
class AbuseIPDBEngine {
    async scan(url) {
        try {
            const domain = new URL(url).hostname;
            const response = await axios.get(
                `https://api.abuseipdb.com/api/v2/check?ipAddress=${domain}&maxAgeInDays=90`,
                {
                    headers: {
                        'Key': process.env.ABUSEIPDB_API_KEY,
                        'Accept': 'application/json'
                    },
                    timeout: 10000
                }
            );

            const data = response.data.data;
            const abuseConfidence = data.abuseConfidencePercentage;
            
            let threatLevel = 'clean';
            if (abuseConfidence > 75) threatLevel = 'malicious';
            else if (abuseConfidence > 25) threatLevel = 'suspicious';
            
            return {
                engine: 'AbuseIPDB',
                threatLevel,
                abuseConfidence,
                totalReports: data.totalReports,
                details: {
                    countryCode: data.countryCode,
                    usageType: data.usageType,
                    isp: data.isp
                }
            };
        } catch (error) {
            return {
                engine: 'AbuseIPDB',
                threatLevel: 'clean',
                status: 'error',
                details: { error: error.message }
            };
        }
    }
}

// IPQualityScore Engine Implementation
class IPQualityScoreEngine {
    async scan(url) {
        try {
            const response = await axios.get(
                `https://ipqualityscore.com/api/json/url/${process.env.IPQS_API_KEY}/${encodeURIComponent(url)}`,
                { timeout: 10000 }
            );

            const data = response.data;
            
            let threatLevel = 'clean';
            if (data.malware || data.phishing || data.suspicious) {
                threatLevel = 'malicious';
            } else if (data.risk_score > 75) {
                threatLevel = 'suspicious';
            }
            
            return {
                engine: 'IPQualityScore',
                threatLevel,
                riskScore: data.risk_score,
                malware: data.malware,
                phishing: data.phishing,
                suspicious: data.suspicious,
                details: {
                    category: data.category,
                    domainAge: data.domain_age,
                    countryCode: data.country_code,
                    server: data.server
                }
            };
        } catch (error) {
            return {
                engine: 'IPQualityScore',
                threatLevel: 'clean',
                status: 'error',
                details: { error: error.message }
            };
        }
    }
}

module.exports = SecurityEngineManager;
