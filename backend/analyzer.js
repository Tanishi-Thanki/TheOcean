const fastLevenshtein = require('fast-levenshtein');
const trustedDomains = require('./trustedDomains');
const OpenAI = require('openai');
require('dotenv').config();

// Initialize OpenAI client if key is present
let openai = null;
if (process.env.OPENAI_API_KEY) {
    openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
}

// Suspicious keywords often used in phishing
const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'account', 'update', 'confirm', 'secure', 'banking', 'free', 'gift', 'prize', 'reward'];

// Common URL shorteners
const URL_SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do'];

/**
 * Extract domain from URL safely
 */
function getDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch (error) {
        return null; // Invalid URL
    }
}

/**
 * Check for typosquatting against trusted domains
 */
function checkTyposquatting(domain) {
    if (!domain) return null;

    const findings = [];

    for (const trusted of trustedDomains) {
        if (domain === trusted) continue; // Exact match is fine (usually)

        // Calculate Levenshtein distance
        const distance = fastLevenshtein.get(domain, trusted);

        // If distance is small (1-2 chars) and domain is not trusted, it's suspicious
        // Also check if trusted domain is a substring of the scanned domain
        if (distance > 0 && distance <= 2) {
            findings.push(`Startlingly similar to trusted domain: ${trusted}`);
        } else if (domain.includes(trusted) && domain !== trusted) {
            // e.g. "google-login.com" vs "google.com"
            findings.push(`Contains trusted brand name: ${trusted}`);
        }
    }

    return findings;
}

/**
 * AI Analysis fallback (Rule-based explanation)
 */
function getRuleBasedExplanation(signals) {
    if (signals.length === 0) {
        return {
            riskLevel: "Low",
            riskScore: 10,
            attackVector: "None Detected",
            explanation: "No obvious threats detected by static analysis."
        };
    }

    const score = Math.min(100, signals.length * 25);
    let vector = "Suspicious Activity";
    if (signals.some(s => s.includes('Typosquatting'))) vector = "Typosquatting / Brand Spoofing";
    else if (signals.some(s => s.includes('IP address'))) vector = "Direct IP Access";

    return {
        riskLevel: score > 70 ? "High" : "Medium",
        riskScore: score,
        attackVector: vector,
        explanation: "Detected potential threats: " + signals.join(", ")
    };
}

/**
 * Main Analysis Function
 */
async function analyzeUrl(url) {
    const signals = [];

    // 1. Basic Validation
    if (!url) return { error: "No URL provided" };

    // 2. Protocol Check
    if (url.startsWith('http://')) {
        signals.push("Insecure HTTP protocol");
    }

    // 3. Domain Extraction & IP Check
    const domain = getDomain(url);
    if (!domain) {
        return {
            riskLevel: "High",
            riskScore: 100,
            attackVector: "Malformed URL",
            explanation: "The provided URL is invalid or malformed."
        };
    }

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
    if (isIp) {
        signals.push("Uses IP address instead of domain name");
    }

    // 4. Shortener Check
    if (URL_SHORTENERS.includes(domain)) {
        signals.push("Uses URL shortener (obfuscates destination)");
    }

    // 5. Keyword Check
    const urlLower = url.toLowerCase();
    const detectedKeywords = SUSPICIOUS_KEYWORDS.filter(k => urlLower.includes(k));
    if (detectedKeywords.length > 0) {
        signals.push(`Suspicious keywords found: ${detectedKeywords.join(', ')}`);
    }

    // 6. Typosquatting
    const typos = checkTyposquatting(domain);
    if (typos.length > 0) {
        signals.push(...typos.map(t => `Typosquatting: ${t}`));
    }

    // 7. AI Analysis (with fallback)
    let aiResult = null;

    if (openai && process.env.OPENAI_API_KEY) {
        try {
            const completion = await openai.chat.completions.create({
                model: "gpt-4o-mini", // Cost-effective
                messages: [
                    {
                        role: "system",
                        content: `You are a cybersecurity expert analyzing a URL for phishing risks. 
            Do not access the URL. Analyze only the string and the provided signals.
            Return a JSON object with: riskLevel (Low/Medium/High), riskScore (0-100), attackVector, and explanation.`
                    },
                    {
                        role: "user",
                        content: `Analyze this URL: "${url}".
            Detected signals: ${JSON.stringify(signals)}.
            Trusted domains comparison: ${typos.length > 0 ? 'Suspicious similarity detected' : 'No obvious typosquatting'}.`
                    }
                ],
                response_format: { type: "json_object" }
            });
            aiResult = JSON.parse(completion.choices[0].message.content);
        } catch (error) {
            console.error("OpenAI API Error:", error.message);
            // Fallback if API fails
        }
    }

    // Merge results
    const baseResult = getRuleBasedExplanation(signals);

    // If AI worked, prefer AI result but keep our signals
    if (aiResult) {
        return {
            url,
            signals,
            riskLevel: aiResult.riskLevel || baseResult.riskLevel,
            riskScore: aiResult.riskScore || baseResult.riskScore,
            attackVector: aiResult.attackVector || baseResult.attackVector,
            explanation: aiResult.explanation || baseResult.explanation,
            aiAnalysis: true
        };
    }

    // Return rule-based result if no AI
    return {
        url,
        signals,
        ...baseResult,
        aiAnalysis: false
    };
}

module.exports = { analyzeUrl };
