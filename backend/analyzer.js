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
const URL_SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'scan.page'];

// Suspicious TLDs
const SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.info', '.review', '.country', '.stream', '.gdn', '.mom', '.win'];

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
        if (domain === trusted) continue; // Exact match is fine

        // Calculate Levenshtein distance
        const distance = fastLevenshtein.get(domain, trusted);

        // If distance is small (1-2 chars) and domain is not trusted, it's suspicious
        if (distance > 0 && distance <= 2) {
            findings.push(`Startlingly similar to trusted domain: ${trusted}`);
        } else if (domain.includes(trusted) && domain !== trusted) {
            findings.push(`Contains trusted brand name: ${trusted}`);
        }
    }

    return findings;
}

/**
 * Robust Fallback Logic (Deterministic Source of Truth when AI fails)
 */
function getFallbackAnalysis(url, signals) {
    let score = 0;
    let issuesDetected = [];

    const domain = getDomain(url) || "";
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
    const urlLower = url.toLowerCase();

    // 1. HTTP vs HTTPS (+25)
    if (urlLower.startsWith('http://')) {
        score += 25;
        issuesDetected.push("Insecure HTTP");
    }

    // 2. URL Shortener / Redirect (+20)
    if (URL_SHORTENERS.some(s => domain.includes(s))) {
        score += 20;
        issuesDetected.push("URL Shortener Detected");
    }

    // 3. Brand Impersonation / Typosquatting (+40)
    if (signals.some(s => s.includes('Typosquatting') || s.includes('trusted brand'))) {
        score += 40;
        issuesDetected.push("Brand Impersonation / Typosquatting");
    }

    // 4. Suspicious Keywords (+25)
    if (SUSPICIOUS_KEYWORDS.some(k => urlLower.includes(k))) {
        score += 25;
        issuesDetected.push("Suspicious Keywords (Phishing Indicators)");
    }

    // 5. IP Address (+40)
    if (isIp) {
        score += 40;
        issuesDetected.push("Direct IP Access");
    }

    // 6. Suspicious TLDs (+20)
    if (SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld))) {
        score += 20;
        issuesDetected.push("Suspicious TLD (" + tld + ")");
    }

    // CRITICAL OVERRIDE: 3+ detection points = Automatic HIGH RISK (100)
    let riskLevel = "Low";
    if (issuesDetected.length >= 3) {
        score = 100;
        riskLevel = "High";
    } else {
        // Standard Mapping
        if (score > 70) riskLevel = "High";
        else if (score > 30) riskLevel = "Medium";
        else riskLevel = "Low";
    }

    // Determine Attack Vector
    let activeVector = "None Detected";
    if (issuesDetected.length > 0) {
        activeVector = issuesDetected[0];
        if (issuesDetected.length > 1) activeVector += " + " + issuesDetected[1];
    }

    return {
        riskLevel: riskLevel,
        riskScore: Math.min(100, Math.max(0, score)), // Ensure 0-100 range
        attackVector: activeVector,
        explanation: issuesDetected.length > 0
            ? "Fallback Analysis detected multiple red flags: " + issuesDetected.join(", ")
            : "No obvious threats detected by static fallback analysis.",
        source: "Fallback (Rule-Based)"
    };
}

/**
 * Main Analysis Function (Hybrid: AI-First -> Fallback)
 */
async function analyzeUrl(url) {
    const signals = [];

    // 1. Basic Validation
    if (!url) return { error: "No URL provided" };

    // Prefetch signals for AI context
    const domain = getDomain(url);
    if (!domain) return getFallbackAnalysis(url, ["Invalid Domain"]); // Immediate fallback for bad URL

    const typos = checkTyposquatting(domain);
    if (typos.length > 0) signals.push(...typos);

    // AI Analysis (Primary Path)
    if (openai && process.env.OPENAI_API_KEY) {
        try {
            const completion = await openai.chat.completions.create({
                model: "gpt-4o-mini",
                messages: [
                    {
                        role: "system",
                        content: `You are a cybersecurity expert. Analyze this URL for phishing risks.
                        Rules:
                        1. Return valid JSON only.
                        2. Analyzy URL string patterns, keywords, and potential obfuscation.
                        3. Use the provided "signals" as hints but form your own conclusion.
                        4. Output keys: riskLevel (Low/Medium/High), riskScore (0-100), attackVector, explanation.`
                    },
                    {
                        role: "user",
                        content: `URL: "${url}"\nSignals: ${JSON.stringify(signals)}`
                    }
                ],
                response_format: { type: "json_object" }
            });

            const aiData = JSON.parse(completion.choices[0].message.content);

            // Return AI Result if successful
            return {
                ...aiData,
                source: "AI (OpenAI)"
            };

        } catch (error) {
            console.error("AI Analysis Failed (Switching to Fallback):", error.message);
            // Proceed to fallback...
        }
    }

    // Fallback Path (Activated if AI fails or key missing)
    return getFallbackAnalysis(url, signals);
}

module.exports = { analyzeUrl };
