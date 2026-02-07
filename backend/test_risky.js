const http = require('http');

function postRequest(urlPath, data) {
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify(data);
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: urlPath,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                } catch (e) {
                    resolve(body);
                }
            });
        });

        req.on('error', (e) => reject(e));
        req.write(postData);
        req.end();
    });
}

async function runTests() {
    console.log("Generating High Risk Examples...\n");

    const riskyUrls = [
        // 1. Typosquatting (g00gle.com instead of google.com)
        "https://g00gle.com",

        // 2. Keyword Stuffing (login + secure + update)
        "http://secure-login-update-account.com",

        // 3. IP Address (direct access is suspicious)
        "http://192.168.0.1/admin",

        // 4. The "Mother of All Phishing Links" (HTTP + Typosquatting + Keywords)
        "http://paypal-secure-login.g00gle.com/verify-account"
    ];

    for (const url of riskyUrls) {
        console.log(`Analyzing: ${url}`);
        try {
            const result = await postRequest('/analyze', { url });
            console.log(`Risk Level: ${result.riskLevel}`);
            console.log(`Score: ${result.riskScore}`);
            console.log(`Reasons: ${result.explanation}`);
            console.log(`Vector: ${result.attackVector}`);
            console.log("-".repeat(40));
        } catch (err) {
            console.error("Failed:", err.message);
        }
    }
}

runTests();
