// Native http module for testing without external dependencies 
// Actually, native fetch is global in Node 18+.
// If not certain, I'll use the 'http' module to be safe.

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
    console.log("Starting Tests...");

    const testCases = [
        { name: "Safe URL", url: "https://google.com" },
        { name: "HTTP URL", url: "http://example.com" },
        { name: "IP Address", url: "http://192.168.1.1" },
        { name: "Typosquatting (g00gle)", url: "https://g00gle.com" },
        { name: "Keywords (login-secure)", url: "https://secure-login-update.com" },
        { name: "Shortener", url: "https://bit.ly/suspicious" }
    ];

    for (const test of testCases) {
        console.log(`\nTesting: ${test.name} (${test.url})`);
        try {
            const result = await postRequest('/analyze', { url: test.url });
            console.log("Result:", JSON.stringify(result, null, 2));
        } catch (err) {
            console.error("Test failed:", err.message);
        }
    }
}

// Wait for server to start roughly
setTimeout(runTests, 2000);
