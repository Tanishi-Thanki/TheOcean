const startScreen = document.getElementById('start-screen');
const scannerContainer = document.getElementById('scanner-container');
const loadingScreen = document.getElementById('loading-screen');
const resultCard = document.getElementById('result-card');
const scanBtn = document.getElementById('scan-btn');
const closeScannerBtn = document.getElementById('close-scanner');
const closeResultBtn = document.getElementById('btn-close');
const openLinkBtn = document.getElementById('btn-open');

// Result Elements
const resultHeader = document.getElementById('result-header');
const decodedUrlEl = document.getElementById('decoded-url');
const attackVectorEl = document.getElementById('attack-vector');
const explanationEl = document.getElementById('explanation');

let html5QrCode;
let currentUrl = "";

// Initialize Scanner
function initScanner() {
    html5QrCode = new Html5Qrcode("reader");
}

// Start Scanning
scanBtn.addEventListener('click', () => {
    startScreen.classList.add('hidden');
    scannerContainer.classList.remove('hidden');
    resultCard.classList.add('hidden');

    if (!html5QrCode) initScanner();

    const config = { fps: 10, qrbox: { width: 250, height: 250 } };

    html5QrCode.start({ facingMode: "environment" }, config, onScanSuccess)
        .catch(err => {
            console.error("Error starting scanner", err);
            alert("Camera permission denied or error starting camera.");
            stopScanning();
        });
});


// File Upload Logic Removed

// Stop Scanning & Reset
function stopScanning() {
    if (html5QrCode && html5QrCode.isScanning) {
        html5QrCode.stop().then(() => {
            scannerContainer.classList.add('hidden');
            startScreen.classList.remove('hidden');
        }).catch(err => console.error("Failed to stop scanner", err));
    } else {
        scannerContainer.classList.add('hidden');
        startScreen.classList.remove('hidden');
    }
}

closeScannerBtn.addEventListener('click', stopScanning);

// Handle Scan Success
function onScanSuccess(decodedText) {
    // Stop scanning immediately
    html5QrCode.stop().then(() => {
        scannerContainer.classList.add('hidden');
        loadingScreen.classList.remove('hidden');

        // Call Backend
        analyzeUrl(decodedText);
    });
}

// Backend Analysis
async function analyzeUrl(url) {
    currentUrl = url;
    decodedUrlEl.textContent = url;
    openLinkBtn.href = url;

    try {
        const response = await fetch('http://localhost:3000/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        const data = await response.json();

        // Hide loading, show result
        loadingScreen.classList.add('hidden');
        resultCard.classList.remove('hidden');

        renderResult(data);

    } catch (error) {
        console.error("Analysis failed:", error);
        alert("Failed to analyze URL. Ensure backend is running on port 3000.");
        loadingScreen.classList.add('hidden');
        startScreen.classList.remove('hidden');
    }
}

function renderResult(data) {
    // Determine styles based on Risk Level
    let color = 'green';
    let bg = 'bg-green-100';
    let text = 'text-green-800';
    let icon = '';

    const riskLevel = data.riskLevel || "Unknown";
    const score = data.riskScore || 0;

    if (riskLevel === 'High') {
        color = 'red';
        bg = 'bg-red-100';
        text = 'text-red-800';
        icon = `<svg class="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>`;
    } else if (riskLevel === 'Medium') {
        color = 'yellow';
        bg = 'bg-yellow-100';
        text = 'text-yellow-800';
        icon = `<svg class="w-8 h-8 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
    } else {
        // Safe / Low
        color = 'green';
        bg = 'bg-green-100';
        text = 'text-green-800';
        icon = `<svg class="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>`;
    }

    resultHeader.innerHTML = `
        <div class="p-2 rounded-full ${bg}">
            ${icon}
        </div>
        <div>
            <h2 class="text-xl font-bold ${text}">${riskLevel} Risk</h2>
            <p class="text-xs text-gray-500">Risk Score: ${score}/100 (Lower is safer)</p>
        </div>
    `;

    attackVectorEl.textContent = data.attackVector || "None Detected";
    attackVectorEl.className = `text-sm font-bold ${text} mb-1`;
    explanationEl.textContent = data.explanation || "No details provided.";
}

// Reset Flow
closeResultBtn.addEventListener('click', () => {
    resultCard.classList.add('hidden');
    startScreen.classList.remove('hidden');
    currentUrl = "";
});

