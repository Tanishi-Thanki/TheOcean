🌊 TheOcean – Safe-Scan Lite

AI-Powered QR Code Safety & Risk Explanation Tool

🚨 Problem Statement

QR codes are widely used for payments, menus, logins, and downloads.
However, they introduce a serious security risk known as Quishing (QR Phishing), where malicious QR codes redirect users to fake or harmful websites.

Most users:

Cannot see the actual URL behind a QR code

Do not understand technical security warnings

Open links immediately without verification

This makes QR codes an effective attack vector for phishing, credential theft, and fraud.

✅ Our Solution

TheOcean – Safe-Scan Lite is a mobile-first, AI-powered security tool that acts as a safety layer before a QR link is opened.

Instead of directly opening the link, our system:

Scans the QR code safely

Decodes the embedded URL without visiting it

Uses AI-assisted reasoning to analyze risk

Explains potential threats in simple, non-technical language

Allows the user to make an informed decision

🔐 Key Features

📱 Mobile-first QR scanning (camera based)

🚫 No automatic redirection to links

🤖 AI-powered risk analysis (prompt-trained)

🧠 Human-readable explanations

🔍 Typo-squatting detection
(e.g., g00gle vs google, paypaI vs paypal)

🎯 Attack vector identification

Quishing

Brand impersonation

Credential phishing

Fake payment pages

🧠 How AI Is Used (Prompt-to-Prototype)

This project follows a prompt-to-prototype approach.

Instead of training a heavy ML model, we use:

A Large Language Model (LLM) for reasoning

Prompt-based few-shot learning with phishing examples

Rule-based signals + AI explanation layer

The AI is responsible for:

Classifying risk level (Low / Medium / High)

Identifying attack vectors

Detecting brand impersonation patterns

Generating simple explanations for users

⚠️ The AI never opens or executes URLs — it only analyzes text.

🔍 Detection Logic (High-Level)

The system combines:

URL structure analysis (HTTP/HTTPS, IP-based URLs)

Suspicious keyword detection (login, verify, free, reward)

URL shortening detection

Domain similarity checks for typo-squatting

AI reasoning for contextual risk explanation

This hybrid approach ensures:

Safety

Explainability

Real-world deployability

📱 User Flow

User opens TheOcean on a mobile device

Scans a QR code using the phone camera

URL is decoded safely (not opened)

Backend + AI analyze the URL

Risk level and explanation are displayed

User chooses whether to proceed

🧰 Technology Stack

Frontend: HTML, CSS, JavaScript

Backend: Node.js, Express

AI: Large Language Model (Prompt-trained)

QR Scanning: html5-qrcode

Platform: Web (Mobile-friendly, PWA-ready)

🚀 Real-World Use Cases

UPI / payment QR safety

Restaurant & café QR menus

Event & poster QR codes

Public Wi-Fi login QR codes

Educational awareness tool for non-technical users

⚠️ Disclaimer

TheOcean – Safe-Scan Lite provides risk analysis and guidance based on known patterns and AI reasoning.
It does not guarantee complete protection against all threats and should be used as a preventive security aid.

🏆 Hackathon Context

This project was built as part of a Prompt-to-Prototype hackathon, focusing on:

Rapid prototyping

AI-assisted development

Explainable security solutions

Real-world impact
