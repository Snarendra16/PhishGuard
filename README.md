# 🛡️ PhishGuard 🛡️
A Lightweight Real-Time Phishing Detection Extension

PhishGuard is a browser-based phishing detection tool that analyzes URLs, content patterns, and even **favicon authenticity** to warn users about suspicious websites or messages.  
The project is built using pure HTML, CSS, and JavaScript — no backend required.

---

##  Features

###  URL Analysis  
- Detects suspicious domain patterns  
- Checks for misspellings, unusual TLDs, long URLs, encoded characters  
- Identifies deceptive subdomains (e.g., `login.google.com.fake-site.xyz`)

###  Content Inspection  
- Highlights phishing keywords (urgent tone, threats, reward baits)  
- Flags mismatched text–link pairs  
- Detects hidden redirects and obfuscated links

###  **Favicon Matching (Unique Feature)**  
PhishGuard compares the favicon of a website against a library of known official icons.  
If a phishing site copies the brand’s favicon, the system checks:  
- Hash similarity  
- Pixel-level differences  
- Unusual image source paths  

This helps detect brand-spoofing phishing pages pretending to be Google, PayPal, Amazon, etc.

###  Clean & Simple UI  
- User-friendly interface with colour-coded warnings  
- Works directly in browser  
- No installations or API keys required

###  100% Client-Side  
- Lightweight and fast  
- Works offline for demo/testing  
- Easily extendable

---

## 🛠️ Tech Stack

- **HTML5** — Page structure  
- **CSS3** — Styling, alerts, animations  
- **JavaScript (Vanilla)** — Detection logic, favicon matcher, DOM manipulation  
- **Canvas API** — Favicon pixel comparison

---

##  Project Structure

```text
PhishGuard/
│
├── index.html              → Main UI
├── css/
│   └── styles.css          → App styling
├── js/
│   ├── detector.js         → URL & content detection logic
│   ├── favicon.js          → Favicon hashing, comparison algorithms
│   ├── ui.js               → Alerts, DOM management
│   └── utils.js            → Helper functions
└── assets/
    ├── icons/              → Known brand favicons for matching
    └── images/             → UI images
