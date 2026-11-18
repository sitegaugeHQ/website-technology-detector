// Website Technology Detector
// Reads the home page of each website once, politely (robots.txt aware, identified user agent), and reports the
// technologies it can see in the response headers, cookies, HTML, the site's tag manager container and DNS records.

import { Actor, log } from 'apify';
import { decodeBuffer } from 'encoding-sniffer';
import { Tokenizer } from 'htmlparser2';
import robotsParser from 'robots-parser';
import { readFileSync } from 'node:fs';
import { Resolver } from 'node:dns/promises';
import net from 'node:net';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { setTimeout as sleep } from 'node:timers/promises';
import {
    TECHNOLOGIES, WORDPRESS_PLUGINS, WORDPRESS_COMMENTS, MX_PROVIDERS, NS_PROVIDERS, TXT_SERVICES, SPF_SENDERS, CNAME_PLATFORMS, DNS_PLATFORM_CATEGORY,
} from './fingerprints.js';

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------

const BOT_NAME = 'SiteAuditBot';
const BOT_INFO_URL = process.env.BOT_INFO_URL || 'https://apify.com/sitegauge/website-technology-detector';
const USER_AGENT = `Mozilla/5.0 (compatible; ${BOT_NAME}/1.0; +${BOT_INFO_URL})`;
const EVENT = 'site-analyzed';

const MAX_HTML_BYTES = 2 * 1024 * 1024;
const PAGE_TIMEOUT_MS = 20_000; // for a response to start
const BODY_IDLE_MS = 10_000; // between two pieces of a response that has started
const ROBOTS_TIMEOUT_MS = 8_000;
const GTM_TIMEOUT_MS = 8_000;
const DNS_TIMEOUT_MS = 4_000;
const MAX_REDIRECTS = 6;
const HOST_INTERVAL_MS = Number(process.env.TECH_DETECTOR_HOST_INTERVAL_MS) || 500; // at most 2 requests per second to one host
const GTM_HOST = 'www.googletagmanager.com';
const FLUSH_ROWS = 100;
const FLUSH_MS = 5_000;
const HARD_MAX_SITES = 200_000;
const CONNECT_ATTEMPT_MS = 3_000;
const MAX_IMAGES_PER_HOST = 40;
let SLICE_MS = 4;
const PROCESSOR_USE = 0.8; // the part of the processor ration that the run plans to use
const MATCHING_PART = 0.5; // the part of the ration that matching may use; the network gets the rest

// Host names that belong to a platform rather than to the site owner. Their DNS records describe the platform.
const PLATFORM_HOSTS = /\.(?:myshopify\.com|wixsite\.com|wixstudio\.(?:com|io)|squarespace\.com|webflow\.io|wordpress\.com|blogspot\.[a-z.]+|github\.io|gitlab\.io|netlify\.app|vercel\.app|pages\.dev|workers\.dev|herokuapp\.com|web\.app|firebaseapp\.com|azurewebsites\.net|azurestaticapps\.net|onrender\.com|fly\.dev|up\.railway\.app|ondigitalocean\.app|substack\.com|tumblr\.com|weebly\.com|weeblysite\.com|framer\.(?:website|app|ai|media)|carrd\.co|bubbleapps\.io|hs-sites[a-z0-9-]*\.com|hubspotpagebuilder\.com|square\.site|godaddysites\.com|tilda\.ws|strikingly\.com|mystrikingly\.com|medium\.com|readthedocs\.io|gitbook\.io|jimdosite\.com|jimdofree\.com|wpengine\.com|wpenginepowered\.com|kinsta\.cloud|pantheonsite\.io|mybigcommerce\.com|unbouncepages\.com|lpages\.co|clickfunnels\.com|myclickfunnels\.com|mykajabi\.com|teachable\.com|thinkific\.com|beehiiv\.com|circle\.so|lemonsqueezy\.com|gumroad\.com|bigcartel\.com|systeme\.io|shoplightspeed\.com|webshopapp\.com|mintlify\.app|cloudfront\.net|amazonaws\.com|appspot\.com|run\.app|notion\.site|softr\.app|glitch\.me|replit\.app|surge\.sh|business\.site|site123\.me|zohosites\.com)$/i;

// Second-level labels that act as a public suffix under a country code, as in example.co.uk or example.com.au.
const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'gob', 'gub', 'govt', 'edu', 'ac', 'or', 'ne', 'go', 'mil', 'nom', 'sch', 'school', 'ltd', 'plc', 'me', 'asn', 'id', 'idv', 'gen', 'firm', 'ind', 'res', 'web', 'biz', 'info', 'k12', 'muni', 'per', 'med', 'pub', 'asso', 'gouv', 'nhs', 'kiwi', 'geek', 'maori']);

const noop = () => {};
// When a host has several addresses, Node gives each of them a quarter of a second to connect before it moves on,
// and gives up when the last one fails. A healthy server far away needs longer than that, so each address gets more.
net.setDefaultAutoSelectFamilyAttemptTimeout(CONNECT_ATTEMPT_MS);

const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
const detach = (s) => (s ? Buffer.from(s, 'utf8').toString('utf8') : '');
const count = (n, word, plural = `${word}s`) => `${n.toLocaleString('en-US')} ${n === 1 ? word : plural}`;
const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// ---------------------------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------------------------

// Turns "example.com", "www.example.com/path" or a full URL into a URL to request. Returns null for anything else.
function toUrl(raw) {
    if (typeof raw !== 'string') return null;
    let value = raw.trim();
    if (!value || /\s/.test(value)) return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = `https://${value}`;
    let u;
    try {
        u = new URL(value);
    } catch {
        return null;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (!u.hostname.includes('.') || u.hostname.endsWith('.')) return null;
    if (/^[\d.]+$/.test(u.hostname) || u.hostname.startsWith('[')) return null; // an IP address is not a website address
    u.hash = '';
    return u;
}

function apexDomain(hostname) {
    const labels = hostname.toLowerCase().replace(/^www\./, '').split('.');
    if (labels.length <= 2) return labels.join('.');
    const tld = labels[labels.length - 1];
    const second = labels[labels.length - 2];
    const take = tld.length === 2 && SECOND_LEVEL.has(second) ? 3 : 2;
    return labels.slice(-take).join('.');
}

// ---------------------------------------------------------------------------------------------
// Processor time
// ---------------------------------------------------------------------------------------------

// On Apify a run gets a fixed ration of processor time in proportion to its memory: an eighth of a processor for every
// gigabyte. A run that asks for more than its ration is put on hold many times a second, and then every response
// trickles in: pages look slow, time-outs fire on healthy websites and results change from run to run. Three rules
// keep that from happening:
//   1. Matching a page against the fingerprints, the one thing here that takes real processor time, is done for one
//      page at a time, in slices of a few milliseconds, and uses no more than a set part of the ration. The rest is
//      left for the network, so that responses and timers are handled on time.
//   2. Websites are started at the pace the ration allows. The processor time one website takes is measured as the
//      run goes.
//   3. No website is started while pages are waiting to be matched.
// Development aid: with "debugTiming": true in the input, every row carries where its time went.
const diag = { on: false };

function readProcessorShare() {
    if (process.env.TECH_DETECTOR_CPU_SHARE) return Number(process.env.TECH_DETECTOR_CPU_SHARE);
    try {
        const [quota, period] = readFileSync('/sys/fs/cgroup/cpu.max', 'utf8').trim().split(/\s+/);
        return quota === 'max' ? null : Number(quota) / Number(period);
    } catch { /* not this kind of system */ }
    try {
        const quota = Number(readFileSync('/sys/fs/cgroup/cpu/cpu.cfs_quota_us', 'utf8'));
        const period = Number(readFileSync('/sys/fs/cgroup/cpu/cpu.cfs_period_us', 'utf8'));
        return quota > 0 && period > 0 ? quota / period : null;
    } catch { /* not this kind of system either */ }
    return null;
}

const ration = {
    share: readProcessorShare(), // processors on offer, for example 0.5; null when processor time is not rationed
    usageAtStart: process.cpuUsage(),
    checks: [], // the last few measurements: websites finished and processor seconds used by then
    secondsPerSite: 0.08, // a first guess, replaced by what is measured
    tokens: 2,
    filledAt: performance.now(),
    sitesDone: 0,
    waiting: 0, // pages waiting to be matched
};

// Rule 1. A slice of matching is followed by a rest that is long enough to keep matching within its part of the ration.
let sliceStart = 0;
let nextSliceAt = 0;
const nextTurn = () => new Promise((resolve) => {
    setImmediate(resolve);
});
function endSlice() {
    const now = performance.now();
    const ran = now - sliceStart;
    const part = ration.share === null ? 1 : Math.min(ration.share * MATCHING_PART, 1);
    nextSliceAt = now + Math.min(ran / part - ran, 300);
}
async function beginSlice() {
    const rest = nextSliceAt - performance.now();
    if (rest >= 1) await sleep(rest);
    else await nextTurn();
    sliceStart = performance.now();
}
async function pause() {
    endSlice();
    await beginSlice();
}
const sliceUsed = () => performance.now() - sliceStart >= SLICE_MS;

let processorQueue = Promise.resolve();
function inTurn(work) {
    ration.waiting += 1;
    const run = processorQueue.then(async () => {
        await beginSlice();
        ration.waiting -= 1;
        try {
            return await work();
        } finally {
            endSlice();
        }
    });
    processorQueue = run.then(noop, noop);
    return run;
}

// Rule 2. Called when a website is finished: every few websites the processor time used is set against the number
// finished. The recent figure counts, but it may not fall far below the figure for the whole run, so that a handful
// of websites that cost nothing (blocked, unreachable) does not open the gates for the heavy ones behind them.
function siteFinished() {
    ration.sitesDone += 1;
    const now = performance.now();
    const last = ration.checks[ration.checks.length - 1];
    if (last && ration.sitesDone - last.sites < 5 && now - last.at < 2_000) return;
    const used = process.cpuUsage(ration.usageAtStart);
    const seconds = (used.user + used.system) / 1e6;
    ration.checks.push({ sites: ration.sitesDone, seconds, at: now });
    if (ration.checks.length > 9) ration.checks.shift();
    const first = ration.checks[0];
    const overall = seconds / ration.sitesDone;
    const lately = ration.sitesDone > first.sites ? (seconds - first.seconds) / (ration.sitesDone - first.sites) : overall;
    ration.secondsPerSite = Math.min(Math.max(lately, overall * 0.6, 0.004), 1);
    ration.share = readProcessorShare(); // the ration can change during a run
}

// Rules 2 and 3. Waits until another website may start.
async function whenProcessorAllows() {
    for (;;) {
        if (ration.share === null) return;
        if (ration.waiting >= 3) {
            await sleep(25);
            continue;
        }
        const perSecond = (ration.share * PROCESSOR_USE) / ration.secondsPerSite;
        const now = performance.now();
        ration.tokens = Math.min(ration.tokens + ((now - ration.filledAt) / 1000) * perSecond, Math.max(2, perSecond / 2));
        ration.filledAt = now;
        if (ration.tokens >= 1) {
            ration.tokens -= 1;
            return;
        }
        await sleep(Math.min(Math.max(((1 - ration.tokens) / perSecond) * 1000, 5), 500));
    }
}

// ---------------------------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------------------------

// For tests only: requests can be sent to a local fixture server that plays every host.
const TEST_SERVER = process.env.TECH_DETECTOR_TEST_SERVER || null;

async function fetchOnce(url, { readBody = 'html', maxBytes = MAX_HTML_BYTES, timeoutMs = PAGE_TIMEOUT_MS } = {}) {
    const t0 = performance.now();
    const ctrl = new AbortController();
    let timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        const headers0 = {
            'user-agent': USER_AGENT,
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
        };
        let target = url;
        if (TEST_SERVER) {
            const u = new URL(url);
            headers0['x-test-url'] = url;
            target = `${TEST_SERVER}${u.pathname}${u.search}`;
        }
        const res = await fetch(target, { redirect: 'manual', signal: ctrl.signal, headers: headers0 });
        const headersMs = Math.round(performance.now() - t0);
        let reads = 0;
        // Once a response has started it may take its time, as long as it keeps coming.
        const latest = t0 + timeoutMs * 3;
        const keepWaiting = () => {
            clearTimeout(timer);
            timer = setTimeout(() => ctrl.abort(), Math.max(Math.min(BODY_IDLE_MS, latest - performance.now()), 1));
        };
        keepWaiting();
        const headers = {};
        for (const [k, v] of res.headers.entries()) {
            const key = k.toLowerCase();
            headers[key] = headers[key] === undefined ? v : `${headers[key]}, ${v}`;
        }
        const cookies = (res.headers.getSetCookie?.() ?? []).map((c) => c.split('=')[0].trim()).filter(Boolean);
        const contentType = (headers['content-type'] || '').toLowerCase();
        const isHtml = /text\/html|application\/xhtml\+xml/.test(contentType);
        let body = null;
        if (res.body && (readBody === 'all' || (readBody === 'html' && isHtml))) {
            const chunks = [];
            let bytes = 0;
            const reader = res.body.getReader();
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                reads += 1;
                keepWaiting();
                bytes += value.byteLength;
                if (bytes > maxBytes) {
                    chunks.push(value.subarray(0, value.byteLength - (bytes - maxBytes)));
                    await reader.cancel().catch(() => {});
                    break;
                }
                chunks.push(value);
            }
            body = Buffer.concat(chunks);
        } else if (res.body) {
            await res.body.cancel().catch(() => {});
        }
        return { ok: true, status: res.status, headers, cookies, contentType, isHtml, body, timeMs: Math.round(performance.now() - t0), headersMs, reads };
    } catch (err) {
        const aborted = err?.name === 'AbortError' || ctrl.signal.aborted;
        const code = aborted ? 'TIMEOUT' : (err?.cause?.code || err?.code || 'FETCH_ERROR');
        return { ok: false, errorCode: String(code), timeMs: Math.round(performance.now() - t0) };
    } finally {
        clearTimeout(timer);
    }
}

// One retry for failures that are often temporary, a connection attempt that timed out among them. A server that
// takes the connection and then stays silent is not asked twice, and neither is one that refuses.
async function fetchWithRetry(url, opts) {
    let res = await fetchOnce(url, opts);
    const temporary = res.ok ? res.status === 502 || res.status === 503 || res.status === 504 : /^(?:ECONNRESET|EPIPE|UND_ERR_SOCKET|EAI_AGAIN|ETIMEDOUT)$/.test(res.errorCode);
    if (temporary) {
        await sleep(1_000);
        res = await fetchOnce(url, opts);
    }
    return res;
}

// Requests to one host are spaced out, also when several websites redirect to the same place.
const hostNextAt = new Map();
async function pace(host) {
    const now = Date.now();
    const at = Math.max(hostNextAt.get(host) ?? 0, now);
    hostNextAt.set(host, at + HOST_INTERVAL_MS);
    if (hostNextAt.size > 20_000) for (const [h, t] of hostNextAt) if (t < now - 60_000) hostNextAt.delete(h);
    if (at > now) await sleep(at - now);
}

// robots.txt per origin, with a small memory so that a long list does not pile up parsed files.
const robotsCache = new Map();
async function getRobots(origin) {
    let hit = robotsCache.get(origin);
    if (!hit) {
        hit = (async () => {
            const url = `${origin}/robots.txt`;
            let current = url;
            let res;
            for (let hop = 0; hop <= 3; hop++) {
                await pace(new URL(current).host);
                res = await fetchOnce(current, { readBody: 'all', maxBytes: 512 * 1024, timeoutMs: ROBOTS_TIMEOUT_MS });
                if (!res.ok || res.status < 300 || res.status >= 400 || !res.headers.location) break;
                try {
                    current = new URL(res.headers.location, current).href;
                } catch {
                    break;
                }
            }
            const exists = res.ok && res.status === 200 && !!res.body && !res.isHtml;
            return { exists, parser: robotsParser(url, exists ? res.body.toString('utf8') : '') };
        })();
        robotsCache.set(origin, hit);
        if (robotsCache.size > 500) robotsCache.delete(robotsCache.keys().next().value);
    }
    return hit;
}

// Loads a page, following redirects by hand so that robots.txt is honoured on every host on the way.
async function loadPage(startUrl) {
    let current = startUrl;
    let hops = 0;
    let res = null;
    const cookies = new Set();
    for (;;) {
        const u = new URL(current);
        const robots = await getRobots(u.origin);
        if (robots.exists && robots.parser.isAllowed(current, BOT_NAME) === false) return { disallowed: true, finalUrl: current, hops, cookies: [] };
        await pace(u.host);
        res = await fetchWithRetry(current);
        if (res.ok) for (const c of res.cookies) cookies.add(c);
        if (!res.ok || res.status < 300 || res.status >= 400 || !res.headers.location || hops >= MAX_REDIRECTS) break;
        let next;
        try {
            next = new URL(res.headers.location, current);
        } catch {
            break;
        }
        if (next.protocol !== 'http:' && next.protocol !== 'https:') break;
        next.hash = '';
        current = next.href;
        hops += 1;
    }
    return { res, finalUrl: current, hops, cookies: [...cookies] };
}

// Encoding precedence follows browsers: byte order mark, then the Content-Type header, then <meta charset>.
function encodingOptions(res) {
    const label = /charset\s*=\s*["']?([^\s;"']+)/i.exec(res.contentType)?.[1];
    if (label) return { transportLayerEncodingLabel: label, defaultEncoding: 'utf-8' };
    try {
        new TextDecoder('utf-8', { fatal: true }).decode(res.body, { stream: true });
        return { defaultEncoding: 'utf-8' };
    } catch {
        return { defaultEncoding: 'windows-1252' };
    }
}

// ---------------------------------------------------------------------------------------------
// Reading a page
// ---------------------------------------------------------------------------------------------

const ASSET_TAGS = new Map([['script', 'src'], ['link', 'href'], ['img', 'src'], ['iframe', 'src'], ['source', 'src'], ['video', 'src'], ['audio', 'src'], ['embed', 'src'], ['object', 'data']]);
// Collects what the fingerprints look at, straight from the HTML tokens. No document tree is built.
function readPage(html) {
    const assets = [];
    const code = []; // scripts and <link>s: the files a page is built from
    const meta = new Map(); // name -> [content, ...]
    let inline = '';
    let title = '';
    let lang = null;
    let tag = '';
    let attrs = null;
    let attrName = '';
    let attrValue = '';
    let inScript = false; // inside an inline <script>
    let inTitle = false;
    // The markup is the HTML without the text of its scripts, which is often most of a page. Marks that a platform
    // leaves in tags and attributes are looked for there; what scripts say is looked for in the scripts.
    const kept = [];
    let keptTo = 0;
    let scriptTextFrom = -1;
    const imagesPerHost = new Map();

    const endStartTag = (endIndex, selfClosing) => {
        const name = tag;
        const a = attrs;
        tag = '';
        attrs = null;
        if (name === 'script' && !selfClosing && scriptTextFrom < 0) scriptTextFrom = endIndex + 1;
        if (!a) return;
        if (name === 'html') {
            if (a.lang) lang = a.lang;
            return;
        }
        if (name === 'title') {
            inTitle = !title;
            return;
        }
        if (name === 'meta') {
            const key = (a.name || a.property || a['http-equiv'] || '').toLowerCase();
            if (key && a.content !== undefined) {
                if (!meta.has(key)) meta.set(key, []);
                if (meta.get(key).length < 10) meta.get(key).push(a.content);
            }
            return;
        }
        const attr = ASSET_TAGS.get(name);
        const value = a[attr] || (name === 'img' ? a['data-src'] : undefined);
        if (value && assets.length < 3_000 && !value.startsWith('data:')) {
            if (name === 'img') {
                // A shop with a thousand product pictures tells nothing new after the first few from each host.
                const host = /^(?:https?:)?\/\/([^/?#]+)/i.exec(value)?.[1] ?? '';
                const seen = imagesPerHost.get(host) ?? 0;
                if (seen >= MAX_IMAGES_PER_HOST) return;
                imagesPerHost.set(host, seen + 1);
            }
            assets.push(value);
            if (name === 'script' || name === 'link') code.push(value);
        }
        if (name === 'script') inScript = !a.src && (!a.type || /javascript|module/i.test(a.type));
    };

    const tokenizer = new Tokenizer({ decodeEntities: true }, {
        onopentagname(start, end) {
            tag = html.slice(start, end).toLowerCase();
            attrs = ASSET_TAGS.has(tag) || tag === 'meta' || tag === 'html' || tag === 'title' ? { __proto__: null } : null;
        },
        onattribname(start, end) {
            if (attrs) attrName = html.slice(start, end).toLowerCase();
        },
        onattribdata(start, end) {
            if (attrs) attrValue += html.slice(start, end);
        },
        onattribentity(codePoint) {
            if (attrs) attrValue += String.fromCodePoint(codePoint);
        },
        onattribend() {
            if (!attrs) return;
            if (!(attrName in attrs)) attrs[attrName] = attrValue;
            attrValue = '';
        },
        onopentagend: (endIndex) => endStartTag(endIndex, false),
        onselfclosingtag: (endIndex) => endStartTag(endIndex, true),
        onclosetag(start, end) {
            const name = html.slice(start, end).toLowerCase();
            if (name === 'script') {
                inScript = false;
                if (scriptTextFrom >= 0) {
                    kept.push(html.slice(keptTo, scriptTextFrom));
                    keptTo = Math.max(scriptTextFrom, start - 2); // the "</" of the closing tag
                    scriptTextFrom = -1;
                }
            } else if (name === 'title') inTitle = false;
        },
        ontext(start, end) {
            if (inScript) {
                if (inline.length < 400_000) inline += `${html.slice(start, end)}\n`;
            } else if (inTitle && title.length < 300) title += html.slice(start, end);
        },
        ontextentity(codePoint) {
            if (inTitle && title.length < 300) title += String.fromCodePoint(codePoint);
        },
        oncomment: noop,
        oncdata: noop,
        ondeclaration: noop,
        onprocessinginstruction: noop,
        onend: noop,
    });
    tokenizer.write(html);
    tokenizer.end();
    kept.push(scriptTextFrom >= 0 ? html.slice(keptTo, scriptTextFrom) : html.slice(keptTo)); // a script that never ends is left out
    return { assets: assets.join('\n'), code: code.join('\n'), markup: kept.join(''), meta, inline, title: clean(title), lang };
}

// ---------------------------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------------------------

const TECH_BY_NAME = new Map(TECHNOLOGIES.map((t) => [t[0], t]));
// Identifiers of analytics and advertising accounts are left out of the evidence. The tool reports technologies, not accounts.
const redact = (s) => s.replace(/\b(G|UA|AW|DC|GTM|ca-pub)-[A-Z0-9][A-Z0-9-]{3,}/gi, '$1-…').replace(/(["'])[A-Za-z0-9_-]{20,}\1/g, '$1…$1').replace(/\d{8,}/g, '…');
const snippet = (s) => detach(redact(clean(s)).slice(0, 80));

function firstGroup(m) {
    for (let i = 1; i < m.length; i++) if (m[i]) return m[i];
    return null;
}

class Findings {
    constructor() {
        this.map = new Map();
    }

    add(name, category, evidence, version = null) {
        let f = this.map.get(name);
        if (!f) {
            f = { name: detach(name), category, version: null, evidence: [] };
            this.map.set(f.name, f);
        }
        if (version && !f.version && /^\d[\w.-]{0,15}$/.test(version)) f.version = detach(version);
        if (evidence && f.evidence.length < 4 && !f.evidence.includes(evidence)) f.evidence.push(evidence);
        return f;
    }

    has(name) {
        return this.map.has(name);
    }
}

function test(findings, tech, re, haystack, label) {
    if (!re || !haystack) return;
    const m = re.exec(haystack);
    if (m) findings.add(tech[0], tech[1], `${label}: ${snippet(m[0])}`, firstGroup(m));
}

async function matchPage(findings, { headers, cookies, page, host }) {
    for (const tech of TECHNOLOGIES) {
        if (page && sliceUsed()) await pause();
        const sig = tech[2];
        if (sig.h) {
            for (const name of Object.keys(sig.h)) {
                const value = headers[name];
                if (value === undefined) continue;
                const rule = sig.h[name];
                if (rule === true) findings.add(tech[0], tech[1], `header ${name}`);
                else test(findings, tech, rule, value, `header ${name}`);
            }
        }
        if (sig.c) for (const c of cookies) test(findings, tech, sig.c, c, 'cookie');
        if (sig.u) test(findings, tech, sig.u, host, 'host name');
        if (!page) continue;
        if (sig.m) {
            for (const name of Object.keys(sig.m)) {
                const rule = sig.m[name];
                if (rule === true) {
                    if (page.meta.has(name)) findings.add(tech[0], tech[1], `meta ${name}`);
                } else for (const value of page.meta.get(name) ?? []) test(findings, tech, rule, value, `meta ${name}`);
            }
        }
        test(findings, tech, sig.a, page.assets, 'loads');
        test(findings, tech, sig.s, page.code, 'loads');
        test(findings, tech, sig.j, page.inline, 'inline script');
        test(findings, tech, sig.x, page.markup, 'html');
    }
}

// Drops technologies whose own conditions are not met: a required technology is missing, or the host is excluded.
function prune(findings, host) {
    for (const name of [...findings.map.keys()]) {
        const sig = TECH_BY_NAME.get(name)?.[2];
        if (!sig) continue;
        if ((sig.r && !findings.has(sig.r)) || (sig.n && sig.n.test(host))) findings.map.delete(name);
    }
}

function addImplied(findings) {
    const queue = [...findings.map.keys()];
    while (queue.length) {
        const name = queue.pop();
        for (const implied of TECH_BY_NAME.get(name)?.[2].i ?? []) {
            if (findings.has(implied)) continue;
            findings.add(implied, TECH_BY_NAME.get(implied)[1], `implied by ${name}`);
            queue.push(implied);
        }
    }
}

// WordPress themes and plugins leave their folder names in the URLs a page loads.
const GENERIC_FOLDERS = new Set(['dist', 'build', 'assets', 'vendor', 'js', 'css', 'public', 'src', 'lib', 'includes', 'static', 'cache']);
function readWordPress(findings, page) {
    if (!findings.has('WordPress')) return null;
    const source = `${page.assets}\n${page.markup}\n${page.inline}`;
    const plugins = new Map();
    for (const m of source.matchAll(/\/wp-content\/plugins\/([A-Za-z0-9_.-]{2,60})\//g)) {
        if (plugins.size >= 150) break;
        const slug = m[1].replace(/-\d+(?:\.\d+)+$/, ''); // some hosts add the version to the folder name
        if (GENERIC_FOLDERS.has(slug.toLowerCase())) continue;
        if (!plugins.has(slug)) plugins.set(slug, WORDPRESS_PLUGINS[slug]?.[0] ?? null);
    }
    const themes = [];
    for (const m of source.matchAll(/\/wp-content\/themes\/([A-Za-z0-9_.-]{2,60})\//g)) {
        if (!themes.includes(m[1])) themes.push(m[1]);
        if (themes.length >= 5) break;
    }
    for (const [slug, known] of plugins) {
        const info = WORDPRESS_PLUGINS[slug];
        if (info) findings.add(info[0], info[1], `plugin folder: ${detach(slug)}`);
        else if (!known) findings.add(`WordPress plugin: ${slug}`, 'WordPress plugin', 'plugin folder');
    }
    for (const [re, build] of WORDPRESS_COMMENTS) {
        const m = re.exec(page.markup);
        if (!m) continue;
        const [name, category, version] = build(m);
        findings.add(name, category, 'html comment', version);
    }
    if (themes[0]) findings.add(`WordPress theme: ${themes[0]}`, 'WordPress theme', 'theme folder');
    return {
        theme: themes[0] ? detach(themes[0]) : null,
        otherThemeFolders: themes.slice(1).map(detach),
        plugins: [...plugins].map(([slug, name]) => ({ slug: detach(slug), name })),
    };
}

function readShopify(findings, page) {
    if (!findings.has('Shopify')) return null;
    const m = /Shopify\.theme\s*=\s*(\{[^;]{0,600}?\})\s*;/.exec(page.inline);
    let theme = null;
    let schema = null;
    if (m) {
        try {
            const t = JSON.parse(m[1]);
            theme = typeof t.name === 'string' ? t.name.slice(0, 80) : null;
            schema = typeof t.schema_name === 'string' ? `${t.schema_name}${t.schema_version ? ` ${t.schema_version}` : ''}`.slice(0, 80) : null;
        } catch { /* not JSON, leave empty */ }
    }
    if (schema) findings.add(`Shopify theme: ${schema.replace(/ [\d.]+$/, '')}`, 'Shopify theme', 'Shopify.theme');
    return { theme, themeBase: schema };
}

// ---------------------------------------------------------------------------------------------
// Google Tag Manager container
// ---------------------------------------------------------------------------------------------

// Tags that load through a tag manager are not in the HTML. The container file lists them, so it is read as well.
const GTM_TAG_TECH = new Map();
for (const tech of TECHNOLOGIES) for (const id of tech[2].g ?? []) GTM_TAG_TECH.set(id, tech);
let gtmAllowed = null;
let gtmNextAt = 0;

// A host name with at least one dot, and the path after it. The look-behind keeps the search from starting in the middle of a word.
const ADDRESS = /(?<![a-z0-9.-])(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*(?::\d+)?(?:\/[^\s"'<>\\]*)?/gi;
const GOOGLE_TAG_KINDS = { G: 'Google Analytics', AW: 'Google Ads', DC: 'Google Marketing Platform Floodlight' };

// Returns the index just after the object literal that opens at `from`, or -1 when it does not close.
function objectEnd(js, from) {
    let depth = 0;
    let inString = false;
    for (let i = from; i < js.length; i++) {
        const c = js.charCodeAt(i);
        if (inString) {
            if (c === 92) i += 1; // a backslash: the next character is escaped
            else if (c === 34) inString = false;
        } else if (c === 34) inString = true;
        else if (c === 123) depth += 1;
        else if (c === 125) {
            depth -= 1;
            if (depth === 0) return i + 1;
        }
    }
    return -1;
}

// A container file holds the tags, the conditions they fire on, the templates the tags use, and then the tag manager's
// own code. Only the tags and their templates are read: a condition such as "the clicked link contains example.com"
// says nothing about what a page loads, and the tag manager's own code is the same for every website.
function containerParts(js) {
    const at = js.indexOf('"resource"');
    if (at < 0) return null;
    const open = js.lastIndexOf('{', at);
    const close = open < 0 ? -1 : objectEnd(js, open);
    const runtimeAt = js.indexOf('"runtime"', at);
    if (close < 0 && runtimeAt < 0) return null;
    const plain = (s) => s.replace(/\\u00([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))).replace(/\\\//g, '/');
    const resource = js.slice(at, runtimeAt >= 0 && (close < 0 || runtimeAt < close) ? runtimeAt : close);
    const tagsAt = resource.indexOf('"tags":[');
    const conditionsAt = tagsAt < 0 ? -1 : resource.indexOf('"predicates":[', tagsAt);
    const tags = plain(tagsAt >= 0 && conditionsAt >= 0 ? resource.slice(tagsAt, conditionsAt) : resource);
    const templates = close >= 0 && runtimeAt >= 0 && runtimeAt < close ? plain(js.slice(runtimeAt, Math.min(close, runtimeAt + 800_000))) : '';
    // Fingerprints for loaded files are tested against the addresses the tags and templates mention, one per line,
    // instead of against all of their text. That is the same test on a fraction of the characters.
    const seen = new Set();
    for (const text of [tags, templates]) {
        for (const m of text.matchAll(ADDRESS)) {
            if (seen.size >= 20_000) break;
            seen.add(m[0]);
        }
    }
    let addresses = '';
    for (const a of seen) addresses += `https://${a}\n`;
    return { tags, addresses };
}

async function readTagManager(findings, page) {
    const ids = [...new Set(`${page.assets}\n${page.inline}`.match(/\bGTM-[A-Z0-9]{4,10}\b/g) ?? [])].slice(0, 2);
    if (!ids.length) return 0;
    if (gtmAllowed === null) {
        const robots = await getRobots(`https://${GTM_HOST}`);
        gtmAllowed = !(robots.exists && robots.parser.isAllowed(`https://${GTM_HOST}/gtm.js?id=GTM-XXXXXX`, BOT_NAME) === false);
        if (!gtmAllowed) log.info('Tag manager containers are not read: the robots.txt of the tag manager host disallows it.');
    }
    if (!gtmAllowed) return 0;
    let read = 0;
    for (const id of ids) {
        const now = Date.now();
        const at = Math.max(gtmNextAt, now);
        gtmNextAt = at + 100;
        if (at > now) await sleep(at - now);
        const res = await fetchOnce(`https://${GTM_HOST}/gtm.js?id=${id}`, { readBody: 'all', maxBytes: 1_500_000, timeoutMs: GTM_TIMEOUT_MS });
        if (!res.ok || res.status !== 200 || !res.body) continue;
        // eslint-disable-next-line no-loop-func
        read += await inTurn(async () => {
            const parts = containerParts(res.body.toString('utf8'));
            if (!parts) return 0;
            for (const m of parts.tags.matchAll(/"function":"(__[a-z0-9_]+)"/g)) {
                let tech = GTM_TAG_TECH.get(m[1]);
                if (m[1] === '__googtag') {
                    // The Google tag serves Analytics and Ads alike. The kind of ID it carries tells which one it is here.
                    const next = parts.tags.indexOf('"function":', m.index + 12);
                    const own = parts.tags.slice(m.index, Math.min(next < 0 ? Infinity : next, m.index + 3_000));
                    tech = TECH_BY_NAME.get(GOOGLE_TAG_KINDS[/"vtp_tagId":"(G|AW|DC)-/.exec(own)?.[1]]);
                }
                if (tech) findings.add(tech[0], tech[1], 'tag manager container: built-in tag');
            }
            for (const tech of TECHNOLOGIES) {
                if (tech[0] === 'Google Tag Manager') continue;
                if (sliceUsed()) await pause();
                test(findings, tech, tech[2].a, parts.addresses, 'tag manager container');
                test(findings, tech, tech[2].j, parts.tags, 'tag manager container');
            }
            return 1;
        });
    }
    return read;
}

// ---------------------------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------------------------

const resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 2 });
const dnsFixture = process.env.TECH_DETECTOR_DNS_FIXTURE ? JSON.parse(readFileSync(process.env.TECH_DETECTOR_DNS_FIXTURE, 'utf8')) : null;

// Returns the records, an empty list when there are none, or null when the lookup itself failed.
async function lookup(name, type) {
    if (dnsFixture) return dnsFixture[`${type} ${name}`] ?? [];
    try {
        const records = await resolver.resolve(name, type);
        // Name servers hand out records in a different order every time. Sorting them makes two runs agree.
        if (type === 'MX') return records.map((r) => ({ priority: r.priority, exchange: r.exchange.toLowerCase() })).sort((a, b) => a.priority - b.priority || (a.exchange < b.exchange ? -1 : 1)).map((r) => r.exchange);
        if (type === 'TXT') return records.map((chunks) => chunks.join('')).sort();
        return records.map((r) => String(r).toLowerCase()).sort();
    } catch (err) {
        return ['ENODATA', 'ENOTFOUND', 'ENONAME'].includes(err?.code) ? [] : null;
    }
}

const firstMatch = (table, value) => table.find(([re]) => re.test(value))?.[1] ?? null;

async function readDns(findings, hostname) {
    const host = hostname.toLowerCase();
    if (/^[\d.]+$|:/.test(host)) return { domain: null, note: 'The address is an IP address, so there are no domain records to read.' };
    if (PLATFORM_HOSTS.test(host)) return { domain: null, note: 'The host name belongs to a platform, so its DNS records describe the platform and were not read.' };
    const domain = apexDomain(host);
    const cnameHost = host === domain ? `www.${domain}` : host;
    const [mx, txt, ns, dmarc, cname] = await Promise.all([
        lookup(domain, 'MX'), lookup(domain, 'TXT'), lookup(domain, 'NS'), lookup(`_dmarc.${domain}`, 'TXT'), lookup(cnameHost, 'CNAME'),
    ]);
    const failed = [mx, txt, ns].every((r) => r === null);
    const emailProvider = mx?.length ? (mx.map((h) => firstMatch(MX_PROVIDERS, h)).find(Boolean) ?? null) : null;
    // Large websites often spread their name servers over two providers. Both are reported.
    const dnsProviders = [...new Set((ns ?? []).map((h) => firstMatch(NS_PROVIDERS, h)).filter(Boolean))].sort();
    const dnsProvider = dnsProviders.join('; ') || null;
    const spf = (txt ?? []).find((r) => /^v=spf1\s/i.test(r)) ?? null;
    const emailSenders = spf ? [...new Set(SPF_SENDERS.filter(([re]) => re.test(spf)).map(([, name]) => name))] : [];
    const connectedServices = [...new Set((txt ?? []).map((r) => firstMatch(TXT_SERVICES, r)).filter(Boolean))].sort();
    const dmarcRecord = (dmarc ?? []).find((r) => /^v=DMARC1/i.test(r)) ?? null;
    const dmarcPolicy = dmarcRecord ? (/\bp=(none|quarantine|reject)\b/i.exec(dmarcRecord)?.[1].toLowerCase() ?? null) : null;
    const servedBy = cname?.length ? firstMatch(CNAME_PLATFORMS, cname[0]) : null;

    // The email provider, the DNS provider and the platform a host name points at are part of how a website is run.
    // Mail senders (SPF) and verification records say what the organisation behind the domain uses elsewhere, so they
    // stay in their own columns and are not counted as technologies of the website.
    if (emailProvider) findings.add(emailProvider, 'Email provider', 'DNS MX record');
    for (const name of dnsProviders) findings.add(name, 'DNS provider', 'DNS NS record');
    if (servedBy && !findings.has(servedBy)) findings.add(servedBy, DNS_PLATFORM_CATEGORY[servedBy] ?? 'Hosting', 'DNS CNAME record');

    return {
        domain,
        emailProvider,
        mailServers: (mx ?? []).slice(0, 5),
        dnsProvider,
        nameServers: (ns ?? []).slice(0, 6),
        hasSpf: txt === null ? null : !!spf,
        emailSenders,
        dmarcPolicy: dmarc === null ? null : (dmarcRecord ? (dmarcPolicy ?? 'unspecified') : 'not published'),
        connectedServices,
        pointsTo: cname?.[0] ?? null,
        note: failed ? 'DNS lookups failed for this domain.' : null,
    };
}

// ---------------------------------------------------------------------------------------------
// One website
// ---------------------------------------------------------------------------------------------

// The order in which categories are listed. Categories that are not named follow in alphabetical order.
const CATEGORY_ORDER = ['CMS', 'Ecommerce', 'Website builder', 'Landing pages', 'Blog platform', 'JavaScript framework', 'Web framework', 'Static site generator', 'Documentation tool',
    'Programming language', 'Web server', 'Hosting', 'CDN', 'Analytics', 'Tag manager', 'Advertising', 'Marketing automation', 'Email marketing', 'CRM', 'Live chat', 'Payments',
    'Cookie consent', 'Email provider', 'DNS provider'];
const categoryRank = (c) => {
    const i = CATEGORY_ORDER.indexOf(c);
    return i < 0 ? CATEGORY_ORDER.length : i;
};

const SUMMARY_FIELDS = {
    cms: ['CMS'], ecommerce: ['Ecommerce'], websiteBuilder: ['Website builder', 'Landing pages', 'Blog platform'],
    frameworks: ['JavaScript framework', 'Web framework', 'Static site generator'], analytics: ['Analytics'], tagManagers: ['Tag manager'],
    advertising: ['Advertising'], marketing: ['Marketing automation', 'Email marketing', 'CRM', 'Popups', 'SMS marketing'], liveChat: ['Live chat', 'Chatbot', 'Help desk'],
    payments: ['Payments'], cookieConsent: ['Cookie consent'], hosting: ['Hosting', 'CDN'],
};

function describeFailure(res) {
    if (!res.ok) {
        const code = res.errorCode;
        if (code === 'ENOTFOUND') return ['unreachable', 'The domain does not resolve (DNS lookup failed).'];
        if (code === 'TIMEOUT') return ['unreachable', `No response within ${PAGE_TIMEOUT_MS / 1000} seconds.`];
        if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|ERR_SSL/i.test(code)) return ['unreachable', `TLS certificate problem (${code}).`];
        return ['unreachable', `Connection failed (${code}).`];
    }
    const s = res.status;
    if ([401, 403, 406, 429, 451, 999].includes(s) || res.headers['cf-mitigated'] === 'challenge' || (s === 503 && /cloudflare/i.test(res.headers.server || ''))) {
        return ['blocked', `The site refused an automated request (HTTP ${s}).`];
    }
    if (s >= 300 && s < 400) return ['unreachable', `Redirect without an end (HTTP ${s}).`];
    if (s >= 400) return ['http_error', `The page returned HTTP ${s}.`];
    return ['not_html', `The address returned ${res.contentType.split(';')[0] || 'no content type'}, not a web page.`];
}

function blankRow(input) {
    const row = { input, url: null, finalUrl: null, status: 'invalid', statusCode: null, message: null, title: null, language: null, technologyCount: 0, technologyList: '' };
    for (const key of Object.keys(SUMMARY_FIELDS)) row[key] = null;
    return Object.assign(row, { emailProvider: null, dnsProvider: null, emailSenders: null, connectedServices: null, technologyNames: [], technologies: [], categories: {}, wordpress: null, shopify: null, dns: null, redirectCount: 0, responseTimeMs: null, checkedAt: new Date().toISOString() });
}

async function analyze(input, options) {
    const row = blankRow(input);
    const start = toUrl(input);
    if (!start) {
        row.message = 'Not a website address.';
        return row;
    }
    row.url = start.href;
    const findings = new Findings();
    const t0 = performance.now();
    const timing = diag.on ? {} : null;
    let loaded = await loadPage(start.href);
    if (timing) timing.loadMs = Math.round(performance.now() - t0);
    const bare = !/^[a-z][a-z0-9+.-]*:\/\//i.test(input.trim()); // a domain was given, not a full URL
    const noAnswer = (l) => !l.disallowed && !l.res.ok;
    // A site that refuses https, or gets it wrong, is tried once on http, as a browser user would. A site that takes
    // the connection and then stays silent is not tried again: that silence is an answer, and waiting twice helps nobody.
    const silent = (l) => /^(?:TIMEOUT|UND_ERR_HEADERS_TIMEOUT|UND_ERR_BODY_TIMEOUT)$/.test(l.res.errorCode);
    const slow = (l) => silent(l) || /^(?:UND_ERR_CONNECT_TIMEOUT|ETIMEDOUT)$/.test(l.res.errorCode);
    if (bare && noAnswer(loaded) && loaded.res.errorCode !== 'ENOTFOUND' && !slow(loaded)) {
        const viaHttp = await loadPage(`http://${start.host}${start.pathname}${start.search}`);
        if (viaHttp.disallowed || viaHttp.res.ok) loaded = viaHttp;
    }
    // Many websites only answer with "www." in front of the domain.
    if (bare && noAnswer(loaded) && !silent(loaded) && !/^www\./i.test(start.hostname)) {
        const viaWww = await loadPage(`https://www.${start.host}${start.pathname}${start.search}`);
        if (viaWww.disallowed || viaWww.res.ok) loaded = viaWww;
    }
    row.finalUrl = loaded.finalUrl;
    row.redirectCount = loaded.hops;
    const finalHost = new URL(loaded.finalUrl).hostname;
    let page = null;

    if (loaded.disallowed) {
        row.status = 'robots_disallowed';
        row.message = 'robots.txt does not allow this crawler to read the page.';
    } else {
        const { res } = loaded;
        row.statusCode = res.ok ? res.status : null;
        row.responseTimeMs = res.timeMs;
        if (res.ok && res.status === 200 && res.isHtml && res.body?.length) {
            row.status = 'analyzed';
            const queuedAt = performance.now();
            if (timing) Object.assign(timing, { fetchMs: res.timeMs, headersMs: res.headersMs, reads: res.reads, bytes: res.body.length });
            page = await inTurn(async () => {
                if (timing) timing.queueMs = Math.round(performance.now() - queuedAt);
                const read = readPage(decodeBuffer(res.body, encodingOptions(res)));
                if (sliceUsed()) await pause();
                await matchPage(findings, { headers: res.headers, cookies: loaded.cookies, page: read, host: finalHost });
                row.wordpress = readWordPress(findings, read);
                row.shopify = readShopify(findings, read);
                read.markup = ''; // not needed any more, and it can be large
                if (timing) timing.matchMs = Math.round(performance.now() - queuedAt) - timing.queueMs;
                return read;
            });
            res.body = null;
            row.title = detach(page.title.slice(0, 200)) || null;
            row.language = page.lang ? detach(page.lang.slice(0, 20)) : null;
            if (options.readTagManager) {
                const tagManagerAt = performance.now();
                try {
                    await readTagManager(findings, page);
                } catch (err) {
                    log.debug(`Tag manager container of ${input} could not be read: ${err.message}`);
                }
                if (timing) timing.tagManagerMs = Math.round(performance.now() - tagManagerAt);
            }
        } else {
            [row.status, row.message] = describeFailure(res);
            // Headers and cookies of a refusal still tell something, for example the CDN in front of the site.
            if (res.ok) await matchPage(findings, { headers: res.headers, cookies: loaded.cookies, page: null, host: finalHost });
        }
        prune(findings, finalHost);
    }

    const dnsAt = performance.now();
    if (options.checkDns && row.status !== 'invalid') {
        try {
            row.dns = await readDns(findings, row.status === 'analyzed' ? finalHost : start.hostname);
            row.emailProvider = row.dns.emailProvider ?? null;
            row.dnsProvider = row.dns.dnsProvider ?? null;
            row.emailSenders = row.dns.emailSenders?.join('; ') || null;
            row.connectedServices = row.dns.connectedServices?.join('; ') || null;
        } catch (err) {
            log.debug(`DNS of ${input} could not be read: ${err.message}`);
        }
    }

    if (timing) {
        timing.dnsMs = Math.round(performance.now() - dnsAt);
        timing.totalMs = Math.round(performance.now() - t0);
        row.timing = timing;
    }
    addImplied(findings);
    const list = [...findings.map.values()].sort((a, b) => categoryRank(a.category) - categoryRank(b.category) || a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
    row.technologies = options.includeEvidence ? list : list.map(({ name, category, version }) => ({ name, category, version }));
    row.technologyNames = list.map((t) => t.name);
    row.technologyCount = list.length;
    row.technologyList = row.technologyNames.join('; ');
    for (const t of list) (row.categories[t.category] ??= []).push(t.name);
    for (const [key, cats] of Object.entries(SUMMARY_FIELDS)) row[key] = cats.flatMap((c) => row.categories[c] ?? []).join('; ') || null;
    return row;
}

// ---------------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------------

// What the report says about websites that were not analyzed: for one website, and for several.
const NOT_ANALYZED_TEXT = {
    blocked: ['website refused an automated request', 'websites refused an automated request'],
    unreachable: ['website could not be reached', 'websites could not be reached'],
    robots_disallowed: ['website does not allow its home page to be read (robots.txt)', 'websites do not allow their home page to be read (robots.txt)'],
    http_error: ['website returned an error page', 'websites returned an error page'],
    not_html: ['website did not return a web page', 'websites did not return a web page'],
    invalid: ['entry was not a valid website address', 'entries were not valid website addresses'],
    error: ['website failed unexpectedly', 'websites failed unexpectedly'],
};

function renderReport(summary) {
    const pct = (n) => (summary.sitesAnalyzed ? `${((n / summary.sitesAnalyzed) * 100).toFixed(n / summary.sitesAnalyzed < 0.1 ? 1 : 0)}%` : '');
    const techRows = summary.topTechnologies.map((t) => `<tr><td>${esc(t.name)}</td><td class="m">${esc(t.category)}</td><td class="n">${t.sites.toLocaleString('en-US')}</td><td class="n">${pct(t.sites)}</td><td><div class="bar" style="width:${Math.max(2, Math.round((t.sites / (summary.topTechnologies[0]?.sites || 1)) * 100))}%"></div></td></tr>`).join('');
    const catBlocks = summary.categories.slice(0, 24).map((c) => `<div class="cat"><h3>${esc(c.category)}</h3><ol>${c.top.map((t) => `<li><span>${esc(t.name)}</span><span class="m">${t.sites.toLocaleString('en-US')} · ${pct(t.sites)}</span></li>`).join('')}</ol></div>`).join('');
    const chips = (list) => list.slice(0, 40).map((t) => `<li><span>${esc(t.name)}</span><span class="m">${t.sites.toLocaleString('en-US')} · ${pct(t.sites)}</span></li>`).join('');
    const dnsBlocks = [['Services that send email for the domain (SPF)', summary.emailSenders], ['Services connected through verification records', summary.connectedServices]]
        .filter(([, list]) => list.length).map(([title, list]) => `<div class="cat"><h3>${esc(title)}</h3><ol>${chips(list)}</ol></div>`).join('');
    const statusNotes = Object.entries(summary.notAnalyzed).filter(([, n]) => n > 0)
        .map(([k, n]) => `<li>${n.toLocaleString('en-US')} ${esc(NOT_ANALYZED_TEXT[k]?.[n === 1 ? 0 : 1] ?? k)}</li>`).join('');
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Website technology report</title>
<style>
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1c2330;margin:0;background:#f5f6f8}
main{max-width:1100px;margin:0 auto;padding:32px 20px 60px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px}h3{font-size:14px;margin:0 0 8px;color:#475467}
.m{color:#667085;font-size:13px}.cards{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}
.c{background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:14px 18px;min-width:130px}
.v{font-size:26px;font-weight:650}.l{color:#667085;font-size:13px}
.t{overflow-x:auto}table{width:100%;min-width:640px;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #eef0f4;vertical-align:middle}
th{background:#fafbfc;font-size:13px;color:#475467}.n{text-align:right;white-space:nowrap}
.bar{height:10px;border-radius:5px;background:linear-gradient(90deg,#0d2b5e,#128f83)}
.cats{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.cat{background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:14px 16px}
.cat ol{margin:0;padding:0;list-style:none}.cat li{display:flex;justify-content:space-between;gap:10px;padding:3px 0;font-size:14px}.cat li .m{white-space:nowrap}
ul{margin:8px 0;padding-left:20px}
</style></head><body><main>
<h1>Website technology report</h1>
<div class="m">${esc(`${summary.finishedAt.slice(0, 16).replace('T', ' ')} UTC`)} &middot; ${count(summary.sitesChecked, 'website')} checked</div>
<div class="cards">
<div class="c"><div class="v">${summary.sitesAnalyzed.toLocaleString('en-US')}</div><div class="l">Websites analyzed</div></div>
<div class="c"><div class="v">${(summary.sitesChecked - summary.sitesAnalyzed).toLocaleString('en-US')}</div><div class="l">Not analyzed</div></div>
<div class="c"><div class="v">${summary.distinctTechnologies.toLocaleString('en-US')}</div><div class="l">Technologies found</div></div>
<div class="c"><div class="v">${summary.averageTechnologiesPerSite}</div><div class="l">Average per website</div></div>
</div>
<h2>Most used technologies</h2>
${techRows ? `<div class="t"><table><thead><tr><th>Technology</th><th>Category</th><th class="n">Websites</th><th class="n">Share</th><th style="width:30%"></th></tr></thead><tbody>${techRows}</tbody></table></div>` : '<p class="m">No technologies were found.</p>'}
${catBlocks ? `<h2>Leaders by category</h2><div class="cats">${catBlocks}</div>` : ''}
${dnsBlocks ? `<h2>Found in DNS records</h2><p class="m">These describe the organisation behind a domain and are not counted as website technologies.</p><div class="cats">${dnsBlocks}</div>` : ''}
${statusNotes ? `<h2>Not analyzed</h2><ul>${statusNotes}</ul><p class="m">These websites are in the dataset with the reason, and they are not charged.</p>` : ''}
<p class="m">Shares are of the websites that were analyzed. The home page is read as the server sends it, together with response headers, cookies, the tag manager container and DNS records.</p>
</main></body></html>`;
}

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------

// An aborted run saves what it has finished instead of exiting empty-handed.
await Actor.init({ gracefulShutdown: false });

const input = (await Actor.getInput()) ?? {};
const seen = new Set();
const sites = [];
for (const item of [...(input.websites ?? []), ...(input.startUrls ?? [])]) {
    const value = clean(typeof item === 'string' ? item : item?.url);
    if (!value || seen.has(value.toLowerCase())) continue;
    seen.add(value.toLowerCase());
    sites.push(value);
    if (sites.length >= HARD_MAX_SITES) break;
}
seen.clear();
if (!sites.length) {
    await Actor.fail('No websites to check. Add at least one domain or URL to "Websites".');
}

const options = {
    checkDns: input.checkDns !== false,
    readTagManager: input.readTagManager !== false,
    includeEvidence: input.includeEvidence !== false,
};
const maxConcurrency = Math.min(Math.max(Number(input.maxConcurrency) || 30, 1), 100);
diag.on = input.debugTiming === true;
if (diag.on && Number(input.debugSliceMs) > 0) SLICE_MS = Number(input.debugSliceMs);
const loopDelay = diag.on ? monitorEventLoopDelay({ resolution: 10 }) : null;
loopDelay?.enable();

// Respect the user's spending limit: never analyze more websites than can be charged for.
const chargingManager = Actor.getChargingManager();
const isPayPerEvent = chargingManager.getPricingInfo().isPayPerEvent;
let paidLimit = Infinity;
if (isPayPerEvent) {
    paidLimit = chargingManager.calculateMaxEventChargeCountWithinLimit(EVENT);
    if (paidLimit <= 0) {
        await Actor.exit('The maximum cost per run is too low to analyze a single website. Raise the limit and run again.');
    }
    if (paidLimit < sites.length) log.info(`This run can pay for ${count(paidLimit, 'analyzed website')} within its maximum cost.`);
}

// What earlier attempts of this run (after a restart or migration) already saved.
const state = (await Actor.getValue('STATE')) ?? { done: [], statuses: {}, techs: {}, techCategory: {}, techTotal: 0, senders: {}, services: {} };
state.senders ??= {};
state.services ??= {};
const done = new Set(state.done);
const startedAt = new Date();
const { timeoutAt, memoryMbytes } = Actor.getEnv();
const hardStop = timeoutAt ? new Date(timeoutAt).getTime() : Infinity;
const reserveMs = Math.min(60_000, Math.max((hardStop - startedAt.getTime()) / 3, 0));
// When a run is aborted or runs out of time, no more websites are started. The ones being worked on get a few
// seconds to finish; after that the results so far are saved without them.
let stopRequested = false;
let stopReason = null;
let closed = false;
let releaseStop;
const stopSignal = new Promise((resolve) => {
    releaseStop = resolve;
});
const requestStop = (reason, graceMs) => {
    if (stopRequested) return;
    stopRequested = true;
    stopReason = reason;
    setTimeout(releaseStop, graceMs).unref();
};
Actor.on('aborting', () => requestStop('aborted', 6_000));

const buffer = [];
let flushing = null;
let lastFlush = Date.now();
let lastStateSave = Date.now();
let analyzed = state.statuses.analyzed ?? 0; // websites charged for so far
let reserved = analyzed; // analyzed plus those being worked on
let limitReached = false;

function tally(row) {
    state.statuses[row.status] = (state.statuses[row.status] ?? 0) + 1;
    if (row.status !== 'analyzed') return;
    state.techTotal += row.technologyCount;
    for (const t of row.technologies) {
        state.techs[t.name] = (state.techs[t.name] ?? 0) + 1;
        state.techCategory[t.name] ??= t.category;
    }
    for (const name of row.dns?.emailSenders ?? []) state.senders[name] = (state.senders[name] ?? 0) + 1;
    for (const name of row.dns?.connectedServices ?? []) state.services[name] = (state.services[name] ?? 0) + 1;
}

// The dataset checks every row against the declared output fields and refuses a whole batch when one row does not
// fit. Such a row is saved in a reduced form, uncharged, so that it cannot hold back the rows around it.
async function saveRows(batch) {
    try {
        await Actor.pushData(batch);
    } catch (err) {
        const invalid = err?.data?.invalidItems;
        if (!Array.isArray(invalid) || !invalid.length) throw err;
        for (const { itemPosition, validationErrors } of invalid) {
            const row = batch[itemPosition];
            if (!row) throw err;
            log.warning(`The row for ${row.input} did not fit the output fields and was saved without its details.`, { validationErrors: JSON.stringify(validationErrors ?? null).slice(0, 500) });
            batch[itemPosition] = Object.assign(blankRow(row.input), {
                url: typeof row.url === 'string' ? row.url : null,
                status: 'error',
                message: 'The result for this website could not be saved in full. Please report it on the Issues tab.',
            });
        }
        await Actor.pushData(batch);
    }
}

// Rows are saved first and charged for afterwards, so nobody pays for a result that was not stored.
async function flush() {
    while (buffer.length) {
        const batch = buffer.slice(0, 200);
        await saveRows(batch);
        buffer.splice(0, batch.length);
        for (const row of batch) {
            tally(row);
            state.done.push(row.input);
        }
        const billable = batch.filter((r) => r.status === 'analyzed').length;
        if (isPayPerEvent && billable) {
            const result = await Actor.charge({ eventName: EVENT, count: billable });
            if (result?.eventChargeLimitReached) limitReached = true;
        }
    }
    lastFlush = Date.now();
    if (Date.now() - lastStateSave > 20_000) {
        lastStateSave = Date.now();
        await Actor.setValue('STATE', state);
    }
}
let flushAgain = false;
function requestFlush(force = false) {
    if (!force && buffer.length < FLUSH_ROWS && Date.now() - lastFlush < FLUSH_MS) return flushing ?? Promise.resolve();
    if (flushing) {
        flushAgain = true;
        return flushing;
    }
    flushing = (async () => {
        try {
            do {
                flushAgain = false;
                await flush();
            } while (flushAgain);
        } catch (err) {
            log.exception(err, 'Saving results failed, will try again');
        } finally {
            flushing = null;
        }
    })();
    return flushing;
}

log.info(`Checking ${count(sites.length, 'website')}${done.size ? ` (${done.size} already saved by an earlier attempt)` : ''}.`);
let next = 0;
let finished = 0;
let lastLog = Date.now();

async function worker() {
    for (;;) {
        if (stopRequested || limitReached) return;
        if (Date.now() > hardStop - reserveMs) {
            requestStop('timeout', Math.min(20_000, reserveMs / 3));
            return;
        }
        if (next >= sites.length) return;
        if (reserved >= paidLimit) {
            // Every paid slot is taken by a website that is being worked on. Wait to see whether one frees up.
            if (analyzed >= paidLimit) {
                limitReached = true;
                return;
            }
            await sleep(200);
            continue;
        }
        const site = sites[next++];
        if (done.has(site)) continue;
        reserved += 1;
        await whenProcessorAllows();
        if (stopRequested) {
            reserved -= 1;
            return;
        }
        let row;
        try {
            row = await analyze(site, options);
        } catch (err) {
            log.warning(`Unexpected error on ${site}: ${err.message}`);
            row = Object.assign(blankRow(site), { status: 'error', message: `Could not be analyzed (${String(err.message).slice(0, 120)})` });
        }
        if (closed) return; // too late: the results are already being wrapped up
        if (row.status === 'analyzed') analyzed += 1;
        else reserved -= 1;
        buffer.push(row);
        finished += 1;
        siteFinished();
        requestFlush();
        if (Date.now() - lastLog > 10_000) {
            lastLog = Date.now();
            const msg = `Checked ${finished + done.size} of ${sites.length} websites (${analyzed} analyzed).`;
            log.info(memoryMbytes ? `${msg} Memory: ${Math.round(process.memoryUsage.rss() / 1048576)} of ${memoryMbytes} MB.` : msg);
            Actor.setStatusMessage(msg).catch(() => {});
        }
    }
}
await Promise.race([Promise.all(Array.from({ length: Math.min(maxConcurrency, sites.length) }, () => worker())), stopSignal]);
closed = true;
if (diag.on) {
    const cpu = process.cpuUsage();
    const file = (path) => {
        try {
            return readFileSync(path, 'utf8').trim().replace(/\s+/g, ' ');
        } catch {
            return null;
        }
    };
    log.info('Timing', {
        wallMs: Date.now() - startedAt.getTime(),
        cpuUserMs: Math.round(cpu.user / 1000),
        cpuSystemMs: Math.round(cpu.system / 1000),
        loopUtilization: Number(performance.eventLoopUtilization().utilization.toFixed(3)),
        loopDelayMs: { mean: Math.round(loopDelay.mean / 1e6), p50: Math.round(loopDelay.percentile(50) / 1e6), p99: Math.round(loopDelay.percentile(99) / 1e6), max: Math.round(loopDelay.max / 1e6) },
        sliceMs: SLICE_MS,
        processorShare: ration.share,
        secondsPerSite: Number(ration.secondsPerSite.toFixed(4)),
        secondsPerSiteOverall: Number(((process.cpuUsage(ration.usageAtStart).user + process.cpuUsage(ration.usageAtStart).system) / 1e6 / Math.max(ration.sitesDone, 1)).toFixed(4)),
        threadPool: process.env.UV_THREADPOOL_SIZE ?? null,
        cpuMax: file('/sys/fs/cgroup/cpu.max'),
        cpuStat: file('/sys/fs/cgroup/cpu.stat'),
        cpuQuotaV1: file('/sys/fs/cgroup/cpu/cpu.cfs_quota_us'),
        cpuStatV1: file('/sys/fs/cgroup/cpu/cpu.stat'),
    });
}
await requestFlush(true);
if (buffer.length) await flush();

if (stopReason === 'timeout') log.warning('Stopping early to save the results before the run timeout.');
else if (stopReason === 'aborted') log.warning('The run is being aborted. What was checked so far is saved.');
if (limitReached) log.warning('The maximum cost of this run was reached. The remaining websites were not checked.');

// Summary
const finishedAt = new Date();
const sitesChecked = Object.values(state.statuses).reduce((a, b) => a + b, 0);
const sitesAnalyzed = state.statuses.analyzed ?? 0;
const techEntries = Object.entries(state.techs).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
const byCategory = new Map();
for (const [name, n] of techEntries) {
    const category = state.techCategory[name];
    if (!byCategory.has(category)) byCategory.set(category, []);
    byCategory.get(category).push({ name, sites: n });
}
const topOf = (counts, n) => Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n).map(([name, sitesCount]) => ({ name, sites: sitesCount }));
const store = await Actor.openKeyValueStore();
const summary = {
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationSecs: Math.round((finishedAt - startedAt) / 1000),
    sitesSubmitted: sites.length,
    sitesChecked,
    sitesAnalyzed,
    notAnalyzed: {
        blocked: state.statuses.blocked ?? 0,
        unreachable: state.statuses.unreachable ?? 0,
        robots_disallowed: state.statuses.robots_disallowed ?? 0,
        http_error: state.statuses.http_error ?? 0,
        not_html: state.statuses.not_html ?? 0,
        invalid: state.statuses.invalid ?? 0,
        error: state.statuses.error ?? 0,
    },
    notChecked: sites.length - sitesChecked,
    stoppedEarly: stopReason ?? (limitReached ? 'cost limit' : null),
    distinctTechnologies: techEntries.length,
    averageTechnologiesPerSite: sitesAnalyzed ? Math.round((state.techTotal / sitesAnalyzed) * 10) / 10 : 0,
    topTechnologies: techEntries.slice(0, 100).map(([name, n]) => ({ name, category: state.techCategory[name], sites: n })),
    categories: [...byCategory].map(([category, list]) => ({ category, technologies: list.length, top: list.slice(0, 8) })).sort((a, b) => (b.top[0]?.sites ?? 0) - (a.top[0]?.sites ?? 0)),
    emailSenders: topOf(state.senders, 50),
    connectedServices: topOf(state.services, 50),
    reportUrl: store.getPublicUrl('REPORT'),
};
await Actor.setValue('REPORT', renderReport(summary), { contentType: 'text/html; charset=utf-8' });
await Actor.setValue('OUTPUT', summary);
await Actor.setValue('STATE', state);

const notAnalyzed = sitesChecked - sitesAnalyzed;
log.info(`HTML report: ${summary.reportUrl}`);
await Actor.exit(`Done: ${count(sitesAnalyzed, 'website')} analyzed, ${techEntries.length.toLocaleString('en-US')} different technologies found.${notAnalyzed ? ` ${count(notAnalyzed, 'website')} could not be analyzed and ${notAnalyzed === 1 ? 'is' : 'are'} not charged.` : ''}${summary.notChecked ? ` ${count(summary.notChecked, 'website')} not checked (${summary.stoppedEarly ?? 'stopped early'}).` : ''}`);
