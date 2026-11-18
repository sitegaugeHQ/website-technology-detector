# Website Technology & Tech Stack Detector

> **Run it on Apify:** [apify.com/sitegauge/website-technology-detector](https://apify.com/sitegauge/website-technology-detector). Nothing to install, and you pay per result. This repository holds the Actor's full source code under the MIT licence.

Find out what any list of websites is built with: CMS, ecommerce platform, website builder, JavaScript frameworks, analytics, advertising and marketing tools, live chat, payments, hosting, CDN, and the email and DNS providers behind the domain.

Paste domains, get one row per website with the technologies found and the evidence for each one. You pay only for websites that were actually analyzed.

## Who it is for

- **Sales and marketing teams** who qualify leads by technology, for example Shopify stores that use Klaviyo, or WordPress sites without a cookie banner.
- **Agencies and freelancers** who want to know a prospect's stack before the first call.
- **Market researchers and product teams** who measure how widely a tool is used across a list of sites.
- **Developers and AI agents** that need a site's tech stack as structured data (JSON, CSV, Excel).

## What you get

1. **One dataset row per website** with ready-to-filter columns (`cms`, `ecommerce`, `websiteBuilder`, `frameworks`, `analytics`, `tagManagers`, `advertising`, `marketing`, `liveChat`, `payments`, `cookieConsent`, `hosting`, `emailProvider`), the full technology list, and every technology with its category, version when it is visible, and the evidence it was recognised by.
2. **What the domain's DNS shows about the organisation**, in columns of their own: the email provider (`emailProvider`), the DNS provider or providers (`dnsProvider`), the services allowed to send email for the domain (`emailSenders`, from SPF), the services the domain has been verified with (`connectedServices`, for example Atlassian, DocuSign, Zoom or OpenAI), and the DMARC policy.
3. **WordPress and Shopify details**: the theme and every plugin folder found on a WordPress page, and the theme of a Shopify store.
4. **An HTML report** (`REPORT` in the key-value store) with the most used technologies across your list, by category.
5. **A JSON summary** (`OUTPUT` in the key-value store) with the same counts.

## What it detects

About 500 technologies in more than 60 categories, including:

| Area | Examples |
|---|---|
| CMS and site builders | WordPress, Drupal, Joomla, HubSpot CMS, Webflow, Wix, Squarespace, Ghost, Framer |
| Ecommerce | Shopify, WooCommerce, Magento, BigCommerce, PrestaShop, Salesforce Commerce Cloud |
| Frameworks and libraries | Next.js, Nuxt, React, Vue.js, Angular, Svelte, Astro, jQuery, Bootstrap, Tailwind CSS |
| Analytics and tag managers | Google Analytics, Google Tag Manager, Matomo, Plausible, Hotjar, Microsoft Clarity, Segment |
| Advertising | Meta Pixel, Google Ads, LinkedIn Insight Tag, TikTok Pixel, Microsoft Advertising |
| Marketing and CRM | HubSpot, Klaviyo, Mailchimp, ActiveCampaign, Marketo, Salesforce |
| Chat and support | Intercom, Zendesk, Drift, Tawk.to, Crisp, LiveChat |
| Payments | Stripe, PayPal, Klarna, Afterpay, Square |
| Cookie consent | OneTrust, Cookiebot, CookieYes, Usercentrics, Termly |
| Hosting, CDN and security | Cloudflare, Vercel, Netlify, Amazon CloudFront, Fastly, Akamai, WP Engine |
| From DNS | Email providers such as Google Workspace, Microsoft 365 and Zoho Mail, DNS providers such as Cloudflare DNS and Amazon Route 53, about 50 email sending services and more than 90 services that leave a verification record |

On WordPress sites every plugin and theme folder that the page loads is listed, also the ones that are not in the fingerprint list.

## How it works

For each website the Actor:

1. Reads `robots.txt` and then requests the **home page once**. Redirects are followed.
2. Compares the response headers, cookie names, meta tags, script and stylesheet addresses, inline scripts and HTML with its fingerprints.
3. If the page uses Google Tag Manager, reads the public container file to find tags that are not in the page itself.
4. Looks up the domain's public DNS records (MX, TXT, NS, DMARC and the CNAME of `www`).

No browser is used and no JavaScript is run. That is why a run gets through hundreds of websites per minute (see [Speed](#speed)).

## How to use it

1. Paste your domains or URLs into **Websites**, one per line. `example.com`, `www.example.com` and `https://example.com/` all work.
2. Run the Actor.
3. Open the **Output** tab for the table, export it as CSV, Excel or JSON, or open the `REPORT` record in the key-value store.

### Input options

| Field | What it does | Default |
|---|---|---|
| `websites` | Domains or URLs to check | required |
| `checkDns` | Read the domain's DNS records | `true` |
| `readTagManager` | Read the Google Tag Manager container when a page uses one | `true` |
| `includeEvidence` | Add the matching signals to every technology | `true` |
| `maxConcurrency` | The most websites worked on at the same time | 30 |

### Example input

```json
{
    "websites": ["example.com", "https://www.example.org/", "shop.example.net"],
    "checkDns": true
}
```

## Example output (one row, shortened)

```json
{
    "input": "shop.example.net",
    "url": "https://shop.example.net/",
    "finalUrl": "https://shop.example.net/",
    "status": "analyzed",
    "statusCode": 200,
    "title": "Example Shop",
    "language": "en",
    "technologyCount": 10,
    "technologyList": "Shopify; Cloudflare; Meta Pixel; Klaviyo; Stripe; Microsoft 365; Amazon Route 53; Judge.me; HSTS; Shopify theme: Dawn",
    "cms": null,
    "ecommerce": "Shopify",
    "analytics": null,
    "advertising": "Meta Pixel",
    "marketing": "Klaviyo",
    "payments": "Stripe",
    "hosting": "Cloudflare",
    "emailProvider": "Microsoft 365",
    "dnsProvider": "Amazon Route 53",
    "emailSenders": "Microsoft 365; Klaviyo",
    "connectedServices": "Meta Business",
    "technologies": [
        { "name": "Shopify", "category": "Ecommerce", "version": null, "evidence": ["header x-shopid", "cookie: _shopify_y", "loads: cdn.shopify.com/"] },
        { "name": "Klaviyo", "category": "Email marketing", "version": null, "evidence": ["loads: static.klaviyo.com/onsite/js/"] }
    ],
    "shopify": { "theme": "Dawn", "themeBase": "Dawn 15.0.0" },
    "dns": {
        "domain": "example.net",
        "emailProvider": "Microsoft 365",
        "dnsProvider": "Amazon Route 53",
        "hasSpf": true,
        "emailSenders": ["Microsoft 365", "Klaviyo"],
        "dmarcPolicy": "quarantine",
        "connectedServices": ["Meta Business"]
    },
    "checkedAt": "2026-11-18T09:00:00.000Z"
}
```

### Status of a row

| Status | Meaning | Charged |
|---|---|---|
| `analyzed` | The home page was read and compared with the fingerprints. | yes |
| `blocked` | The site refused an automated request (for example 403, 429 or a bot challenge). | no |
| `robots_disallowed` | The site's robots.txt does not allow the page to be read. | no |
| `unreachable` | The domain does not resolve, did not answer within 20 seconds or has a certificate problem. | no |
| `http_error` | The page returned an error such as 404 or 500. | no |
| `not_html` | The address returned something other than a web page. | no |
| `invalid` | The line is not a website address. | no |
| `error` | Something unexpected went wrong while this website was checked. The message says what. | no |

Rows that were not analyzed still show what could be seen without the page, for example the CDN from the response headers and the email provider from DNS.

## Pricing

You pay per result: **$2 per 1,000 analyzed websites**, plus Apify's small Actor start fee. Customers on Apify's paid plans pay less: $1.90 per 1,000 on Starter, $1.80 on Scale and $1.60 on Business. There is no monthly rental and you do not pay for platform compute separately.

Websites that could not be analyzed (blocked, unreachable, disallowed by robots.txt, invalid) are in the results but are **not charged**.

Set a maximum cost per run in Apify Console to cap your spend. The Actor never analyzes more websites than your limit can pay for.

| Analyzed websites | Approximate cost |
|---|---|
| 1,000 | $2 |
| 10,000 | $20 |
| 100,000 | $200 |

## Speed

How fast a run goes depends on its memory, because Apify gives a run processor time in proportion to its memory. Measured in November 2026 on a mixed list of 736 well-known websites:

| Memory of the run | Websites per minute |
|---|---|
| 1 GB | about 120 |
| 4 GB (default) | about 550 |
| 8 GB | about 1,000 |

Slow and unreachable websites lower these figures, because each of them is given up to 20 seconds to answer. The price per analyzed website is the same at every memory setting, so the default is a good choice for most lists. Choose 8 GB under **Run options** for very long lists.

The Actor never asks for more processor time than the run has. Websites are started at the pace the processor allows, so a busy run does not mistake its own slowness for a slow website.

## Good to know

- **Only what a visitor's first request shows is detected.** Tools that load after a click, after consent, or only on inner pages such as the checkout are not seen. Tags loaded through Google Tag Manager are found by reading the container.
- **No technology is guessed.** Every entry comes with the signal it was recognised by. Server-side software that leaves no public trace cannot be detected by any tool of this kind.
- **Platform folder names only count in a page's own scripts and stylesheets.** A picture or a text link that points at another website's WordPress folder does not make the page WordPress.
- **The crawler is polite.** It identifies itself as `SiteAuditBot`, respects robots.txt, sends at most two requests per second to one host and makes no attempt to get around blocks.
- **Account identifiers are left out.** The evidence shows that a site uses a tool, not the account or tracking ID it uses.
- **DNS records describe the organisation, not the page.** Mail senders and verification records are therefore kept out of the technology list and the technology count: a company that has verified its domain with Shopify does not necessarily run this website on Shopify. On host names that belong to a platform, such as `example.myshopify.com`, DNS is skipped.
- **Bare domains get a second chance.** If `example.com` does not answer, `www.example.com` is tried before the website is reported as unreachable. A website that accepts the connection and then stays silent is not tried again.
- **Limits:** up to 200,000 websites per run and 2 MB of HTML per page.
- **Aborted and timed-out runs keep their results.** Rows are saved while the run is going. When a run is aborted gracefully or reaches its time-out it stops starting websites, saves what is finished and writes the report.
- This is an independent tool. It is not affiliated with or endorsed by any of the technologies it detects.

## FAQ

**Why is a technology I know is there not listed?**
It may load only after JavaScript runs, after cookie consent, or on a page other than the home page. Open an issue with the website and the technology and it will be looked at.

**Why was a website not analyzed?**
The `status` and `message` columns say why. The most common reasons are a firewall that refuses automated requests and a domain that no longer resolves. These rows are free.

**Can it check inner pages?**
Give the full URL of the page instead of the domain. That page is then read instead of the home page.

**How many websites can I check in one run?**
Up to 200,000. With the default memory a run checks about 550 websites per minute, so 10,000 websites take about 20 minutes. A run stops at its time-out, which is one hour unless you change it, and keeps what it has checked. For more than about 30,000 websites raise the time-out or the memory under **Run options**. See [Speed](#speed).

**Can I schedule it?**
Yes. Use Apify schedules to re-check a list every month and compare the results.

## Related tools

- [Technical SEO Audit & Site Crawler](https://apify.com/sitegauge/seo-audit-crawler): crawls a site and audits every URL with 57 technical and on-page SEO checks, a score per page and an HTML report.
- [Broken Link Checker & Bulk URL Status Checker](https://apify.com/sitegauge/broken-link-checker): checks every link on a site, or a list of URLs, and reports the broken ones with the pages that link to them.

## Feedback

Missing a technology or found a wrong match? Open an issue on the Issues tab and it will be looked at.

## Run it locally

You need Node.js 20 or newer.

```bash
npm install
mkdir -p storage/key_value_stores/default
echo '{"websites": ["apify.com", "crawlee.dev", "wordpress.org"]}' > storage/key_value_stores/default/INPUT.json
APIFY_LOCAL_STORAGE_DIR=./storage npm start
```

The rows are written to `storage/datasets/default`, and the report and summary to `storage/key_value_stores/default`.

### Run it against the test fixture

```bash
node test/fixture.mjs &
echo '{"websites": ["wp.example", "shop.example", "next.example"]}' > storage/key_value_stores/default/INPUT.json
TECH_DETECTOR_TEST_SERVER=http://127.0.0.1:8300 TECH_DETECTOR_DNS_FIXTURE=test/dns-fixture.json APIFY_LOCAL_STORAGE_DIR=./storage npm start
```

The fixture is one local server that plays several websites, and `test/dns-fixture.json` stands in for their DNS records, so the run needs no network.

## Licence

MIT. See [LICENSE](LICENSE).
