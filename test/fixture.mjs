// Local fixture for the technology detector: one server that plays several websites, chosen by the x-test-url header.
import http from 'node:http';

const page = (head, body, attrs = '') => `<!doctype html><html lang="en"${attrs}><head><meta charset="utf-8"><title>Fixture &amp; site</title>${head}</head><body>${body}</body></html>`;

const sites = {
    'wp.example': {
        headers: { server: 'nginx/1.24.0', 'x-powered-by': 'PHP/8.2.12', link: '<https://wp.example/wp-json/>; rel="https://api.w.org/"', 'set-cookie': ['PHPSESSID=abc; path=/', 'woocommerce_cart_hash=1; path=/'] },
        html: page(`<meta name="generator" content="WordPress 6.6.2"><meta name="generator" content="WooCommerce 9.3.1"><meta name="generator" content="Elementor 3.24.5; features: e_font_icon_svg">
<link rel="stylesheet" href="https://wp.example/wp-content/themes/astra/style.css?ver=4.8.1"><link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script><script src="/wp-content/plugins/woocommerce/assets/js/frontend/cart-fragments.min.js"></script>
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js"></script><script src="/wp-content/plugins/my-custom-thing/app.js"></script>
<!-- This site is optimized with the Yoast SEO plugin v23.5 - https://yoast.com/wordpress/plugins/seo/ -->
<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s);j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','GTM-ABCD123');</script>
<link rel="preconnect" href="https://fonts.googleapis.com"><meta property="og:title" content="x"><script type="application/ld+json">{}</script>`,
            `<div class="woocommerce">shop</div><noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABCD123"></iframe></noscript><!-- Performance optimized by W3 Total Cache -->`),
    },
    'shop.example': {
        headers: { 'x-shopid': '12345678', 'x-shopify-stage': 'production', server: 'cloudflare', 'cf-ray': '8abc-SYD', 'set-cookie': ['_shopify_y=1; path=/', '__cf_bm=x; path=/'], 'strict-transport-security': 'max-age=7889238' },
        html: page(`<link rel="preconnect" href="https://cdn.shopify.com"><script src="https://cdn.shopify.com/s/files/1/0001/theme.js"></script>
<script>var Shopify = Shopify || {}; Shopify.shop = "fixture.myshopify.com"; Shopify.theme = {"name":"Dawn custom","id":1234,"schema_name":"Dawn","schema_version":"13.0.1","theme_store_id":887,"role":"main"}; Shopify.routes = {};</script>
<script async src="https://static.klaviyo.com/onsite/js/klaviyo.js?company_id=AbC123"></script>
<script>!function(f,b,e,v,n,t,s){}(window, document,'script','https://connect.facebook.net/en_US/fbevents.js'); fbq('init', '123456789012345'); fbq('track', 'PageView');</script>
<script src="https://cdn.judge.me/widget_preloader.js"></script><script src="https://js.stripe.com/v3/"></script>`, `<img src="https://cdn.shopify.com/s/files/1/0001/a.png" alt="a">`),
    },
    'next.example': {
        headers: { server: 'Vercel', 'x-vercel-id': 'syd1::abc', 'x-vercel-cache': 'HIT', 'x-powered-by': 'Next.js', 'content-security-policy': "default-src 'self'" },
        html: page(`<link rel="stylesheet" href="/_next/static/css/abc.css"><script src="/_next/static/chunks/main-abc.js" defer></script>
<script src="https://js.sentry-cdn.com/abc.min.js"></script><script>window.intercomSettings = {app_id: "x"};</script><script async src="https://widget.intercom.io/widget/x"></script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEF1234"></script><script>gtag('config', 'G-ABCDEF1234');</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>`, `<div id="__next"></div><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script><iframe src="https://www.youtube.com/embed/abc"></iframe>`),
    },
    'blocked.example': { status: 403, headers: { server: 'cloudflare', 'cf-ray': '8abd-SYD', 'cf-mitigated': 'challenge' }, html: '<html><body>Just a moment...</body></html>' },
    'norobots.example': { robots: 'User-agent: *\nDisallow: /\n', headers: {}, html: page('', 'hidden') },
    'json.example': { type: 'application/json', headers: {}, html: '{"ok":true}' },
    'old.example': { redirect: 'https://next.example/' },
    'www.wwwonly.example': { headers: { server: 'nginx' }, html: page('<meta name="generator" content="Joomla! - Open Source Content Management"><script src="/media/system/js/core.js"></script><script src="https://cdn.example.net/bootstrap.js"></script><script src="/js/bootstrap.bundle.min.js"></script>', '<img src="https://other.example/wp-content/uploads/a.png" alt=""><a href="https://shop.example/integrations/squarespace-commerce/">x</a>') },
    'plain.example': { headers: { server: 'Apache/2.4.58 (Ubuntu)' }, html: page('<meta name="generator" content="Hugo 0.128.0">', '<p>hello</p>') },
    'www.googletagmanager.com': {
        type: 'application/javascript', headers: {},
        // Tags: Hotjar and LinkedIn built in, Clarity as custom HTML, three Google tags (Analytics, Ads, unknown ID).
        // Conditions mention Klaviyo and Salesforce only as link targets. A custom template loads Intercom.
        // The library code after the data mentions Segment. Only the tags and the template may be read.
        html: [
            '// Copyright 2012 Google Inc.', '(function(){', '', 'var data = {', '"resource": {', '  "version":"42",',
            '  "macros":[{"function":"__e"},{"function":"__jsm","vtp_javascript":["template","(function(){return \\"cdn.amplitude.com\\/script\\/x\\"})();"]}],',
            '  "tags":[{"function":"__hjtc","vtp_hotjar_site_id":"1234567","tag_id":3},{"function":"__bzi","vtp_id":"987654","tag_id":5},'
                + '{"function":"__html","vtp_html":"\\u003Cscript\\u003E(function(c,l,a,r,i,t,y){c[a]=c[a]||function(){};t=l.createElement(r);t.src=\\"https:\\/\\/www.clarity.ms\\/tag\\/\\"+i;})(window, document, \\"clarity\\", \\"script\\", \\"abcdefghij\\");\\u003C\\/script\\u003E","tag_id":7},'
                + '{"function":"__googtag","vtp_tagId":"G-ZZZZZZ9999","tag_id":9},{"function":"__googtag","metadata":["map"],"vtp_tagId":"AW-123456789","tag_id":11},{"function":"__googtag","vtp_tagId":["macro",1],"tag_id":12},'
                + '{"function":"__cvt_1_2","vtp_appId":"abc","tag_id":13}],',
            '  "predicates":[{"function":"_cn","arg0":["macro",0],"arg1":"static.klaviyo.com\\/onsite\\/js\\/"},{"function":"_cn","arg0":["macro",0],"arg1":"https:\\/\\/acme.my.salesforce.com\\/"}],',
            '  "rules":[[["if",0],["add",0]]]', '},',
            '"runtime":[ [50,"__cvt_1_2",[46,"a"],[52,"b","https:\\/\\/widget.intercom.io\\/widget\\/"]] ]',
            ',"entities":{"__cvt_1_2":{"2":true}}',
            ',"permissions":{"__cvt_1_2":{"inject_script":{"urls":["https:\\/\\/widget.intercom.io\\/widget\\/*"]}}}',
            ',"security_groups":{"google":["__e"]}', '', '};', '', '/*', '', ' Copyright The Closure Library Authors.', '*/',
            'var aa="https://cdn.segment.com/analytics.js/v1/x",ba={a:"}"};', '})();',
        ].join('\n'),
    },
};

http.createServer((req, res) => {
    const url = new URL(req.headers['x-test-url'] || `http://unknown${req.url}`);
    const site = sites[url.hostname];
    if (url.hostname === 'wwwonly.example') return req.socket.destroy(); // answers only with "www." in front
    if (!site) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        return res.end('no such fixture');
    }
    if (url.pathname === '/robots.txt') {
        if (!site.robots) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('none'); }
        res.writeHead(200, { 'content-type': 'text/plain' });
        return res.end(site.robots);
    }
    if (site.redirect) { res.writeHead(301, { location: site.redirect }); return res.end(); }
    res.writeHead(site.status || 200, { 'content-type': site.type || 'text/html; charset=utf-8', ...site.headers });
    res.end(site.html);
}).listen(8300, () => console.log('tech fixture on 8300'));
