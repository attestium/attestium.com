const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');
const crypto = require('node:crypto');
const {build, slugify, structuredData} = require('../scripts/build-site.js');

const SITE = 'https://attestium.com';

// Schema.org types used in the structured data, with the properties each may carry.
const CREATIVE_WORK = ['@type', '@id', 'url', 'name', 'headline', 'description', 'inLanguage', 'isPartOf', 'publisher', 'author', 'image', 'dateModified', 'keywords', 'breadcrumb', 'mainEntity'];
const SCHEMA_ORG = {
  Organization: ['@type', '@id', 'name', 'url', 'logo', 'sameAs'],
  WebSite: ['@type', '@id', 'url', 'name', 'description', 'inLanguage', 'publisher'],
  WebPage: CREATIVE_WORK,
  TechArticle: CREATIVE_WORK,
  FAQPage: CREATIVE_WORK,
  Question: ['@type', 'name', 'acceptedAnswer'],
  Answer: ['@type', 'text'],
  BreadcrumbList: ['@type', '@id', 'itemListElement'],
  ListItem: ['@type', 'position', 'name', 'item'],
  Offer: ['@type', 'price', 'priceCurrency'],
  'SoftwareApplication,SoftwareSourceCode': ['@type', '@id', 'name', 'description', 'url', 'image', 'applicationCategory', 'operatingSystem', 'runtimePlatform', 'programmingLanguage', 'codeRepository', 'license', 'softwareVersion', 'downloadUrl', 'isAccessibleForFree', 'offers', 'publisher', 'author'],
};

function htmlFiles(dir) {
  return fs.readdirSync(dir, {withFileTypes: true}).flatMap(entry => {
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return htmlFiles(file);
    }

    return entry.name.endsWith('.html') ? [file] : [];
  });
}

function targetFile(outDir, url) {
  const file = path.join(outDir, decodeURIComponent(url));
  return url.endsWith('/') ? path.join(file, 'index.html') : file;
}

function ids(html) {
  return new Set([...html.matchAll(/\sid="([^"]+)"/g)].map(m => m[1]));
}

function metaContent(html, attribute, name) {
  const match = new RegExp(`<meta ${attribute}="${name}" content="([^"]*)">`).exec(html);
  return match ? match[1] : null;
}

// Every node of the graph (and nested objects with a type) uses known types and properties.
function checkNode(node, where, problems) {
  if (Array.isArray(node)) {
    for (const item of node) {
      checkNode(item, where, problems);
    }

    return;
  }

  if (!node || typeof node !== 'object') {
    return;
  }

  if (node['@type']) {
    const type = [node['@type']].flat().join(',');
    const allowed = SCHEMA_ORG[type];
    if (allowed) {
      for (const key of Object.keys(node).filter(key => !allowed.includes(key))) {
        problems.push(`${where}: ${type} has unexpected property ${key}`);
      }
    } else {
      problems.push(`${where}: unexpected type ${type}`);
    }
  }

  for (const value of Object.values(node)) {
    checkNode(value, where, problems);
  }
}

test('slugs match GitHub heading ids', () => {
  assert.equal(slugify('TPM 2.0'), 'tpm-20');
  assert.equal(slugify('`new Attestium(options?)`'), 'new-attestiumoptions');
  assert.equal(slugify('Pass, fail and inconclusive'), 'pass-fail-and-inconclusive');
  assert.equal(slugify('NuGet (.NET)'), 'nuget-net');
});

test('site builds; links, metadata and structured data are complete', async t => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'attestium-site-'));
  t.after(() => fs.rmSync(outDir, {recursive: true, force: true}));
  const {pages} = await build({outDir});

  for (const url of ['/', '/spec/', '/docs/getting-started/', '/faq/', '/brand/', '/remote-attestation/']) {
    assert.ok(pages.includes(url), `${url} is not built`);
  }

  for (const file of ['404.html', 'sitemap.xml', 'robots.txt', 'llms.txt', 'llms-full.txt', 'manifest.webmanifest', 'style.css', 'site.js', 'favicon.svg', 'og.png', 'icon-512.png', 'brand/logo.svg', 'CNAME']) {
    assert.ok(fs.existsSync(path.join(outDir, file)), `${file} is missing`);
  }

  const robots = fs.readFileSync(path.join(outDir, 'robots.txt'), 'utf8');
  assert.match(robots, new RegExp(`Sitemap: ${SITE}/sitemap.xml`));
  // Every crawler and AI agent may read every page.
  assert.match(robots, /^User-agent: \*\nAllow: \/$/m);
  assert.doesNotMatch(robots, /Disallow/);

  const sitemap = fs.readFileSync(path.join(outDir, 'sitemap.xml'), 'utf8');
  for (const url of pages) {
    assert.match(sitemap, new RegExp(`<loc>${SITE}${url}</loc><lastmod>\\d{4}-\\d\\d-\\d\\dT[\\d:]+(?:Z|[+-]\\d\\d:\\d\\d)</lastmod>`), `${url} is not in the sitemap`);
  }

  const llms = fs.readFileSync(path.join(outDir, 'llms.txt'), 'utf8');
  assert.match(llms, /^# Attestium\n\n> .+\n/);
  for (const [, url] of llms.matchAll(/]\((https:\/\/attestium\.com\/[^)]*)\)/g)) {
    assert.ok(fs.existsSync(path.join(outDir, url.slice(SITE.length))), `llms.txt links to missing ${url}`);
  }

  const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'manifest.webmanifest'), 'utf8'));
  for (const icon of manifest.icons) {
    assert.ok(fs.existsSync(path.join(outDir, icon.src)), icon.src);
  }

  for (const file of ['schema/evidence.schema.json', 'schema/evidence-v2.json']) {
    assert.equal(JSON.parse(fs.readFileSync(path.join(outDir, file), 'utf8')).$schema, 'https://json-schema.org/draft/2020-12/schema');
  }

  const cache = new Map();
  const read = file => {
    if (!cache.has(file)) {
      cache.set(file, fs.readFileSync(file, 'utf8'));
    }

    return cache.get(file);
  };

  const problems = [];
  const titles = new Map();
  const descriptions = new Map();
  for (const file of htmlFiles(outDir)) {
    const html = read(file);
    const page = path.relative(outDir, file);
    const title = /<title>([^<]+)<\/title>/.exec(html);
    const description = metaContent(html, 'name', 'description');
    assert.match(html, /<html lang="en">/, page);
    assert.ok(title, `${page} has no title`);
    assert.ok(description && description.length <= 160, `${page}: description missing or longer than 160 characters`);
    assert.equal((html.match(/<h1[\s>]/g) || []).length, 1, `${page} must have one h1`);
    assert.match(html, /<main id="main"/, page);
    for (const [name, value] of [['og:title', title[1]], ['og:description', description]]) {
      assert.equal(metaContent(html, 'property', name), value, `${page}: ${name}`);
    }

    assert.equal(metaContent(html, 'property', 'og:image'), `${SITE}/og.png`, page);
    assert.match(html, /<link rel="canonical" href="https:\/\/attestium\.com\/[^"]*">/, page);
    titles.set(title[1], [...(titles.get(title[1]) || []), page]);
    descriptions.set(description, [...(descriptions.get(description) || []), page]);

    const scripts = [...html.matchAll(/<script type="application\/ld\+json">([^<]+)<\/script>/g)];
    assert.equal(scripts.length, 1, `${page} needs one JSON-LD block`);
    const data = JSON.parse(scripts[0][1]);
    assert.equal(data['@context'], 'https://schema.org', page);
    checkNode(data['@graph'], page, problems);

    const alternate = /<link rel="alternate" type="text\/markdown" href="https:\/\/attestium\.com([^"]+)"/.exec(html);
    if (alternate && !fs.existsSync(path.join(outDir, alternate[1]))) {
      problems.push(`${page}: Markdown copy ${alternate[1]} is missing`);
    }

    assert.equal(new Set(ids(html)).size, [...html.matchAll(/\sid="([^"]+)"/g)].length, `${page} has duplicate ids`);
    for (const [img] of html.matchAll(/<img [^>]*>/g)) {
      assert.match(img, / alt="[^"]+"/, `${page}: image without alt`);
      assert.match(img, / width="\d+" height="\d+"/, `${page}: image without width and height`);
    }

    for (const [, raw] of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
      const href = raw.replaceAll('&amp;', '&');
      if (/^(?:https?:|mailto:)/.test(href)) {
        continue;
      }

      if (!href.startsWith('/') && !href.startsWith('#')) {
        problems.push(`${page}: relative link ${href}`);
        continue;
      }

      const [pathname, anchor] = href.split('#');
      const target = pathname ? targetFile(outDir, pathname.split('?')[0]) : file;
      if (!fs.existsSync(target)) {
        problems.push(`${page}: ${href} does not exist`);
        continue;
      }

      if (anchor && target.endsWith('.html') && !ids(read(target)).has(decodeURIComponent(anchor))) {
        problems.push(`${page}: ${href} has no matching id`);
      }
    }
  }

  for (const [value, where] of [...titles, ...descriptions]) {
    if (where.length > 1) {
      problems.push(`${where.join(', ')} share "${value}"`);
    }
  }

  assert.deepEqual(problems, []);
});

test('structured data cannot end its script element', () => {
  const title = '</script><script>alert(1)</script><!--';
  const json = structuredData({
    kind: 'doc', url: '/x/', title, description: 'line\u2028separator', lastmod: '2026-01-01T00:00:00Z',
  });
  assert.ok(!json.includes('<'), json);
  assert.ok(!json.includes('\u2028'));
  assert.ok(JSON.parse(json)['@graph'].some(node => node.name === title));
});

test('every page has a Content-Security-Policy that allows what it loads, and no inline script but the theme', async t => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'site-csp-'));
  t.after(() => fs.rmSync(outDir, {recursive: true, force: true}));
  await build({outDir});
  const files = htmlFiles(outDir);
  assert.ok(files.length > 5);
  for (const file of files) {
    const where = path.relative(outDir, file);
    const html = fs.readFileSync(file, 'utf8');
    const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html);
    assert.ok(meta, `${where}: no Content-Security-Policy`);
    // Before anything it governs.
    assert.ok(meta.index < html.indexOf('<script') && meta.index < html.indexOf('<link'), `${where}: the policy comes too late`);
    const policy = new Map(meta[1].replaceAll('&amp;', '&').split(';').map(directive => directive.trim().split(/\s+/)).map(([name, ...values]) => [name, values]));
    assert.deepEqual(policy.get('default-src'), ['\'none\'']);
    assert.deepEqual(policy.get('base-uri'), ['\'none\'']);
    assert.deepEqual(policy.get('form-action'), ['\'none\'']);
    const scriptSources = policy.get('script-src');
    assert.ok(!scriptSources.some(source => /unsafe|\*|https?:/.test(source)), `${where}: ${scriptSources.join(' ')}`);
    const allows = (directive, url) => {
      if (url.startsWith('/') && !url.startsWith('//')) {
        return policy.get(directive).includes('\'self\'');
      }

      const {origin} = new URL(url);
      return policy.get(directive).includes(origin);
    };

    // Every inline script runs by its hash; data blocks do not run.
    for (const [, attributes, body] of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
      const src = /\ssrc="([^"]+)"/.exec(attributes);
      if (src) {
        assert.ok(allows('script-src', src[1]), `${where}: script ${src[1]} is not allowed`);
      } else if (!/type="application\/ld\+json"/.test(attributes)) {
        const hash = `'sha256-${crypto.createHash('sha256').update(body).digest('base64')}'`;
        assert.ok(scriptSources.includes(hash), `${where}: inline script ${body.slice(0, 40)} is not allowed`);
      }
    }

    assert.doesNotMatch(html, /<[a-z][^>]*\son[a-z]+=/i, `${where}: inline event handler`);
    assert.doesNotMatch(html, /\s(?:href|src)="\s*javascript:/i, `${where}: javascript: URL`);
    for (const [, href] of html.matchAll(/<link rel="stylesheet" href="([^"]+)"/g)) {
      assert.ok(allows('style-src', href), `${where}: stylesheet ${href} is not allowed`);
    }

    for (const [, href] of html.matchAll(/<link rel="preload" href="([^"]+)" as="font"/g)) {
      assert.ok(allows('font-src', href), `${where}: font ${href} is not allowed`);
    }

    for (const [, src] of html.matchAll(/<img[^>]*\ssrc="([^"]+)"/g)) {
      assert.ok(allows('img-src', /^https?:/.test(src) ? src : '/'), `${where}: image ${src} is not allowed`);
    }
  }
});
