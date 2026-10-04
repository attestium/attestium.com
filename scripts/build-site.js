#!/usr/bin/env node
'use strict';

// Builds attestium.com into _site/: a hand-written landing page, one page per
// document in docs/ and SPEC.md, guides from site/pages/, a brand page, and
// the files search engines and agents read (sitemap.xml, robots.txt,
// llms.txt, a Markdown copy of every document). Plain HTML, one CSS file
// (site/style.css) and one small script (site/site.js); no framework.

const {execFileSync} = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Marked is ESM-only: loaded with import() in build(), which works on Node 18 too.
let Marked;

const root = path.resolve(__dirname, '..');
const siteDir = path.join(root, 'site');

const SITE = {
  name: 'Attestium',
  url: 'https://attestium.com',
  repo: 'https://github.com/attestium/attestium.com',
  branch: 'main',
  tagline: 'Remote attestation for Node.js',
  description: 'Remote attestation for Node.js: collect evidence of what a server runs and verify it against references the verifier obtains itself.',
  keywords: 'remote attestation, runtime verification, TPM, IMA, SEV-SNP, TDX, supply chain security, Node.js',
  locale: 'en_US',
  themeLight: '#f6f5f0',
  themeDark: '#0f1a26',
  imageAlt: 'Attestium: remote attestation for Node.js',
  fonts: 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap',
  // The Latin subset of Source Serif 4 that the stylesheet above serves: headings and the wordmark.
  fontPreload: 'https://fonts.gstatic.com/s/sourceserif4/v14/vEFI2_tTDB4M7-auWDN0ahZJW1gb8tc.woff2',
};

const PUBLISHER = {
  '@type': 'Organization',
  '@id': 'https://forwardemail.net/#organization',
  name: 'Forward Email',
  url: 'https://forwardemail.net',
  logo: 'https://forwardemail.net/img/logo-square.svg',
  sameAs: ['https://github.com/forwardemail'],
};

// Guides in site/pages/, in this order; faq.md is the FAQ page.
const GUIDES = ['remote-attestation', 'tpm-attestation', 'supply-chain-verification', 'confidential-computing', 'evidence-format'];

const NAV = [
  {group: 'Start', pages: [['docs/README.md', 'Overview'], ['docs/getting-started.md'], ['docs/concepts.md']]},
  {group: 'Guides', pages: [['docs/ecosystems.md'], ['docs/hardware.md'], ['docs/forged-answers.md'], ['docs/signatures.md'], ['docs/other-languages.md'], ['docs/security.md']]},
  {group: 'Reference', pages: [['docs/api.md', 'API reference'], ['SPEC.md', 'Specification']]},
];

// Glossary: the first use of each term on a docs page gets a tooltip.
// [pattern, definition, regular expression flags]
const GLOSSARY = [
  ['relying party', 'Whoever reads the verifier\'s result, for example on a status page.', 'i'],
  ['attester', 'The component on the machine being checked. It collects facts and reports them; it never decides the result.', 'i'],
  ['verifier', 'The component that runs elsewhere, typically in CI: it sends a nonce, obtains references itself and compares.', 'i'],
  ['nonce', 'A random value the verifier chooses for one request, so that an old answer cannot be replayed.', 'i'],
  ['RATS', 'Remote ATtestation procedureS: the IETF architecture (RFC 9334) that defines attester, verifier and relying party.'],
  ['TPM', 'Trusted Platform Module: a chip with keys that cannot be exported and registers (PCRs) that can be extended but never set.'],
  ['PCRs?', 'Platform Configuration Register: a TPM register that can only be extended with a hash. Firmware, bootloader and kernel extend PCRs with what they load.'],
  ['IMA', 'Integrity Measurement Architecture: the Linux kernel hashes files as they are used, logs each hash and extends PCR 10.'],
  ['EK', 'Endorsement key: the TPM\'s identity key, certified by its manufacturer.'],
  ['AK', 'Attestation key: a key held by the TPM that signs quotes. The verifier pins it at enrollment.'],
  ['SEV-SNP', 'AMD Secure Encrypted Virtualization with Secure Nested Paging: confidential VMs whose launch measurement the AMD chip signs.'],
  ['TDX', 'Intel Trust Domain Extensions: confidential VMs whose measurement is signed through Intel\'s quoting enclave.'],
  ['VCEK', 'Versioned Chip Endorsement Key: the AMD per-chip key that signs SEV-SNP reports, certified through the ASK to AMD\'s root.'],
  ['DSSE', 'Dead Simple Signing Envelope: signs a payload together with its type. Used by in-toto and Sigstore attestations.'],
  ['Sigstore', 'A public signing service: short-lived certificates from Fulcio tied to an OIDC identity, with signatures logged in Rekor.'],
  ['Rekor', 'Sigstore\'s public, append-only transparency log of signatures.'],
  ['Fulcio', 'Sigstore\'s certificate authority. It issues short-lived signing certificates for OIDC identities.'],
  ['TUF', 'The Update Framework: signed, versioned metadata for distributing keys and files. Sigstore ships its trusted root with it.'],
  ['OCI', 'Open Container Initiative: the standard image and registry formats. Manifests and layers are addressed by SHA-256 digest.'],
  ['SBOM', 'Software bill of materials: a list of the components in a piece of software.'],
];

const LANGS = {
  js: 'JavaScript', javascript: 'JavaScript', ts: 'TypeScript', json: 'JSON', sh: 'Shell', bash: 'Shell', shell: 'Shell', console: 'Shell', python: 'Python', py: 'Python', yaml: 'YAML', yml: 'YAML', text: 'Text', txt: 'Text',
};

// ---------------------------------------------------------------------------
// Helpers

function esc(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

// JSON inside a <script> element: "<" is written \u003c (as are U+2028 and
// U+2029), so no value can end the element or open a comment.
function jsonForScript(value) {
  return JSON.stringify(value).replaceAll('<', String.raw`\u003c`).replaceAll('\u2028', String.raw`\u2028`).replaceAll('\u2029', String.raw`\u2029`);
}

// The only inline script: applies the saved theme before the first paint.
const THEME_SCRIPT = 'try{var t=localStorage.getItem(\'theme\');if(t===\'light\'||t===\'dark\')document.documentElement.dataset.theme=t}catch(e){}';

// Content-Security-Policy: scripts from this site and the theme script (by
// hash), styles and fonts from this site and Google Fonts.  Inline style
// attributes stay allowed (colour swatches, table alignment).
function contentSecurityPolicy() {
  const hash = crypto.createHash('sha256').update(THEME_SCRIPT).digest('base64');
  return [
    'default-src \'none\'',
    `script-src 'self' 'sha256-${hash}'`,
    'style-src \'self\' \'unsafe-inline\' https://fonts.googleapis.com',
    'font-src https://fonts.gstatic.com',
    'img-src \'self\' https://forwardemail.net',
    'manifest-src \'self\'',
    'base-uri \'none\'',
    'form-action \'none\'',
    'upgrade-insecure-requests',
  ].join('; ');
}

function stripTags(html) {
  return html.replaceAll(/<[^>]*>/g, '')
    .replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&#39;', '\'').replaceAll('&amp;', '&');
}

// GitHub's heading id algorithm (github-slugger), so existing anchors keep working.
function slugify(text) {
  return text.toLowerCase().trim().replaceAll(/[^\p{L}\p{M}\p{N}\p{Pc}\- ]/gu, '').replaceAll(' ', '-');
}

function createSlugger() {
  const occurrences = new Map();
  return text => {
    const original = slugify(text);
    let slug = original;
    while (occurrences.has(slug)) {
      occurrences.set(original, occurrences.get(original) + 1);
      slug = `${original}-${occurrences.get(original)}`;
    }

    occurrences.set(slug, 0);
    return slug;
  };
}

function hash(content) {
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 10);
}

function plain(markdown) {
  return markdown.replaceAll(/`([^`]*)`/g, '$1').replaceAll(/\[([^\]]*)]\([^)]*\)/g, '$1').replaceAll(/[*_]/g, '').replaceAll(/\s+/g, ' ').trim();
}

function truncate(text, max) {
  if (text.length <= max) {
    return text;
  }

  const cut = text.slice(0, max);
  return `${cut.slice(0, cut.lastIndexOf(' ')).replace(/[,;:.]$/, '')}…`;
}

// ---------------------------------------------------------------------------
// Syntax highlighting: comments, strings, keywords and numbers. Nothing more.

const KEYWORDS = {
  js: 'async|await|break|case|catch|class|const|continue|default|delete|else|export|extends|false|finally|for|function|if|import|in|instanceof|let|new|null|of|return|static|switch|this|throw|true|try|typeof|undefined|var|while',
  python: 'and|as|assert|async|await|break|class|continue|def|elif|else|except|False|finally|for|from|if|import|in|is|lambda|None|not|or|pass|raise|return|True|try|while|with|yield',
  json: 'true|false|null',
  sh: 'if|then|else|fi|for|do|done|case|esac|export|sudo',
  yaml: 'true|false|null',
};

const COMMENTS = {
  js: String.raw`\/\/[^\n]*|\/\*[\s\S]*?\*\/`, python: String.raw`#[^\n]*`, json: '(?!)', sh: String.raw`(?<=^|\s)#[^\n]*`, yaml: String.raw`(?<=^|\s)#[^\n]*`,
};

const LEXERS = {};
for (const [lang, words] of Object.entries(KEYWORDS)) {
  const string = lang === 'js'
    ? String.raw`'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|\x60(?:\\.|[^\x60\\])*\x60`
    : String.raw`'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"`;
  const key = lang === 'yaml' ? String.raw`|(?<p>^[ \t-]*[\w.-]+(?=:))` : '';
  LEXERS[lang] = new RegExp(String.raw`(?<c>${COMMENTS[lang]})|(?<s>${string})|(?<k>\b(?:${words})\b)|(?<n>\b\d[\d_.]*\b)${key}`, 'gm');
}

Object.assign(LEXERS, {
  javascript: LEXERS.js, ts: LEXERS.js, py: LEXERS.python, bash: LEXERS.sh, shell: LEXERS.sh, yml: LEXERS.yaml,
});

function highlight(code, lang) {
  const lexer = LEXERS[lang];
  if (!lexer) {
    return esc(code);
  }

  let out = '';
  let last = 0;
  for (const match of code.matchAll(lexer)) {
    if (match[0] === '') {
      continue;
    }

    const kind = Object.keys(match.groups).find(name => match.groups[name] !== undefined);
    out += esc(code.slice(last, match.index)) + `<span class="t-${kind}">${esc(match[0])}</span>`;
    last = match.index + match[0].length;
  }

  return out + esc(code.slice(last));
}

function codeBlock(code, lang, label) {
  const name = label || LANGS[lang] || (lang ? lang.toUpperCase() : 'Text');
  return `<div class="code"><div class="code-bar"><span>${esc(name)}</span><button class="copy" type="button">Copy</button></div>`
    + `<pre><code${lang ? ` class="language-${esc(lang)}"` : ''}>${highlight(code.replace(/\n$/, ''), lang)}</code></pre></div>\n`;
}

// ---------------------------------------------------------------------------
// Pages and links

function listDocs() {
  const files = [];
  const walk = dir => {
    const entries = fs.readdirSync(path.join(root, dir), {withFileTypes: true}).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const rel = `${dir}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(rel);
      } else if (entry.name.endsWith('.md')) {
        files.push(rel);
      }
    }
  };

  walk('docs');
  return files;
}

function urlFor(source) {
  if (source === 'README.md') {
    return '/';
  }

  if (source === 'SPEC.md') {
    return '/spec/';
  }

  return `/${source.replace(/(^|\/)README\.md$/, '$1').replace(/\.md$/, '/')}`;
}

// Repository files published on the site as they are: path in repo -> URL.
const PUBLISHED = {
  'attestium-whitepaper.pdf': '/attestium-whitepaper.pdf',
  'schema/evidence.schema.json': '/schema/evidence.schema.json',
};

function rewriteLink(href, source, pages) {
  if (!href || href.startsWith('#') || href.startsWith('/') || /^[a-z][a-z\d+.-]*:/i.test(href)) {
    return href;
  }

  const [target, anchor] = href.split('#');
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(source), target)).replace(/^\.\//, '');
  const suffix = anchor === undefined ? '' : `#${anchor}`;
  if (pages.has(resolved)) {
    return urlFor(resolved) + suffix;
  }

  if (PUBLISHED[resolved]) {
    return PUBLISHED[resolved] + suffix;
  }

  const full = path.join(root, resolved);
  const kind = fs.existsSync(full) && fs.statSync(full).isDirectory() ? 'tree' : 'blob';
  return `${SITE.repo}/${kind}/${SITE.branch}/${resolved.replace(/\/$/, '')}${suffix}`;
}

// ---------------------------------------------------------------------------
// Markdown

function renderMarkdown(markdown, source, pages) {
  const slug = createSlugger();
  const toc = [];
  const marked = new Marked({gfm: true});
  marked.use({
    renderer: {
      heading({tokens, depth}) {
        const inner = this.parser.parseInline(tokens);
        const id = slug(stripTags(inner));
        if (depth === 2 || depth === 3) {
          toc.push({id, depth, html: inner.replaceAll(/<\/?a[^>]*>/g, '')});
        }

        return `<h${depth} id="${id}">${inner}<a class="h-anchor" href="#${id}" aria-label="Link to this section">#</a></h${depth}>\n`;
      },
      link({href, title, tokens}) {
        const url = rewriteLink(href, source, pages);
        const external = /^https?:/.test(url) && !url.startsWith(SITE.url);
        return `<a href="${esc(url)}"${title ? ` title="${esc(title)}"` : ''}${external ? ' rel="noopener"' : ''}>${this.parser.parseInline(tokens)}</a>`;
      },
      image({href, text}) {
        return `<img src="${esc(rewriteLink(href, source, pages))}" alt="${esc(text)}" loading="lazy">`;
      },
      code({text, lang}) {
        return codeBlock(text, (lang || '').split(/\s/)[0].toLowerCase());
      },
      table(token) {
        const cell = (c, tag) => `<${tag}${c.align ? ` style="text-align:${c.align}"` : ''}>${this.parser.parseInline(c.tokens)}</${tag}>`;
        const head = token.header.map(c => cell(c, 'th')).join('');
        const rows = token.rows.map(row => `<tr>${row.map(c => cell(c, 'td')).join('')}</tr>`).join('\n');
        const headless = token.header.every(c => c.text.trim() === '');
        return `<div class="table-wrap"><table${headless ? ' class="no-head"' : ''}>${headless ? '' : `<thead><tr>${head}</tr></thead>`}<tbody>${rows}</tbody></table></div>\n`;
      },
    },
  });
  return {html: marked.parse(markdown), toc};
}

// Wrap the first use of each glossary term in a tooltip, outside code, links,
// headings and buttons.
function addGlossary(html, prefix) {
  const skip = new Set(['a', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'button', 'script', 'style', 'svg', 'th']);
  const remaining = new Map(GLOSSARY.map(([term, text, flags]) => [term, {text, pattern: new RegExp(String.raw`(?<![\w-])${term}(?![\w-])`, flags || '')}]));
  let depth = 0;
  let count = 0;
  return html.split(/(<[^>]+>)/).map(part => {
    if (part.startsWith('<')) {
      const match = /^<(\/?)([a-z\d]+)/i.exec(part);
      if (match && skip.has(match[2].toLowerCase())) {
        depth += match[1] ? -1 : 1;
      }

      return part;
    }

    if (depth > 0 || remaining.size === 0 || part.trim() === '') {
      return part;
    }

    const found = [];
    for (const [term, {text: definition, pattern}] of remaining) {
      const m = pattern.exec(part);
      if (!m || found.some(f => m.index < f.end && m.index + m[0].length > f.start)) {
        continue;
      }

      found.push({
        start: m.index, end: m.index + m[0].length, definition, word: m[0],
      });
      remaining.delete(term);
    }

    let text = part;
    for (const f of found.sort((a, b) => b.start - a.start)) {
      const id = `${prefix}-${++count}`;
      text = `${text.slice(0, f.start)}<span class="term" tabindex="0" aria-describedby="${id}">${f.word}<span class="tip" role="tooltip" id="${id}">${esc(f.definition)}</span></span>${text.slice(f.end)}`;
    }

    return text;
  }).join('');
}

// ---------------------------------------------------------------------------
// Templates

// A brand SVG from site/brand/, for use inside a page: its own title and
// styles removed (site/style.css styles the at-* classes), hidden from
// assistive technology because a text label always sits next to it.
function svgInline(file, className) {
  return fs.readFileSync(path.join(siteDir, 'brand', file), 'utf8')
    .replace(/<title[^>]*>[^<]*<\/title>/, '')
    .replace(/<style>[^<]*<\/style>/, '')
    .replace(' role="img" aria-labelledby="t"', '')
    .replace('<svg ', `<svg class="${className}" aria-hidden="true" focusable="false" `)
    .replaceAll(/\n\s*/g, '')
    .trim();
}

const ICONS = {
  theme: '<svg class="i-system" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 3.5a6.5 6.5 0 0 1 0 13z" fill="currentColor"/></svg>'
    + '<svg class="i-light" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="3.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 1.5v2.5M10 16v2.5M1.5 10H4M16 10h2.5M4 4l1.8 1.8M14.2 14.2 16 16M4 16l1.8-1.8M14.2 5.8 16 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>'
    + '<svg class="i-dark" viewBox="0 0 20 20" aria-hidden="true"><path d="M16.5 12.2A7 7 0 0 1 7.8 3.5a7 7 0 1 0 8.7 8.7z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
  menu: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 6h14M3 10h14M3 14h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
  github: '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>',
};

function brandLink() {
  return `<a class="brand" href="/">${svgInline('favicon.svg', 'mark')}<span>${SITE.name}</span></a>`;
}

// Structured data: the publisher and the site on every page, plus what the page is.
function structuredData(p) {
  const url = SITE.url + p.url;
  const image = `${SITE.url}/og.png`;
  const website = {
    '@type': 'WebSite',
    '@id': `${SITE.url}/#website`,
    url: `${SITE.url}/`,
    name: SITE.name,
    description: SITE.description,
    inLanguage: 'en',
    publisher: {'@id': PUBLISHER['@id']},
  };
  const graph = [PUBLISHER, website];
  const crumbs = p.crumbs
    ? {
      '@type': 'BreadcrumbList',
      '@id': `${url}#breadcrumbs`,
      itemListElement: p.crumbs.map((crumb, index) => ({
        '@type': 'ListItem', position: index + 1, name: crumb.name, item: SITE.url + crumb.url,
      })),
    }
    : null;
  const article = type => ({
    '@type': type,
    '@id': `${url}#main`,
    url,
    name: p.title,
    headline: p.heading || p.title,
    description: p.description,
    inLanguage: 'en',
    isPartOf: {'@id': website['@id']},
    publisher: {'@id': PUBLISHER['@id']},
    author: {'@id': PUBLISHER['@id']},
    image,
    dateModified: p.lastmod,
    ...(p.keywords ? {keywords: p.keywords} : {}),
    ...(crumbs ? {breadcrumb: {'@id': crumbs['@id']}} : {}),
  });

  switch (p.kind) {
    case 'home': {
      const {version} = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
      graph.push({
        '@type': ['SoftwareApplication', 'SoftwareSourceCode'],
        '@id': `${SITE.url}/#software`,
        name: SITE.name,
        description: SITE.description,
        url: `${SITE.url}/`,
        image,
        applicationCategory: 'DeveloperApplication',
        operatingSystem: 'Linux',
        runtimePlatform: 'Node.js 18 or later',
        programmingLanguage: 'JavaScript',
        codeRepository: SITE.repo,
        license: 'https://opensource.org/licenses/MIT',
        softwareVersion: version,
        downloadUrl: 'https://www.npmjs.com/package/attestium',
        isAccessibleForFree: true,
        offers: {'@type': 'Offer', price: '0', priceCurrency: 'USD'},
        publisher: {'@id': PUBLISHER['@id']},
        author: {'@id': PUBLISHER['@id']},
      });

      break;
    }

    case 'doc':
    case 'guide': {
      graph.push(article('TechArticle'));

      break;
    }

    case 'faq': {
      graph.push({
        ...article('FAQPage'),
        mainEntity: p.faq.map(item => ({
          '@type': 'Question', name: item.question, acceptedAnswer: {'@type': 'Answer', text: item.answer},
        })),
      });

      break;
    }

    default: {
      graph.push(article('WebPage'));
    }
  }

  if (crumbs) {
    graph.push(crumbs);
  }

  return jsonForScript({'@context': 'https://schema.org', '@graph': graph});
}

function head(p, assets) {
  const url = SITE.url + p.url;
  const image = `${SITE.url}/og.png`;
  const meta = (name, content) => `<meta name="${name}" content="${esc(content)}">`;
  const property = (name, content) => `<meta property="${name}" content="${esc(content)}">`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${esc(contentSecurityPolicy())}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(p.title)}</title>
${meta('description', p.description)}
${p.keywords ? meta('keywords', p.keywords) : ''}
${p.kind === 'error' ? meta('robots', 'noindex') : ''}
<link rel="canonical" href="${url}">
${p.markdown ? `<link rel="alternate" type="text/markdown" href="${url}index.md" title="Markdown">` : ''}
${property('og:type', p.kind === 'home' ? 'website' : 'article')}
${property('og:site_name', SITE.name)}
${property('og:locale', SITE.locale)}
${property('og:title', p.title)}
${property('og:description', p.description)}
${property('og:url', url)}
${property('og:image', image)}
${property('og:image:width', '1200')}
${property('og:image:height', '630')}
${property('og:image:alt', SITE.imageAlt)}
${meta('twitter:card', 'summary_large_image')}
${meta('twitter:title', p.title)}
${meta('twitter:description', p.description)}
${meta('twitter:image', image)}
${meta('twitter:image:alt', SITE.imageAlt)}
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="${SITE.themeLight}" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="${SITE.themeDark}" media="(prefers-color-scheme: dark)">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon-32.png" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<script>${THEME_SCRIPT}</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="preload" href="${SITE.fontPreload}" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="${SITE.fonts}">
<link rel="stylesheet" href="/style.css?v=${assets.css}">
<script src="/site.js?v=${assets.js}" defer></script>
<script type="application/ld+json">${structuredData(p)}</script>
</head>`.replaceAll(/\n{2,}/g, '\n');
}

function header(active) {
  const link = (href, label, key) => `<li><a href="${href}"${active === key ? ' aria-current="page"' : ''}>${label}</a></li>`;
  return `<a class="skip" href="#main">Skip to content</a>
<header class="site-header">
<div class="wrap header-row">
${brandLink()}
<nav class="site-nav" id="site-nav" aria-label="Main">
<ul>
${link('/docs/', 'Docs', 'docs')}
${link('/spec/', 'Specification', 'spec')}
${link('/attestium-whitepaper.pdf', 'Whitepaper <span class="muted">PDF</span>', 'pdf')}
<li><a href="${SITE.repo}" rel="noopener">${ICONS.github}<span>GitHub</span></a></li>
</ul>
</nav>
<div class="header-actions">
<button class="icon-button theme-toggle" type="button" aria-label="Theme: system" title="Theme: system">${ICONS.theme}</button>
<button class="icon-button menu-toggle" type="button" aria-expanded="false" aria-controls="site-nav" aria-label="Menu">${ICONS.menu}</button>
</div>
</div>
</header>`;
}

function footer(guides) {
  const list = (id, title, links) => `<nav aria-labelledby="${id}"><h2 id="${id}">${title}</h2><ul>${links.map(([href, label]) => `<li><a href="${href}"${href.startsWith('http') ? ' rel="noopener"' : ''}>${label}</a></li>`).join('')}</ul></nav>`;
  return `<footer class="site-footer">
<div class="wrap footer-grid">
<div class="footer-brand">
${brandLink()}
<p>Remote attestation building blocks. <a href="${SITE.repo}/blob/${SITE.branch}/LICENSE" rel="noopener">MIT license</a>, © Forward Email LLC.</p>
</div>
${list('f-docs', 'Documentation', [['/docs/getting-started/', 'Getting started'], ['/docs/concepts/', 'Concepts'], ['/docs/api/', 'API reference'], ['/spec/', 'Specification'], ['/faq/', 'FAQ']])}
${list('f-guides', 'Use cases', guides.map(g => [g.url, g.label]))}
${list('f-project', 'Project', [[SITE.repo, 'GitHub'], ['https://www.npmjs.com/package/attestium', 'npm'], ['/attestium-whitepaper.pdf', 'Whitepaper (PDF)'], ['/docs/security/#reporting-a-vulnerability', 'Security'], ['/brand/', 'Brand']])}
${list('f-related', 'Related', [['https://auditstatus.com/', 'Audit Status'], ['https://forwardemail.net', 'Forward Email'], ['https://status.forwardemail.net', 'Forward Email status']])}
</div>
</footer>`;
}

function render(p, context) {
  return `${head(p, context.assets)}
<body class="page-${p.kind}">
${header(p.active)}
${p.body}
${footer(context.guides)}
</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// Landing page

const TILES = [
  ['pk', 'Np', 'npm', 'Every file under node_modules, compared with the registry tarball that pnpm-lock.yaml or package-lock.json pins.', 'docs/ecosystems.md#npm-npm-and-pnpm'],
  ['pk', 'Py', 'PyPI', 'Virtual environments, compared with the wheels that uv.lock, pylock.toml, poetry.lock, Pipfile.lock or hashed requirements pin.', 'docs/ecosystems.md#pypi'],
  ['pk', 'Rb', 'RubyGems', 'Bundler\'s vendor/bundle, compared with the .gem files pinned by the CHECKSUMS section of Gemfile.lock.', 'docs/ecosystems.md#rubygems-bundler'],
  ['pk', 'Hx', 'Hex', 'Mix\'s deps/, compared with the tarballs pinned by the outer checksums of mix.lock.', 'docs/ecosystems.md#hex-erlang-elixir'],
  ['pk', 'Cp', 'Composer', 'vendor/, compared with the git tree of the commit that composer.lock pins.', 'docs/ecosystems.md#composer-php'],
  ['pk', 'Mv', 'Maven', 'Directories of jars, compared with the hashes in Gradle verification metadata or a Maven lockfile.', 'docs/ecosystems.md#maven-java'],
  ['pk', 'Ng', 'NuGet', 'A published .NET application, compared file by file with the packages whose content hashes packages.lock.json pins.', 'docs/ecosystems.md#nuget-net'],
  ['bn', 'Go', 'Go', 'The build information inside a Go binary, compared with go.sum and the commit. The binary\'s own hash proves the rest.', 'docs/ecosystems.md#go-binaries'],
  ['bn', 'Rs', 'Rust', 'The cargo-auditable crate list inside a binary, compared with Cargo.lock at the commit.', 'docs/ecosystems.md#rust-binaries'],
  ['bn', 'Nb', 'Native', 'The hash of a running binary, compared with a signed checksum list, an artifact attestation, a release manifest or a pinned hash.', 'docs/ecosystems.md#native-binaries'],
  ['bn', 'Nd', 'Node.js', 'The node executable, compared with bin/node inside the official release archive listed in SHASUMS256.txt.', 'docs/ecosystems.md#language-runtimes'],
  ['sy', 'Oc', 'OCI', 'A container\'s root filesystem, compared with the image layers fetched by digest from the registry and applied in order.', 'docs/ecosystems.md#containers-and-oci-images'],
  ['sy', 'Db', 'Debian', 'Each running file\'s owning Debian or Ubuntu package, compared with the .deb reached from the signed InRelease file.', 'docs/ecosystems.md#debian-and-ubuntu-packages'],
  ['hw', 'Tp', 'TPM', 'A TPM 2.0 quote over SHA-256(nonce ‖ digest), checked with the attestation key pinned at enrollment and expected PCR values.', 'docs/hardware.md#tpm-20'],
  ['hw', 'Im', 'IMA', 'The kernel\'s measurement log, replayed to the quoted PCR 10. Each running file\'s hash is compared with its measurement.', 'docs/hardware.md#ima'],
  ['hw', 'Sn', 'SEV-SNP', 'An AMD SEV-SNP report over SHA-512(nonce ‖ digest), chained through the VCEK to AMD\'s root, with debugging off.', 'docs/hardware.md#amd-sev-snp'],
  ['hw', 'Td', 'TDX', 'An Intel TDX quote over SHA-512(nonce ‖ digest), chained to Intel\'s root. The MRTD is compared with the expected image.', 'docs/hardware.md#intel-tdx'],
  ['sg', 'Sg', 'Sigstore', 'A Sigstore bundle: the Fulcio certificate chain, the Rekor log entry, and the signer identity the verifier requires.', 'docs/signatures.md#sigstore-bundles'],
  ['sg', 'Ga', 'GitHub', 'A GitHub artifact attestation for a file\'s SHA-256, signed for the expected repository, workflow and ref.', 'docs/signatures.md#github-artifact-attestations'],
  ['sg', 'Cs', 'Checksums', 'A published checksum list signed with gpg, minisign or Sigstore. The file\'s hash must be in the list.', 'docs/signatures.md#signed-checksum-lists'],
];

const FAMILIES = {
  pk: 'Packages', bn: 'Binaries and runtimes', sy: 'System', hw: 'Hardware', sg: 'Signatures',
};

// [level, backed by, proves, does not prove]
const LEVELS = [
  ['Software evidence', 'The attester\'s report, bound to the nonce by the digest.', 'Drift, failed deploys, modified files and packages, injected libraries, attached debuggers, unexplained programs.', 'Anything against root that anticipates the check: root can run a modified attester.'],
  ['TPM-bound', 'A TPM 2.0 quote over the nonce and digest, signed by an attestation key pinned at enrollment.', 'The report came from the enrolled machine, now; with pinned PCRs, that it booted the expected firmware and kernel.', 'That root did not misreport files and processes after boot.'],
  ['TPM and IMA', 'The quote, plus the kernel\'s IMA log replayed to the quoted PCR 10.', 'The logged hashes are the files the kernel loaded, even against a hostile root user.', 'Files outside the IMA policy, or a compromised kernel or firmware.'],
  ['Confidential VM', 'An AMD SEV-SNP or Intel TDX report over the nonce and digest, chained to the vendor\'s root.', 'The VM\'s launch measurement, with debugging off, in memory the host cannot read.', 'Software loaded after launch, unless the launch measurement covers it.'],
];

const STEPS = [
  ['Verifier to attester', 'nonce', 'Sends a nonce: 16 to 64 random bytes, hex encoded.'],
  ['Attester', 'collect', 'Collects facts about files, packages, processes and containers, computes evidenceDigest, and asks the TPM or CPU to sign both values.'],
  ['Attester to verifier', 'evidence', 'Returns the evidence: nonce, digest, files, processes and any hardware statement.'],
  ['Verifier to references', 'fetch', 'Fetches references itself, by digest: the commit, lockfile-pinned tarballs, image layers, signed archives.'],
  ['References to verifier', 'references', 'Each reference is checked against the digest that names it.'],
  ['Verifier', 'compare', 'Checks the nonce, the digest and the hardware signature, then compares every fact with its reference.'],
  ['Verifier to relying party', 'result', 'Publishes the result, pass, fail or inconclusive, with its evidence level.'],
];

function sequenceDiagram() {
  const lanes = [['Attester', 'on the server', 110], ['Verifier', 'in CI', 360], ['References', 'registries, git, archives', 610], ['Relying party', 'status page', 840]];
  const arrow = (from, to, y, n, label, sub) => {
    const dir = to > from ? 1 : -1;
    const x1 = from + (dir * 5);
    const x2 = to - (dir * 5);
    const mid = (from + to) / 2;
    return `<g class="msg"><line x1="${x1}" y1="${y}" x2="${x2 - (dir * 8)}" y2="${y}"/><path class="head" d="M${x2} ${y}l${-dir * 10} -5v10z"/>`
      + `<text x="${mid}" y="${y - 10}" text-anchor="middle"><tspan class="n">${n}</tspan>  ${label}</text>${sub ? `<text class="sub" x="${mid}" y="${y + 20}" text-anchor="middle">${sub}</text>` : ''}</g>`;
  };

  const note = (x, y, w, n, lines) => `<g class="note"><rect x="${x - (w / 2)}" y="${y}" width="${w}" height="${(lines.length * 19) + 16}" rx="3"/>${lines.map((line, i) => `<text x="${x}" y="${y + 23 + (i * 19)}" text-anchor="middle">${i === 0 ? `<tspan class="n">${n}</tspan>  ` : ''}${line}</text>`).join('')}</g>`;
  return `<svg class="seq" viewBox="0 0 950 490" role="img" aria-labelledby="seq-title"><title id="seq-title">The verifier sends a nonce, the attester answers with evidence, the verifier compares it with references it fetched itself and publishes a result.</title>
${lanes.map(([name, sub, x]) => `<g class="lane"><rect x="${x - 82}" y="6" width="164" height="54" rx="3"/><text x="${x}" y="29" text-anchor="middle" class="lane-name">${name}</text><text x="${x}" y="48" text-anchor="middle" class="sub">${sub}</text><line class="life" x1="${x}" y1="60" x2="${x}" y2="484"/></g>`).join('\n')}
${arrow(360, 110, 104, '1', 'nonce', '16–64 random bytes')}
${note(110, 144, 196, '2', ['collect facts', 'compute evidenceDigest', 'hardware signs both'])}
${arrow(110, 360, 252, '3', 'evidence', 'nonce, digest, files, processes')}
${arrow(360, 610, 302, '4', 'fetch by digest', '')}
${arrow(610, 360, 344, '5', 'references', 'commits, tarballs, layers, .debs')}
${note(360, 380, 250, '6', ['check nonce, digest, signature', 'compare every fact'])}
${arrow(360, 840, 462, '7', 'result', '')}
</svg>`;
}

function landing(pages) {
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  const example = /## Example[\s\S]*?```js\n([\s\S]*?)```/.exec(readme);
  const tiles = TILES.map(([family, symbol, name, tip, href], i) => {
    const id = `tile-${symbol.toLowerCase()}`;
    return `<li><a class="tile f-${family}" href="${rewriteLink(href, 'README.md', pages)}" aria-describedby="${id}"><span class="tile-n tabular">${i + 1}</span><span class="tile-sym">${symbol}</span><span class="tile-name">${name}</span></a><span class="tip" role="tooltip" id="${id}"><strong>${name}.</strong> ${esc(tip)}</span></li>`;
  }).join('\n');
  const legend = Object.entries(FAMILIES).map(([key, label]) => `<li><span class="swatch f-${key}" aria-hidden="true"></span>${label}</li>`).join('');
  const levels = LEVELS.map(([name, backed, proves, not], i) => `<li class="level">
<div class="level-bar" aria-hidden="true">${[0, 1, 2, 3].map(n => `<span${n <= i ? ' class="on"' : ''}></span>`).join('')}</div>
<h3><span class="level-n tabular">${i + 1}</span>${name}</h3>
<dl><dt>Backed by</dt><dd>${backed}</dd><dt>Proves</dt><dd>${proves}</dd><dt>Does not prove</dt><dd>${not}</dd></dl>
</li>`).join('\n');
  const steps = STEPS.map(([who, what, text]) => `<li><span class="who">${who}</span><strong>${what}</strong> ${text}</li>`).join('\n');

  const body = `<main id="main">
<section class="hero">
<div class="wrap hero-grid">
<div class="hero-text">
<h1>Evidence that a server runs the code that was published.</h1>
<p class="lede">Attestium is a Node.js library for remote attestation. It collects evidence of what a machine runs and verifies it against references the verifier obtains itself.</p>
<p class="lede-2">Publishing source code proves nothing about production. Attestation makes that claim checkable by anyone.</p>
<div class="install" id="install">
<code><span class="prompt" aria-hidden="true">$ </span>npm install attestium</code>
<button class="copy" type="button" data-copy="npm install attestium">Copy</button>
</div>
<p class="hero-links"><a class="button" href="/docs/getting-started/">Get started</a><a class="button button-quiet" href="/spec/">Read the specification</a></p>
</div>
<div class="hero-aside">
<div class="element">${svgInline('mark.svg', 'hero-mark')}</div>
<dl class="datasheet">
<div><dt>Format</dt><dd>JSON evidence, version 2</dd></div>
<div><dt>Binding</dt><dd>Nonce and SHA-256 digest</dd></div>
<div><dt>Hardware</dt><dd>TPM 2.0, IMA, SEV-SNP, TDX</dd></div>
<div><dt>Runtime</dt><dd>Node.js <span class="tabular">18+</span> on Linux</dd></div>
<div><dt>License</dt><dd>MIT</dd></div>
</dl>
</div>
</div>
</section>

<section class="section" id="how-it-works" aria-labelledby="how-it-works-h">
<div class="wrap">
<div class="section-head">
<h2 id="how-it-works-h">How it works</h2>
<p>Following the IETF remote attestation architecture (RATS), the attester reports facts and never decides. The verifier trusts nothing from the machine that it cannot check against an outside reference or a hardware signature.</p>
</div>
<figure class="diagram">
${sequenceDiagram()}
<ol class="steps">
${steps}
</ol>
<figcaption>A replayed answer fails the nonce check, changed evidence fails the digest check, and evidence produced elsewhere fails the hardware check. Without hardware, a server that controls its attester can forge the whole answer. <a href="/docs/concepts/#nonce-and-digest-binding">Nonce and digest binding</a> <a href="/docs/forged-answers/">Forged answers</a></figcaption>
</figure>
</div>
</section>

<section class="section" id="what-can-be-verified" aria-labelledby="verifies-h">
<div class="wrap">
<div class="section-head">
<h2 id="verifies-h">What it verifies</h2>
<p>Every running file must be explained by a reference: a verified package, an image layer, an official release, a signed archive or a hardware measurement. Hover, focus or tap an element to see what is compared with what.</p>
</div>
<ol class="elements">
${tiles}
</ol>
<ul class="legend" aria-label="Legend">${legend}</ul>
<p class="more"><a href="/docs/ecosystems/">Ecosystems and references</a><a href="/docs/hardware/">Hardware-backed evidence</a><a href="/docs/signatures/">Signatures and trust</a></p>
</div>
</section>

<section class="section" id="evidence-levels" aria-labelledby="levels-h">
<div class="wrap">
<div class="section-head">
<h2 id="levels-h">Evidence levels</h2>
<p>The strength of a result depends on what backs it. Report the level with every result. <a href="/docs/security/">Security model and limits</a></p>
</div>
<ol class="levels">
${levels}
</ol>
</div>
</section>

<section class="section" id="example" aria-labelledby="example-h">
<div class="wrap split">
<div class="section-head">
<h2 id="example-h">Example</h2>
<p>An attester answers a nonce with evidence about a deployed directory. The verifier checks shape, nonce and digest, then compares every file with a checkout of the expected commit.</p>
<p>On its own this is software evidence: whoever controls the attester can forge it. A TPM quote with a pinned key and IMA, or a confidential VM, makes a forgery fail.</p>
<p><a href="/docs/getting-started/#an-attester-and-a-verifier">Build an attester and a verifier</a> <a href="/docs/forged-answers/">Forged answers</a></p>
</div>
${example ? codeBlock(example[1], 'js', 'example.js') : ''}
</div>
</section>

<section class="section" id="attestium-and-audit-status" aria-labelledby="related-h">
<div class="wrap">
<div class="section-head">
<h2 id="related-h">Attestium and Audit Status</h2>
<p>Two projects with different purposes.</p>
</div>
<div class="compare">
<div>
<h3>Attestium</h3>
<p>The library and the format: collecting facts on a machine, the evidence schema, and the checks against each kind of reference. Use it to build an attester or a verifier, to verify one thing, or to implement the format in another language.</p>
<p><a href="/docs/other-languages/">Implement it in another language</a></p>
</div>
<div>
<h3>Audit Status</h3>
<p>A ready-made tool built on Attestium: one binary with an attester, invoked over a restricted SSH key, and a verifier that runs in CI and publishes reports and a status badge.</p>
<p><a href="https://auditstatus.com/">auditstatus.com</a></p>
</div>
</div>
<div class="credit">
<a class="credit-logo" href="https://forwardemail.net"><img src="https://forwardemail.net/img/logo-square.svg" width="44" height="44" alt="Forward Email"></a>
<p>A project by <a href="https://forwardemail.net">Forward Email</a>, the open-source, privacy-focused email service, which publishes verification results for its own production servers on <a href="https://status.forwardemail.net">status.forwardemail.net</a>.</p>
</div>
</div>
</section>
</main>`;

  return {
    url: '/',
    kind: 'home',
    title: `${SITE.name} — ${SITE.tagline}`,
    description: SITE.description,
    keywords: SITE.keywords,
    sources: ['README.md', 'scripts/build-site.js'],
    body,
    markdown: null,
  };
}
// ---------------------------------------------------------------------------
// Docs pages

function sidebar(nav, current) {
  const extra = '<li><a href="/schema/evidence.schema.json">JSON Schema</a></li><li><a href="/attestium-whitepaper.pdf">Whitepaper <span class="muted">PDF</span></a></li>';
  return nav.map(({group, pages}) => `<div class="side-group"><h2>${group}</h2><ul>${pages.map(p => `<li><a href="${p.url}"${p.source === current ? ' aria-current="page"' : ''}>${esc(p.label)}</a></li>`).join('')}${group === 'Reference' ? extra : ''}</ul></div>`).join('\n');
}

function tocNav(toc) {
  return toc.length > 1
    ? `<nav class="toc" aria-labelledby="toc-h"><h2 id="toc-h">On this page</h2><ul>${toc.map(t => `<li class="toc-${t.depth}"><a href="#${t.id}">${t.html}</a></li>`).join('')}</ul></nav>`
    : '<div class="toc toc-empty"></div>';
}

function docPage(doc, nav, order, pages) {
  const index = order.indexOf(doc);
  const prev = order[index - 1];
  const next = order[index + 1];
  const {html, toc} = renderMarkdown(doc.body, doc.source, pages);
  const pager = `<nav class="pager" aria-label="Previous and next page">${prev ? `<a class="prev" href="${prev.url}"><span>Previous</span>${esc(prev.label)}</a>` : '<span></span>'}${next ? `<a class="next" href="${next.url}"><span>Next</span>${esc(next.label)}</a>` : ''}</nav>`;
  const body = `<div class="wrap docs">
<aside class="sidebar">
<button class="side-toggle" type="button" aria-expanded="false" aria-controls="side-nav"><span><span class="muted">Docs /</span> ${esc(doc.label)}</span><svg viewBox="0 0 20 20" aria-hidden="true"><path d="m6 8 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
<nav id="side-nav" class="side-nav" aria-label="Documentation">
${sidebar(nav, doc.source)}
</nav>
</aside>
<main id="main" class="doc">
<article class="prose">
<h1>${doc.titleHtml}</h1>
${addGlossary(html, 'g')}
</article>
<p class="edit"><a href="${SITE.repo}/blob/${SITE.branch}/${doc.source}" rel="noopener">Edit this page on GitHub</a></p>
${pager}
</main>
${tocNav(toc)}
</div>`;
  const spec = doc.source === 'SPEC.md';
  return {
    url: doc.url,
    kind: 'doc',
    active: spec ? 'spec' : 'docs',
    title: doc.title.includes(SITE.name) ? doc.title : `${doc.title} — ${SITE.name}`,
    heading: doc.title,
    description: doc.description,
    sources: [doc.source],
    crumbs: spec || doc.url === '/docs/'
      ? [{name: SITE.name, url: '/'}, {name: spec ? 'Specification' : 'Documentation', url: doc.url}]
      : [{name: SITE.name, url: '/'}, {name: 'Documentation', url: '/docs/'}, {name: doc.label, url: doc.url}],
    markdown: markdownCopy(doc.title, doc.body, doc.source, pages, doc.url),
    group: spec ? 'Specification' : 'Documentation',
    body,
  };
}

function loadDoc(source, label) {
  const markdown = fs.readFileSync(path.join(root, source), 'utf8');
  const titleMatch = /^# (.+)$/m.exec(markdown);
  const title = titleMatch ? plain(titleMatch[1]) : path.basename(source, '.md');
  const body = titleMatch ? markdown.slice(titleMatch.index + titleMatch[0].length) : markdown;
  const paragraph = body.split(/\n\s*\n/).map(s => s.trim()).find(s => s && !/^[#|`>\-*!<\d]/.test(s)) || SITE.description;
  const titleHtml = titleMatch ? new Marked().parseInline(titleMatch[1]) : esc(title);
  return {
    source, url: urlFor(source), title, titleHtml, label: label || title, description: truncate(plain(paragraph), 158), body,
  };
}

// A document as Markdown for agents: links made absolute, nothing else changed.
function markdownCopy(title, body, source, pages, url) {
  const absolute = href => {
    const target = rewriteLink(href, source, pages);
    if (target.startsWith('#')) {
      return `${SITE.url}${url}${target}`;
    }

    return target.startsWith('/') ? SITE.url + target : target;
  };

  const text = body.split(/(```[\s\S]*?```)/).map(part => (part.startsWith('```')
    ? part
    : part.replaceAll(/(!?\[[^\]]*])\(([^)\s]+)((?:\s+"[^"]*")?)\)/g, (match, label, href, title) => `${label}(${absolute(href)}${title})`))).join('');
  return `# ${title}\n\n${text.trim()}\n`;
}

// ---------------------------------------------------------------------------
// Guides, FAQ and brand pages

function frontMatter(text) {
  // Page metadata sits in an HTML comment at the top, which Markdown tools leave alone.
  const match = /^<!--\n([\s\S]*?)\n-->\n/.exec(text);
  const data = {};
  for (const line of match ? match[1].split('\n') : []) {
    const index = line.indexOf(':');
    if (index > 0) {
      data[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    }
  }

  return {data, body: match ? text.slice(match[0].length) : text};
}

function guidePage(slug, pages, guides) {
  const source = `site/pages/${slug}.md`;
  const {data, body: markdown} = frontMatter(fs.readFileSync(path.join(root, source), 'utf8'));
  const titleMatch = /^# (.+)$/m.exec(markdown);
  const heading = titleMatch ? plain(titleMatch[1]) : data.title;
  const body = titleMatch ? markdown.slice(titleMatch.index + titleMatch[0].length) : markdown;
  const url = `/${slug}/`;
  const {html, toc} = renderMarkdown(body, source, pages);
  const faq = slug === 'faq'
    ? body.split(/^## /m).slice(1).map(section => {
      const [question, ...rest] = section.split('\n');
      return {question: question.trim(), answer: stripTags(new Marked().parse(rest.join('\n'))).replaceAll(/\s+/g, ' ').trim()};
    })
    : null;
  const related = guides.filter(g => g.url !== url);
  const aside = `<aside class="related" aria-labelledby="related-h"><h2 id="related-h">${slug === 'faq' ? 'Guides' : 'More guides'}</h2><ul>${related.map(g => `<li><a href="${g.url}">${esc(g.label)}</a><span>${esc(g.description)}</span></li>`).join('')}</ul></aside>`;
  const label = data.label || heading;
  const bodyHtml = `<div class="wrap guide">
<main id="main" class="doc">
<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">${SITE.name}</a></li><li><span aria-current="page">${esc(label)}</span></li></ol></nav>
<article class="prose">
<h1>${esc(heading)}</h1>
${addGlossary(html, 'g')}
</article>
<p class="edit"><a href="${SITE.repo}/blob/${SITE.branch}/${source}" rel="noopener">Edit this page on GitHub</a></p>
${aside}
</main>
${tocNav(toc)}
</div>`;
  return {
    url,
    kind: slug === 'faq' ? 'faq' : 'guide',
    active: slug === 'faq' ? 'faq' : 'guide',
    title: `${data.title || heading} — ${SITE.name}`,
    heading,
    label,
    description: data.description,
    keywords: data.keywords,
    sources: [source],
    crumbs: [{name: SITE.name, url: '/'}, {name: label, url}],
    markdown: markdownCopy(heading, body, source, pages, url),
    group: slug === 'faq' ? 'FAQ' : 'Guides',
    faq,
    body: bodyHtml,
  };
}

const COLORS = [
  ['Navy', '#13202E', 'Text, dark backgrounds'],
  ['Tile', '#11263E', 'The element tile'],
  ['Mint', '#73BCA6', 'Tile border, rules, highlights'],
  ['Bright mint', '#7FE3C0', 'The symbol on the tile; links on dark'],
  ['Deep mint', '#1F6B56', 'Links on light'],
  ['Paper', '#F6F5F0', 'Light background'],
  ['Cream', '#F1F0EB', 'Wordmark on dark'],
];

function brandPage() {
  const files = [
    ['logo.svg', 'Logo', 'Mark and wordmark, for light backgrounds'],
    ['logo-dark.svg', 'Logo, dark', 'Mark and wordmark, for dark backgrounds'],
    ['mark.svg', 'Mark', 'The element tile, 48 pixels and larger'],
    ['favicon.svg', 'Small mark', 'The simplified tile, below 48 pixels'],
    ['mark-mono.svg', 'Monochrome mark', 'One color, follows currentColor'],
  ];
  const swatches = COLORS.map(([name, hex, use]) => `<li><span class="swatch-lg" style="background:${hex}"></span><span><strong>${name}</strong><code>${hex}</code><span class="muted">${use}</span></span></li>`).join('');
  const downloads = files.map(([file, name, use]) => `<li><a href="/brand/${file}" download>${name}</a><span class="muted">${use}</span></li>`).join('');
  const body = `<div class="wrap brand-page">
<main id="main" class="doc">
<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">${SITE.name}</a></li><li><span aria-current="page">Brand</span></li></ol></nav>
<div class="prose">
<h1>Brand</h1>
<p>The Attestium mark is an element tile: the symbol At, atomic number 85, and a shield with a check. Use the files below as they are.</p>
</div>

<section class="brand-section" aria-labelledby="b-logo">
<h2 id="b-logo">Logo</h2>
<div class="brand-panels">
<figure class="panel panel-light">${svgInline('logo.svg', 'brand-logo')}<figcaption>On light</figcaption></figure>
<figure class="panel panel-dark">${svgInline('logo-dark.svg', 'brand-logo')}<figcaption>On dark</figcaption></figure>
</div>
</section>

<section class="brand-section" aria-labelledby="b-mark">
<h2 id="b-mark">Mark</h2>
<p>Use the full tile at 48 pixels and larger. Below that, the number and the shield are too small to read: use the simplified tile, which is also the favicon.</p>
<div class="brand-sizes">
<figure>${svgInline('mark.svg', 'size-256')}<figcaption>Mark, 128 px</figcaption></figure>
<figure>${svgInline('mark.svg', 'size-64')}<figcaption>Mark, 64 px</figcaption></figure>
<figure>${svgInline('favicon.svg', 'size-32')}<figcaption>Small, 32 px</figcaption></figure>
<figure>${svgInline('favicon.svg', 'size-16')}<figcaption>Small, 16 px</figcaption></figure>
<figure class="mono">${svgInline('mark-mono.svg', 'size-64')}<figcaption>Monochrome</figcaption></figure>
</div>
</section>

<section class="brand-section" aria-labelledby="b-space">
<h2 id="b-space">Clear space and size</h2>
<div class="brand-split">
<figure class="clearspace">${svgInline('mark.svg', 'size-128')}<figcaption>Keep a quarter of the tile's width clear on every side.</figcaption></figure>
<ul class="brand-rules">
<li>Clear space: one quarter of the tile's width on every side, more where possible.</li>
<li>Minimum size: 48 pixels for the full mark, 16 pixels for the small mark, 120 pixels wide for the logo.</li>
<li>The wordmark sits to the right of the tile, its cap height half the tile's height.</li>
</ul>
</div>
</section>

<section class="brand-section" aria-labelledby="b-color">
<h2 id="b-color">Color</h2>
<ul class="swatches">${swatches}</ul>
<p class="muted">The SVG files take their colors from CSS custom properties when placed inline, with these values as defaults:</p>
${codeBlock(':root {\n  --attestium-tile: #11263E;\n  --attestium-line: #73BCA6;\n  --attestium-glyph: #7FE3C0;\n  --attestium-word: #13202E;\n}', 'css', 'CSS')}
</section>

<section class="brand-section" aria-labelledby="b-type">
<h2 id="b-type">Type</h2>
<dl class="type-specimens">
<div><dt>Source Serif 4, semibold</dt><dd class="spec-serif">Headings and the wordmark</dd></div>
<div><dt>System sans-serif</dt><dd class="spec-sans">Body text, at the reader's system font</dd></div>
<div><dt>JetBrains Mono</dt><dd class="spec-mono">Code, commands and hashes</dd></div>
</dl>
</section>

<section class="brand-section" aria-labelledby="b-use">
<h2 id="b-use">Use</h2>
<div class="dos">
<div><h3>Do</h3><ul><li>Use the SVG files unchanged.</li><li>Use the dark logo on dark backgrounds.</li><li>Use the monochrome mark where only one color can print.</li><li>Link the mark to attestium.com.</li></ul></div>
<div><h3>Do not</h3><ul><li>Stretch, rotate or outline the mark.</li><li>Recolor the tile outside the palette, or add gradients and shadows.</li><li>Set the wordmark in another typeface.</li><li>Use the full tile below 48 pixels.</li></ul></div>
</div>
</section>

<section class="brand-section" aria-labelledby="b-files">
<h2 id="b-files">Files</h2>
<ul class="downloads">${downloads}<li><a href="/icon-512.png" download>App icon</a><span class="muted">PNG, 512 by 512</span></li></ul>
</section>
</main>
</div>`;
  return {
    url: '/brand/',
    kind: 'brand',
    active: 'brand',
    title: `Brand — ${SITE.name}`,
    heading: 'Brand',
    description: 'The Attestium logo, mark, colors and type: SVG downloads, clear space, minimum sizes and how to use them.',
    sources: ['site/brand/logo.svg', 'site/brand/mark.svg'],
    crumbs: [{name: SITE.name, url: '/'}, {name: 'Brand', url: '/brand/'}],
    markdown: null,
    body,
  };
}

function notFound() {
  return {
    url: '/404.html',
    kind: 'error',
    title: `Page not found — ${SITE.name}`,
    description: 'Nothing is published at this address. The documentation, the specification and the guides are linked from the home page.',
    sources: [],
    markdown: null,
    body: `<main id="main" class="wrap not-found">
${svgInline('mark.svg', 'not-found-mark')}
<h1>Page not found</h1>
<p>Nothing is published at this address.</p>
<p class="hero-links"><a class="button" href="/">Home</a><a class="button button-quiet" href="/docs/">Documentation</a></p>
</main>`,
  };
}

// ---------------------------------------------------------------------------
// Files for search engines and agents

const lastModified = new Map();
function lastmod(sources, fallback) {
  const dates = sources.map(source => {
    if (!lastModified.has(source)) {
      let date = '';
      try {
        date = execFileSync('git', ['-C', root, 'log', '-1', '--format=%cI', '--', source], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim();
      } catch {}

      lastModified.set(source, date);
    }

    return lastModified.get(source);
  }).filter(Boolean).sort();
  return dates.length > 0 ? dates.at(-1) : fallback;
}

function robots() {
  return `# Everything on this site is public. Search engines, crawlers and AI agents are welcome;\n# /llms.txt lists the pages for language models.\nUser-agent: *\nAllow: /\n\nSitemap: ${SITE.url}/sitemap.xml\n`;
}

function sitemap(pages) {
  const entries = pages.filter(p => p.kind !== 'error').map(p => `<url><loc>${SITE.url}${p.url}</loc><lastmod>${p.lastmod}</lastmod></url>`);
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries.join('\n')}\n</urlset>\n`;
}

function llms(pages) {
  const link = p => `- [${p.heading || p.title}](${SITE.url}${p.url}index.md): ${p.description}`;
  const group = name => pages.filter(p => p.group === name && p.markdown).map(p => link(p)).join('\n');
  return `# ${SITE.name}

> ${SITE.description}

Attestium is a Node.js library and an open, language-independent evidence format. An attester collects facts about a server (files, installed packages, processes, containers, TPM quotes, confidential VM reports); a verifier compares every fact with references it fetches itself. Each link below is the Markdown source of a page.

## Documentation

${group('Documentation')}

## Specification

${group('Specification')}
- [JSON Schema](${SITE.url}/schema/evidence.schema.json): the machine-readable definition of the evidence format, JSON Schema 2020-12

## Guides

${group('Guides')}
${group('FAQ')}

## Optional

- [All documentation in one file](${SITE.url}/llms-full.txt): every page above, concatenated
- [Whitepaper](${SITE.url}/attestium-whitepaper.pdf): architecture, security model and background (PDF)
- [Audit Status](https://auditstatus.com/llms.txt): a ready-made attester and verifier built on Attestium
- [Source code](${SITE.repo}): the library, tests and examples
`;
}

function llmsFull(pages) {
  return pages.filter(p => p.markdown).map(p => `<!-- ${SITE.url}${p.url} -->\n\n${p.markdown}`).join('\n\n');
}

function manifest() {
  return `${JSON.stringify({
    name: SITE.name,
    short_name: SITE.name, // eslint-disable-line camelcase
    description: SITE.description,
    // eslint-disable-next-line camelcase
    start_url: '/',
    scope: '/',
    display: 'browser',
    // eslint-disable-next-line camelcase
    background_color: SITE.themeLight,
    // eslint-disable-next-line camelcase
    theme_color: SITE.themeDark,
    icons: [
      {src: '/icon-192.png', sizes: '192x192', type: 'image/png'},
      {src: '/icon-512.png', sizes: '512x512', type: 'image/png'},
      {src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml'},
    ],
  }, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Build

function write(outDir, url, content) {
  const file = url.endsWith('/') ? path.join(outDir, url, 'index.html') : path.join(outDir, url);
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, content);
}

function copy(from, outDir, url) {
  const target = path.join(outDir, url);
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.copyFileSync(from, target);
}

async function build({outDir = path.join(root, '_site')} = {}) {
  ({Marked} = await import('marked'));
  fs.rmSync(outDir, {recursive: true, force: true});
  fs.mkdirSync(outDir, {recursive: true});
  const buildTime = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  const css = fs.readFileSync(path.join(siteDir, 'style.css'), 'utf8');
  const js = fs.readFileSync(path.join(siteDir, 'site.js'), 'utf8');
  const assets = {css: hash(css), js: hash(js)};
  fs.writeFileSync(path.join(outDir, 'style.css'), css);
  fs.writeFileSync(path.join(outDir, 'site.js'), js);
  for (const file of ['favicon-32.png', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png', 'og.png']) {
    copy(path.join(siteDir, file), outDir, file);
  }

  for (const file of fs.readdirSync(path.join(siteDir, 'brand')).filter(name => name.endsWith('.svg'))) {
    copy(path.join(siteDir, 'brand', file), outDir, `brand/${file}`);
  }

  copy(path.join(siteDir, 'brand', 'favicon.svg'), outDir, 'favicon.svg');

  // Navigation: configured pages first, then any other document in docs/.
  const listed = new Set(NAV.flatMap(g => g.pages.map(([source]) => source)));
  const extra = listDocs().filter(source => !listed.has(source));
  const groups = extra.length > 0 ? [...NAV, {group: 'More', pages: extra.map(source => [source])}] : NAV;
  const nav = groups.map(({group, pages}) => ({
    group,
    pages: pages.filter(([source]) => fs.existsSync(path.join(root, source))).map(([source, label]) => loadDoc(source, label)),
  }));
  const order = nav.flatMap(g => g.pages);
  const sources = new Set(['README.md', ...order.map(p => p.source)]);

  const guideSummaries = GUIDES.map(slug => {
    const {data} = frontMatter(fs.readFileSync(path.join(siteDir, 'pages', `${slug}.md`), 'utf8'));
    return {url: `/${slug}/`, label: data.label, description: data.description};
  });
  const pages = [
    landing(sources),
    ...order.map(doc => docPage(doc, nav, order, sources)),
    ...GUIDES.map(slug => guidePage(slug, sources, guideSummaries)),
    guidePage('faq', sources, guideSummaries),
    brandPage(),
    notFound(),
  ];

  const context = {assets, guides: guideSummaries};
  for (const p of pages) {
    p.lastmod = lastmod(p.sources, buildTime);
    write(outDir, p.url, render(p, context));
    if (p.markdown) {
      write(outDir, `${p.url}index.md`, p.markdown);
    }
  }

  for (const [source, url] of Object.entries(PUBLISHED)) {
    if (fs.existsSync(path.join(root, source))) {
      copy(path.join(root, source), outDir, url);
    }
  }

  // The schema's $id points into this site: publish it there as well.
  const schema = path.join(root, 'schema/evidence.schema.json');
  if (fs.existsSync(schema)) {
    const id = JSON.parse(fs.readFileSync(schema, 'utf8')).$id || '';
    if (id.startsWith(`${SITE.url}/`)) {
      copy(schema, outDir, id.slice(SITE.url.length));
    }
  }

  fs.writeFileSync(path.join(outDir, 'sitemap.xml'), sitemap(pages));
  fs.writeFileSync(path.join(outDir, 'robots.txt'), robots());
  fs.writeFileSync(path.join(outDir, 'llms.txt'), llms(pages));
  fs.writeFileSync(path.join(outDir, 'llms-full.txt'), llmsFull(pages));
  fs.writeFileSync(path.join(outDir, 'manifest.webmanifest'), manifest());
  fs.writeFileSync(path.join(outDir, '.nojekyll'), '');
  if (fs.existsSync(path.join(root, 'CNAME'))) {
    copy(path.join(root, 'CNAME'), outDir, 'CNAME');
  }

  return {outDir, pages: pages.filter(p => p.kind !== 'error').map(p => p.url)};
}

module.exports = {build, slugify, structuredData};

if (require.main === module) {
  const outArg = process.argv.indexOf('--out');
  build(outArg === -1 ? {} : {outDir: path.resolve(process.argv[outArg + 1])}).catch(error => {
    console.error(error);
    process.exitCode = 1;
  }).then(({outDir, pages}) => {
    console.log(`Built ${pages.length} pages into ${path.relative(process.cwd(), outDir) || '.'}`);
  });
}
