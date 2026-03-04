#!/usr/bin/env node

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {marked} = require('marked');

const root = path.resolve(__dirname, '..');
const outDir = path.join(root, '_site');

// Read README
const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');

// Convert to HTML
const body = marked.parse(readme);

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Attestium – Element of Attestation</title>
  <meta name="description" content="Runtime code verification and integrity monitoring for Node.js applications. Hardware-backed attestation with TPM 2.0.">
  <meta property="og:title" content="Attestium – Element of Attestation">
  <meta property="og:description" content="Runtime code verification and integrity monitoring for Node.js applications.">
  <meta property="og:url" content="https://attestium.com">
  <meta property="og:type" content="website">
  <link rel="icon" href="assets/favicon.png" type="image/png">
  <style>
    :root {
      --navy: #081a2a;
      --blue: #1a73e8;
      --bg: #fafbfc;
      --text: #24292e;
      --border: #e1e4e8;
      --code-bg: #f6f8fa;
      --max-width: 860px;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }
    .container {
      max-width: var(--max-width);
      margin: 0 auto;
      padding: 2rem 1.5rem 4rem;
    }
    h1 { font-size: 2rem; margin: 1.5rem 0 1rem; color: var(--navy); }
    h2 { font-size: 1.5rem; margin: 2rem 0 0.75rem; padding-bottom: 0.3rem; border-bottom: 1px solid var(--border); color: var(--navy); }
    h3 { font-size: 1.2rem; margin: 1.5rem 0 0.5rem; color: var(--navy); }
    h4 { font-size: 1.05rem; margin: 1.25rem 0 0.5rem; }
    p { margin: 0.5rem 0; }
    a { color: var(--blue); text-decoration: none; }
    a:hover { text-decoration: underline; }
    img { max-width: 100%; height: auto; }
    img[alt="Attestium Logo"] { width: 120px; margin: 1rem 0; }
    img[alt="Forward Email"] { width: 80px; }
    blockquote {
      border-left: 4px solid var(--blue);
      padding: 0.5rem 1rem;
      margin: 1rem 0;
      background: var(--code-bg);
      border-radius: 0 4px 4px 0;
    }
    code {
      background: var(--code-bg);
      padding: 0.15rem 0.4rem;
      border-radius: 3px;
      font-size: 0.9em;
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    }
    pre {
      background: var(--code-bg);
      padding: 1rem;
      border-radius: 6px;
      overflow-x: auto;
      margin: 1rem 0;
      border: 1px solid var(--border);
    }
    pre code { background: none; padding: 0; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 1rem 0;
      font-size: 0.85rem;
      display: block;
      overflow-x: auto;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 0.5rem 0.75rem;
      text-align: left;
    }
    th { background: var(--code-bg); font-weight: 600; }
    ul, ol { margin: 0.5rem 0 0.5rem 1.5rem; }
    li { margin: 0.25rem 0; }
    hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }
    .badges img { height: 20px; margin-right: 4px; }
    @media (max-width: 600px) {
      .container { padding: 1rem; }
      h1 { font-size: 1.5rem; }
      h2 { font-size: 1.25rem; }
      table { font-size: 0.75rem; }
    }
  </style>
</head>
<body>
  <div class="container">
    ${body}
  </div>
</body>
</html>`;

// Write output
fs.mkdirSync(outDir, {recursive: true});
fs.writeFileSync(path.join(outDir, 'index.html'), html);

// Copy CNAME
const cname = path.join(root, 'CNAME');
if (fs.existsSync(cname)) {
  fs.copyFileSync(cname, path.join(outDir, 'CNAME'));
}

// Copy assets
const assetsDir = path.join(root, 'assets');
const outAssets = path.join(outDir, 'assets');
fs.mkdirSync(outAssets, {recursive: true});
for (const file of fs.readdirSync(assetsDir)) {
  fs.copyFileSync(path.join(assetsDir, file), path.join(outAssets, file));
}

// Copy whitepaper PDF
const pdf = path.join(root, 'attestium-whitepaper.pdf');
if (fs.existsSync(pdf)) {
  fs.copyFileSync(pdf, path.join(outDir, 'attestium-whitepaper.pdf'));
}

console.log('Site built to _site/');
