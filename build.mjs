#!/usr/bin/env node
import {readFileSync, writeFileSync} from 'node:fs';

// Create package.json for lib directory
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const libPkg = {
  name: pkg.name,
  version: pkg.version,
  description: pkg.description,
  main: 'index.js',
  types: 'index.d.ts',
  license: pkg.license,
  dependencies: pkg.dependencies,
  repository: pkg.repository,
  bugs: pkg.bugs,
  homepage: pkg.homepage,
};
writeFileSync('lib/package.json', JSON.stringify(libPkg, null, 2));
console.log('Build completed successfully!');
