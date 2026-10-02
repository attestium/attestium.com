/**
 * Attestium - hardened HTTP GET
 *
 * HTTPS only (plain HTTP is accepted for loopback hosts, which is what
 * local test fixtures and mirrors use, and when the caller authenticates
 * the content itself), bounded redirects that never
 * forward credentials to another host, a response size limit, a timeout,
 * and retry with back-off on 429/5xx.  With denyPrivateAddresses, no
 * connection (first request or redirect) reaches a loopback, private,
 * link-local or other local address, whatever a name resolves to when
 * the connection is made (so DNS rebinding does not reach one either).
 *
 * @license MIT
 */

'use strict';

const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
// The longest one response (redirects each have their own) may take.
const DEADLINE = 60 * 60 * 1000;

const CREDENTIAL_HEADERS = new Set(['authorization', 'cookie', 'proxy-authorization']);

// IPv4 ranges no request for a name taken from evidence should reach:
// [first address, prefix length].
const IPV4_LOCAL = [
  ['0.0.0.0', 8], // This network (0.0.0.0 is any local address)
  ['10.0.0.0', 8], // Private
  ['100.64.0.0', 10], // Carrier-grade NAT
  ['127.0.0.0', 8], // Loopback
  ['169.254.0.0', 16], // Link-local (cloud metadata services)
  ['172.16.0.0', 12], // Private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.168.0.0', 16], // Private
  ['198.18.0.0', 15], // Benchmarking
  ['224.0.0.0', 4], // Multicast
  ['240.0.0.0', 4], // Reserved, broadcast
].map(([address, bits]) => [ipv4Number(address) >>> (32 - bits), bits]);

/**
 * @param {string} address - dotted IPv4
 * @returns {number}
 */
function ipv4Number(address) {
  return address.split('.').reduce((number, octet) => (number * 256) + Number(octet), 0);
}

/**
 * The eight 16-bit groups of an IPv6 address.
 * @param {string} address - a valid IPv6 address, without a zone
 * @returns {number[]}
 */
function ipv6Groups(address) {
  let text = address;
  const dotted = text.match(/((?:\d+\.){3}\d+)$/);
  if (dotted) {
    const number = ipv4Number(dotted[1]);
    text = `${text.slice(0, -dotted[1].length)}${(number >>> 16).toString(16)}:${(number & 0xFF_FF).toString(16)}`;
  }

  const [head, tail] = text.split('::');
  const parse = part => (part ? part.split(':').map(group => Number.parseInt(group, 16)) : []);
  const left = parse(head);
  const right = parse(tail);
  return tail === undefined ? left : [...left, ...Array.from({length: 8 - left.length - right.length}).fill(0), ...right];
}

/**
 * An IPv4 address from two 16-bit groups.
 * @param {number} high
 * @param {number} low
 * @returns {string}
 */
function ipv4Of(high, low) {
  return `${high >>> 8}.${high & 0xFF}.${low >>> 8}.${low & 0xFF}`;
}

/**
 * Whether an IP address is loopback, private (RFC 1918), carrier-grade
 * NAT, link-local, unspecified, unique-local, multicast or reserved,
 * including IPv4 addresses inside IPv6 ones (mapped, compatible, NAT64,
 * 6to4).  Anything that is not an IP address counts as private.
 *
 * @param {string} address
 * @returns {boolean}
 */
function isPrivateAddress(address) {
  const text = String(address).replaceAll(/^\[|]$/g, '').replace(/%.*$/, '');
  if (net.isIPv4(text)) {
    const number = ipv4Number(text);
    return IPV4_LOCAL.some(([prefix, bits]) => number >>> (32 - bits) === prefix);
  }

  if (!net.isIPv6(text)) {
    return true;
  }

  const groups = ipv6Groups(text);
  const zero = (from, to) => groups.slice(from, to).every(group => group === 0);
  if (zero(0, 6)) {
    // Unspecified, loopback, and IPv4-compatible addresses.
    return true;
  }

  if ((zero(0, 5) && groups[5] === 0xFF_FF) || (groups[0] === 0x64 && groups[1] === 0xFF_9B && zero(2, 6))) {
    // IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d).
    return isPrivateAddress(ipv4Of(groups[6], groups[7]));
  }

  if (groups[0] === 0x20_02) {
    // 6to4 (2002:aabb:ccdd::) carries an IPv4 address.
    return isPrivateAddress(ipv4Of(groups[1], groups[2]));
  }

  return (groups[0] === 0x64 && groups[1] === 0xFF_9B && groups[2] === 1) // Local-use NAT64 (64:ff9b:1::/48)
    || (groups[0] & 0xFE_00) === 0xFC_00 // Unique local
    || (groups[0] & 0xFF_C0) === 0xFE_80 // Link-local
    || (groups[0] & 0xFF_C0) === 0xFE_C0 // Site-local
    || (groups[0] & 0xFF_00) === 0xFF_00; // Multicast
}

/**
 * A lookup (dns.lookup's signature) that fails for a name resolving to a
 * private address (isPrivateAddress), even one among public ones.  Given
 * to a request, it is what the connection uses, so a name that resolves
 * differently when connecting than when checked (DNS rebinding) is still
 * refused.
 *
 * @param {Function} [resolve=dns.lookup]
 * @returns {Function}
 */
function privateAddressLookup(resolve = dns.lookup) {
  return (hostname, lookupOptions, callback) => {
    if (typeof lookupOptions === 'function') {
      callback = lookupOptions;
      lookupOptions = {};
    }

    // A connection's lookup option takes a callback.
    // eslint-disable-next-line n/prefer-promises/dns
    resolve(hostname, {...lookupOptions, all: true}, (error, addresses) => {
      if (error) {
        callback(error);
        return;
      }

      const refused = addresses.find(item => isPrivateAddress(item.address));
      if (refused || addresses.length === 0) {
        callback(refused
          ? Object.assign(new Error(`Refusing to connect to ${hostname}: it resolves to a private address (${refused.address})`), {code: 'EPRIVATEADDRESS'})
          : Object.assign(new Error(`${hostname} resolves to no address`), {code: 'ENOTFOUND'}));
      } else if (lookupOptions.all) {
        callback(null, addresses);
      } else {
        callback(null, addresses[0].address, addresses[0].family);
      }
    });
  };
}

/**
 * Connection options for a request (http.request's lookup and agent): with
 * denyPrivateAddresses, a lookup that refuses private addresses, and no
 * shared agent, so no pooled socket opened without the check is reused.
 *
 * @param {Object} [options]
 * @param {boolean} [options.denyPrivateAddresses]
 * @param {Function} [options.lookup] - resolves names (dns.lookup's signature; default dns.lookup)
 * @returns {{lookup?: Function, agent?: false}}
 */
function connectOptions(options = {}) {
  if (options.denyPrivateAddresses) {
    return {lookup: privateAddressLookup(options.lookup), agent: false};
  }

  return options.lookup ? {lookup: options.lookup} : {};
}

/**
 * Throws for a URL httpGet refuses: not HTTPS (unless loopback or
 * allowHttp), or, with denyPrivateAddresses, a private IP address as the
 * host (connected to without a lookup).
 *
 * @param {URL} url
 * @param {Object} [options]
 * @param {boolean} [options.allowHttp]
 * @param {boolean} [options.denyPrivateAddresses]
 */
function assertAllowedUrl(url, options = {}) {
  const literal = url.hostname.replaceAll(/^\[|]$/g, '');
  if (options.denyPrivateAddresses && net.isIP(literal) && isPrivateAddress(literal)) {
    throw Object.assign(new Error(`Refusing to connect to a private address: ${literal}`), {code: 'EPRIVATEADDRESS'});
  }

  if (url.protocol === 'https:') {
    return;
  }

  if (url.protocol === 'http:' && (LOOPBACK.has(url.hostname) || options.allowHttp)) {
    return;
  }

  throw new Error(`Refusing to fetch non-HTTPS URL: ${url.protocol}//${url.host}`);
}

/**
 * Fetch a URL and return the body as a Buffer.
 *
 * @param {string} urlString
 * @param {Object} [options]
 * @param {Object<string,string>} [options.headers]
 * @param {number} [options.timeout=30000] - per-request idle timeout (ms)
 * @param {number} [options.deadline=3600000] - the longest one request may take, however steadily data arrives (ms)
 * @param {number} [options.maxBytes=268435456] - maximum body size
 * @param {number} [options.maxRedirects=5]
 * @param {number} [options.maxRetries=3] - retries on 429 and 5xx
 * @param {number} [options.retryDelay=1000] - base back-off (ms)
 * @param {string|Buffer} [options.ca] - extra trusted CA certificates (PEM) for HTTPS
 * @param {boolean} [options.allowHttp=false] - allow plain HTTP to any host (only for content
 *   authenticated some other way, such as signed package archive indexes)
 * @param {boolean} [options.denyPrivateAddresses=false] - refuse
 *   to connect to private addresses (see isPrivateAddress), on every redirect
 * @param {Function} [options.lookup] - resolves names (dns.lookup signature)
 * @returns {Promise<Buffer>}
 */
async function httpGet(urlString, options = {}) {
  const maxRetries = options.maxRetries ?? 3;
  const retryDelay = options.retryDelay ?? 1000;
  let attempt = 0;
  for (;;) {
    try {
      return await requestOnce(urlString, options, options.maxRedirects ?? 5);
    } catch (error) {
      if (!error.retryable || attempt >= maxRetries) {
        throw error;
      }

      const delay = Math.max(error.retryAfterMs || 0, retryDelay * (2 ** attempt));
      attempt++;
      await new Promise(resolve => {
        setTimeout(resolve, delay);
      });
    }
  }
}

/**
 * @param {string} urlString
 * @param {Object} options
 * @param {number} redirectsLeft
 * @returns {Promise<Buffer>}
 */
function requestOnce(urlString, options, redirectsLeft) {
  return new Promise((_resolve, _reject) => {
    // The idle timeout does not bound a server that sends a byte now and
    // then; the deadline bounds the whole response.
    let timer = null;
    const resolve = value => {
      clearTimeout(timer);
      _resolve(value);
    };

    const reject = error => {
      clearTimeout(timer);
      _reject(error);
    };

    const url = new URL(urlString);
    assertAllowedUrl(url, options);
    const client = url.protocol === 'https:' ? https : http;
    const maxBytes = options.maxBytes ?? 256 * 1024 * 1024;
    const headers = {'user-agent': 'attestium', ...options.headers};

    const requestOptions = {headers, timeout: options.timeout ?? 30_000, ...connectOptions(options)};
    if (options.ca && url.protocol === 'https:') {
      requestOptions.ca = options.ca;
    }

    const request = client.get(url, requestOptions, response => {
      const {statusCode} = response;
      if (statusCode >= 300 && statusCode < 400 && response.headers.location) {
        response.resume();
        if (redirectsLeft <= 0) {
          reject(new Error(`Too many redirects fetching ${url.origin}${url.pathname}`));
          return;
        }

        const next = new URL(response.headers.location, url);
        if (url.protocol === 'https:' && next.protocol !== 'https:') {
          reject(new Error(`Refusing to follow a redirect from HTTPS to ${next.protocol}//${next.host}`));
          return;
        }

        const nextOptions = {...options, headers: {...options.headers}};
        if (next.host !== url.host) {
          // Never forward credentials to a different host.
          for (const key of Object.keys(nextOptions.headers)) {
            if (CREDENTIAL_HEADERS.has(key.toLowerCase())) {
              delete nextOptions.headers[key];
            }
          }
        }

        requestOnce(next.href, nextOptions, redirectsLeft - 1).catch(reject).then(resolve);
        return;
      }

      if (statusCode !== 200) {
        response.resume();
        const error = new Error(`HTTP ${statusCode} fetching ${url.origin}${url.pathname}`);
        error.statusCode = statusCode;
        error.retryable = statusCode === 429 || statusCode >= 500;
        const retryAfter = Number(response.headers['retry-after']);
        if (Number.isFinite(retryAfter) && retryAfter > 0) {
          error.retryAfterMs = Math.min(retryAfter, 60) * 1000;
        }

        reject(error);
        return;
      }

      const declared = Number(response.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxBytes) {
        response.destroy();
        reject(new Error(`Response too large (${declared} bytes) from ${url.origin}${url.pathname}`));
        return;
      }

      const chunks = [];
      let received = 0;
      response.on('data', chunk => {
        received += chunk.length;
        if (received > maxBytes) {
          response.destroy();
          reject(new Error(`Response exceeded ${maxBytes} bytes from ${url.origin}${url.pathname}`));
          return;
        }

        chunks.push(chunk);
      });
      response.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
      response.on('error', error => {
        // The connection reset before the body ended ("aborted"): retried
        // like a reset before the response.
        error.retryable = true;
        reject(error);
      });
    });

    const deadline = options.deadline ?? DEADLINE;
    timer = setTimeout(() => {
      request.destroy(new Error(`Deadline of ${deadline} ms exceeded fetching ${url.origin}${url.pathname}`));
    }, deadline);
    request.on('timeout', () => {
      const error = new Error(`Timeout fetching ${url.origin}${url.pathname}`);
      error.retryable = true;
      request.destroy(error);
    });
    request.on('error', error => {
      if (error.code === 'ECONNRESET' || error.code === 'ECONNREFUSED') {
        error.retryable = true;
      }

      reject(error);
    });
  });
}

/**
 * Fetch and parse JSON.
 * @param {string} url
 * @param {Object} [options]
 * @returns {Promise<*>}
 */
async function httpGetJson(url, options = {}) {
  const body = await httpGet(url, {
    ...options,
    headers: {accept: 'application/json', ...options.headers},
  });
  return JSON.parse(body.toString('utf8'));
}

module.exports = {
  httpGet,
  httpGetJson,
  assertAllowedUrl,
  isPrivateAddress,
  privateAddressLookup,
  connectOptions,
};
