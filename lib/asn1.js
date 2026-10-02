/**
 * Attestium - DER reading
 *
 * Just enough ASN.1 (DER) to read what Node.js's X509Certificate does not
 * expose: certificate extensions (Sigstore's Fulcio claims, TPM
 * endorsement key certificates), CMS signed data (RFC 3161 timestamps) and
 * a few AMD and Intel attestation structures.  Strict: indefinite lengths
 * and trailing data are errors.
 *
 * @license MIT
 */

'use strict';

class Asn1Error extends Error {}

/**
 * Parse one DER element starting at `offset`.
 *
 * @param {Buffer} buffer
 * @param {number} [offset=0]
 * @param {number} [limit=buffer.length]
 * @param {number} [depth=0]
 * @returns {{tagClass: number, constructed: boolean, tag: number, start: number, contentStart: number, end: number, children: Object[]|null, buffer: Buffer}}
 */
function parseElement(buffer, offset = 0, limit = buffer.length, depth = 0) {
  if (depth > 64) {
    throw new Asn1Error('DER nesting too deep');
  }

  if (offset + 2 > limit) {
    throw new Asn1Error('DER element truncated');
  }

  const first = buffer[offset];
  const tagClass = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1F;
  let cursor = offset + 1;
  if (tag === 0x1F) {
    tag = 0;
    let byte;
    do {
      if (cursor >= limit) {
        throw new Asn1Error('DER tag truncated');
      }

      byte = buffer[cursor++];
      tag = (tag * 128) + (byte & 0x7F);
    } while (byte & 0x80);
  }

  if (cursor >= limit) {
    throw new Asn1Error('DER element truncated');
  }

  let length = buffer[cursor++];
  if (length === 0x80) {
    throw new Asn1Error('Indefinite lengths are not DER');
  }

  if (length > 0x80) {
    const bytes = length & 0x7F;
    if (bytes > 6 || cursor + bytes > limit) {
      throw new Asn1Error('DER length out of range');
    }

    length = 0;
    for (let index = 0; index < bytes; index++) {
      length = (length * 256) + buffer[cursor++];
    }
  }

  const contentStart = cursor;
  const end = contentStart + length;
  if (end > limit) {
    throw new Asn1Error('DER element exceeds its container');
  }

  let children = null;
  if (constructed) {
    children = [];
    let child = contentStart;
    while (child < end) {
      const element = parseElement(buffer, child, end, depth + 1);
      children.push(element);
      child = element.end;
    }
  }

  return {
    tagClass, constructed, tag, start: offset, contentStart, end, children, buffer,
  };
}

/**
 * Parse a complete DER value (no trailing bytes).
 * @param {Buffer} buffer
 * @returns {Object}
 */
function parse(buffer) {
  const element = parseElement(buffer);
  if (element.end !== buffer.length) {
    throw new Asn1Error('Trailing data after DER value');
  }

  return element;
}

const content = element => element.buffer.subarray(element.contentStart, element.end);
const raw = element => element.buffer.subarray(element.start, element.end);

/**
 * @param {Object} element
 * @returns {string} dotted object identifier
 */
function oid(element) {
  const bytes = content(element);
  if (element.tag !== 6 || bytes.length === 0) {
    throw new Asn1Error('Not an OBJECT IDENTIFIER');
  }

  if (bytes.at(-1) & 0x80) {
    throw new Asn1Error('truncated OBJECT IDENTIFIER');
  }

  const parts = [];
  let value = 0;
  for (const byte of bytes) {
    value = (value * 128) + (byte & 0x7F);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }

  const first = parts.shift();
  const head = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];
  return [...head, ...parts].join('.');
}

/**
 * A string-typed element's text (UTF8String, PrintableString, IA5String,
 * VisibleString, T61String, BMPString).
 */
function text(element) {
  const bytes = content(element);
  if (element.tag === 30) {
    let result = '';
    for (let index = 0; index + 1 < bytes.length; index += 2) {
      result += String.fromCodePoint(bytes.readUInt16BE(index));
    }

    return result;
  }

  if (![12, 19, 20, 22, 26].includes(element.tag)) {
    throw new Asn1Error(`Not a string (tag ${element.tag})`);
  }

  return bytes.toString(element.tag === 12 ? 'utf8' : 'latin1');
}

/**
 * INTEGER as a BigInt.
 */
function integer(element) {
  const bytes = content(element);
  if (element.tag !== 2 || bytes.length === 0) {
    throw new Asn1Error('Not an INTEGER');
  }

  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }

  return bytes[0] & 0x80 ? value - (1n << BigInt(bytes.length * 8)) : value;
}

/**
 * UTCTime or GeneralizedTime as a Date.
 */
function time(element) {
  const value = content(element).toString('latin1');
  const match = element.tag === 23
    ? value.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/)
    : value.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/);
  if (!match || (element.tag !== 23 && element.tag !== 24)) {
    throw new Asn1Error(`Not a time: ${value.slice(0, 20)}`);
  }

  let year = Number(match[1]);
  if (element.tag === 23) {
    year += year >= 50 ? 1900 : 2000;
  }

  const milliseconds = match[7] ? Number(`0.${match[7]}`) * 1000 : 0;
  const fields = [year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6])];
  const date = new Date(Date.UTC(...fields, milliseconds));
  // Date.UTC rolls 30 February over into March; a time must name itself.
  const actual = [date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()];
  if (actual.some((value, index) => value !== fields[index])) {
    throw new Asn1Error(`Not a time: ${value.slice(0, 20)}`);
  }

  return date;
}

/**
 * Certificate extensions by OID, from a certificate's DER.
 *
 * @param {Buffer} der
 * @returns {Map<string, {critical: boolean, value: Buffer}>}
 */
function certificateExtensions(der) {
  const certificate = parse(der);
  const tbs = certificate.children[0];
  const extensions = new Map();
  const wrapper = tbs.children.find(child => child.tagClass === 2 && child.tag === 3);
  if (!wrapper) {
    return extensions;
  }

  const list = wrapper.children && wrapper.children[0];
  if (!list || list.tag !== 16 || !list.children) {
    throw new Asn1Error('Malformed certificate extensions');
  }

  for (const extension of list.children) {
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    const [id, ...rest] = extension.children || [];
    const value = rest.at(-1);
    if (!id || rest.length === 0 || rest.length > 2 || value.tag !== 4 || (rest.length === 2 && (rest[0].tag !== 1 || content(rest[0]).length !== 1))) {
      throw new Asn1Error('Malformed certificate extension');
    }

    const name = oid(id);
    // RFC 5280: at most one of each; readers that keep the first and ones
    // that keep the last would disagree about a certificate's claims.
    if (extensions.has(name)) {
      throw new Asn1Error(`Duplicate certificate extension ${name}`);
    }

    extensions.set(name, {critical: rest.length === 2 && content(rest[0])[0] !== 0, value: content(value)});
  }

  return extensions;
}

module.exports = {
  Asn1Error,
  parse,
  parseElement,
  content,
  raw,
  oid,
  text,
  integer,
  time,
  certificateExtensions,
};
