// AWS Signature Version 4 for a request with a known body. Used for the Storage S3 protocol.

const crypto = require('node:crypto');

const ALGORITHM = 'AWS4-HMAC-SHA256';

const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const encode = (value) =>
  encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

const EMPTY_PAYLOAD_SHA256 = sha256Hex('');

// S3 signs the path as sent. Other services encode each path segment a second time.
const canonicalPath = (pathname, service) => (service === 's3' ? pathname : pathname.split('/').map(encode).join('/'));

function canonicalQuery(searchParams) {
  return [...searchParams]
    .map(([name, value]) => [encode(name), encode(value)])
    .sort(([a, av], [b, bv]) => (a === b ? (av < bv ? -1 : av > bv ? 1 : 0) : a < b ? -1 : 1))
    .map(([name, value]) => `${name}=${value}`)
    .join('&');
}

// Returns the headers to send (without Host, which the HTTP client sets from the URL) and the
// intermediate values. Every header in `headers`, the date, the host and the session token are signed.
function signRequest({
  method = 'GET',
  url,
  region,
  service,
  accessKeyId,
  secretAccessKey,
  sessionToken,
  headers = {},
  body = '',
  now = new Date(),
}) {
  const target = new URL(url);
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = amzDate.slice(0, 8);
  const signed = {
    host: target.host,
    'x-amz-date': amzDate,
    ...Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])),
    ...(sessionToken && { 'x-amz-security-token': sessionToken }),
  };
  const names = Object.keys(signed).sort();
  const canonicalHeaders = names.map((name) => `${name}:${String(signed[name]).trim().replace(/\s+/g, ' ')}\n`).join('');
  const signedHeaders = names.join(';');
  const canonicalRequest = [
    method.toUpperCase(),
    canonicalPath(target.pathname, service),
    canonicalQuery(target.searchParams),
    canonicalHeaders,
    signedHeaders,
    sha256Hex(body),
  ].join('\n');
  const scope = `${date}/${region}/${service}/aws4_request`;
  const stringToSign = [ALGORITHM, amzDate, scope, sha256Hex(canonicalRequest)].join('\n');
  const signingKey = ['aws4_request', service, region, date].reduceRight(
    (key, part) => hmac(key, part),
    `AWS4${secretAccessKey}`
  );
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  const { host, ...sendHeaders } = signed;
  return {
    headers: {
      ...sendHeaders,
      authorization: `${ALGORITHM} Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    },
    signature,
    canonicalRequest,
    stringToSign,
  };
}

module.exports = { EMPTY_PAYLOAD_SHA256, signRequest };
