const test = require('node:test');
const assert = require('node:assert/strict');
const { signRequest, EMPTY_PAYLOAD_SHA256 } = require('../sigv4');

const AWS_EXAMPLE = {
  accessKeyId: 'AKIDEXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
  now: new Date('2015-08-30T12:36:00Z'),
};

test('matches the AWS SigV4 test suite vector get-vanilla', () => {
  const r = signRequest({ ...AWS_EXAMPLE, url: 'https://example.amazonaws.com/', region: 'us-east-1', service: 'service' });
  assert.equal(
    r.canonicalRequest,
    'GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n' + EMPTY_PAYLOAD_SHA256
  );
  assert.equal(r.signature, '5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
  assert.equal(
    r.headers.authorization,
    'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31'
  );
  assert.equal(r.headers['x-amz-date'], '20150830T123600Z');
  assert.ok(!('host' in r.headers));
});

test('matches the AWS IAM ListUsers example (query, extra signed header)', () => {
  const r = signRequest({
    ...AWS_EXAMPLE,
    url: 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08',
    region: 'us-east-1',
    service: 'iam',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
  });
  assert.equal(r.signature, '5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7');
  assert.match(r.headers.authorization, /SignedHeaders=content-type;host;x-amz-date, /);
});

test('signs the session token header and sends it', () => {
  const r = signRequest({
    ...AWS_EXAMPLE,
    url: 'https://example.amazonaws.com/',
    region: 'us-east-1',
    service: 's3',
    sessionToken: 'session-token',
  });
  assert.equal(r.headers['x-amz-security-token'], 'session-token');
  assert.match(r.headers.authorization, /SignedHeaders=host;x-amz-date;x-amz-security-token, /);
  assert.ok(!r.headers.authorization.includes('session-token'));
});
