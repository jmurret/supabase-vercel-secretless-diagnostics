const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeGatewayVersion, notForwardedReason, isForwarded, FORWARDING_LOOP } = require('../gateway-variants');

test('several sb-gateway-version values are a forwarding loop', () => {
  const header = [...Array(15).fill('2'), '1'].join(', ');
  assert.equal(normalizeGatewayVersion(header), 'loop');
  assert.equal(isForwarded('v2', 'loop'), false);
  assert.equal(notForwardedReason('loop'), FORWARDING_LOOP);
});

test('a single v1 answer is reported as not forwarded', () => {
  assert.equal(normalizeGatewayVersion('1'), 'v1');
  assert.match(notForwardedReason('v1'), /not forwarded/);
  assert.match(notForwardedReason('unknown'), /not forwarded/);
});
