// api-gateway v1 forwards a request that has the header sb-forward-traffic (any value except "false") to
// api-gateway v2. Each gateway check sends a v1 request without the header and a v2 request with it.

const GATEWAY_HEADER = 'sb-gateway-version';
const FORWARD_HEADER = 'sb-forward-traffic';
const VARIANTS = ['v1', 'v2'];
const NOT_FORWARDED = 'request was not forwarded to api-gateway v2';

const FORWARDING_LOOP =
  'request looped between api-gateway v1 and v2 (one sb-gateway-version value per hop), so no gateway answered it';
const notForwardedReason = (gatewayVersion) => (gatewayVersion === 'loop' ? FORWARDING_LOOP : NOT_FORWARDED);

const variantHeaders = (variant) => (variant === 'v2' ? { [FORWARD_HEADER]: 'true' } : {});

// fetch joins repeated headers with ", ". Each gateway hop adds one value, so several values mean the request
// was forwarded back and forth.
function normalizeGatewayVersion(value) {
  if (String(value ?? '').includes(',')) return 'loop';
  const match = /^v?(\d+)(?:\.\d+)*$/i.exec(String(value ?? '').trim());
  return match ? `v${Number(match[1])}` : 'unknown';
}

const isForwarded = (variant, gatewayVersion) => variant !== 'v2' || gatewayVersion === 'v2';

// The first value in `order` is the worst.
const worstOf = (order) => (values) => values.reduce((a, b) => (order.indexOf(b) < order.indexOf(a) ? b : a));
const worstResult = worstOf(['accepted', 'inconclusive', 'rejected']);
const worstStatus = worstOf(['fail', 'warn', 'pass', 'skip']);

module.exports = {
  GATEWAY_HEADER,
  FORWARD_HEADER,
  VARIANTS,
  FORWARDING_LOOP,
  notForwardedReason,
  variantHeaders,
  normalizeGatewayVersion,
  isForwarded,
  worstResult,
  worstStatus,
};
