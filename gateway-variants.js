// api-gateway v1 forwards a request that has the header sb-forward-traffic (any value except "false") to
// api-gateway v2. Each gateway check sends a v1 request without the header and a v2 request with it.

const GATEWAY_HEADER = 'sb-gateway-version';
const FORWARD_HEADER = 'sb-forward-traffic';
const VARIANTS = ['v1', 'v2'];
const NOT_FORWARDED = 'request was not forwarded to api-gateway v2';

const variantHeaders = (variant) => (variant === 'v2' ? { [FORWARD_HEADER]: 'true' } : {});

function normalizeGatewayVersion(value) {
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
  NOT_FORWARDED,
  variantHeaders,
  normalizeGatewayVersion,
  isForwarded,
  worstResult,
  worstStatus,
};
