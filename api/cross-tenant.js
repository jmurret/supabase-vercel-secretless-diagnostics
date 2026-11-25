const { runCrossTenantDiagnostics, serve } = require('../diagnostics-core');

module.exports = serve('Cross-tenant', runCrossTenantDiagnostics);
