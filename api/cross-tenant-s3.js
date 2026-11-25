const { runCrossTenantS3Diagnostics, serve } = require('../diagnostics-core');

module.exports = serve('Cross-tenant S3', runCrossTenantS3Diagnostics);
