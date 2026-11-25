const http = require('http');
const diagnostics = require('./api/diagnostics');
const crossTenant = require('./api/cross-tenant');
const crossTenantS3 = require('./api/cross-tenant-s3');
const dashboardHtml = require('./dashboard');

const server = http.createServer(async (req, res) => {
  const path = req.url.split('?')[0];
  if (path === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(dashboardHtml);
  } else if (path === '/api/diagnostics') {
    await diagnostics(req, res);
  } else if (path === '/api/cross-tenant') {
    await crossTenant(req, res);
  } else if (path === '/api/cross-tenant-s3') {
    await crossTenantS3(req, res);
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }
});

server.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
