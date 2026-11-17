const http = require('http');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  { auth: { persistSession: false } }
);

const server = http.createServer(async (req, res) => {
  if (req.url === '/api/countries' && req.method === 'GET') {
    try {
      const { data: rows, error } = await supabase
        .from('countries')
        .select('name')
        .order('name');
      if (error) throw error;
      const html = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>Countries</title>
            <style>
              body { font-family: Arial, sans-serif; padding: 20px; }
              table { border-collapse: collapse; width: 100%; max-width: 600px; }
              th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
              th { background-color: #f2f2f2; }
            </style>
          </head>
          <body>
            <h1>Countries</h1>
            <table>
              <thead>
                <tr><th>Name</th></tr>
              </thead>
              <tbody>
                ${rows.map(row => `<tr><td>${row.name}</td></tr>`).join('')}
              </tbody>
            </table>
          </body>
        </html>
      `;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html);
    } catch (error) {
      console.error('Database query error:', error);
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end(`<h1>Error</h1><p>${error.message}</p>`);
    }
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h1>hhello    world!!!!1 wooo!!1!!</h1>');
  }
});

server.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
