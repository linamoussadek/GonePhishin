// Simple HTTP server to serve the phishing test site
// Run with: node serve-test-site.js
// Then visit: http://localhost:8080/phishing-test-site.html

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8081; // Changed to avoid conflict with port 8080

const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.wav': 'audio/wav',
    '.mp4': 'video/mp4',
    '.woff': 'application/font-woff',
    '.ttf': 'application/font-ttf',
    '.eot': 'application/vnd.ms-fontobject',
    '.otf': 'application/font-otf',
    '.wasm': 'application/wasm'
};

const server = http.createServer((req, res) => {
    console.log(`${req.method} ${req.url}`);

    // Parse URL
    let filePath = '.' + req.url;
    if (filePath === './') {
        filePath = './phishing-test-site.html';
    }

    const extname = String(path.extname(filePath)).toLowerCase();
    const contentType = mimeTypes[extname] || 'application/octet-stream';

    fs.readFile(filePath, (error, content) => {
        if (error) {
            if (error.code === 'ENOENT') {
                res.writeHead(404, { 'Content-Type': 'text/html' });
                res.end(`
                    <html>
                        <head><title>404 Not Found</title></head>
                        <body>
                            <h1>404 - File Not Found</h1>
                            <p>The file ${req.url} was not found.</p>
                            <p><a href="/phishing-test-site.html">Go to Phishing Test Site</a></p>
                        </body>
                    </html>
                `, 'utf-8');
            } else {
                res.writeHead(500);
                res.end(`Server Error: ${error.code}`, 'utf-8');
            }
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content, 'utf-8');
        }
    });
});

server.listen(PORT, () => {
    console.log(`🚀 Test server running at http://localhost:${PORT}/`);
    console.log(`📄 Phishing test site: http://localhost:${PORT}/phishing-test-site.html`);
    console.log(`\n⚠️  Note: Your extension should upgrade HTTP to HTTPS automatically`);
    console.log(`   So you'll likely see: https://localhost:${PORT}/phishing-test-site.html`);
    console.log(`\n📋 Instructions:`);
    console.log(`   1. Page starts clean with no threats`);
    console.log(`   2. Click buttons to dynamically add phishing patterns`);
    console.log(`   3. Watch anomaly score increase in extension popup`);
    console.log(`\nPress Ctrl+C to stop the server`);
});

