// A CONNECT proxy over TLS, for integration/proxy-https.sh.  MODE h2 speaks
// HTTP/2 (CONNECT on a stream); MODE h1 speaks HTTP/1.1 in the TLS.  It
// listens on a port of its own, which it prints, and tunnels to any target
// except the ports it is told to refuse.
//
//   node https-proxy.js MODE CERT KEY [USER:PASS] [REFUSED_PORT]
'use strict';
const net = require('net');
const fs = require('fs');
const [mode, certFile, keyFile, credentials, refused] = process.argv.slice(2);
const options = { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) };
const want = credentials ? 'Basic ' + Buffer.from(credentials).toString('base64') : null;

function allowed(auth, authority) {
  const port = authority.slice(authority.lastIndexOf(':') + 1);
  if (want && auth !== want) return 407;
  if (refused && port === refused) return 403;
  return 200;
}

function target(authority) {
  const i = authority.lastIndexOf(':');
  let host = authority.slice(0, i);
  if (host.startsWith('[')) host = host.slice(1, -1);
  return { host, port: parseInt(authority.slice(i + 1), 10) };
}

if (mode === 'h2') {
  const http2 = require('http2');
  const server = http2.createSecureServer({ ...options, ALPNProtocols: ['h2'] });
  server.on('stream', (stream, headers) => {
    if (headers[':method'] !== 'CONNECT') {
      stream.respond({ ':status': 405 }); stream.end(); return;
    }
    const status = allowed(headers['proxy-authorization'], headers[':authority']);
    if (status !== 200) {
      stream.respond({ ':status': status }); stream.end(); return;
    }
    const t = target(headers[':authority']);
    const up = net.connect(t.port, t.host);
    up.on('connect', () => {
      stream.respond({ ':status': 200 });
      stream.pipe(up); up.pipe(stream);
    });
    up.on('error', () => { try { stream.respond({ ':status': 502 }); } catch (e) {} stream.end(); });
    stream.on('error', () => up.destroy());
    stream.on('close', () => up.destroy());
    up.on('close', () => stream.close());
  });
  server.listen(0, '127.0.0.1', () => console.log(server.address().port));
} else {
  const https = require('https');
  const server = https.createServer({ ...options, ALPNProtocols: ['http/1.1'] });
  server.on('connect', (req, socket, head) => {
    const status = allowed(req.headers['proxy-authorization'], req.url);
    if (status !== 200) {
      socket.end('HTTP/1.1 ' + status + ' No\r\nContent-Length: 0\r\n\r\n'); return;
    }
    const t = target(req.url);
    const up = net.connect(t.port, t.host);
    up.on('connect', () => {
      socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
      if (head.length) up.write(head);
      socket.pipe(up); up.pipe(socket);
    });
    up.on('error', () => socket.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'));
    socket.on('error', () => up.destroy());
    socket.on('close', () => up.destroy());
    up.on('close', () => socket.destroy());
  });
  server.listen(0, '127.0.0.1', () => console.log(server.address().port));
}
