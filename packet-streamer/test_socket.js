const { io } = require('socket.io-client');
const http = require('http');

const socket = io('http://localhost:3000');

socket.on('connect', () => {
  console.log('[Test Client] Connected to backend Socket.io successfully! ID:', socket.id);

  // Send a test packet via HTTP POST to trigger broadcast
  const payload = JSON.stringify({
    srcIp: '10.10.10.5',
    dstIp: '10.10.10.1',
    protocol: 'UDP',
    srcPort: 5353,
    dstPort: 53,
    length: 84,
    info: 'DNS Standard query A google.com'
  });

  const req = http.request({
    hostname: 'localhost',
    port: 3000,
    path: '/api/packets',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  }, (res) => {
    console.log('[Test Client] HTTP POST sent, status code:', res.statusCode);
  });

  req.write(payload);
  req.end();
});

socket.on('packet', (data) => {
  console.log('[Test Client] Received real-time packet via Socket.io event:');
  console.log('             ID:', data.id, '| Protocol:', data.protocol, '|', data.srcIp, '->', data.dstIp);
  socket.disconnect();
  process.exit(0);
});

socket.on('connect_error', (err) => {
  console.error('[Test Client] Socket connection error:', err.message);
  process.exit(1);
});
