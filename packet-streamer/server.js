const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');
const dns = require('dns');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

const PORT = process.env.PORT || 3000;
const MAX_PACKET_HISTORY = 300;
const MAX_DNS_HISTORY = 100;

// In-memory packet and DNS stores
let packetSequence = 0;
const packetBuffer = [];
const dnsBuffer = [];
const serverStartTime = new Date();

// --- Middleware ---
// Morgan for request logging
app.use(morgan(':date[iso] :method :url :status :response-time ms - :res[content-length] bytes'));

// Cross-Origin Resource Sharing
app.use(cors());

// Body Parsers (support JSON and urlencoded)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend assets
app.use(express.static(path.join(__dirname, 'public')));

// --- Helper Functions ---
function normalizePacket(body) {
  packetSequence++;

  let protocol = (body.protocol || body.proto || 'TCP').toUpperCase();
  const srcIp = body.srcIp || body.src_ip || body.source_ip || body.source || '127.0.0.1';
  const dstIp = body.dstIp || body.dst_ip || body.destination_ip || body.destination || '127.0.0.1';
  const srcPort = body.srcPort || body.src_port || body.sport || null;
  const dstPort = body.dstPort || body.dst_port || body.dport || null;
  const length = parseInt(body.length || body.len || body.size || 0, 10);
  const macSrc = body.macSrc || body.mac_src || body.ether_shost || null;
  const macDst = body.macDst || body.mac_dst || body.ether_dhost || null;

  // Classify port 53 traffic as DNS protocol
  if ((protocol === 'UDP' || protocol === 'TCP') && (srcPort === 53 || dstPort === 53)) {
    protocol = 'DNS';
  }

  const info = body.info || body.summary || body.payload || `${protocol} traffic ${srcIp} -> ${dstIp}`;

  return {
    id: packetSequence,
    timestamp: body.timestamp || new Date().toISOString(),
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    protocol,
    length,
    macSrc,
    macDst,
    info
  };
}

// --- REST Endpoints ---

/**
 * POST /api/packets
 * Primary endpoint for C++ packet sniffer to post captured packet data
 */
app.post(['/api/packets', '/packet'], (req, res) => {
  try {
    const rawData = req.body;

    // Validate minimum requirements
    if (!rawData || (typeof rawData !== 'object')) {
      return res.status(400).json({ error: 'Invalid packet payload. Expected JSON object.' });
    }

    const packet = normalizePacket(rawData);

    // Save to history buffer (ring buffer up to MAX_PACKET_HISTORY)
    packetBuffer.push(packet);
    if (packetBuffer.length > MAX_PACKET_HISTORY) {
      packetBuffer.shift();
    }

    // Stream real-time packet to all connected Socket.io dashboards
    io.emit('packet', packet);

    return res.status(201).json({
      status: 'success',
      message: 'Packet captured and broadcasted',
      packetId: packet.id
    });
  } catch (err) {
    console.error('Error processing packet:', err);
    return res.status(500).json({ error: 'Internal server error processing packet' });
  }
});

/**
 * POST /api/dns
 * Endpoint for DNS server to report incoming DNS queries
 */
app.post('/api/dns', (req, res) => {
  try {
    const { domain, clientIp, queryType } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Missing domain in request body' });
    }

    packetSequence++;
    const timestamp = new Date().toISOString();
    const qType = (queryType || 'A').toUpperCase();
    const client = clientIp || '127.0.0.1';

    const dnsPacket = {
      id: packetSequence,
      timestamp,
      srcIp: client,
      dstIp: '8.8.8.8',
      srcPort: 53,
      dstPort: 53,
      protocol: 'DNS',
      length: domain.length + 12,
      macSrc: null,
      macDst: null,
      info: `DNS Query: ${domain} (${qType})`
    };

    packetBuffer.push(dnsPacket);
    if (packetBuffer.length > MAX_PACKET_HISTORY) {
      packetBuffer.shift();
    }

    const dnsEvent = {
      id: dnsPacket.id,
      domain,
      clientIp: client,
      queryType: qType,
      timestamp
    };

    dnsBuffer.push(dnsEvent);
    if (dnsBuffer.length > MAX_DNS_HISTORY) {
      dnsBuffer.shift();
    }

    // Stream real-time DNS query to dashboards
    io.emit('packet', dnsPacket);
    io.emit('dns_query', dnsEvent);

    console.log(`[DNS Monitor] Logged query for domain: ${domain} (${qType}) from ${client}`);

    return res.status(201).json({
      status: 'success',
      message: 'DNS query recorded and broadcasted',
      domain,
      queryType: qType,
      packetId: dnsPacket.id
    });
  } catch (err) {
    console.error('Error processing DNS report:', err);
    return res.status(500).json({ error: 'Internal server error processing DNS query' });
  }
});

/**
 * GET /api/dns
 * Retrieve recent DNS queries recorded by dns_server
 */
app.get('/api/dns', (req, res) => {
  res.json({
    totalQueries: dnsBuffer.length,
    queries: dnsBuffer.slice(-50)
  });
});

/**
 * POST /api/dns/test
 * Trigger an actual DNS query against the local C++ DNS server on 127.0.0.1:53
 */
app.post('/api/dns/test', (req, res) => {
  const testDomains = [
    'google.com', 'github.com', 'cloudflare.com', 'kali.org',
    'wikipedia.org', 'kernel.org', 'archlinux.org', 'debian.org'
  ];
  const targetDomain = req.body && req.body.domain
    ? req.body.domain
    : testDomains[Math.floor(Math.random() * testDomains.length)];

  const resolver = new dns.Resolver();
  resolver.setServers(['127.0.0.1']);

  resolver.resolve4(targetDomain, (err, addresses) => {
    if (err) {
      return res.status(502).json({
        status: 'error',
        message: `DNS resolution failed via 127.0.0.1:53 (${err.message})`,
        domain: targetDomain
      });
    }
    return res.json({
      status: 'success',
      message: 'Successfully resolved via local DNS server (127.0.0.1:53)',
      domain: targetDomain,
      addresses
    });
  });
});

/**
 * GET /api/packets
 * Retrieve recent packet buffer
 */
app.get('/api/packets', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, MAX_PACKET_HISTORY);
  res.json({
    total: packetSequence,
    count: packetBuffer.length,
    packets: packetBuffer.slice(-limit)
  });
});

/**
 * GET /api/stats
 * Basic runtime statistics
 */
app.get('/api/stats', (req, res) => {
  const protoCounts = {};
  for (const pkt of packetBuffer) {
    protoCounts[pkt.protocol] = (protoCounts[pkt.protocol] || 0) + 1;
  }

  res.json({
    totalPackets: packetSequence,
    bufferedPackets: packetBuffer.length,
    dnsQueries: dnsBuffer.length,
    protocols: protoCounts,
    connectedClients: io.engine.clientsCount,
    uptimeSeconds: Math.floor((Date.now() - serverStartTime.getTime()) / 1000)
  });
});

/**
 * DELETE /api/packets
 * Clear memory buffer
 */
app.delete('/api/packets', (req, res) => {
  packetBuffer.length = 0;
  dnsBuffer.length = 0;
  io.emit('clear_packets');
  res.json({ status: 'cleared', message: 'Packet history reset' });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    dnsServerPort: 53
  });
});

// Fallback to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Socket.io Events ---
io.on('connection', (socket) => {
  console.log(`[Socket.io] Dashboard connected: ${socket.id} (Total: ${io.engine.clientsCount})`);

  // Send the newly connected client recent packets and DNS queries
  socket.emit('init', {
    packets: packetBuffer.slice(-100),
    dnsQueries: dnsBuffer.slice(-50),
    totalCount: packetSequence,
    serverStartTime: serverStartTime.toISOString()
  });

  socket.on('disconnect', () => {
    console.log(`[Socket.io] Dashboard disconnected: ${socket.id} (Total: ${io.engine.clientsCount})`);
  });
});

// --- Start Server ---
server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(` Network Packet Streamer Backend running on port ${PORT}`);
  console.log(` Dashboard URL:        http://localhost:${PORT}`);
  console.log(` Packet POST Endpoint: http://localhost:${PORT}/api/packets`);
  console.log(` DNS POST Endpoint:    http://localhost:${PORT}/api/dns`);
  console.log(`====================================================`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nGracefully shutting down server...');
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
});
