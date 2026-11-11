
const http = require('http');
const net = require('net');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');

const HOST = '127.0.0.1';
const PORT = 3000;

const SERVICES = {
    20: 'FTP Data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    8080: 'HTTP Proxy'
};

const PRESETS = {
    common: '21,22,23,25,53,80,110,143,443,445,3306,3389',
    web: '80,443,8080,8443'
};

function sendJSON(res, status, data) {
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': 'http://127.0.0.1:3000'
    });
    res.end(JSON.stringify(data));
}

function parsePorts(input) {
    const ports = new Set();

    for (const part of String(input).split(',')) {
        const item = part.trim();

        if (!item) continue;

        if (/^\d+$/.test(item)) {
            const port = Number(item);

            if (port < 1 || port > 65535) {
                throw new Error('Ports must be between 1 and 65535.');
            }

            ports.add(port);
        } else if (/^\d+-\d+$/.test(item)) {
            const [start, end] = item.split('-').map(Number);

            if (start < 1 || end > 65535 || start > end) {
                throw new Error('Invalid port range.');
            }

            if (end - start + 1 > 2000) {
                throw new Error('A port range cannot exceed 2000 ports.');
            }

            for (let port = start; port <= end; port++) {
                ports.add(port);
            }
        } else {
            throw new Error('Invalid port format.');
        }

        if (ports.size > 2000) {
            throw new Error('Maximum of 2000 ports per scan.');
        }
    }

    if (!ports.size) {
        throw new Error('Enter at least one port.');
    }

    return [...ports].sort((a, b) => a - b);
}

async function resolveTarget(target) {
    if (net.isIP(target)) return target;

    const result = await dns.lookup(target);
    return result.address;
}

function probePort(host, port, timeout, signal) {
    return new Promise(resolve => {
        const socket = new net.Socket();
        const started = Date.now();
        let settled = false;
        let banner = '';

        const finish = (status) => {
            if (settled) return;
            settled = true;

            const latency = Date.now() - started;

            socket.destroy();

            resolve({
                port,
                status,
                service: SERVICES[port] || 'Unknown',
                latency,
                banner
            });
        };

        if (signal.aborted) {
            finish('Cancelled');
            return;
        }

        const onAbort = () => finish('Cancelled');

        signal.addEventListener('abort', onAbort, { once: true });

        socket.setTimeout(timeout);

        socket.once('connect', () => {
            banner = 'Connected';
            finish('Open');
        });

        socket.once('timeout', () => {
            finish('Filtered');
        });

        socket.once('error', error => {
            if (error.code === 'ECONNREFUSED') {
                finish('Closed');
            } else {
                finish('Filtered');
            }
        });

        socket.once('close', () => {
            signal.removeEventListener('abort', onAbort);
        });

        socket.connect(port, host);
    });
}

async function readRequest(req) {
    let body = '';

    for await (const chunk of req) {
        body += chunk;

        if (body.length > 20000) {
            throw new Error('Request body is too large.');
        }
    }

    return JSON.parse(body);
}

function sendEvent(res, data) {
    if (!res.destroyed && !res.writableEnded) {
        res.write(JSON.stringify(data) + '\n');
    }
}

async function runScan(config, res, signal) {
    const {
        target,
        ports,
        threads,
        timeout
    } = config;

    const host = await resolveTarget(target);

    sendEvent(res, {
        type: 'start',
        target: host,
        total: ports.length
    });

    let index = 0;
    let scanned = 0;

    async function worker() {
        while (index < ports.length && !signal.aborted) {
            const port = ports[index++];

            const result = await probePort(
                host,
                port,
                timeout,
                signal
            );

            if (signal.aborted) break;

            scanned++;

            sendEvent(res, {
                type: 'result',
                result,
                scanned,
                total: ports.length
            });
        }
    }

    const workers = Array.from(
        { length: Math.min(threads, ports.length) },
        () => worker()
    );

    await Promise.all(workers);

    sendEvent(res, {
        type: 'done',
        scanned,
        cancelled: signal.aborted
    });
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${HOST}:${PORT}`);

    if (req.method === 'GET' && url.pathname === '/') {
        const file = path.join(__dirname, 'public', 'index.html');

        fs.readFile(file, (error, content) => {
            if (error) {
                res.writeHead(500);
                res.end('Could not load index.html');
                return;
            }

            res.writeHead(200, {
                'Content-Type': 'text/html; charset=utf-8'
            });

            res.end(content);
        });

        return;
    }

    if (req.method === 'GET' && url.pathname === '/api/config') {
        sendJSON(res, 200, {
            presets: PRESETS,
            maxPorts: 2000,
            minThreads: 5,
            maxThreads: 150,
            minTimeout: 200,
            maxTimeout: 5000
        });

        return;
    }

    if (req.method === 'POST' && url.pathname === '/api/scan') {
        let config;

        try {
            config = await readRequest(req);

            if (config.authorized !== true) {
                sendJSON(res, 403, {
                    error: 'Confirm that you have permission to scan this target.'
                });
                return;
            }

            const target = String(config.target || '').trim();

            if (!target || target.length > 253 ||
                /[\s/\\]/.test(target)) {
                throw new Error('Enter a valid IP address or hostname.');
            }

            const ports = parsePorts(config.ports);

            const threads = Number(config.threads);
            const timeout = Number(config.timeout);

            if (!Number.isInteger(threads) ||
                threads < 5 || threads > 150) {
                throw new Error('Concurrency must be between 5 and 150.');
            }

            if (!Number.isInteger(timeout) ||
                timeout < 200 || timeout > 5000) {
                throw new Error('Timeout must be between 200 and 5000 ms.');
            }

            const controller = new AbortController();

            res.writeHead(200, {
                'Content-Type': 'application/x-ndjson',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Content-Type-Options': 'nosniff'
            });

            res.on('close', () => controller.abort());

            await runScan({
                target,
                ports,
                threads,
                timeout
            }, res, controller.signal);

            if (!res.destroyed) res.end();

        } catch (error) {
            if (!res.headersSent) {
                sendJSON(res, 400, {
                    error: error.message || 'Scan failed.'
                });
            } else if (!res.destroyed) {
                sendEvent(res, {
                    type: 'error',
                    error: error.message || 'Scan failed.'
                });
                res.end();
            }
        }

        return;
    }

    sendJSON(res, 404, {
        error: 'Endpoint not found.'
    });
});

server.listen(PORT, HOST, () => {
    console.log('================================');
    console.log('       NETSCAN PRO SERVER       ');
    console.log('================================');
    console.log(`Server running at http://${HOST}:${PORT}`);
    console.log('Ready for authorized network scans.');
});
