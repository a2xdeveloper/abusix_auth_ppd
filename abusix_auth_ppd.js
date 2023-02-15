#!/usr/bin/env node
/*

Abusix Compromised Account Detection
Postfix Policy daemon
(c) 2023, Abusix Inc.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software 
Foundation, either version 3 of the License, or (at your option) any later 
version.

This program is distributed in the hope that it will be useful, but WITHOUT 
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with 
this program. If not, see https://www.gnu.org/licenses/.

*/

"use strict";
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const net = require('net');
const crypto = require('crypto');
const byline = require('byline');
const fs = require('fs');
const path = require('path');
const child_process = require('child_process');
const ini = require('ini');
const dns = require('dns');
const dnsp = dns.promises;
const ipaddr = require('ipaddr.js');
const sprintf = require('sprintf-js').sprintf;
const Redis = require('redis');
const DEBUG = process.env.DEBUG || false;

// Load configuration
var cfg;
try {
    cfg = ini.parse(fs.readFileSync(path.join(__dirname, './abusix_auth_ppd.ini'),'utf-8'));
}
catch (e) {
    console.error(`Unable to load configuration file: ${e?.message}`);
    process.exit(1);
}

// Common functions
const debug = (text) => {
    if (DEBUG) console.error(`DEBUG: ${text}`);
}

exports.ipv6_to_nibble = (ipv6) => {
    ipv6 = ipaddr.parse(ipv6);
    return ipv6.toNormalizedString()
               .split(':')
               .map((n) => { return sprintf('%04x', parseInt(n, 16)); })
               .join('')
               .split('')
               .reverse()
               .join('.');
}

exports.lookup_ip = async (item, zone) => {
    let lookup;
    switch (net.isIP(item)) {
        case 4:
            var rev_ip = item.split('.').reverse().join('.');
            lookup = `${rev_ip}.${cfg.apikey}.${zone}.`;
            break; 
        case 6:
            var rev_ip = this.ipv6_to_nibble(item);
            lookup = `${rev_ip}.${cfg.apikey}.${zone}.`;
            break;
        case 0:
            // Non-IP input, calculate SHA-1 of input
            let hash = crypto.createHash('sha1').update(item).digest('hex');
            lookup = `${hash}.${cfg.apikey}.${zone}.`;
            break; 
        default:
            throw new Error("net.isIP() returned unhandled value!");
    }       
    
    let result;
    try {
        result = await dnsp.resolve4(lookup);
        result.forEach((r) => {
            if (r.split('.')[0] !== '127') {
                throw new Error(`Invalid return code: ${r}`);
            }
        });
    }   
    catch (err) {
        if (err.code === dns.NOTFOUND) return null;
        // Re-throw on any other error 
        throw err;
    }   
    debug(`dns item=${item} lookup=${lookup} result=${result}`);
    return result;
}   

/*
** Setup master process
** This only forks workers to ensure the process doesn't crash
*/
if (cluster.isMaster) {
    process.title = "abusix_ppd_auth (main)"
    console.log(`started (Node ${process.version} on ${process.platform}/${process.arch})`);

    // Check that we have an API Key
    if (!cfg?.['apikey']) {
        console.error(`Error: API Key is not set`);
        process.exit(1);
    }

    (async () => {
        // Make sure that the API Key works
        let test;
        try {
            test = await exports.lookup_ip('127.0.0.2', 'authbl.mail.abusix.zone');
            if (!test?.includes('127.0.0.4')) {
                throw new Error(`Invalid response from test!`);
            }
        }
        catch (e) {
            console.error(`Error: test lookup failed, check your API Key (${e.message})`);
            process.exit(1);
        }

        // Fork workers.
        for (let i = 0; i < numCPUs; i++) {
            cluster.fork();
        }
    })();

    cluster.on('online', (worker) => {
        if (DEBUG) console.log(`worker ${worker.id} online with PID ${worker.process.pid}`);
    });

    cluster.on('exit', (worker, code, signal) => {
        if (code === 2) {
            // Worker was unable to start and listen, so let it die
            // When the last worker dies, this process will exit.
        }
        else {
            console.log(`worker ${worker.id} with PID ${worker.process.pid} died (code: ${code}, signal: ${signal})`);
            cluster.fork();
        }
    });

    cluster.on('error', (error) => {
        console.error(error.message);
    });

    return;
}

/*
** Per-process worker code is here
*/

process.title = `abusix_auth_ppd (worker)`;

// Set-up Redis
const redis = Redis.createClient({
    socket: {
        host: cfg?.redis?.host,
        port: cfg?.redis?.port,
    },
    database: cfg?.redis?.database,
    username: cfg?.redis?.username,
    password: cfg?.redis?.password,
});

redis.on('error', (err) => {
    console.error(`Redis error: ${err.message}`);
});

const server = net.createServer(async (client) => {
    debug(`client connected: ${client.remoteAddress}:${client.remotePort}`);

    const bl = byline(client, { keepEmptyLines: true });

    var attrs = {};

    bl.on('data', async (line) => {
        line = line.toString('ascii');
        if (line !== '') {
            // Store attributes
            var pos = line.indexOf('=');
            var lhs = line.substr(0,pos);
            var rhs = line.substr(pos+1);
            attrs[lhs] = rhs;
        }
        else {
            // Ignore as we get a blank entry on disconnect
            if (!Object.keys(attrs).length) return;
            // EOD
            await this.process_data(attrs, client);
        }
    });

    client.on('close', (err) => {
        debug(`client ${client.remoteAddress}:${client.remotePort} closed connection (error=${err?.message || null})`);
    });

    client.on('error', (err) => {
        debug(`client ${client.remoteAddress}:${client.remotePort} error ${err?.message || null}`);
    });

    client.on('end', () => {
        debug(`client ${client.remoteAddress}:${client.remotePort} disconnected`);
    });
});

var started = false;

server.on('error', (err) => {
    console.error(`server error: ${err.message}`); 
    // If we couldn't start at all, exit with a code so the master
    // can tell that this process never able to listen on the socket
    // or is crashing immediately, so we don't end up in a crash loop.
    if (!started) {
        process.exit(2);
    }
});

exports.process_data = async (attrs, client) => {
    async function perform_actions (cached) {
        if (!cached) {
            // Add to cache
            await redis.sAdd('compromised_accts', attrs.sasl_username);
            // Write to log
            console.log(`[${attrs.instance || null}] ip=${attrs.client_address} username=${attrs.sasl_username} found new compromised account!`);
            // Run command if specified
            if (cfg.command) {
                child_process.exec(cfg.command, {
                    // Pass in all attributes as shell variables
                    env: attrs
                }, (err, stdout, stderr) => {
                    if (err) {
                        return console.log(`[${attrs.instance || null}] command "${cfg.command}" returned error: ${err.message.replace(/\r?\n/, ' ').trim()}`);
                    }
                    if (stdout || stderr) {
                        console.log(`[${attrs.instance || null}] ${cfg.command}: ${stdout || ''} ${stderr || ''}`);
                    }
                });
            }
        }
        switch (cfg.action.toLowerCase()) {
            case 'reject':
                client.write('action=REJECT\n\n', { encoding: 'ascii' });
                break;
            case 'hold':
                client.write('action=HOLD\n\n', { encoding: 'ascii' });
                break;
            case 'log':
                // We always log anyway, so just skip this
                client.write('action=DUNNO\n\n', { encoding: 'ascii' });
                break;
            default:
                console.log(`[${attrs.instance || null}] ip=${attrs.client_address} username=${attrs.sasl_username} Error: unknown action ${cfg.action}; logging only!`);
                client.write('action=DUNNO\n\n', { encoding: 'ascii' });
        }
    }

    debug(`received attributes: ${JSON.stringify(attrs, null, '\t')}`);

    // We are only interested in AUTHenticated sessions
    if (!(attrs?.sasl_method && attrs?.sasl_username)) {
        debug(`[${attrs?.instance || null }] ip=${attrs?.client_address} skipping as non-authenticated connection`);
        return client.write('action=DUNNO\n\n', { encoding: 'ascii' });
    }

    // Lowercase the username
    attrs.sasl_username = attrs.sasl_username.toLowerCase();

    let cached = await redis.sIsMember('compromised_accts', attrs.sasl_username);
    if (cached) {
        console.log(`[${attrs.instance || null}] ip=${attrs.client_address} username=${attrs.sasl_username} found in cache database`);
        await perform_actions(true);
        return;
    }

    // Do DNS lookups
    let result;

    // Check IP with authbl
    try {
        result = await this.lookup_ip(attrs.client_address, 'authbl.mail.abusix.zone');
    }
    catch (err) {
        debug(`DNS lookup error: ${err?.message} (${err?.code})`);
    }

    if (result) {
        await perform_actions();
        return;
    }

    // Check recipient with authbl-rcpt
    try {
        result = await this.lookup_ip(attrs.recipient.toLowerCase(), 'authbl-rcpt.mail.abusix.zone');
    }
    catch (err) {
        debug(`DNS lookup error: ${err?.message} (${err?.code})`);
    }   

    if (result) {
        await perform_actions();
        return;
    }

    // If we get here, we didn't find anything, so tell Postfix to continue
    client.write('action=DUNNO\n\n', { encoding: 'ascii' });
}

// Main async block
(async () => {
    await redis.connect();
    debug(`redis client connected`);

    // Start server
    server.listen(cfg.listen_port || 9998, () => {
        debug(`opened server: ${JSON.stringify(server.address())}`);
        started = true;
    });

})().catch((e) => {
    console.error(`main caught error: ${e.message}`);
});
