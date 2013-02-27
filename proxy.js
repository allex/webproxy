/**
 * A simple proxy server written in node.js for web develop primary on mobile web
 * development.
 *
 * @author Allex (allex.wxn@gmail.com)
 *
 * Extends:
 *  Auto responder local files for web develop.
 *  beautify js code if needed (require beautify module).
 *  Fix request 302 redirect problem. see also https://github.com/mikeal/request/
 */

'use strict';

(function(require, exports, module) {

var http     = require('http'),
    util     = require('util'),
    fs       = require('fs'),
    url      = require('url'),
    colors   = require('colors'),
    zlib     = require('zlib'),
    mime     = require('mime'),
    request  = require('request'),

    WritableBufferStream = require('buffertools').WritableBufferStream,

    blacklist     = [],
    iplist        = [],
    responderlist = [],
    hostfilters   = {}
;

function log(s) { util.log(s); }
function error(e) { util.puts((e && e.message || e || 'undefined').red); }
function dump(s) { util.puts(JSON.stringify(s).green); }

// removing c-styled comments using javascript
function removeComments(str) {
    // Remove all C-style slash comments
    str = str.replace(/(?:^|[^\\])\/\/.*$/gm, '');
    // Remove all C-style star comments
    str = str.replace(/\/\*[\s\S]*?\*\//gm, '');
    return str;
}

// get file extension by url string
function getExtension(url) {
    var i = url.indexOf('?');
    if (i !== -1) {
        url = url.substring(0, i);
    }
    i = url.lastIndexOf('.');
    return (i < 0) ? '' : url.substr(i + 1);
}

var rPlainExt = /^(html|js|css|txt|json)$/;
function isBinary(ext) {
    return !rPlainExt.test(ext);
}

function isGzip(response) {
    return response.headers['content-encoding'] === 'gzip';
}

var rPattern = /\(([^)]*)\)/;
var rEscRegExp = /([-.*+?^${}()|[\]\/\\])/g;

function escapeRegExp(s) {
    return String(s).replace(rEscRegExp, '\\$1');
}
function wildcardToRegex(str, flag) {
    return new RegExp('^' + escapeRegExp(str).replace(/\\\*/g, '.*').replace(/\\\?/g, '.')
            .replace(/\\\(\.\*\\\)/g, '(.*)') + '$', flag);
}
function patternToRegex(str, flag) {
    var sb = [], m, offset = 0, token;

    while (str) {
        if (m = str.match(rPattern)) {
            offset = m.index;
            sb.push(escapeRegExp(str.slice(0, offset)));

            token = m[1];
            // fix the specific tokens.
            if (token.length === 1) {
                switch (token) {
                case '*':
                    token = '.*';
                    break;
                case '?':
                    token = '.?';
                    break;
                }
            }
            sb.push('(' + token + ')');
            str = str.slice(offset + m[0].length);
        } else {
            sb.push(escapeRegExp(str));
            str = '';
        }
    }
    str = sb.join('');

    return new RegExp(str, flag);
}

var hasOwn = Object.prototype.hasOwnProperty;
function hasProp(obj, prop) {
    return hasOwn.call(obj, prop);
}

function getOwn(obj, prop) {
    return hasProp(obj, prop) && obj[prop];
}

function clone(o) {
    var newObj = Array.isArray(o) ? [] : {};
    for (var i in o) {
        if (o[i] && typeof o[i] === 'object') {
            newObj[i] = clone(o[i]);
        } else newObj[i] = o[i];
    }
    return newObj;
}

function extract(source, whitelist) {
    var o = {};
    whitelist.forEach(function(prop, i) {
        var k = prop[0], v = source[k];
        o[k] = v === undefined ? prop[1] : v;
    });
    return o;
}

function beautify(source) {
    var unpack = require('unpack').unpack, js_beautify = require('beautify').js_beautify;
    source = source.toString();
    return js_beautify(unpack(source));
}

var RE_STRICT = /\s*(['"])use strict\1;/g;

// strip "use strict";
function stripStrict(source) {
    return source.replace(RE_STRICT, '');
}

function isLocalRequest(req) {
    return req.connection.remoteAddress === '127.0.0.1';
}

// decode host and port info from header
function decode_host(host) {
    var out = {};
    host = host.split(':');
    out.host = host[0];
    out.port = host[1] || '80';
    return out;
}
// encode host field
function encode_host(host) {
    return host.host + ((host.port == 80) ? '' : ':' + host.port);
}

// pac functions {{{
function dnsDomainIs(host, domain) {
    return (host.length >= domain.length && host.substring(host.length - domain.length) === domain);
}
function isPlainHostName(host) {
    return (host.search('\\.') === -1);
}
function convert_addr(ipchars) {
    var bytes = ipchars.split('.');
    return ((bytes[0] & 0xff) << 24) |
        ((bytes[1] & 0xff) << 16) |
        ((bytes[2] & 0xff) <<  8) |
        (bytes[3] & 0xff);
}
function isInNet(ipaddr, pattern, maskstr) {
    var test = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ipaddr);
    if (test[1] > 255 || test[2] > 255 ||
        test[3] > 255 || test[4] > 255) {
        return false;    // not an IP address
    }
    var host = convert_addr(ipaddr);
    var pat  = convert_addr(pattern);
    var mask = convert_addr(maskstr);
    return ((host & mask) == (pat & mask));
}
function localHostOrDomainIs(host, hostdom) {
    return (host == hostdom) || (hostdom.lastIndexOf(host + '.', 0) == 0);
}
function shExpMatch(url, pattern) {
    pattern = pattern.replace(/\./g, '\\.');
    pattern = pattern.replace(/\*/g, '.*');
    pattern = pattern.replace(/\?/g, '.');
    var regexp = new RegExp('^' + pattern + '$');
    return regexp.test(url);
}
// }}}

function route_match(url) {
    var list = responderlist, l = list.length, item, src, dist, m;
    while (l--) {
        if (item = list[l]) {
            src = item.src;
            if (item.type === 'regex') { // replace with regex
                src.lastIndex = 0;
                if (m = src.test(url)) {
                    dist = item.dist;
                    dist = url.replace(src, dist);
                    // local file responder.
                    if (!item.redirect) {
                        dist = dist.replace(/[?#].*$/, ''); // strip params from local file path.
                    }
                    item = clone(item);
                    item.dist = dist;
                    return item;
                }
            }
            else {
                if (src === url) return clone(item);
            }
        }
    }
    return null;
}

// filtering rules
function ip_allowed(ip) {
    return !iplist.length || iplist.some(function(k) { return ip === k; });
}
function host_allowed(host) {
    return !blacklist.some(function(k) { return k.test(host); });
}

// header decoding
function authenticate(request) {
    var token = {'login': 'anonymous', 'pass': ''}, basic;
    if (request.headers.authorization && request.headers.authorization.search('Basic ') === 0) {
        // fetch login and password
        basic = (new Buffer(request.headers.authorization.split(' ')[1], 'base64').toString());
        log('Authentication token received: ' + basic);
        basic = basic.split(':');
        token.login = basic[0];
        token.pass = basic[1]; // fixme: potential trouble if there is a ':' in the pass
    }
    return token;
}

// proxying
// handle 2 rules:
//  * redirect (301)
//  * proxyto
function handle_proxy_rule(rule, target, token) {
    // handle authorization
    if ('validuser' in rule) {
        if (!(token.login in rule.validuser) || (rule.validuser[token.login] != token.pass)) {
            target.action = 'authenticate';
            target.msg = rule.description || '';
            return target;
        }
    }

    // handle real actions
    if ('redirect' in rule) {
        target = decode_host(rule.redirect);
        target.action = 'redirect';
    } else {
        if ('proxyto' in rule) {
            target = decode_host(rule.proxyto);
            target.action = 'proxyto';
        }
    }

    return target;
}

function findRoute(types) {
    for (var mappings = hostfilters, i = -1, l = types.length, v; ++i < l; ) {
        v = getOwn(mappings, types[i]);
        if (v) return v;
    }
    return null;
}

function handle_proxy_route(host, url, token) {
    // extract target host and port
    var conf = decode_host(host),
        domain = conf.host,
        port = conf.port,
        rule,
        mappings = hostfilters;

    // dnsDomainIs or shExpMatch
    for (var key in mappings) {
        if (hasProp(mappings, key)) {
            var hostname = key.split(':')[0];
            if (dnsDomainIs(host, hostname) || shExpMatch(url, key)) {
                rule = mappings[key];
                break;
            }
        }
    }

    if (!rule) {
        rule = findRoute([host, domain, '*:' + port, '*']);
    }

    conf.action = 'proxyto';
    if (rule) {
        conf = handle_proxy_rule(rule, conf, token);
    }

    return conf;
}

function prevent_loop(request, response) {
    if (request.headers.proxy === 'node.jtlebi') { // if request is already tooted => loop
        error('Loop detected');
        response.writeHead(500);
        response.write('Proxy loop !');
        response.end();
        return false;
    } else {
        // append a tattoo to prevent dead proxies.
        request.headers.proxy = 'node.jtlebi';
        return request;
    }
}

function action_authenticate(response, msg) {
    response.writeHead(401, {
        'WWW-Authenticate': 'Basic realm="' + msg + '"'
    });
    response.end();
}

function action_deny(response, msg) {
    error(msg);
    response.writeHead(403);
    response.write(msg);
    response.end();
}

function action_notfound(response, msg) {
    error(msg);
    response.writeHead(404);
    response.write(
        '<h1>400 Page Not Found</h1>\n' +
        '<p>' + msg + '</p>'
    );
    response.end();
}

function action_redirect(response, host) {
    log('Redirecting to ' + host);
    if (!/^https?:\/\//i.test(host)) {
        host = 'http://' + host;
    }
    response.writeHead(301, {'Location': host});
    response.end();
}

function action_responder(config, req, resp) {
    var file = config.dist, url = req.url;
    if (!config.redirect) {
        // responder with local files.
        fs.stat(file, function(err, stats) {
            if (!err) {
                var extension = getExtension(file) || getExtension(url);
                resp.setHeader('Content-Type',  mime.lookup(extension));
                fs.readFile(file, function(err, data) {
                    var buffer = processBuffer(data, extension);
                    resp.end(data, 'binary');
                });
            } else { action_notfound(resp, 'File "' + file + '" was not found.'); }
        });
    }
    else {
        // responder with remote redirect url.
        var x = get(file, resp, req);
        x.on('error', function(err) {
            action_notfound(resp, err.message);
        });
        req.on('end', function() { x.end(); });
    }
}

/**
 * @param {Object} options The options info, include proxy properties if manally.
 * @param {Respond} response
 * @param {Request} request
 */
function get(uri, resp, req) {
    var req = request(uri);
    req.on('response', function(response) {
        if (argv.nocache) {
            resp.setHeader('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
        }
        forwardResponse(req.req, response, resp);
    });
    return req;
}

function sendRequest(options, request, response) {
    delete options.headers['proxy-connection'];

    // launch new request
    // http://nodejs.org/api/http.html#http_http_request_options_callback
    var req = http.request(options);

    // proxies to SEND request to real server
    request.on('data', function(chunk) { req.write(chunk, 'binary'); });
    request.on('end', function() { req.end(); });

    // proxies to FORWARD answer to real client
    req.on('response', function(resp) {
        forwardResponse(req, resp, response);
    });

    return req;
}

function forwardResponse(request, sResponse, rResponse) {
    var headers = sResponse.headers,
        legacyHTTP = request.httpVersionMajor === 1 && request.httpVersionMinor < 1 || request.httpVersionMajor < 1,
        extension = mime.extension(headers['content-type']) || getExtension(request.path);

    // simple forward for binary response.
    if (isBinary(extension)) {
        rResponse.writeHead(sResponse.statusCode, headers);
        sResponse.on('data', function(chunk) { rResponse.write(chunk, 'binary'); });
        sResponse.on('end', function() { rResponse.end(); });
    }
    else {
        var stream = new WritableBufferStream(),
            gziped = isGzip(sResponse),
            onEnd = function(buffer) {
                buffer = processBuffer(buffer, extension);
                if (gziped) {
                    delete headers['content-encoding'];
                }
                headers['content-length'] = buffer.length; // cancel transfer encoding 'chunked'
                rResponse.writeHead(sResponse.statusCode, headers);
                rResponse.end(buffer, 'binary');
            };

        sResponse.on('data', function(chunk) {
            stream.write(chunk);
        });
        sResponse.on('end', function() {
            var buffer = stream.getBuffer();
            if (gziped) {
                // unGzip
                zlib.gunzip(buffer, function(err, buffer) {
                    onEnd(buffer);
                });
            } else {
                onEnd(buffer);
            }
        });
    }
}

/**
 * Process buffer object.
 *
 * @param {Buffer} buffer The buffer to process.
 * @param {String} extension The file extension of the buffer content.
 */
function processBuffer(buffer, extension, encoding) {
    var str;
    if (argv.weinre) {
        str = buffer.toString(encoding || 'utf8').trim();
        if (extension === 'html' && str.charAt(0) !== '<') {
            extension = 'js';
        }
        if (extension === 'html') {
            str += '\n<script src="http://192.168.0.2:8080/target/target-script-min.js#anonymous"></script>';
        } else {
            if (extension === 'js') {
                str = stripStrict(str);
            }
        }
    }
    if (argv.beautify && extension === 'js') {
        str = beautify(str || buffer.toString());
    }
    return str ? new Buffer(str) : buffer;
}

function action_proxy(response, request, host, port) {
    var reqUrl = request.url, options = url.parse(reqUrl);

    options.method = request.method;
    options.headers = request.headers;
    options.agent = false;

    // optional set proxy server
    var proxy = options.hostname !== host;
    if (proxy) {
        log('Proxy: ' + 'http://' + host + ':' + port);
        options.host = host;
        options.port = port;
        options.path = reqUrl;
        delete options.hostname;
    }

    var x = sendRequest(options, request, response);
    // deal with errors, timeout, con refused, ...
    x.on('error', function(err) {
        action_notfound(response, 'Requested resource (' + reqUrl + ') is not accessible on host "' + host + ':' + port + '"');
    });
}

// special security logging function
function security_log(request, response, msg) {
    var ip = request.connection.remoteAddress;
    log('**SECURITY VIOLATION**, ' + ip + ',' + request.method || '' + ' ' + request.url || '' + ',' + msg);
}

// security filter
// true if OK
// false to return immediatlely
function security_filter(request, response) {
    // HTTP 1.1 protocol violation: no host, no method, no url
    if (request.headers.host === undefined || request.method === undefined || request.url === undefined) {
        security_log(request, response, 'Either host, method or url is poorly defined');
        return false;
    }
    return true;
}

// actual server loop
function server_cb(request, response) {
    // the *very* first action here is to handle security conditions
    // all related actions including logging are done by specialized functions
    // to ensure compartimentation
    if (!security_filter(request, response)) return;

    var ip = request.connection.remoteAddress, msg;
    if (!ip_allowed(ip)) {
        action_deny(response, 'IP ' + ip + ' is not allowed to use this proxy');
        return;
    }

    var url = request.url;
    if (!host_allowed(url)) {
        action_deny(response, 'Host ' + url + ' has been denied by proxy configuration');
        return;
    }

    var conf = route_match(url);
    if (conf) {
        // auto responder hosts.
        stdout(request, 'Location', url + ' -> ' + conf.dist);
        action_responder(conf, request, response);
    }
    else {
        // handle proxy action
        request = prevent_loop(request, response);
        if (request) {
            var action = handle_proxy_route(request.headers.host, authenticate(request)), mode = action.action;
            stdout(request, mode);
            if (mode == 'proxyto') {
                action_proxy(response, request, action.host, action.port);
            }
            else if (mode == 'redirect') {
                action_redirect(response, encode_host(action));
            }
            else if (mode == 'authenticate') {
                action_authenticate(response, action.msg);
            }
        }
    }
}

var G_COLORS = {
    'L': 'magenta', // location
    'R': 'red',     // redirect
    'P': 'green',   // proxy
    'A': 'white'    // authenticate
};
// console log message to stdout
function stdout(request, type, message) {
    var ip = request.connection.remoteAddress, method = request.method, type = type.charAt(0).toUpperCase();
    type = G_COLORS[type] ? ('[' + type + ']')[G_COLORS[type]] : '[' + type + ']';
    log([ip.cyan, type, method, (message || request.url)].join(' '));
}

/**
 * @param {Object} cfg The proxy configuration object.
 */
function startup(options) {
    function watchConfig(file, updater) {
        fs.stat(file, function(err, stats) {
            if (!err) {
                updater(file);
                fs.watchFile(file, function(c, p) { updater(file) });
            } else {
                DEBUG && error('File \'' + file + '\' was not found.');
            }
        });
    }
    // config files loaders/updaters
    function update_list(msg, file, lineParser, resultHandler) {
        fs.stat(file, function(err, stats) {
            if (!err) {
                log(msg);
                fs.readFile(file, function(err, data) {
                    resultHandler(data.toString().split('\n').filter(function(line) {
                        return line.length && line.charAt(0) !== '#';
                    }).map(lineParser));
                });
            } else {
                DEBUG && error('File \'' + file + '\' was not found.');
                resultHandler([]);
            }
        });
    }

    // Initial config file watchers
    watchConfig(options.host_filters, function(file) {
        fs.stat(file, function(err, stats) {
            if (!err) {
                log('Updating host filter');
                fs.readFile(file, function(err, data) {
                    hostfilters = JSON.parse(removeComments(data.toString()));
                });
            } else {
                DEBUG && error('File \'' + file + '\' was not found.');
                hostfilters = {};
            }
        });
    });
    watchConfig(options.black_list, function(file) {
        update_list('Updating host black list.', file, function(rx) {
            return RegExp(rx);
        }, function(list) { blacklist = list; });
    });
    watchConfig(options.allow_ip_list, function(file) {
        update_list('Updating allowed ip list.', file, function(ip) {
            return ip;
        }, function(list) { iplist = list; });
    });
    watchConfig(options.responder_list, function(file) {
        update_list('Updating host routers.', file, function(line) {
            var type, src, pairs, role, dist, pos = line.indexOf(':');
            if (pos !== -1) {
                type = line.substring(0, pos);
                line = line.substring(pos + 1);
                pairs = line.split(/\s\s*/);
                src = pairs[0];
                dist = pairs[1];
                if (type === 'regex') {
                    src = new RegExp(src, 'i');
                } else {
                    if (type === 'wildcard') {
                        type = 'regex';
                        src = patternToRegex(src, 'ig');
                    }
                }
                role = {type: type, src: src, dist: dist};
                if (/^https?:\/\//.test(dist)) {
                    role.redirect = true;
                }
                return role;
            }
            return {};
        },
        function(list) { responderlist = list; });
    });

    // Crete HTTP proxy server
    var p = options.listen.http;
    http.createServer(server_cb).listen(p.port, p.host);

    console.log('HTTP proxy server started' + ' on ' + (p.host + ':' + p.port).underline.yellow);
}

var argv = extract(require('optimist').argv, [
    ['debug'   , 0],
    ['weinre'  , 0],
    ['beautify', 0],
    ['nocache' , 0]
]);

var DEBUG = argv.debug;

console.log('OPTIONS:'.green, argv);

// last chance error handler
// it catch the exception preventing the application from crashing.
// I recommend to comment it in a development environment as it
// "Hides" very interesting bits of debugging informations.
process.on('uncaughtException', function (err) {
    if (DEBUG) throw err;
    else error('Unexcpted Error: ' + err);
});

// startup proxy server
startup(require('./config'));

})(require, exports, module);
/* vim: set tw=85 sw=4: */
