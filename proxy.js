/* vim: set tw=85 sw=4: */

/**
 * A simple proxy server written in node.js, Auto responder local files for web develop)
 * @author Allex (allex.wxn@gmail.com)
 */

var http     = require('http'),
    util     = require('util'),
    fs       = require('fs'),
    url      = require('url'),
    colors   = require('colors'),
    argv     = require('optimist').argv,
    zlib     = require('zlib'),
    unpack   = require('unpack').unpack,
    beautify = require('beautify'),
    mime     = require('mime'),
    request  = require('request'),

    blacklist       = [],
    iplist          = [],
    hostfilters     = {},
    responderlist   = [],

    BufferHelper    = require('./bufferhelper'),
    config          = require('./config').config
;

var DEBUG = argv.debug || argv.d;

function log(s) { util.log(s); }

// removing c-styled comments using javascript
function removeComments(str) {
    // Remove all C-style slash comments
    str = str.replace(/(?:^|[^\\])\/\/.*$/gm, '');
    // Remove all C-style star comments
    str = str.replace(/\/\*[\s\S]*?\*\//gm, '');
    return str;
}

function getExt(path) {
    var i = path.indexOf('?');
    if (i !== -1) {
        path = path.substring(0, i);
    }
    i = path.lastIndexOf('.');
    return (i < 0) ? '' : path.substr(i + 1);
}

var rEscRegExp = /([-.*+?^${}()|[\]\/\\])/g;
function escapeRegExp(s) {
    return String(s).replace(rEscRegExp, '\\$1');
}

function wildcardToRegex(pattern, flag) {
    return new RegExp('^' + escapeRegExp(pattern).replace(/\\\*/g, '.*').replace(/\\\?/g, '.')
            .replace(/\\\(\.\*\\\)/g, '(.*)') + '$', flag);
}

function clone(o) {
    return JSON.parse(JSON.stringify(o));
}

function js_beautify(source) {
    return beautify.js_beautify(unpack(source));
}

// decode host and port info from header
function decode_host(host) {
    var out = {};
    host = host.split(':');
    out.host = host[0];
    out.port = host[1] || 80;
    return out;
}
// encode host field
function encode_host(host) {
    return host.host + ((host.port == 80) ? '' : ':' + host.port);
}

/** PAC helper functions {{{ */

function dnsDomainIs(host, domain) {
    return (host.length >= domain.length && host.substring(host.length - domain.length) == domain);
}

function isPlainHostName(host) {
    return (host.search('\\.') == -1);
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
    return new RegExp('^' + pattern + '$').test(url);
}

/** PAC helper functions (end) }}} */

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
            if (DEBUG) {
                log('File \'' + file + '\' was not found.');
            }
            resultHandler([]);
        }
    });
}
function update_hostfilters() {
    file = config.host_filters;
    fs.stat(file, function(err, stats) {
        if (!err) {
            util.log('Updating host filter');
            fs.readFile(file, function(err, data) {
                hostfilters = JSON.parse(removeComments(data.toString()));
            });
        } else {
            DEBUG && log('File \'' + file + '\' was not found.');
            hostfilters = {};
        }
    });
}
function update_blacklist() {
    update_list('Updating host black list.', config.black_list, function(rx) {
        return RegExp(rx);
    }, function(list) { blacklist = list; });
}
function update_iplist() {
    update_list('Updating allowed ip list.', config.allow_ip_list, function(ip) {
        return ip;
    }, function(list) { iplist = list; });
}
function update_responderlist() {
    update_list('Updating host routers.', config.responder_list, function(line) {
        var type, src, pairs, role, pos = line.indexOf(':');
        if (pos !== -1) {
            type = line.substring(0, pos);
            line = line.substring(pos + 1);
            pairs = line.split(' ');
            src = pairs[0];
            dist = pairs[1];
            if (type === 'regex') {
                src = new RegExp(src, 'i');
            } else {
                if (type === 'wildcard') {
                    type = 'regex';
                    src = wildcardToRegex(src, 'ig');
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
    function(list) {
        responderlist = list;
    });
}

function route_match(url) {
    var list = responderlist, l = list.length, item, src, dist, m;

    while (l--) {
        if (item = list[l]) {
            src = item.src;

            // replace with regex
            if (item.type === 'regex') {
                src.lastIndex = 0;
                if (m = src.test(url)) {
                    dist = item.dist;
                    dist = url.replace(src, dist);

                    // local file responder.
                    if (!item.redirect) {
                        // strip params from local file path.
                        dist = dist.replace(/[?#].*$/, '');
                    }

                    item = clone(item);
                    item.dist = dist;
                    return item;
                }
            } else {
                if (src === url) {
                    return clone(item);
                }
            }
        }
    }

    return null;
}

// filtering rules
function ip_allowed(ip) {
    return iplist.some(function(ip_) {
        return ip === ip_;
    }) || iplist.length < 1;
}

function host_allowed(host) {
    return !blacklist.some(function(host_) {
        return host_.test(host);
    });
}

// header decoding
function authenticate(request) {
    var token = {'login': 'anonymous', 'pass': ''};
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

function handle_proxy_route(host, url, token) {
    // extract target host and port
    var action = decode_host(host), key, rule, mappings = hostfilters;

    action.action = 'proxyto';

    // rule of the form "foo.domain.tld:port"
    key = action.host + ':' + action.port;
    if (key in mappings) {
        rule = mappings[key];
    } else {

        // rule of the form "foo.domain.tld"
        if (action.host in mappings) {
            rule = mappings[action.host];
        }

        // rule of the form "*:port"
        key = '*:' + action.port;
        if (key in mappings) {
            rule = mappings[key];
        }

        // default rule "*"
        key = '*';
        if (key in mappings) {
            rule = mappings[key];
        }

        // dnsDomainIs or shExpMatch
        for (key in mappings) {
            if (mappings.hasOwnProperty(key)) {
                if (dnsDomainIs(host, key.split(':')[0]) || shExpMatch(url, key.split(':')[0])) {
                    rule = mappings[key];
                    break;
                }
            }
        }
    }

    if (rule) {
        action = handle_proxy_rule(rule, action, token);
    }

    return action;
}

function prevent_loop(request, response) {
    if (request.headers.proxy === 'node.jtlebi') { // if request is already tooted => loop
        log('Loop detected');
        response.writeHead(500);
        response.write('Proxy loop !');
        response.end();
        return false;
    } else { // append a tattoo to it
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
    response.writeHead(403);
    response.write(msg);
    response.end();
}

function action_notfound(response, msg) {
    response.writeHead(404);
    response.write(msg);
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

function action_responder(config, req, res) {
    var file = config.dist, url = req.url, contentType = mime.lookup(getExt(url) || getExt(file));

    if (contentType) {
        res.setHeader('Content-Type',  contentType);
    }

    if (!config.redirect) {
        // responder with local files.
        fs.stat(file, function(err, stats) {
            if (!err) {
                fs.readFile(file, function(err, data) {
                    log('Respond ' + url + ' ==> ' + file);
                    res.write(data, 'utf8');
                    res.end();
                });
            } else {
                var msg = 'File \'' + file + '\' was not found.';
                log(msg);
                action_notfound(res, msg);
            }
        });
    } else {
        // responder with remote redirect url.
        request(file, function(err, response, body) {
            if (!err && response.statusCode === 200) {
                log('Respond ' + url + ' ==> ' + file);
                res.write(body, 'utf8');
                res.end();
            } else {
                log(err);
                action_notfound(res, err);
            }
        });
    }
}

function action_proxy(response, request, host, port) {// {{{
    var path = request.url, options = url.parse(path);

    options.method = request.method;
    options.headers = request.headers;
    options.agent = false;

    // optional set proxy server
    if (options.hostname !== host) {
        options.host = host;
        options.port = port;
        options.path = path;
    }

    // launch new request
    // http://nodejs.org/api/http.html#http_http_request_options_callback
    var proxy_request = http.request(options);

    // deal with errors, timeout, con refused, ...
    proxy_request.on('error', function(err) {
        log(err.toString() + ' on request to ' + host + ':' + port);
        return action_notfound(response, 'Requested resource (' + path + ') is not accessible on host "' + host + ':' + port + '"');
    });

    // detect HTTP version
    var legacy_http = request.httpVersionMajor == 1 && request.httpVersionMinor < 1 || request.httpVersionMajor < 1;

    // proxies to FORWARD answer to real client
    proxy_request.on('response', function(proxy_response) {
        var buffer, filetype = getExt(path), headers = proxy_response.headers;

        if (legacy_http && headers['transfer-encoding'] != undefined) {
            log('legacy HTTP: ' + request.httpVersion);

            buffer = new BufferHelper();

            // filter headers
            delete headers['transfer-encoding'];

            // buffer answer
            proxy_response.on('data', function(chunk) {
                buffer.concat(chunk);
            });
            proxy_response.on('end', function() {
                headers['Content-length'] = buffer.length; // cancel transfer encoding 'chunked'
                response.writeHead(proxy_response.statusCode, headers);
                response.end(buffer, 'binary');
            });

        } else {
            var rewrite = /^js$/i.test(filetype), decodeEnabled = headers['content-encoding'] === 'gzip';
            if (rewrite) {
                delete headers['content-encoding'];
                delete headers['content-length'];

                // buffer connector
                buffer = new BufferHelper();
            }

            // send headers as received
            response.writeHead(proxy_response.statusCode, proxy_response.headers);

            proxy_response.on('data', function(chunk) {
                if (rewrite) {
                    buffer.concat(chunk);
                } else {
                    // simple data forward
                    response.write(chunk, 'binary');
                }
            });
            proxy_response.on('end', function() {
                if (rewrite) {
                    if (decodeEnabled) {
                        buffer = buffer.toBuffer();
                        zlib.gunzip(buffer, function(err, buffer) {
                            response.end(js_beautify(buffer.toString()));
                        });
                    } else {
                        var s = js_beautify(buffer.toString());
                        response.end(s);
                    }
                    buffer = null;
                } else {
                    response.end();
                }
            });
        }
    });

    // proxies to SEND request to real server
    request.on('data', function(chunk) {
        proxy_request.write(chunk, 'binary');
    });

    request.on('end', function() {
        proxy_request.end();
    });

}// }}}

// special security logging function
function security_log(request, response, msg) {
    var ip = request.connection.remoteAddress;
    msg = '**SECURITY VIOLATION**, ' + ip + ',' + request.method || '' + ' ' + request.url || '' + ',' + msg;
    log(msg);
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

    var ip = request.connection.remoteAddress;
    if (!ip_allowed(ip)) {
        msg = 'IP ' + ip + ' is not allowed to use this proxy';
        action_deny(response, msg);
        log(msg);
        return;
    }

    var url = request.url;

    if (!host_allowed(url)) {
        msg = 'Host ' + url + ' has been denied by proxy configuration';
        action_deny(response, msg);
        log(msg);
        return;
    }

    // Check auto responder hosts.
    var resConfig = route_match(url);

    // handle responder.
    if (resConfig) {
        action_responder(resConfig, request, response);
        return;
    }

    // loop filter
    request = prevent_loop(request, response);
    if (!request) {
        return;
    }

    // get authorization token
    authorization = authenticate(request);

    // calc new host info
    var action = handle_proxy_route(request.headers.host, url, authorization);
    var host = encode_host(action);
    var mode = action.action;

    log(ip + ': ' + '[' + mode.charAt(0).toUpperCase() + '] ' + request.method + ' ' + url );

    // handle action
    if (mode == 'redirect') {
        action_redirect(response, host);
    }
    else if (mode == 'proxyto') {
        action_proxy(response, request, action.host, action.port);
    }
    else if (mode == 'authenticate') {
        action_authenticate(response, action.msg);
    }
}

if (!DEBUG) {
    // last chance error handler
    // it catch the exception preventing the application from crashing.
    // I recommend to comment it in a development environment as it
    // "Hides" very interesting bits of debugging informations.
    process.on('uncaughtException', function (err) {
        util.puts('Unexcpted Error: '.red + err);
    });
}

// config files watchers
fs.watchFile(config.black_list, function(c, p) { update_blacklist(); });
fs.watchFile(config.allow_ip_list, function(c, p) { update_iplist(); });
fs.watchFile(config.host_filters, function(c, p) { update_hostfilters(); });
fs.watchFile(config.responder_list, function(c, p) { update_responderlist(); });

// startup
update_blacklist();
update_iplist();
update_hostfilters();
update_responderlist();

// Crete HTTP proxy server
var cfg = config.listen.http;
http.createServer(server_cb).listen(cfg.port, cfg.host);
util.puts('HTTP proxy server' + ' started'.green.bold + ' on ' + (cfg.host + ':' + cfg.port).underline.yellow);
