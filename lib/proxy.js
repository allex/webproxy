/**
 * A web proxy server for web develop debugger localize forwordings.
 *
 * @author Allex Wang (allex.wxn@gmail.com)
 *
 * Extends:
 *  Auto responder local files for web develop.
 *  beautify js code if needed (require beautify module).
 *  Fix request 302 redirect problem. see also https://github.com/mikeal/request/
 */
(function(require, exports, module) {
'use strict';

var http = require('http')
  , https = require('https')
  , net = require('net')
  , fs = require('fs')
  , path = require('path')
  , url = require('url')
  , util = require('util')
  , colors = require('colors')
  , zlib = require('zlib')
  , mime = require('mime')
  , request = require('request')
  , WritableStreamBuffer = require('stream-buffers').WritableStreamBuffer
  , log = require('./logger')
  , utils = require('./utils')
  , escapeRegExp = utils.escapeRegExp
  , getClientIp = utils.getClientIp

  , blacklist = []
  , responder = []
  , hosts = {}

  , pkg = require('../package')
  , config = require('../config')

var INTERNAL_HTTPS_PORT = 8000

// internal log function
function logRequest(req, type, info) {
    var c = req.connection
    log.info(util.format('%s:%s '.white + '%s "%s %s"', getClientIp(req), c.remotePort, type, req.method, info || req.url))
}

// get file extension by url string
function getExtension(url) {
    var i = url.indexOf('?')
    if (i !== -1) {
        url = url.substring(0, i)
    }
    i = url.lastIndexOf('.')
    return (i < 0) ? '' : url.substr(i + 1)
}

function isGzip(res) {
    var headers = res.headers, contentEncoding = headers['content-encoding'] || headers['Content-Encoding']
    return contentEncoding === 'gzip'
}

function wildcardToRegex(str, flag) {
    return new RegExp('^' + escapeRegExp(str).replace(/\\\*/g, '.*').replace(/\\\?/g, '.')
            .replace(/\\\(\.\*\\\)/g, '(.*)') + '$', flag)
}

var rPattern = /\(([^)]*)\)/
function patternToRegex(str, flag) {
    var sb = [], m, offset = 0, token

    while (str) {
        if (m = str.match(rPattern)) {
            offset = m.index
            sb.push(escapeRegExp(str.slice(0, offset)))

            token = m[1]
            // fix the specific tokens.
            if (token.length === 1) {
                switch (token) {
                case '*':
                    token = '.*'
                    break
                case '?':
                    token = '.?'
                    break
                }
            }
            sb.push('(' + token + ')')
            str = str.slice(offset + m[0].length)
        } else {
            sb.push(escapeRegExp(str))
            str = ''
        }
    }
    str = sb.join('')

    return new RegExp(str, flag)
}

function beautify(source) {
    var unpack = require('unpack').unpack, js_beautify = require('beautify').js_beautify
    source = source.toString()
    return js_beautify(unpack(source))
}

function isLocalRequest(req) {
    return getClientIp(req) === '127.0.0.1'
}

// decode host and port info from header
function decode_host(host) {
    var out = {}
    host = host.split(':')
    out.host = host[0]
    out.port = host[1] || '80'
    return out
}
// encode host field
function encode_host(host) {
    return host.host + ((host.port == 80) ? '' : ':' + host.port)
}

// pac functions {{{
function dnsDomainIs(host, domain) {
    return (host.length >= domain.length &&
        host.substring(host.length - domain.length) === domain)
}
function isPlainHostName(host) {
    return (host.search('\\.') === -1)
}
function convert_addr(ipchars) {
    var bytes = ipchars.split('.')
    return ((bytes[0] & 0xff) << 24) |
        ((bytes[1] & 0xff) << 16) |
        ((bytes[2] & 0xff) <<  8) |
        (bytes[3] & 0xff)
}
function isInNet(ipaddr, pattern, maskstr) {
    var test = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ipaddr)
    if (test[1] > 255 || test[2] > 255 ||
        test[3] > 255 || test[4] > 255) {
        return false    // not an IP address
    }
    var host = convert_addr(ipaddr)
    var pat  = convert_addr(pattern)
    var mask = convert_addr(maskstr)
    return ((host & mask) == (pat & mask))
}
function localHostOrDomainIs(host, hostdom) {
    return (host == hostdom) || (hostdom.lastIndexOf(host + '.', 0) == 0)
}
function shExpMatch(text, exp) {
    exp = exp.replace(/\.|\*|\?/g, function (m) {
        if (m === '.') {
            return '\\.'
        } else if (m === '*') {
            return '.*?'
        } else if (m === '?') {
            return '.'
        }
    })
    return new RegExp(exp).test(text)
}
// }}}

function route_match(url) {
    var list = responder, l = list.length, item, src, dist, m
    while (l--) {
        if (item = list[l]) {
            src = item.src
            if (item.type === 'regex') { // replace with regex
                src.lastIndex = 0
                if (m = src.test(url)) {
                    dist = item.dist
                    dist = url.replace(src, dist)
                    // local file responder.
                    if (!item.redirect) {
                        dist = dist.replace(/[?#].*$/, '') // strip params from local file path.
                    }
                    item = utils.clone(item)
                    item.dist = dist
                    return item
                }
            }
            else {
                if (src === url) return utils.clone(item)
            }
        }
    }
    return null
}

// filtering rules
function host_allowed(host) {
    return !blacklist.some(function(k) { return k.test(host) })
}

// header decoding
function authenticate(request) {
    var token = {'login': 'anonymous', 'pass': ''}, basic, headers = request.headers
    if (headers.authorization && headers.authorization.search('Basic ') === 0) {
        // fetch login and password
        basic = (new Buffer(headers.authorization.split(' ')[1], 'base64').toString())
        log.info('Authentication token received: ' + basic)
        basic = basic.split(':')
        token.login = basic[0]
        token.pass = basic[1] // fixme: potential trouble if there is a ':' in the pass
    }
    return token
}

// proxying
// handle 2 rules:
//  * redirect (301)
//  * proxyto
function handle_proxy_rule(rule, target, token) {
    // handle authorization
    if ('validuser' in rule) {
        if (!(token.login in rule.validuser) || (rule.validuser[token.login] != token.pass)) {
            target.mode = 'AUTHENTICATE'
            target.msg = rule.description || ''
            return target
        }
    }
    // handle real actions
    if ('redirect' in rule) {
        target = decode_host(rule.redirect)
        target.mode = 'REDIRECT'
    }
    return target
}

function get_proxy_rule(host, url, token) {
    // extract target host and port
    var ret = {}, rule, mappings = hosts
    // dnsDomainIs or shExpMatch
    for (var k in mappings) {
        if (mappings.hasOwnProperty(k)) {
            var domain = k.split(':')[0]
            if (shExpMatch(url, k) || dnsDomainIs(host, domain)) {
                rule = mappings[k]
                break
            }
        }
    }
    var proxy = (rule || 0).proxy
    return {
        mode: proxy ? 'proxy' : '',
        conf: proxy || null
    }
}

function prevent_loop(request, response) {
    var headers = request.headers
    if (headers.proxy === 'allex.proxy') { // if request is already tooted => loop
        log.error('Loop detected')
        response.writeHead(500)
        response.write('Proxy loop !')
        response.end()
        return false
    } else {
        // append a tattoo to prevent dead proxies.
        headers.proxy = 'allex.proxy'
        return request
    }
}

function responseAuthenticate(response, msg) {
    response.writeHead(401, {
        'WWW-Authenticate': 'Basic realm="' + msg + '"'
    })
    response.end()
}

function responseDeny(response, msg) {
    log.error(msg)
    response.writeHead(403)
    response.write(msg)
    response.end()
}

function responseNotFound(response, msg) {
    log.error(msg)
    response.writeHead(404)
    response.write(
        '<h1>400 Page Not Found</h1>\n' +
        '<p>' + msg + '</p>'
    )
    response.end()
}

function responseRedirect(response, host) {
    log.info('Redirecting to ' + host)
    if (!/^https?:\/\//i.test(host)) {
        host = 'http://' + host
    }
    response.writeHead(301, {'Location': host})
    response.end()
}

function action_rewrite(conf, req, res) {
    var file = conf.dist, url = req.url

    // Forward remote url resources.
    if (file.indexOf('//') === 0 || /^https?:\/\//.test(file)) {
        var x = utils.request(file, res, req)
        x.on('error', function(err) {
            responseNotFound(res, err.message)
        })
        x.on('response', function(response) {
            if (config.nocache) {
                res.setHeader('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0')
            }
            forwardResponse(x, response, res)
        })
        req.on('end', function() { x.end() })
    } else {
        // responder with local files.
        fs.stat(file, function(err, stats) {
            if (!err) {
                var ext = getExtension(file) || getExtension(url)
                res.setHeader('Content-Type',  mime.lookup(ext))
                fs.readFile(file, function(err, data) {
                    var buffer = processBuffer(data, ext)
                    res.end(data, 'binary')
                })
            }
            else { responseNotFound(res, 'File "' + file + '" was not found.') }
        })
    }
}

function forwardResponse(request, sResponse, rResponse) {
    var headers =  sResponse.headers,
        legacyHTTP = request.httpVersionMajor === 1 && request.httpVersionMinor < 1 || request.httpVersionMajor < 1,
        contentType = headers['content-type'],
        ext = contentType && mime.extension(contentType) || getExtension(request.path) || ''

    // add the `X-Remote-Address` header ip
    headers['X-Remote-Address'] = request.socket.remoteAddress

    // simple forward for binary response.
    if (request.method == 'HEAD' || !ext || utils.isBinary(ext)) {
        rResponse.writeHead(sResponse.statusCode, utils.capitalizeHeaders(headers))
        sResponse.on('data', function(chunk) { rResponse.write(chunk, 'binary') })
        sResponse.on('end', function() { rResponse.end() })
    }
    else {
        var stream = new WritableStreamBuffer({initialSize: 100 * 1024})
        , gziped = isGzip(sResponse)
        , onEnd = function(buffer) {
            buffer = processBuffer(buffer, ext)
            if (buffer) {
                if (gziped) {
                    delete headers['content-encoding']
                }
                headers['content-length'] = buffer.length // cancel transfer encoding 'chunked'
            }
            rResponse.writeHead(sResponse.statusCode, utils.capitalizeHeaders(headers))
            rResponse.end(buffer, 'binary')
            stream.destroy()
            stream = null
            onEnd = null
        }
        sResponse.on('data', function(chunk) {
            stream.write(chunk)
        })
        sResponse.on('end', function() {
            var buffer = stream.getContents()
            if (gziped) {
                zlib.gunzip(buffer, function(err, buffer) { onEnd(buffer)}) // unGzip
            } else {
                onEnd(buffer)
            }
        })
    }
}

/**
 * Process buffer object.
 *
 * @param {Buffer} buffer The buffer to process.
 * @param {String} ext The file extension of the buffer content.
 */
function processBuffer(buffer, ext, encoding) {
    var str
    if (config.weinre) {
        str = buffer.toString(encoding || 'utf8').trim()
        if (ext === 'html' && str.charAt(0) !== '<') {
            ext = 'js'
        }
        if (ext === 'html') {
            str += '\n<script src="http://192.168.1.2:8080/target/target-script-min.js#anonymous"></script>'
        } else {
            if (ext === 'js') {
                str = utils.stripStrict(str)
            }
        }
    }
    if (config.beautify && ext === 'js') {
        str = beautify(str || buffer.toString())
    }
    return str ? new Buffer(str) : buffer
}

function responseProxy(response, request, proxy) {
    var sUrl = request.url, options = url.parse(sUrl), logMsg

    options.agent = false
    options.method = request.method
    options.headers = request.headers
    delete options.headers['proxy-connection']

    // optional set proxy server
    if (proxy) {
        options.proxy = proxy
        options.path = sUrl
        delete options.hostname
        logMsg = sUrl + ' by proxy ' + proxy
    }

    // log request info.
    logRequest(request, ('-->>')[proxy ? 'green' : 'white'], logMsg)

    var req = utils.request(options, request, response)
        // proxies to FORWARD answer to real client
        .on('response', function(_response) {
            forwardResponse(req, _response, response)
        })
        .on('error', function(err) {
            log.error('Requested resource (\"' + sUrl + '\") is not accessible on "' + (options.proxy || options.host + '"'))
        })

    // proxies to SEND request to real server
    request.on('data', function(chunk) { req.write(chunk, 'binary') })
    request.on('end', function() { req.end() })
}

// security filter
// true if OK
// false to return immediatlely
function isRequestValid(request) {
    // HTTP 1.1 protocol violation: no host, no method, no url
    if (request.headers.host === undefined || request.method === undefined || request.url === undefined) {
        var ip = request.connection.remoteAddress
        log.info('**SECURITY VIOLATION**, ' + ip + ',' + request.method || '' + ' ' + request.url || 'UNKNOW_URL')
        return false
    }
    return true
}

var httpServer, httpsServer

/**
 * Listen the CONNECTION method and forward the https request to internal https server
 */
function proxyHttps() {
  httpServer.on('connect', function(req, socket, upgradeHead) {
    var netClient = net.createConnection(INTERNAL_HTTPS_PORT)

    socket
      .on('data', function(chunk) { netClient.write(chunk) })
      .on('end', function() { netClient.end() })
      .on('close', function() { netClient.end() })
      .on('error', function(err) {
        log.error('socket error ' + err.message)
        netClient.end()
      })

    netClient
      .on('connect', function() {
        log.debug('connect to https server successfully!')
        socket.write( "HTTP/1.1 200 Connection established\r\nProxy-agent: Netscape-Proxy/1.1\r\n\r\n")
      })
      .on('data', function(chunk) { socket.write(chunk) })
      .on('end', function() { socket.end() })
      .on('close', function() { socket.end() })
      .on('error', function(err) {
        log.error('netClient error ' + err.message)
        socket.end()
      })
  })
}

// actual server loop
function server_cb(request, response) {
    // the *very* first action here is to handle security conditions
    // all related actions including logging are done by specialized functions
    // to ensure compartimentation
    if (!isRequestValid(request)) return

    var url = utils.normalizeUrl(request)

    // polyfill https url
    request.url = url

    if (!host_allowed(url)) {
        responseDeny(response, 'Host ' + url + ' has been denied by proxy configuration')
        return
    }

    response.setHeader('X-Proxied-By', pkg.name + '/' + pkg.version)

    var conf = route_match(url)
    if (conf) {
        // auto responder hosts.
        logRequest(request, 'rewrit'.magenta, url + ' -> ' + conf.dist)
        action_rewrite(conf, request, response)
    }
    else {
        // handle proxy actions.
        if (request = prevent_loop(request, response)) {
            var action = get_proxy_rule(request.headers.host, url, authenticate(request)),
                mode = action.mode

            if (!mode || mode === 'proxy') {
                responseProxy(response, request, action.conf)
            }
            else if (mode === 'REDIRECT') {
                responseRedirect(response, encode_host(action))
            }
            else if (mode === 'AUTHENTICATE') {
                responseAuthenticate(response, action.msg)
            }
        }
    }
}

function watchConfig(file, updater) {
    fs.stat(file, function(err, stats) {
        if (!err) {
            updater(file)
            fs.watchFile(file, function(c, p) { updater(file) })
        } else {
            log.debug('File \'' + file + '\' was not found.')
        }
    })
}

// config files loaders/updaters
function update_list(message, file, lineParser, resultHandler) {
    fs.stat(file, function(err, stats) {
        if (!err) {
            log.info(message)
            fs.readFile(file, function(err, data) {
                resultHandler(data.toString().split('\n').filter(function(line) {
                    return line.length && line.charAt(0) !== '#'
                }).map(lineParser))
            })
        } else {
            log.debug('File \'' + file + '\' was not found.')
            resultHandler([])
        }
    })
}

/**
 * Proxy entry
 * @param {Object} cfg The proxy configuration object.
 */
function proxy() {
    // initial config file watchers
    watchConfig(config.hosts, function(file) {
        fs.stat(file, function(err, stats) {
            if (!err) {
                log.info('=> hosts updated.')
                fs.readFile(file, function(err, data) {
                    hosts = JSON.parse(data.toString())
                })
            } else {
                log.debug('File \'' + file + '\' was not found.')
                hosts = {}
            }
        })
    })
    watchConfig(config.blacklist, function(file) {
        update_list('=> blacklist updated.', file, function(rx) {
            return RegExp(rx)
        }, function(list) { blacklist = list })
    })
    watchConfig(config.responder, function(file) {
        update_list('=> responder updated.', file, function(line) {
            var type, src, pairs, role, dist, pos = line.indexOf(':')
            if (pos !== -1) {
                type = line.substring(0, pos)
                line = line.substring(pos + 1)
                pairs = line.split(/\s\s*/)
                src = pairs[0]
                dist = pairs[1]
                if (type === 'regex') {
                    src = new RegExp(src, 'i')
                } else {
                    if (type === 'wildcard') {
                        type = 'regex'
                        src = patternToRegex(src, 'ig')
                    }
                }
                role = {type: type, src: src, dist: dist}
                if (/^https?:\/\//.test(dist)) {
                    role.redirect = true
                }
                return role
            }
            return {}
        },
        function(list) { responder = list })
    })

    var ip = config.listen.host, port = config.listen.port

    // create HTTP proxy server
    httpServer = http.createServer(function(req, res) {
        req.type = 'http'
        server_cb(req, res)
    }).listen(port, ip)

    var privateKeyFile = path.join(__dirname, '../etc/keys', 'server.key')
    var certificateFile = path.join(__dirname, '../etc/keys', 'server.crt')
    httpsServer = https.createServer({
        key: fs.readFileSync(privateKeyFile),
        cert: fs.readFileSync(certificateFile)
    }, function(req, res) {
        req.type = 'https'
        server_cb(req, res)
    }).listen(INTERNAL_HTTPS_PORT)

    proxyHttps()

    // set process title.
    process.title = pkg.name + '-v' + pkg.version
    process.on('uncaughtException', function (err) { log.error(err) })
    process.on('SIGINT', function() { process.exit(); })

    log.info('HTTP proxy server started' + ' on ' + (ip + ':' + port).underline.yellow)
}

// Exports
module.exports = proxy

})(require, exports, module)
/* vim: set tw=85 sw=4: */
