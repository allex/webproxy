/**
 * Some usefull utilities.
 *
 * @author Allex Wang (allex.wxn@gmail.com)
 */

var url = require('url')
  , http = require('http')
  , https = require('https')
  , lang = require('lang-ext')
  , forEach = lang.forEach

/**
* Parse url with valid format especially in https cases
* in which, req.url doesn't include protocol and host
*
* @param {Object} req
*/
exports.normalizeUrl = function(req) {
    var hostArr = req.headers.host.split(':')
    var hostname = hostArr[0]
    var port = hostArr[1]
    var parsedUrl = url.parse(req.url, true)
    if (!parsedUrl.protocol) {
        parsedUrl.protocol = req.type + ':'
    }
    if (!parsedUrl.hostname) {
        parsedUrl.hostname = hostname
    }
    if (parsedUrl.port === undefined && port !== undefined) {
        parsedUrl.port = port
    }
    return url.format(parsedUrl)
}

// removing c-styled comments using javascript
exports.removeComments = function(str) {
    // Remove all C-style slash comments
    str = str.replace(/(?:^|[^\\])\/\/.*$/gm, '')
    // Remove all C-style star comments
    str = str.replace(/\/\*[\s\S]*?\*\//gm, '')
    return str
}

var RE_STRICT = /\s*(['"])use strict\1;/g
// strip "use strict"
exports.stripStrict = function(s) {
    return s.replace(RE_STRICT, '')
}

var rEscRegExp = /([-.*+?^${}()|[\]\/\\])/g
exports.escapeRegExp = function(s) {
    return String(s).replace(rEscRegExp, '\\$1')
}

var rPlainExt = /^(html|js|css|txt|json)$/
exports.isBinary = function(ext) {
    return !rPlainExt.test(ext)
}

// deepth clone
exports.clone = function clone(o) {
    var newObj = Array.isArray(o) ? [] : {}
    for (var i in o) {
        if (o[i] && typeof o[i] === 'object') {
            newObj[i] = clone(o[i])
        } else newObj[i] = o[i]
    }
    return newObj
}

exports.getClientIp = function(req) {
    var headers = req.headers
    return (headers && (headers['X-Forwarded-For'] ||
            headers['x-forwarded-for'] || '').split(',')[0]) || req.client.remoteAddress
}

var rWord = /\b[a-z]/g
exports.capitalizeHeaders = function(headers) {
    // Fix header lowercase issues https://github.com/joyent/node/issues/1954
    forEach(headers, function(v, k) {
        delete headers[k]
        k = k.replace(rWord, function($0) { return $0.toUpperCase(); })
        v && (headers[k] = v)
    })
    return headers
}

var RE_PROXY = /([^:]+):\/\/([^:]+):([\d]+)/
var matchProxy = function(s) {
    var r = s && s.match(RE_PROXY)
    if (r) {
        return {type: r[1], host: r[2], port: r[3]}
    }
    return null;
}

var requestWithSocksProxy = function(sUrl, proxy) {
    var shttp = require('socks5-http-client')
    var shttps = require('socks5-https-client')
    var uri = typeof sUrl === 'string' ? url.parse(sUrl) : sUrl
    if (typeof proxy === 'string') {
        var proxy = matchProxy(proxy)
    }
    if (!proxy.host || !proxy.port) {
        throw 'Not a valid socks proxy.'
    }
    uri.socksHost = proxy.host
    uri.socksPort = proxy.port
    return (uri.protocol === 'http:' ? shttp : shttps).request(uri)
}

/**
 * Create a http(s) request, proxy will be detected automatical.
 *
 * @method request
 * @param {Object|String} url or parsed uri object to request.
 *
 * @return Returns a http.ClientRequest instance.
 */
exports.request = function(options) {
    if (typeof options === 'string') {
        options = url.parse(options)
    }
    var req, isSocksProxy, proxy = options.proxy
    if ( proxy && (proxy = matchProxy(proxy)) ) {
        isSocksProxy = proxy.type.indexOf('socks') === 0
        if (!isSocksProxy) {
            options.host = proxy.host
            options.port = proxy.port
        }
    }
    if (isSocksProxy) {
        req = requestWithSocksProxy(options, proxy)
    } else {
        // http://nodejs.org/api/http.html#http_http_request_options_callback
        req = (options.protocol === 'https:' ? https : http ).request(options)
    }
    return req
}

/**
 * Create a http(s) request with socks5 proxy.
 *
 * @param {String} url The targe url to request
 * @param {Object|String} proxy setting, socks5://host:port if a string formats.
 *
 * @method requestWithSocksProxy
 * @author Allex Wang (allex.wxn@gmail.com)
 */
exports.requestWithSocksProxy = requestWithSocksProxy
