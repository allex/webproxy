var lang = require('lang-ext')
var confdir = __dirname + '/etc'

function extendArgs(o) {
    var params = require('optimist').argv
    lang.forEach({
        'weinre': false,
        'nocache': false,
        'beautify': false,
        'debug': false
    }, function(v, k) { o[k] = params[k] || v })
    return o
}

// Exports
module.exports = extendArgs({
    listen: {
        host: '0.0.0.0',
        port: 8581
    },
    hosts: confdir + '/hosts',
    rules: confdir + '/rules.json',
    responder: confdir + '/responder',
    blacklist: confdir + '/blacklist'
})
