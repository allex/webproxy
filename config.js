var p = require('path')
var fs = require('fs-x')
var util = require('util')

var PX_ROOT_PATH = ''
var env = process.env

if (env.PX_HOME)
  PX_ROOT_PATH = env.PX_HOME
else if (env.HOME || env.HOMEPATH)
  PX_ROOT_PATH = p.resolve(env.HOME || env.HOMEPATH, '.proxy2')
else
  PX_ROOT_PATH = p.resolve('/etc', '.proxy2')

var CONF_FILE = p.join(PX_ROOT_PATH, 'conf.json')
var DEFAULT_LOG_PATH = p.join(PX_ROOT_PATH, 'logs')
var DEFAULT_RULE_PATH = p.join(PX_ROOT_PATH, 'rules')
var DEFAULT_KEYS_PATH = p.join(PX_ROOT_PATH, 'keys')

var cfg = {
  debug: false,
  hostname: '0.0.0.0',
  port: 8581,
  nocache: false,
  beautify: false,
  https: {
      keyFile: p.join(DEFAULT_KEYS_PATH, 'server.key'),
      certFile: p.join(DEFAULT_KEYS_PATH, 'server.crt')
  }
}

var configInit = function(cfg) {
  [PX_ROOT_PATH, DEFAULT_KEYS_PATH, DEFAULT_RULE_PATH, DEFAULT_LOG_PATH].forEach(function(dir, i) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }
  })

  if (fs.existsSync(CONF_FILE))
    util._extend(cfg, require(CONF_FILE))

  // merge argv options
  var argv = require('optimist').argv
  Object.keys(cfg).forEach(function(k) {
    if (argv[k] !== undefined) cfg[k] = argv[k]
  })

  fs.writeFileSync(CONF_FILE, JSON.stringify(cfg))

  var keyFile = cfg.https.keyFile, certFile = cfg.https.certFile
  if (!fs.existsSync(keyFile)) {
    fs
      .createReadStream(p.join(__dirname, './etc/keys/server.key'))
      .pipe(fs.createWriteStream(keyFile))
  }
  if (!fs.existsSync(certFile)) {
    fs
      .createReadStream(p.join(__dirname, './etc/keys/server.crt'))
      .pipe(fs.createWriteStream(certFile))
  }

  ['hosts', 'responder'].forEach(function(i) {
    var file = p.join(DEFAULT_RULE_PATH, i)
    if (!fs.existsSync(file))
      fs
        .createReadStream(p.join(__dirname, './etc/', i))
        .pipe(fs.createWriteStream(file))
  })
}

configInit(cfg)

// Exports
module.exports = util._extend({
  hosts: p.join(DEFAULT_RULE_PATH, 'hosts'),
  rules: p.join(DEFAULT_RULE_PATH, 'rules.json'),
  responder: p.join(DEFAULT_RULE_PATH, 'responder'),
  blacklist: p.join(DEFAULT_RULE_PATH, 'blacklist')
}, cfg)

//  vim: set fdm=marker ts=2 sw=2 sts=2 tw=85 et :
