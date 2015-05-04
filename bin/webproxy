#!/usr/bin/env node

var util = require('util')
  , config = require('../config')
  , proxy = require('../')

// startup proxy server
if (config.debug) {
  // output memory usage info every 5 minutes
  var min = 0, last = 0, interval = .1 * 60 * 1000
  process.nextTick(function f() {
    var o = process.memoryUsage()
    var percent = ~~((o.heapUsed / o.heapTotal) * 100) + '%'
    if (!min || o.heapUsed < last) {
      min = o.heapUsed
      console.warn([(min / 1048576) + 'm', (o.heapTotal / 1048576) + 'm', percent])
    }
    last = o.heapUsed
    setTimeout(f, interval)
  })
}

proxy()

// vim: set ft=javascript fdm=marker ts=2 sw=2 sts=2 tw=85 et :
