## HTTP(s) proxy
================

<pre>
A HTTP(S) reverse proxy server written in node. with features for web develop.
Based on the Nodejs-proxy INITIAL commits written by Peteris Krumins (peter@catonmat.net).

Author: Allex Wang (allex.wxn@gmail.com)
</pre>

## Feautures:
* http(s) request forwarding.
* weinre debugger. (need weinre installed)
* javascript code beautify.

## Proxy setup
<pre>
cd ~/local/
git clone git://github.com/allex/webproxy.git webproxy
node ./webproxy/proxy.js [--weinre | --beautify]
</pre>

## TODO:
* Supports HTTPS forwarding.
* Publish to npm, for easy installer.
