HTTP(s) Proxy
=============

<pre>
A HTTP(S) reverse proxy server written in node. with features for web develop.
Author: Allex Wang (allex.wxn@gmail.com)
</pre>

## Features:

* Host simulation by some configuration proxy forwardings.
* Http(s) request forwarding, support proxy forwardings (http, socks)
* Add remote address to response headers `X-Remote-Address`.
* Javascript code beautify for codes online.

## Proxy Setup

```sh
cd ~/local/
git clone git://github.com/allex/webproxy.git webproxy
node ./webproxy/proxy.js [--weinre | --beautify | --nocache | --debug]
```

## Configuration

### host (support third-party proxies forwardings)

cat ~/.proxy2/rules/hosts

```json
{
    "*.twitter.com": {
        "hosts": "199.16.158.168"
    },
    "*.blogspot.com/*": {
        "proxy": "http://proxy:8087"
    },
    ".youtube.com": {
        "proxy": "socks5://127.0.0.1:7070"
    },
    "*.gravatar.com": {
        "proxy": "socks5://127.0.0.1:7070"
    }
}
```

### responder

cat ~/.proxy2/rules/responder

```ini
# exact pattern
exact:http://iallex.com/ /Users/allex/iallex.com/index.html

# wildcard pattern
wildcard:(*)/theia.js /Users/allex/dev/weibo/stk/theia.js

# replace pattern
wildcard:(*)/foo/images/(*) /var/www/foo/assets/images/$2
```

## TODO:

* Publish to npm, for easy installer.
