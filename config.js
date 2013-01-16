var confdir = __dirname + '/conf.d';

// Exports
module.exports = {
    allow_ip_list   : confdir + '/allow_ip_list',
    black_list      : confdir + '/black_list',
    host_filters    : confdir + '/host_filters',
    responder_list  : confdir + '/responder_list',
    listen: {
        http: {
            host: '0.0.0.0',
            port: 8581
        },
        https: {
            host: '0.0.0.0',
            port: 8582
        }
    }
};
