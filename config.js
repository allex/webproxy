var DIR = __dirname;

var config = {
    allow_ip_list:  DIR + '/config/allow_ip_list',
    black_list:     DIR + '/config/black_list',
    host_filters:   DIR + '/config/host_filters',
    responder_list: DIR + '/config/responder_list',
    listen: {
        http : {host: '0.0.0.0', port: 8581},
        https: {host: '0.0.0.0', port: 8582}
    }
};

exports.config = config;
