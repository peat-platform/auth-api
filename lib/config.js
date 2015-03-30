var config = {};
config.piwik = {};
config.mysql = {};

config.piwik.token_auth = "90871c8584ddf2265f54553a305b6ae1";
config.piwik.domain = "http://dev.openi-ict.eu:8888/piwik/";

config.mysql.host = 'localhost';
config.mysql.user = 'piwik';
config.mysql.password = 'password';
config.mysql.database = 'piwik';
config.mysql.multipleStatements = 'true';


module.exports = config;