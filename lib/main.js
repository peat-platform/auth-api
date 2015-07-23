/*
 * auth_api
 * peat-platform.org
 */

'use strict';

var zmq             = require('m2nodehandler');
var peatUtils      = require('cloudlet-utils');
var querystring     = require('querystring');
var https           = require('https');
var uuid            = require('uuid');
var jwt             = require('jsonwebtoken');
//var rrd            = require('peat-rrd');
//loglet             = loglet.child({component: 'auth-api'});

var mongrelHandler  = require('./mongrel2MsgHandler.js');
var internalHandler = require('./internalWorker.js');


var authApi = function(config) {

   var senderToDao    = zmq.sender(config.dao_sink);
   var senderToClient = zmq.sender(config.mongrel_handler.sink);

  internalHandler(config, senderToDao, senderToClient);
  mongrelHandler(config, senderToDao, senderToClient);

};

module.exports = authApi;
