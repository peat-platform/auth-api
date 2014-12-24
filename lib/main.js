/*
 * openi_data_api
 * openi-ict.eu
 *
 * Copyright (c) 2013 dmccarthy
 */

'use strict';

var zmq    = require('m2nodehandler');
var rrd    = require('openi_rrd');

var openiLogger  = require('openi-logger');
var openiUtils   = require('openi-cloudlet-utils');
var querystring  = require('querystring');
var https        = require('https');
var loglet       = require('loglet');
var uuid         = require('uuid');
var jwt          = require('jsonwebtoken');

var scrypt = require("scrypt");
var scryptParameters = scrypt.params(0.1);
scrypt.hash.config.keyEncoding = "utf8";
scrypt.verify.config.keyEncoding = "utf8";

loglet = loglet.child({component: 'auth-api'});

var logger;

var actions = {
  "users": ['GENERIC_CREATE'],
  "sessions": ['GENERIC_CREATE', 'GENERIC_DELETE'],
  "clients": ['GENERIC_CREATE'],
  "authorizations": ['GENERIC_CREATE', 'GENERIC_DELETE']
};

var baseRequest = function (sink, uuid, cid, action, db, id, json, opt, intent)
{
  return {
    'dao_actions'      :
    [
      {
        'action'       : action,
        'database'     : db,
        'id'           : id,
        'data'         : json,
        'authorization': 'dbkeys_29f81fe0-3097-4e39-975f-50c4bf8698c7', /*secret*/
        'options'      : opt,
        'intent': intent
      }
    ],
    'mongrel_sink' : sink,
    'clients'      :
    [
      {
        'uuid' : uuid,
        'connId' : cid
      }
    ]
  };
}

var addAction = function(br, action, db, id, json, opt, msg)
{
  br.dao_actions.push({
        'action'       : action,
        'database'     : db,
        'id'           : id,
        'data'         : json,
        'authorization': 'dbkeys_29f81fe0-3097-4e39-975f-50c4bf8698c7', /*secret*/
        'options'      : opt,
      });
}

var authApi = function(config) {

   logger = openiLogger(config.logger_params);
   rrd.init("auth");
   zmq.addPreProcessFilter(rrd.filter);

   var senderToDao    = zmq.sender(config.dao_sink);
   var senderToClient = zmq.sender(config.mongrel_handler.sink);

  //console.log(jwt.sign({ 'username': 'msg.body[0].data.username', 'client': 'intent.data.client' }, config.key.sign, { algorithm: 'RS256'}));

    zmq.receiver(config.api_handler.source, config.api_handler.sink, function (msg) {
      //logger.logMongrel2Message(msg);
      //console.log(JSON.stringify(msg));
      //console.log(msg);
      //senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, msg);


      var intent;
      if(Array.isArray(msg.body))
      {
        for(var i = 0; msg.body[i].error; ++i)
          if(msg.body[i].error)
          {
            senderToClient.send(msg.uuid, msg.connId, msg.status, zmq.standard_headers.json, msg.body[i]);
            return;
          }

        intent = msg.body[0].request.intent;
      }
      else
      {
        if(msg.body.error)
        {
          senderToClient.send(msg.uuid, msg.connId, msg.status, zmq.standard_headers.json, msg.body);
          return;
        }

        intent = msg.body.request.intent;
      }

      if(!intent && !ret)
      {
        senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error': 'Your request was incompatible.'});
        return;
      }

      //console.log(intent);

      var iact = intent.action;
      var idb = intent.db;
      var iid = intent.id;
      var idat = intent.data;

        // console.log('----');
        // console.log(msg);
        // console.log(msg.body);
        // console.log(msg.body.request);
        // console.log(intent);
        // console.log(intent.data);
        // console.log('----');

      if(intent.action === 'GENERIC_RETURN')
      {
        if(intent.db === 'sessions')
          senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, {'session': msg.body.request.id.replace('sessions_','')});
        else if(intent.db === 'authorizations')
        {
          //{"jti":"f2199ebd-a766-4063-a79d-071c398bd791","sub":"26513c33-cfdd-40fc-8535-5eafa9ffe750","scope":["openid"],"client_id":"openi","cid":"openi","user_id":"26513c33-cfdd-40fc-8535-5eafa9ffe750","user_name":"olong","email":"email@example.org","iat":1419439687,"exp":1419482887,"iss":"http://localhost:8080/uaa/oauth/token","aud":["openid"]}
          var t = {'token': jwt.sign({'user_id': intent.data.username, 'client_id': intent.data.client}, config.key.sign, { algorithm: 'RS256'}) };
          senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, t);
        }
        else
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error': 'Your request was incompatible.'});
        return;
      }
      else if(intent.action === 'GENERIC_CREATE' && intent.db === 'sessions')
      {
        var verified = scrypt.verify(new Buffer(msg.body.data.password, 'base64'), intent.data.password);
        if(verified)
        {  //intent.id = 'sessions_' + intent.data.session + '_' + intent.data.client_id;
          idat = {'username': msg.body.data.username };
          intent.action = 'GENERIC_RETURN';
        }
        else
        {
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error': 'Your password and username did not match.'});
          return;
        }
      }
      else if(intent.action === 'GENERIC_DELETE' && intent.db === 'sessions')
      {
        senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, {});
        return;
      }
      else if(intent.action === 'GENERIC_CREATE' && intent.db === 'users')
      {
        senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, {});
        return;
      }
      else if(intent.action === 'GENERIC_CREATE' && intent.db === 'clients')
      {
        senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, {});
        return;
      }
      else if((intent.action === 'GENERIC_CREATE' || intent.action === 'GENERIC_UPSERT') && intent.db === 'authorizations')
      {
        // console.log('----');
        // console.log(msg);
        // console.log(msg.body);
        // console.log(msg.body.request);
        // console.log(intent);
        // console.log(intent.data);
        // console.log('----');

        //iact = 'GENERIC_CREATE';
        //idb = 'authorizations';
        iid = 'authorizations_' + msg.body[0].data.username + '_' + intent.data.client;
        idat = { 'username': msg.body[0].data.username, 'client': intent.data.client }
        intent.data = idat;
        intent.action = 'GENERIC_RETURN';
      }
      else
      {
        senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error': 'Your request was ... weird'});

        console.log('----');
        console.log(msg);
        console.log(msg.body);
        console.log(msg.body.request);
        console.log(intent);
        console.log(intent.data);
        console.log('----');

        return;
      }

      senderToDao.send(baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
          iact, idb, iid, idat, {}, intent));
    });

   zmq.receiver(config.mongrel_handler.source, config.mongrel_handler.sink, function(msg) {

       var action;
       var p = msg.path.split('/');

       var query = querystring.parse(msg.headers.QUERY);

       logger.logMongrel2Message(msg);

       for(var key in msg.json) { /*no knowledge why this may be tainted*/
          if(msg.json.hasOwnProperty(key)) {
             if(msg.json[key] === null) {
                delete msg.json[key];
             }
          }
       }

       switch(msg.headers['METHOD']) {
          case 'POST':
             action = 'GENERIC_CREATE';
             break;
          case 'GET':
             action = 'GENERIC_READ';
             break;
          case 'PUT':
             action = 'GENERIC_UPDATE';
             break;
          case 'DELETE':
             action = 'GENERIC_DELETE';
             break;
          case 'PATCH':
             action = 'GENERIC_PATCH';
             break;
       }

       if(action == undefined) {
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Incorrect HTTP action.' });
          return;
       }

       if(p.length < 5)
       {
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Incompatible request URL (missing something?).' });
          return;
       }

       if(!(p[1] === 'api' || p[2] === 'v1' || p[3] === 'auth')) {
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Base Path incorect (' + path + ').' });
          return;
       }

       if(actions[p[4]] == undefined)
       {
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Wrong request URL.' });
          return;
       }

       // if(actions[p[4]].indexOf(action) < 0)
       // {
       //    senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method URL.' });
       //    return;
       // }

       if(p.length < 6) {
          if(action === 'GENERIC_CREATE') {
             p.push(p[4] + '_' + uuid.v4());
          }
          else {
             senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'No ID specified.' });
             return;
          }
       }
       else if(action === 'GENERIC_CREATE')
       {
             senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'You are not allowed to provide an ID to this resource.' });
             return;          
       }

       if(action === 'GENERIC_CREATE' && msg.json == null) {
        senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'No Json data provided.' });
        return;
       }

        var req;
        var handled = false;

        var intent = {}
        intent.action = action;
        intent.db = p[4];
        intent.id = p[5];
        intent.data = msg.json;
        msg.intent = intent;

        if(action === 'GENERIC_CREATE' && p[4] === 'sessions')
        {
          if(msg.json && typeof msg.json.username === 'string' && msg.json.username != "" && typeof msg.json.password === 'string' && msg.json.password != "")
          {
            //msg.json.password = scrypt.hash(msg.json.password, scryptParameters).toString('base64');
            req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
             'GENERIC_READ', 'users', 'users_' + msg.json.username, {}, {}, msg.intent);
            handled = true;
          }
        }
        else if(action === 'GENERIC_DELETE' && p[4] === 'sessions')
        {
          if(typeof p[5] === 'string')
          {
            req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
             'GENERIC_DELETE', 'sessions', 'sessions_' + p[5], {}, {}, msg.intent);
            handled = true;
          }
        }
        else if(action === 'GENERIC_CREATE' && p[4] === 'users')
        {
          if(msg.json && typeof msg.json.username === 'string' && msg.json.username != "" && typeof msg.json.password === 'string' && msg.json.password != "")
          {
            msg.json.password = scrypt.hash(msg.json.password, scryptParameters).toString('base64');
            req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
             'GENERIC_CREATE', 'users', 'users_' + msg.json.username, msg.json, {}, msg.intent);
            handled = true;
          }
        }
        else if(action === 'GENERIC_CREATE' && p[4] === 'clients')
        {
          if(msg.json && typeof msg.json.client === 'string')// && msg.json.secret)
          {
            if(typeof msg.json.secret === 'string')
              msg.json.secret = scrypt.hash(msg.json.secret, scryptParameters).toString('base64');
            req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
             'GENERIC_CREATE', 'clients', 'clients_' + msg.json.client, msg.json, {}, msg.intent);
            handled = true;
          }
        }
        else if(action === 'GENERIC_CREATE' && p[4] === 'authorizations')
        {
          if(msg.json && typeof msg.json.session === 'string' && typeof msg.json.client === 'string')// && msg.json.secret)
          {
            msg.intent.action = 'GENERIC_UPSERT';
            req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
             'GENERIC_READ', 'sessions', 'sessions_' + msg.json.session, {}, {}, msg.intent);
            addAction(req, 'GENERIC_READ', 'clients', 'clients_' + msg.json.client, {}, {});
            handled = true;
          }
        }

        if(handled)
          senderToDao.send(req);
        else
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method, URL, or params.' });
   });
};

module.exports = authApi;