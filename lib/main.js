/*
 * auth_api
 * openi-ict.eu
 */

'use strict';

var zmq    = require('m2nodehandler');
//var rrd    = require('openi_rrd');

var openiLogger  = require('openi-logger');
var openiUtils   = require('openi-cloudlet-utils');
var querystring  = require('querystring');
var https        = require('https');
//var loglet       = require('loglet');
var uuid         = require('uuid');
var jwt          = require('jsonwebtoken');

var scrypt = require("scrypt");
var scryptParameters = scrypt.params(0.1);
scrypt.hash.config.keyEncoding = "utf8";
scrypt.verify.config.keyEncoding = "utf8";

//loglet = loglet.child({component: 'auth-api'});

var logger;

var actions = {
  "users": ['GENERIC_CREATE'],
  "sessions": ['GENERIC_CREATE', 'GENERIC_DELETE', 'GENERIC_UPDATE'],
  "clients": ['GENERIC_CREATE'],
  "authorizations": ['GENERIC_CREATE', 'GENERIC_DELETE', 'GENERIC_READ'],
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
        'data'         : json || {},
        'authorization': 'dbkeys_29f81fe0-3097-4e39-975f-50c4bf8698c7', /*secret*/
        'options'      : opt || {},
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

var logger;

var authApi = function(config) {

   logger = openiLogger(config.logger_params);
   //rrd.init("auth");
   //zmq.addPreProcessFilter(rrd.filter);

   var senderToDao    = zmq.sender(config.dao_sink);
   var senderToClient = zmq.sender(config.mongrel_handler.sink);

    zmq.receiver(config.api_handler.source, config.api_handler.sink, function (msg) {
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

      if(!intent)
      {
        senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error': 'Your request was incompatible.'});
        return;
      }

      var iact = intent.action;
      var idb = intent.db;
      var iid = intent.id;
      var idat = intent.data;

      if(intent.action === 'GENERIC_RETURN')
      {
        if(intent.db === 'authorizations')
        {
          var date = Math.floor((new Date()).getTime() / 1000);
          var t = {
              "jti": intent.data.username + '_' + intent.data.client + '_' + uuid.v4(),
              "iss": "https://" + intent.http.headers.host + "/auth/token",
              "sub": intent.data.username,
              "aud": intent.data.client,
              "exp": date + 43200,
              "iat": date,
              "nonce": uuid.v4(),
              'user_id': intent.data.username,
              'client_id': intent.data.client,
              "scope": "openi",
              "openi-token-type": "token",
              "response_type": "id_token",
            };
          var t = { 'token': jwt.sign(t, config.key.sign, { algorithm: 'RS256'}) };
          senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, t);
          return;
        }
        else
        {
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error': 'Your request was incompatible!'});
          return;
        }
      }
      else if(intent.action === 'GENERIC_CREATE' && intent.db === 'sessions')
      {
        var verified = scrypt.verify(new Buffer(msg.body.response.password, 'base64'), intent.data.password);
        if(verified)
        {
          var date = Math.floor((new Date()).getTime() / 1000);
          var t = {
              "jti": intent.data.username + '_' + uuid.v4(),
              "iss": "https://" + intent.http.headers.host + "/auth/token",
              "sub": intent.data.username,
              "exp": date + 43200,
              "iat": date,
              "nonce": uuid.v4(),
              'user_id': intent.data.username,
              "scope": "openi",
              "openi-token-type": "session",
              "response_type": "id_token",
            };
          var t = { 'session': jwt.sign(t, config.key.sign, { algorithm: 'RS256'}) };
          senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, t);
          return; 
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
        iid = 'authorizations_' + msg.body[0].response.username + '_' + msg.body[1].response.client;
        idat = { 'username': msg.body[0].response.username, 'client': msg.body[1].response.client }
        intent.data = idat;
        intent.action = 'GENERIC_RETURN';
      }
      else if(intent.action === 'GENERIC_READ' && intent.db === 'authorizations')
      {
        senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, msg.body.response);
        return;
      }
      else if(intent.action === 'GENERIC_DELETE' && intent.db === 'authorizations')
      {
        senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, {});
        return;
      }
      else
      {
        senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error': 'Your request was ... weird'});
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

       if(p.length < 6) {
        p.push(p[4] + '_' + uuid.v4());
       }

        var req;
        var handled = false;

        var intent = {}
        intent.action = action;
        intent.db = p[4];
        intent.id = p[5];
        intent.data = msg.json || {};
        msg.intent = intent;
        intent.http = {};
        intent.http.headers = {}
        intent.http.headers.host = msg.headers.host;

        if(action === 'GENERIC_CREATE' && p[4] === 'sessions')
        {
          if(msg.json && typeof msg.json.username === 'string' && msg.json.username != "" && typeof msg.json.password === 'string' && msg.json.password != "")
          {
            req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
             'GENERIC_READ', 'users', 'users_' + msg.json.username, {}, {}, msg.intent);
            handled = true;
          }
        }
        else if(action === 'GENERIC_UPDATE' && p[4] === 'sessions')
        {
          if(msg.json && typeof msg.json.session === 'string' && msg.json.session != "")
          {
            try{
              var verified = jwt.verify(msg.json.session, config.key.verify, { algorithm: 'RS256'});

              if(verified && verified["openi-token-type"] === "session")
              {
                verified.exp = Math.floor((new Date()).getTime() / 1000) + 43200;
                verified.nonce = uuid.v4();
                msg.json.session = jwt.sign(verified, config.key.sign, { algorithm: 'RS256'});
              }
            }
            catch(_){}

            senderToClient.send(msg.uuid, msg.connId, zmq.status.OK_200, zmq.standard_headers.json, msg.json);
            return;
          }
        }
        else if(action === 'GENERIC_DELETE' && p[4] === 'sessions')
        {
          senderToClient.send(msg.uuid, msg.connId, zmq.status.OK_200, zmq.standard_headers.json, {});
          return;
        }
        else if(action === 'GENERIC_CREATE' && p[4] === 'token')
        {
            try{
              var verified = jwt.verify(msg.headers.authorization, config.key.verify, { algorithm: 'RS256'});

              if(verified && verified["openi-token-type"] === "token")
              {
                msg.intent.action = 'GENERIC_UPSERT';
                req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
                  'GENERIC_READ', 'users', 'users_' + verified.user_id, {}, {}, msg.intent);
                addAction(req, 'GENERIC_READ', 'clients', 'clients_' + p[5], {}, {});
                handled = true;
              }
            }
            catch(_){}
        }
        else if(action === 'GENERIC_UPDATE' && p[4] === 'token')
        {
          if(msg.json && typeof msg.json.token === 'string' && msg.json.token != "")
          {
            try{
              var verified = jwt.verify(msg.json.token, config.key.verify, { algorithm: 'RS256'});

              if(verified && verified["openi-token-type"] === "token")
              {
                verified.exp = Math.floor((new Date()).getTime() / 1000) + 43200;
                verified.nonce = uuid.v4();
                msg.json.token = jwt.sign(verified, config.key.sign, { algorithm: 'RS256'});
              }
            }
            catch(_){}

            senderToClient.send(msg.uuid, msg.connId, zmq.status.OK_200, zmq.standard_headers.json, msg.json);
            return;
          }
        }
        else if(action === 'GENERIC_DELETE' && p[4] === 'token')
        {
          senderToClient.send(msg.uuid, msg.connId, zmq.status.OK_200, zmq.standard_headers.json, {});
          return;
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
        else if(action === 'GENERIC_READ' && p[4] === 'authorizations')
        {
          if(msg.headers.authorization && typeof msg.headers.authorization === 'string')// && msg.json.secret)
          {
            try{
              var verified = jwt.verify(msg.headers.authorization, config.key.verify, { algorithm: 'RS256'});
              if(verified && verified["openi-token-type"] === "session")
              {
                req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
                  'GENERIC_QUERY', 'query', 'query', "SELECT * FROM authorizations WHERE username = '" + verified.user_id + "'", {}, msg.intent);
                handled = true;
              }
            }
            catch(e){
              senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : e.message});
           }
          }
        }
        else if(action === 'GENERIC_CREATE' && p[4] === 'authorizations')
        {
          if(msg.headers.authorization && typeof msg.headers.authorization === 'string' && typeof p[5] === 'string')// && msg.json.secret)
          {
            try{
              var verified = jwt.verify(msg.headers.authorization, config.key.verify, { algorithm: 'RS256'});

              if(verified && verified["openi-token-type"] === "session")
              {
                msg.intent.action = 'GENERIC_UPSERT';
                req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
                  'GENERIC_READ', 'users', 'users_' + verified.user_id, {}, {}, msg.intent);
                addAction(req, 'GENERIC_READ', 'clients', 'clients_' + p[5], {}, {});
                handled = true;
              }
            }
            catch(_){}
          }
        }
        else if(action === 'GENERIC_DELETE' && p[4] === 'authorizations')
        {
          if(msg.headers.authorization && typeof msg.headers.authorization === 'string' && typeof p[5] === 'string')// && msg.json.secret)
          {
            try{
              var verified = jwt.verify(msg.headers.authorization, config.key.verify, { algorithm: 'RS256'});

              if(verified && verified["openi-token-type"] === "session")
              {
                req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
                  'GENERIC_DELETE', 'authorizations', 'authorizations_' + verified.user_id + '_' + p[5], {}, {}, msg.intent);
                handled = true;
              }
            }
            catch(_){}
          }
        }

        if(handled)
          senderToDao.send(req);
        else
          senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method, URL, or params.' });
   });
};

module.exports = authApi;
