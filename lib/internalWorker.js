
var scrypt           = require("scrypt");
var zmq              = require('m2nodehandler');
var jwt              = require('jsonwebtoken');
var uuid             = require('uuid');
var loglet           = require('loglet');
loglet               = loglet.child({component: 'auth-api'});

scrypt.hash.config.keyEncoding   = "utf8";
scrypt.verify.config.keyEncoding = "utf8";


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
               'intent'       : intent
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


var extractIntent = function(msg, senderToClient){

   if(Array.isArray(msg.body)){
      for(var i = 0; i < msg.body.length; ++i) {
         if (msg.body[i].error) {
            senderToClient.send(msg.uuid, msg.connId, msg.status, zmq.standard_headers.json, msg.body[i]);
            return false;
         }
      }

      if (undefined === msg.body[0].request.intent){
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
            {'error': 'Your request was incompatible.'});
         loglet.error({'error': 'Your request was incompatible.'});
         return false;
      }

      return msg.body[0].request.intent;
   }
   else{
      if(msg.body.error){
         senderToClient.send(msg.uuid, msg.connId, msg.status, zmq.standard_headers.json, msg.body);
         return false;
      }
      else if (undefined === msg.body.request.intent){
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
            {'error': 'Your request was incompatible.'});
         loglet.error({'error': 'Your request was incompatible.'});
         return false;
      }

      return msg.body.request.intent;
   }
}


var processAuthorisations = function (config, intent, msg, senderToClient, senderToDao){

   if(intent.action === 'GENERIC_CREATE')
   {
      var verified_user    = scrypt.verify(new Buffer(msg.body[0].response.password, 'base64'), intent.data.password);
      var verified_secret  = ( msg.body[1].response.secret === intent.data.secret )

      if(verified_user && verified_secret)
      {
         var date = Math.floor((new Date()).getTime() / 1000);
         var t = {
            "jti"              : msg.body[0].response.cloudlet + '_' + uuid.v4(),
            "iss"              : "https://" + intent.http.headers.host + "/auth/token",
            "sub"              : msg.body[0].response.cloudlet,
            "exp"              : date + 43200,
            "iat"              : date,
            "nonce"            : uuid.v4(),
            "user_id"          : msg.body[0].response.cloudlet,
            "cloudlet"         : msg.body[0].response.cloudlet,
            "client_id"        : msg.body[1].response.api_key,
            "client_name"      : msg.body[1].response.name,
            "context"          : msg.body[1].response.cloudlet,
            "scope"            : "peat",
            "peat-token-type"  : "token",
            "response_type"    : "id_token"
         };

         var token = { 'session': jwt.sign(t, config.key.sign, { algorithm: 'RS256'}) };

         senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, token);
      }
      else
      {
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
            {'error': 'Auth failed, check username, password, and api keys.'});
         loglet.error({'error': 'Auth failed, check username, password, and api keys.'});
      }

   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
         {'error': 'Unsupported request.'});
      loglet.error({'error': 'Unsupported request.'});
   }

}


var processSessions = function (config, intent, msg, senderToClient){


   if(intent.action === 'GENERIC_CREATE')
   {
      if (undefined === intent.data.scope){
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
            {'error': 'Please specify a scope (user or developer)'});
         return
      }

      var verified_user = scrypt.verify(new Buffer(msg.body.response.password, 'base64'), intent.data.password);

      if(verified_user)
      {
         var date = Math.floor((new Date()).getTime() / 1000);
         var t = {
            "jti"              : intent.data.username + '_' + uuid.v4(),
            "iss"              : "https://" + intent.http.headers.host + "/auth/token",
            "sub"              : intent.data.username,
            "exp"              : date + 43200,
            "iat"              : date,
            "nonce"            : uuid.v4(),
            'user_id'          : intent.data.username,
            "cloudlet"         : msg.body.response.cloudlet,
            "scope"            : intent.data.scope,
            "peat-token-type"  : "session",
            "response_type"    : "id_token"
         };

         var token = { 'session': jwt.sign(t, config.key.sign, { algorithm: 'RS256'}) };

         senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, token);
      }
      else
      {
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
            {'error': 'Your password and username did not match.'});
         loglet.error({'error': 'Your password and username did not match.'});
      }
   }
   else if(intent.action === 'GENERIC_DELETE')
   {
      senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, {});
      return;
   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
         {'error': 'Unsupported request.'});
      loglet.error({'error': 'Unsupported request.'});
   }
}


var processUsers = function (intent, msg, senderToClient){
   if(intent.action === 'GENERIC_CREATE')
   {
      senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, {});
   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
         {'error': 'Unsupported request.'});
      loglet.error({'error': 'Unsupported request.'});
   }
}


var processClients = function (intent, msg, senderToClient){
   if(intent.action === 'GENERIC_CREATE')
   {
      intent.data.secret = msg.body.request.options.secret
      senderToClient.send(msg.uuid, msg.connId, msg.status, msg.headers, intent.data);
   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
         {'error': 'Unsupported request.'});
      loglet.error({'error': 'Unsupported request.'});
   }
}

var handler = function(config, senderToDao, senderToClient){

   zmq.receiver(config.api_handler.source, config.api_handler.sink, function (msg) {

      var intent = extractIntent(msg, senderToClient);

      if(!intent)
      {
         return;
      }

      var iact = intent.action;
      var idb  = intent.db;
      var iid  = intent.id;
      var idat = intent.data;


      switch (intent.db){
      case 'authorizations':
         processAuthorisations(config, intent, msg, senderToClient, senderToDao)
         break;
      case 'sessions':
         processSessions(config, intent, msg, senderToClient)
         break;
      case 'users':
         processUsers(intent, msg, senderToClient)
         break;
      case 'clients':
         processClients(intent, msg, senderToClient)
         break;
      default:
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error': 'Unsupported request'});
         //senderToDao.send(baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
         //   iact, idb, iid, idat, {}, intent));
         break;
      }

   });
}

module.exports = handler