
var zmq              = require('m2nodehandler');
var peatLogger       = require('peat-logger');
var scrypt           = require("scrypt");
var scryptParameters = scrypt.params(0.1);
var jwt              = require('jsonwebtoken');
var uuid             = require('uuid');
var crypto           = require('crypto');
var loglet           = require('loglet');
loglet               = loglet.child({component: 'auth-api'});
var tracklet         = require('tracklet');


scrypt.hash.config.keyEncoding   = "utf8";
scrypt.verify.config.keyEncoding = "utf8";


var actions = {
   "users"          : ['GENERIC_CREATE'],
   "sessions"       : ['GENERIC_CREATE', 'GENERIC_DELETE', 'GENERIC_UPDATE'],
   "clients"        : ['GENERIC_CREATE', 'GENERIC_READ'],
   "authorizations" : ['GENERIC_CREATE', 'GENERIC_DELETE', 'GENERIC_READ']
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
};


var addAction = function(br, action, db, id, json, opt, msg)
{
   br.dao_actions.push({
      'action'       : action,
      'database'     : db,
      'id'           : id,
      'data'         : json,
      'authorization': 'dbkeys_29f81fe0-3097-4e39-975f-50c4bf8698c7', /*secret*/
      'options'      : opt
   });
};


var isPathValid = function(p){

   if(p.length < 5 || !(p[1] === 'api' || p[2] === 'v1' || p[3] === 'auth') || actions[p[4]] == undefined)
   {
      return false;
   }
   return true
};


/*no knowledge why this may be tainted*/
/*Querky bug that occured a few times and this was the only solution, could have been people messing with
* the arrays prototype object*/
var sanitizeJSONBody = function(msg){

   for(var key in msg.json) {
      if(msg.json.hasOwnProperty(key)) {
         if(msg.json[key] === null) {
            delete msg.json[key];
         }
      }
   }
};


var extractAction = function(msg){
   var action;
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
   default :
      break;
   }

   return action
};



var processSessionAction = function(action, msg, config, baseRequest, senderToClient, senderToDao){

   if(action === 'GENERIC_CREATE' && msg.json && typeof msg.json.username === 'string' && msg.json.username != "" && typeof msg.json.password === 'string' && msg.json.password != ""){

      var req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
         'GENERIC_READ', 'users', 'users_' + msg.json.username, {}, {}, msg.intent);

      senderToDao.send(req);

   }
   else if(action === 'GENERIC_UPDATE' && msg.json && typeof msg.json.session === 'string' && msg.json.session != ""){

      var verified = verifyJWT(msg.json.session, config, senderToClient, msg)

      if(verified && verified["peat-token-type"] === "session")
      {
         verified.exp     = Math.floor((new Date()).getTime() / 1000) + 43200;
         verified.nonce   = uuid.v4();
         msg.json.session = jwt.sign(verified, config.key.sign, { algorithm: 'RS256'});

         senderToClient.send(msg.uuid, msg.connId, zmq.status.OK_200, zmq.standard_headers.json, msg.json);
      }
   }
   else if(action === 'GENERIC_DELETE'){
      senderToClient.send(msg.uuid, msg.connId, zmq.status.OK_200, zmq.standard_headers.json, {});
   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method, URL, or params.' });
      loglet.error({'error' : 'Unsupported method, URL, or params.' });
   }

};


var processTokenAction = function(action, msg, config, baseRequest, senderToClient, senderToDao){

   if(action === 'GENERIC_CREATE')
   {
      var authHeader = msg.headers.authorization.replace("Bearer ", "")

      var verified = verifyJWT(authHeader, config, senderToClient, msg)

      if(verified && verified["peat-token-type"] === "token")
      {
         msg.intent.action = 'GENERIC_UPSERT';
         var req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
            'GENERIC_READ', 'users', 'users_' + verified.user_id, {}, {}, msg.intent);
         addAction(req, 'GENERIC_READ', 'clients', 'clients_' + restId, {}, {});

         senderToDao.send(req);
      }
   }
   else if(action === 'GENERIC_UPDATE' && msg.json && typeof msg.json.token === 'string' && msg.json.token != "") {

      var verified = verifyJWT(msg.json.token, config, senderToClient, msg)

      if(verified && verified["peat-token-type"] === "token")
      {
         verified.exp   = Math.floor((new Date()).getTime() / 1000) + 43200;
         verified.nonce = uuid.v4();
         msg.json.token = jwt.sign(verified, config.key.sign, { algorithm: 'RS256'});

         senderToClient.send(msg.uuid, msg.connId, zmq.status.OK_200, zmq.standard_headers.json, msg.json);
      }

   }
   else if(action === 'GENERIC_DELETE'){
      senderToClient.send(msg.uuid, msg.connId, zmq.status.OK_200, zmq.standard_headers.json, {});
   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method, URL, or params.' });
      loglet.error({'error' : 'Unsupported method, URL, or params.' });
   }
};

var processUserAction = function (action, msg, config, baseRequest, senderToClient, senderToDao){
   if(action === 'GENERIC_CREATE' && msg.json && typeof msg.json.username === 'string' && msg.json.username != "" && typeof msg.json.password === 'string' && msg.json.password != "") {
      var password = msg.json.password;

      if (password.length < 8 || password.length > 80) {
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'The password length must be between 6 and 80 characters.' });
      } else {
         msg.json.password = scrypt.hash(msg.json.password, scryptParameters).toString('base64');
         msg.json.cloudlet = "c_" + crypto.createHash('md5').update(crypto.randomBytes(256)).digest('hex');
         var req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
            'GENERIC_CREATE', 'users', 'users_' + msg.json.username, msg.json, {}, msg.intent);
         var email = msg.json.cloudlet + '@peat-platform.org';
         tracklet.init({
            name    : msg.json.username,
            password: password,
            email   : email,
            cloudlet: msg.json.cloudlet,
            access  : 'view'
         }, function (error) {
               if (error) {
                  console.log(error);
               }
             }
         );
         senderToDao.send(req);
      }
   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method, URL, or params.' });
      loglet.error({'error' : 'Unsupported method, URL, or params.' });
   }
};


var verifyJWT = function(authHeader, config, senderToClient, msg){
   try{
      var ver = jwt.verify(authHeader, config.key.verify, { algorithm: 'RS256'});

      if (!ver){
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
            {'error':'JWT cannot be verified'});
         loglet.error({'error':'JWT cannot be verified'});
      }

      return ver
   }
   catch (e){
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json,
         {'error':'JWT cannot be verified'});
      loglet.error({'error':'JWT cannot be verified'});
      return false
   }
}


var processClientsAction = function(action, msg, config, baseRequest, senderToClient, senderToDao){

   //verify  jwt

   if(action === 'GENERIC_CREATE' && msg.json && typeof msg.json.name === 'string'){

      var authHeader = msg.headers.authorization.replace("Bearer ", "");

      var verified = verifyJWT(authHeader, config, senderToClient, msg)

      if(verified && verified["peat-token-type"] === "session"){

         var api_key = crypto.createHash('md5').update(crypto.randomBytes(256)).digest('hex');
         var secret  = crypto.createHash('md5').update(crypto.randomBytes(256)).digest('hex')
                         + crypto.createHash('md5').update(crypto.randomBytes(256)).digest('hex');

         msg.json.cloudlet = verified.cloudlet;
         msg.json.api_key  = api_key;
         msg.json.secret   = secret;
         //msg.json.secret   = scrypt.hash(secret, scryptParameters).toString('base64')

         //clients_developer

         var req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
            'GENERIC_CREATE', 'clients', 'clients_' + msg.json.api_key, msg.json, {'secret':secret}, msg.intent);

         senderToDao.send(req);
      }
      else{
         senderToClient.send(msg.uuid, msg.connId, zmq.status.FORBIDDEN_402, zmq.standard_headers.json,
            {'error' : 'Permission denied' });
         loglet.error({'error' : 'Permission denied'});
      }

   }
   else if(action === 'GENERIC_READ' && typeof msg.headers.authorization === 'string' && msg.headers.authorization != "") {

      var authHeader = msg.headers.authorization.replace("Bearer ", "")

      var verified = verifyJWT(authHeader, config, senderToClient, msg)

      if(verified && verified["peat-token-type"] === "session") {

         var meta = {
            "limit"       : 1000,
            "offset"      : 0,
            "total_count" : 0,
            "prev"        : null,
            "next"        : null
         };

         var action = {
            'dao_actions' : [
               {
                  'action'     : 'VIEW',
                  'start_key'  : verified.cloudlet,
                  'end_key'    : verified.cloudlet + '\uefff',
                  'design_doc' : 'clients_views',
                  'view_name'  : "clients_by_cloudlet_id",
                  'meta'       : meta,
                  'resp_type'  : 'clients',
                  'cloudlet'   : verified.cloudlet,
                  'bucket'     : 'clients',
                  'intent'     : msg.intent
               }
            ],
            'mongrel_sink': config.mongrel_handler.sink,
            'clients'     : [
               {
                  'uuid'  : msg.uuid,
                  'connId': msg.connId
               }
            ]
         }

         senderToDao.send(action);
      }
      else{
         senderToClient.send(msg.uuid, msg.connId, zmq.status.FORBIDDEN_402, zmq.standard_headers.json,
            {'error' : 'Permission denied' });
         loglet.error({'error' : 'Permission denied'});
      }
   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method, URL, or params.' });
      loglet.error({'error' : 'Unsupported method, URL, or params.' });
   }
};


var processAuthAction = function(action, msg, config, baseRequest, senderToClient, senderToDao){


   if(action === 'GENERIC_CREATE' && msg.json && typeof msg.json.username === 'string' && msg.json.username != "" && typeof msg.json.password === 'string' && msg.json.password != ""){

      var req = baseRequest(config.api_handler.sink, msg.uuid, msg.connId,
                              'GENERIC_READ', 'users', 'users_' + msg.json.username, {}, {}, msg.intent);

      addAction(req, 'GENERIC_READ', 'clients', 'clients_' + msg.json.api_key, {}, {});

      //console.log(req)

      senderToDao.send(req);

   }
   else{
      senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method, URL, or params.' });
      loglet.error({'error' : 'Unsupported method, URL, or params.' });
   }
};


var handler = function(config, senderToDao, senderToClient){

   var logger = peatLogger(config.logger_params);
   tracklet.config(config.tracklet);

   zmq.receiver(config.mongrel_handler.source, config.mongrel_handler.sink, function(msg) {

      var p          = msg.path.split('/');
      var restAction = p[4];
      var restId     = p[5];
      var action     = extractAction(msg);

      logger.logMongrel2Message(msg);

      if(false === isPathValid(p))
      {
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Malformed request url (' + msg.path + ').' });
         loglet.error({'error' : 'Malformed request url (' + msg.path + ').' });

         return;
      }
      if (undefined === action){
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Incorrect HTTP action.' });
         loglet.error({'error' : 'Incorrect HTTP action.' });
         return
      }

      if(p.length < 6) {
         p.push(restAction + '_' + uuid.v4());
      }

      sanitizeJSONBody(msg);


      msg.intent                   = {};
      msg.intent.action            = action;
      msg.intent.db                = restAction;
      msg.intent.id                = restId;
      msg.intent.data              = msg.json || {};
      msg.intent.http              = {};
      msg.intent.http.headers      = {};
      msg.intent.http.headers.host = msg.headers.host;

      switch (restAction){
      case 'sessions':
         processSessionAction(action, msg, config, baseRequest, senderToClient, senderToDao);
         break;
      case 'token':
         processTokenAction(action, msg, config, baseRequest, senderToClient, senderToDao);
         break;
      case 'users':
         processUserAction(action, msg, config, baseRequest, senderToClient, senderToDao);
         break;
      case 'clients':
         processClientsAction(action, msg, config, baseRequest, senderToClient, senderToDao);
         break;
      case 'authorizations':
         processAuthAction(action, msg, config, baseRequest, senderToClient, senderToDao);
         break;
      default :
         senderToClient.send(msg.uuid, msg.connId, zmq.status.BAD_REQUEST_400, zmq.standard_headers.json, {'error' : 'Unsupported method, URL, or params.' });
         loglet.error({'error' : 'Unsupported method, URL, or params.' });
         break;
      }
   });
};

module.exports = handler;
