/**
 * Created by dmccarthy on 14/11/2013.
 */


'use strict';

var authApi = require('./main.js');

var config = {
   dao_sink        : {
      spec:'tcp://127.0.0.1:49999',
      bind:false,
      type:'push',
      id:'a'
   },
   mongrel_handler : {
      source : {spec:'tcp://127.0.0.1:49917', bind:false, id:'b', type:'pull', isMongrel2:true },
      sink   : {spec:'tcp://127.0.0.1:49918', bind:false, id:'c', type:'pub', isMongrel2:true }
   },
   api_handler : {
      source : {spec : 'tcp://127.0.0.1:49559', bind : true,  subscribe: '', type : 'sub', id : 'AuthSource'},
      sink   : {spec : 'tcp://127.0.0.1:49559', bind : false, subscribe: '', type : 'pub', id : 'AuthSink', asJson: true}
   },
   logger_params : {
      'path'     : '/opt/peat/cloudlet_platform/logs/crud_api',
      'log_level': 'debug',
      'as_json'  : false
   },
   key: {
      sign: '-----BEGIN RSA PRIVATE KEY-----\n'+
        'MIIBOQIBAAJBAKT8kGk6ZNo3sC4IIo29leRLVD23T2r0vWXBEkk2pV42HsxKAmPs\n'+
        '789AGHH9XwbGpD7FvrcBWWgb65v32Hg/NGkCAwEAAQJAVCNxShi7ggXQVUlUxdAf\n'+
        'dvNrnKW1XKg/Rns15hx2LRq+6oKv0RsPH3N4P64ZYDt62Yf0o1uLC66YtVgf5BgN\n'+
        'mQIhANCAIYQ3KSXLLmDW/wSCE85eOipP7Duxaan694LdO8+XAiEAypKs/I9t7Ef5\n'+
        'k4zpmm1/qS7ht/LWr+FsqHPB1nQ9m/8CIE19YXeHHLbcJbd+EDd3tK69HHb/Tzf8\n'+
        'Pt4a1QSA/qqvAiBLupGYyTXawv12P5OE+7Jh2Pjg/5NqpOcuAjhQp5vwmQIgNFWQ\n'+
        'km1fT/DDO4nwU7EP3WgBpn26E9eckdtgxIO+FEM=\n'+
        '-----END RSA PRIVATE KEY-----',
      verify: '-----BEGIN PUBLIC KEY-----\n'+
        'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKT8kGk6ZNo3sC4IIo29leRLVD23T2r0\n'+
        'vWXBEkk2pV42HsxKAmPs789AGHH9XwbGpD7FvrcBWWgb65v32Hg/NGkCAwEAAQ==\n'+
        '-----END PUBLIC KEY-----'
   },
   tracklet : {
      piwik : {
         token_auth : '90871c8584ddf2265f54553a305b6ae1',
         domain : 'http://localhost:8888/piwik/'
      },
      mysql : {
         host : 'localhost',
         user : 'piwik',
         password : 'password',
         database : 'piwik',
         multipleStatements : 'true'
      }
   }
};

authApi(config);