/**
 * Created by showjoy on 16/5/30.
 */
var path = require('path');
var fs = require('fs');
module.exports = function(spon){
  var esprima = require('./esprima.js');
  var engine = require('./engine.js');
  var analyzer = require('./analyzer.js');
  var log = function(msg){
    require('./stdout.js')(msg);
  };

  spon.cli
    .command('xss [cmd]')
    .description('xss检测')
    .action(function(cmd,op){
      if(typeof cmd == 'string'){
        fs.readFile(path.join(process.cwd(),'src/pages/',cmd,cmd + '.js'),'utf8',function(err,data){
          if(err){
            log('[{red}]error: XSS Plugin发生错误，无法读取指定js代码[{/red}]')
          }
          var result = esprima.parse(data, {
            loc: true,
            comment: false,
            raw: false,
            range: false,
            tolerant: false
          });
          var str_result = JSON.stringify(result, null, 4);

          engine.analyze(str_result);
          engine.asignFunctionReturnValue(analyzer.sink);
          analyzer.analyzeArrays(engine.real_func_names, engine.real_func_call, engine.real_variable_const, engine.real_variable_var, engine.real_variable_obj, engine.startScope, engine.endScope, data);
        });
      }

    });
};