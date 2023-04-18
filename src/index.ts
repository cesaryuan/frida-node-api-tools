// debugger;
// Process.enumerateModules().forEach(function (module) {
//     console.log(module.name, module.base, module.size);
//     // for (var i = 0; i < module.enumerateExports().length; i++) {
//     //     if (module.enumerateExports()[i].name == 'function') {
//     //         console.log(module.enumerateExports()[i].name, module.enumerateExports()[i].address);
//     //     }
//     // }
// });

import { NapiEnv, NapiValue, buffer_to_file } from "./node-api-tools.js";


function hook_create_string(){
    let napi_create_string_utf8 = Module.getExportByName(null, 'napi_create_string_utf8');
    let index = 0;
    if (napi_create_string_utf8) {
        console.log('绑定成功');
        Interceptor.attach(napi_create_string_utf8, {
            onEnter: function (args) {
                let [env, str, len, result] = [args[0], args[1], args[2], args[3]]
                console.log('napi_create_string_utf8', '调用', env, str.readCString(), len, result);
                if (len.toInt32() > 100) { // 过滤出大文件
                    index += 1;
                    let f = new File('export_' + String(index) + '.js', 'wb');
                    f.write(str.readByteArray(len.toInt32())!);
                    f.flush();
                    f.close();
                }
            }
        });
    } else {
        console.log('绑定失败');
    }
}

function hook_set_named_property(){
    enum napi_valuetype {
        // ES6 types (corresponds to typeof)
        napi_undefined,
        napi_null,
        napi_boolean,
        napi_number,
        napi_string,
        napi_symbol,
        napi_object,
        napi_function,
        napi_external,
        napi_bigint,
    }
    let napi_set_named_property = Module.getExportByName(null, 'napi_set_named_property');
    if (napi_set_named_property) {
        console.log('绑定成功');
        let filenum = 0;
        Interceptor.attach(napi_set_named_property, {
            onEnter: function (args) {
                let [env, object, name, value] = [args[0], args[1], args[2], args[3]]
                // console.log('napi_set_named_property', '调用', env, object, name.readCString(), value);
                if (name.readCString() == 'cachedData') {
                    let cachedData = NapiValue.from(NapiEnv.from(env), value);
                    buffer_to_file(cachedData.getArrayBuffer(), `cachedData_${filenum++}.bin`);
                    console.log('cachedData', cachedData.getProperty('constructor').getProperty('name').getString());
                }

            }
        });
    } else {
        console.log('绑定失败');
    }
}

hook_set_named_property()

