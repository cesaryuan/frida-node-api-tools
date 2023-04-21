/* eslint-disable @typescript-eslint/no-non-null-assertion */
// import { NapiValue, buffer_to_file } from "./node-api-tools.js";

import { forceOpenDevtools } from "./electron-exe-tools.js";


// function hook_create_string() {
//     const napi_create_string_utf8 = Module.getExportByName(null, "napi_create_string_utf8");
//     let index = 0;
//     if (napi_create_string_utf8) {
//         console.log("绑定成功");
//         Interceptor.attach(napi_create_string_utf8, {
//             onEnter: function (args) {
//                 const [env, str, len, result] = [args[0], args[1], args[2], args[3]];
//                 console.log("napi_create_string_utf8", "调用", env, str.readCString(), len, result);
//                 if (len.toInt32() > 100) {
//                     // 过滤出大文件
//                     index += 1;
//                     buffer_to_file(
//                         str.readByteArray(len.toInt32())!,
//                         "export_" + String(index) + ".js"
//                     );
//                 }
//             },
//         });
//     } else {
//         console.log("绑定失败");
//     }
// }

// function hook_set_named_property() {
//     const napi_set_named_property = Module.getExportByName(null, "napi_set_named_property");
//     if (napi_set_named_property) {
//         console.log("绑定成功");
//         let filenum = 0;
//         Interceptor.attach(napi_set_named_property, {
//             onEnter: function (args) {
//                 const [env, , name, value] = [args[0], args[1], args[2], args[3]];
//                 // console.log('napi_set_named_property', '调用', env, object, name.readCString(), value);
//                 if (name.readCString() == "cachedData") {
//                     const cachedData = NapiValue.from(env, value);
//                     buffer_to_file(cachedData.getArrayBuffer(), `cachedData_${filenum++}.bin`);
//                     console.log(
//                         "cachedData",
//                         cachedData.getProperty("constructor").getProperty("name").getString()
//                     );
//                 }
//             },
//         });
//     } else {
//         console.log("绑定失败");
//     }
// }


function main(){
    const module = Process.enumerateModules()[0];
    console.log(module.name, module.base, new NativePointer(module.size).toString(16));
    forceOpenDevtools(module);
    // findOpenDevToolsAddress();
    // findGinHelperGetdevTools();
    // findLoadURLAddress();
    // findBaseWindowOnWindowShow();
}

main();