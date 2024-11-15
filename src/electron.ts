/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
// import { NapiValue, buffer_to_file } from "./node-api-tools.js";

import { forceOpenDevtools } from "./utils/electron-exe-tools.js";
import { NapiValue, buffer_to_file } from "./utils/node-api-tools.js";
import { appendLineToFile, getProcessDir } from "./utils/frida-utils.js";

function hook_create_string() {
    const napi_create_string_utf8 = Module.getExportByName(null, "napi_create_string_utf8");
    let index = 0;
    if (napi_create_string_utf8) {
        console.log("绑定成功");
        Interceptor.attach(napi_create_string_utf8, {
            onEnter: function (args) {
                const [env, str, len, result] = [args[0], args[1], args[2], args[3]];
                console.log("napi_create_string_utf8", "调用", env, str.readCString(), len, result);
                if (len.toInt32() > 100) {
                    // 过滤出大文件
                    index += 1;
                    buffer_to_file(
                        str.readByteArray(len.toInt32())!,
                        "export_" + String(index) + ".js"
                    );
                }
            },
        });
    } else {
        console.log("绑定失败");
    }
}

function saveByteCodeToFile(processDir: string) {
    const napi_set_named_property = Module.getExportByName(null, "napi_set_named_property");
    if (napi_set_named_property) {
        let filenum = 0;
        Interceptor.attach(napi_set_named_property, {
            onEnter: function (args) {
                const [env, , name, value] = [args[0], args[1], args[2], args[3]];
                const nameStr = name.readCString();
                console.log(`Enter napi_set_named_property: name: ${nameStr}, value: ${value}`);
                if (nameStr == "cachedData") {
                    const cachedData = NapiValue.from(env, value);
                    const buf = cachedData.getArrayBuffer();
                    buffer_to_file(
                        buf,
                        processDir + `\\cachedData_${filenum++}_${buf.byteLength}.bin`
                    );
                }
            },
        });
    } else {
        console.error("Cannot find napi_set_named_property");
    }
}

function main() {
    const module = Process.enumerateModules()[0];
    console.log(module.name, module.base, new NativePointer(module.size).toString(16));
    // const TargetProcessCreate = module.base.add(0x20E2C00)
    // Interceptor.attach(TargetProcessCreate, {
    //     onEnter: function (args) {
    //         const [exePath, fullPathWithCmd, ] = [args[0], args[1], args[2]];
    //         console.log(`Enter TargetProcessCreate: exePath: ${exePath.readUtf16String()}, fullPathWithCmd: ${fullPathWithCmd.readUtf16String()}`);

    //         const modifiedCmd = fullPathWithCmd.readUtf16String()!.replace(/--remote-debugging-port=9222/g, "--remote-debugging-port=9223");
    //         const buf = Memory.allocUtf16String(modifiedCmd);
    //         this.buf = buf;
    //         args[1] = buf;
    //     },
    // });

    Interceptor.attach(module.base.add(0x1403B1F60 - 0x140000000), {
        onEnter: function (args) {
            const thisPtr = (this.context as X64CpuContext)["rdx"];
            // const [thisPtr, activate] = [args[0], args[1]];
            console.log(`Enter ShowDevTools`, thisPtr, args[1]);
        }
    });
}

interface Parameters {
    forceOpenDevTools?: boolean;
    logToFile?: boolean;
    saveByteCodeToFile?: boolean;
}

let logFile: File | null = null;
rpc.exports = {
    init(stage, options: Parameters) {
        // main(); return;
        const is32 = Process.arch === "ia32";
        const defaultOption: Parameters = {
            "forceOpenDevTools": true,
            "logToFile": true,
            "saveByteCodeToFile": false,
        };
        options = Object.assign(defaultOption, options);
        if (options.logToFile) {
            const processPath = Process.enumerateModules()[0].path;
            type overrideKeys = "log" | "warn" | "error";
            const keys = ["log", "warn", "error"] as overrideKeys[];
            const origin: Pick<Console, overrideKeys> = {
                log: console.log,
                warn: console.warn,
                error: console.error,
            };
            logFile = new File(processPath + ".frida.log", "a");
            for (const key of keys) {
                const originFunc = origin[key];
                console[key] = function (...args) {
                    appendLineToFile(
                        logFile!,
                        `[${new Date().toLocaleString()}] ${key}: ${args.join(" ")}`
                    );
                    originFunc.apply(console, args);
                };
            }
        }
        const module = Process.enumerateModules()[0];
        console.log(
            `Init: Stage: , found module ${module.name}, base: ${module.base}, size: ${
                module.size
            }, parameters: ${JSON.stringify(options)}`
        );
        if (!module.name.toLocaleLowerCase().endsWith(".exe")) return;
        try {
            if (options.forceOpenDevTools) {
                forceOpenDevtools(module, {
                    whenF12Pressed: true,
                    whenWindowShow: false,
                });
            }
            if (options.saveByteCodeToFile) {
                saveByteCodeToFile(getProcessDir());
            }
        } catch (e) {
            console.error(e);
        }

    },
    dispose() {
        logFile?.close();
        console.log("Dispose");
    },
};
