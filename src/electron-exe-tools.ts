import { findInReadableRanges } from "./frida-utils.js";

/**
 * WebContents::OpenDevTools
 */
function findOpenDevToolsAddress(electronModule: Module | undefined = undefined): NativePointer {
    const m = electronModule ?? Process.enumerateModules()[0];
    // Firstly, find the middle part of the openDevTools function
    const pattern = new MatchPattern("8B 41 68 83 F8 03 0F 84 ?? ?? ?? ?? 89 CE 80 79 75 00 0F 84");
    const a = findInReadableRanges(m, pattern);
    if (a.length > 1) throw new Error("find more than one matches");
    if (a.length == 0) throw new Error("find no matches");
    const [match] = a;
    // Then, find the start of the function
    const [func_start] = Memory.scanSync(match.address.sub(0x20), 0x20, "55 89 e5 53 57 56");
    console.log(`Find WebContents::OpenDevTools start at ${func_start.address}`);
    return func_start.address;
}

/**
 * gin_helper::Dictionary::Get<char[9],bool>
 */
function findGinHelperGetdevTools(electronModule: Module | undefined = undefined): NativePointer {
    const m = electronModule ?? Process.enumerateModules()[0];

    // Firstly, find the string "devTools" address in the memory
    const pattern = new MatchPattern("65 6D 62 65 64 64 65 72 00 64 65 76 54 6F 6F 6C 73");
    const string_embedder_devtools = findInReadableRanges(m, pattern)[0];
    const string_devTools = string_embedder_devtools.address.add(9);
    console.log(string_devTools.readCString(), "at address", string_devTools, ". MatchPattern:", string_devTools.toMatchPattern());
    
    // Then, because "devTools" is a parameter of this func, we can find the call instruction calling gin_helper::Dictionary::Get<char[9],bool>
    // In the pattern, 68 means push, and e8 means call
    const call_GinHelperGetdevTools = findInReadableRanges(m, `68 ${string_devTools.toMatchPattern()} e8`)[0].address.add(5)
    
    // Finally, we can find the start of the function
    const GinHelperGetdevTools = call_GinHelperGetdevTools.add(call_GinHelperGetdevTools.add(1).readS32()).add(5);
    console.log("Find GinHelperGetdevTools at", GinHelperGetdevTools);
    return GinHelperGetdevTools;
}

/** 
 * WebContents::LoadURL
 */
function findLoadURLAddress(electronModule: Module | undefined = undefined): NativePointer {
    const m = electronModule ?? Process.enumerateModules()[0];
    // Firstly, find the middle part of the LoadURL function
    const pattern = new MatchPattern("89 84 24 ?? ?? ?? ?? 80 7B 0C 00 74 1E 89 D9 E8");
    const a = findInReadableRanges(m, pattern);
    if (a.length > 1) throw new Error("find more than one matches");
    if (a.length == 0) throw new Error("find no matches");
    const [match] = a;
    // Then, find the start of the function
    const [func_start] = Memory.scanSync(match.address.sub(0x35), 0x35, "55 89 e5 53 57 56");
    console.log(`Find WebContents::LoadURL start at ${func_start.address}`);
    return func_start.address;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function findBrowserWindowOnWindowFocus(electronModule: Module | undefined = undefined): NativePointer {
    // todo: not tested
    const m = electronModule ?? Process.enumerateModules()[0];
    const pattern = new MatchPattern("84 C0 74 3B 8B 8E ?? ?? ?? ?? ?? ?? ?? ?? ?? 84 C0 75 1E 8B 4D F0 E8");
    const a = findInReadableRanges(m, pattern);
    if (a.length > 1) throw new Error("find more than one matches");
    if (a.length == 0) throw new Error("find no matches");
    const [match] = a;
    const [func_start] = Memory.scanSync(match.address.sub(0x50), 0x50, "55 89 e5 53 57 56");
    console.log(`Find WebContents::LoadURL start at ${func_start.address}`);
    return func_start.address;
}

function findBaseWindowOnWindowShow(electronModule: Module | undefined = undefined): NativePointer {
    const m = electronModule ?? Process.enumerateModules()[0];
    // Firstly, find the string "show" address
    const pattern = new MatchPattern("62 6c 75 72 00 73 68 6f 77 00 68 69");
    const a = findInReadableRanges(m, pattern);
    if (a.length > 1) throw new Error("find more than one matches");
    if (a.length == 0) throw new Error("find no matches");
    const [string_blur_show_hide] = a;
    const string_show = string_blur_show_hide.address.add(5);

    // Then, because OnWindowShow will emit the "show" event, we can find the fucntion by this
    const [BaseWindowOnWindowShow] = findInReadableRanges(m, `55 89 E5 83 C1 F4 6A 04 68 ${string_show.toMatchPattern()} E8 ?? ?? ?? ?? 5D C3`);
    console.log(`Find BaseWindow::OnWindowShow start at ${BaseWindowOnWindowShow.address}`);
    return BaseWindowOnWindowShow.address;
}

function findWebContentsPreHandleKeyboardEvent(electronModule: Module | undefined = undefined): NativePointer {
    const m = electronModule ?? Process.enumerateModules()[0];
    // Firstly, find the string "show" address
    const pattern = new MatchPattern("53 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 88 44 24 ?? 89 D9 E8");
    const a = findInReadableRanges(m, pattern);
    if (a.length > 1) throw new Error("find more than one matches");
    if (a.length == 0) throw new Error("find no matches");
    const [match] = a;
    // Then, find the start of the function
    const [func_start] = Memory.scanSync(match.address.sub(0x174-0xe8), 0x174-0xe8, "55 89 e5 53 57 56");
    console.log(`Find WebContents::PreHandleKeyboardEvent start at ${func_start.address}`);
    return func_start.address;
}

function forceOpenDevtools(electronModule: Module | undefined = undefined, {whenF12Pressed = true, whenWindowShow = false} = {}) {
    const module = electronModule ?? Process.enumerateModules()[0];
    const OpenDevToolsFunction = new NativeFunction(
        findOpenDevToolsAddress(module),
        // m.add(0x59f640 - 0x400000),
        'void',
        ['pointer', 'pointer'],
        "thiscall"
    );
    // let devTools option always true
    // const gin_helper_get_devtools = m.add(0x541400 - 0x400000);
    const gin_helper_get_devtools = findGinHelperGetdevTools(module);
    Interceptor.attach(gin_helper_get_devtools, {
        onEnter: function (args) {
            const thisPtr = (this.context as Ia32CpuContext)['ecx'];
            console.log("Enter gin_helper::Dictionary::Get: thisPtr", thisPtr);
            const [key, output, ] = [args[0], args[1], args[2]];
            this.output = output;
            this.key = key.readUtf8String();
            console.log("gin_helper::Dictionary::Get", key.readCString())
        },
        onLeave: function () {
            console.log("Leave gin_helper::Dictionary::Get");
            console.log("gin_helper::Dictionary::Get", this.key + " option before hook", this.output.readU8() == 1);
            this.output.writeU8(1);
            console.log("gin_helper::Dictionary::Get", this.key + " option after hook", this.output.readU8() == 1);
        }
    });

    if(whenWindowShow){
        let firstWebContentsPtr: NativePointer | null = null;
        let firstBaseWindowPtr: NativePointer | null = null;
        let offsetWinAndWebContents: number | null = null;
        /**
         * 这里采取的计算offset的方式是通过记录第一个被创建的BrowserWindow和WebContents的地址，然后计算出offset
         * WebContents的地址是通过Hook WebContents::LoadURL获取的；BrowserWindow的地址是通过Hook BrowserWindow::OnWindowShow获取的
         * 这基于以下假设：
         * 1. 所有WebContents都会调用LoadURL
         * 2. 每一个WebContents都会被一个BrowserWindow持有
         * @param windowPtr 
         * @returns 
         */
        const windowPtrToWebContentsPtr = function(windowPtr: NativePointer): NativePointer {
            if (offsetWinAndWebContents === null && firstBaseWindowPtr !== null && firstWebContentsPtr !== null) {
                offsetWinAndWebContents = Memory.scanSync(firstBaseWindowPtr, 0x100, firstWebContentsPtr.toMatchPattern())[0].address.sub(firstBaseWindowPtr).toInt32();
                console.log('Calculate offset between BrowserWindow and WebContents:', offsetWinAndWebContents);
            } else {
                offsetWinAndWebContents = 0x8c;
            }
            const webContentsPtr = windowPtr.add(offsetWinAndWebContents).readPointer();
            console.log("webContentsPtr", webContentsPtr);
            return webContentsPtr;
        }
        // const WebContentsLoadURL = m.add(0x59e200 - 0x400000);
        const WebContentsLoadURL = findLoadURLAddress(module);
        Interceptor.attach(WebContentsLoadURL, {
            onEnter: function (args) {
                const thisPtr = (this.context as Ia32CpuContext)['ecx'];
                if (firstWebContentsPtr === null) {
                    firstWebContentsPtr = thisPtr;
                }
                const [url,] = [args[0], args[1]];
                const urlString = url.add(8).readPointer().readCString();
                console.log(`Enter WebContents::LoadURL: thisPtr ${thisPtr}, url ${urlString}`);
            }
        });

        const BaseWindowOnWindowShow = findBaseWindowOnWindowShow(module);
        Interceptor.attach(BaseWindowOnWindowShow, {
            onEnter: function () {
                const thisPtr = (this.context as Ia32CpuContext)['ecx'];
                console.log(`Enter BaseWindow::OnWindowShow: thisPtr ${thisPtr}`);
                if (firstBaseWindowPtr === null) {
                    firstBaseWindowPtr = thisPtr;
                }
                OpenDevToolsFunction(windowPtrToWebContentsPtr(thisPtr), ptr(0));
            }
        });
    }

    if(whenF12Pressed){
        const WebContentsPreHandleKeyboardEvent = findWebContentsPreHandleKeyboardEvent(module);
        Interceptor.attach(WebContentsPreHandleKeyboardEvent, {
            onEnter: function (args) {
                const thisPtr = (this.context as Ia32CpuContext)['ecx'];
                const [, nativeWebKeyboardEvent] = [args[0], args[1]];
                const eventType = nativeWebKeyboardEvent.add(0x20).readU32();
                const modifiers_ = nativeWebKeyboardEvent.add(0x24).readU32();
                const windows_key_code = nativeWebKeyboardEvent.add(0x28).readU32();
                console.log(`Enter WebContents::PreHandleKeyboardEvent: thisPtr ${thisPtr}, eventType ${eventType}, modifiers_ ${modifiers_}, windows_key_code ${windows_key_code}`);
                // if key is F12 and type is kKeyUp
                if (windows_key_code === 123 && (eventType === 9)) {
                    console.log(`F12 pressed, open devtools`);
                    // todo: 我也不知道为什么这里要减0x1c，理论上应该是不需要的
                    OpenDevToolsFunction(thisPtr.sub(0x1c), ptr(0));
                }
            }
        });
    }
}

export {
    forceOpenDevtools,
}