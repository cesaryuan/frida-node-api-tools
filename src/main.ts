import { findInReadableRanges } from "./utils/frida-utils";

function findJSONGetFuncAddress(electronModule: Module | undefined = undefined): NativePointer {
    const m = electronModule ?? Process.enumerateModules()[0];

    // Firstly, find the string "devTools" address in the memory
    const pattern = new MatchPattern("65 6D 62 65 64 64 65 72 00 64 65 76 54 6F 6F 6C 73");
    const string_embedder_devtools = findInReadableRanges(m, pattern)[0];
    const string_devTools = string_embedder_devtools.address.add(9);
    console.log(
        string_devTools.readCString(),
        "at address",
        string_devTools,
        ". MatchPattern:",
        string_devTools.toMatchPattern()
    );

    // Then, because "devTools" is a parameter of this func, we can find the call instruction calling gin_helper::Dictionary::Get<char[9],bool>
    // In the pattern, 68 means push, and e8 means call
    const call_GinHelperGetdevTools = findInReadableRanges(
        m,
        `68 ${string_devTools.toMatchPattern()} e8`
    )[0].address.add(5);

    // Finally, we can find the start of the function
    const GinHelperGetdevTools = call_GinHelperGetdevTools
        .add(call_GinHelperGetdevTools.add(1).readS32())
        .add(5);
    console.log("Find GinHelperGetdevTools at", GinHelperGetdevTools);
    return GinHelperGetdevTools;
}