/**
 * Scan the readable ranges of a module for a pattern.
 * When scanning the module directly, it will throw an `access violation accessing` Error if there is section(range) with `---` permission.
 * This function is a workaround for this issue.
 * @param model The module to scan
 * @param pattern The pattern to match
 * @returns The matches
 */
function findInReadableRanges(model: Module, pattern: MatchPattern | string) {
    let matches: MemoryScanMatch[] = [];
    for (const range of model.enumerateRanges("r--")) {
        matches = matches.concat(Memory.scanSync(range.base, range.size, pattern));
    }
    return matches;
}

export {
    findInReadableRanges,
}