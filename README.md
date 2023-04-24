
# frida-node-api-tools

Frida script to intercept with NodeJS API and Electron Application


## Usage

See `src/index.js` for sample code.

## Features

- [x] Intercept NodeJS API
- [x] Intercept Electron API
- [x] Force open Electron devtools (only support 32bit Electron)
  `frida -l build/_agent.js --exit-on-error --kill-on-exit -f <path/to/electron>` Then press F12 in Electron window.