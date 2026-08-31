// Non-Node backend selector.
//
// Resolved by the "#native" subpath import in package.json for every runtime
// that is not Node: browsers, Deno's browser-ish targets, bundlers. There is no
// OpenSSL to reach for there, so the wrapper uses its JavaScript backend and
// nothing about its behaviour changes.
//
// Keeping this as a separate file rather than a runtime check is deliberate: a
// bundler that saw `import('node:crypto')` anywhere in the graph would either
// fail to resolve it or ship a polyfill, and this package is documented as
// working unmodified in a browser.

export const native = null
