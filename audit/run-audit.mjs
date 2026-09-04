// Dependency audit: every production dependency, reviewed and then re-checked.
//
// `npm audit` answers one question, which is whether anything in the tree has a
// published advisory. That is worth knowing and it is not an audit. It says
// nothing about why a package is present, what is actually called from it,
// whether anyone has ever reviewed its source, whether the version is pinned or
// floating, or whether it can run code at install time.
//
// audit/dependency-review.json holds the answers to those, written by a person.
// This file re-derives every mechanical fact from the lockfile, the registry and
// the installed tree, and fails if any of them has moved away from what the
// review records. A new or bumped dependency therefore breaks the build until
// somebody reviews it, which is the only way a document like this stays true.
//
// Usage:  node audit/run-audit.mjs [--json PATH] [--offline] [--quiet]

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, resolve as resolvePath, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolvePath(HERE, '..')
const args = process.argv.slice(2)
const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null
const offline = args.includes('--offline')
const quiet = args.includes('--quiet')

// npm is a .cmd shim on Windows, and since the CVE-2024-27980 mitigation Node
// refuses to spawn one without a shell. Both have to be handled or the two
// network checks fail with ENOENT then EINVAL and report as a tooling problem
// rather than as the passes they are.
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const SHELL = process.platform === 'win32'
const npmJson = (argv) => execFileSync(NPM, argv, {
  cwd: ROOT, encoding: 'utf8', shell: SHELL, stdio: ['ignore', 'pipe', 'ignore'],
})

const read = (p) => JSON.parse(readFileSync(join(ROOT, p), 'utf8'))
const pkg = read('package.json')
const lock = read('package-lock.json')
const review = read('audit/dependency-review.json')

const findings = []
function check(name, ok, detail, extra = {}) {
  findings.push({ name, ok, detail: ok ? '' : detail, ...extra })
  return ok
}

// ------------------------------------------------------- the production tree
//
// From the lockfile rather than from `npm ls`, so the audit reads the same file
// the installer does and a report can be produced without a working install.

const treePackages = new Map()
for (const [path, entry] of Object.entries(lock.packages ?? {})) {
  if (!path.startsWith('node_modules/')) continue
  if (entry.dev || entry.optional || entry.peer) continue
  const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length)
  treePackages.set(name, {
    name,
    version: entry.version,
    resolved: entry.resolved,
    integrity: entry.integrity,
    licence: entry.license,
    hasInstallScript: entry.hasInstallScript === true,
  })
}

// ------------------------------------------------------------- reachability
//
// Which packages this package's published surface can actually load. Walked
// statically from every entry point in `exports`, resolving each specifier with
// import.meta.resolve so subpath exports and the #native conditional import are
// resolved the way Node resolves them rather than guessed at.
//
// Both branches of #native are reached because both files live in src/, so the
// answer is the union of the Node and browser paths. That is the safe direction
// to be wrong in: it can only over-report what is reachable.

// Import specifiers are read from code only. A plain regex over the whole file
// also matches inside comments and strings, and it did: src/seed.js throws
// `the public key derived from 'priv' does not match 'pub'`, so the scanner
// reported an unresolvable module named "priv" and failed the audit. A false
// FAIL in the dependency job is worse than no job, because it teaches everyone
// to ignore a red supply-chain check.
//
// This walks the source once tracking comment and string state, and treats a
// quote as a specifier only when the code before it ends in `from`, `import(`
// or `require(`.
function specifiersOf(src) {
  const out = []
  // Not preceded by a dot: `Buffer.from('020100', 'hex')` is a method call,
  // not an import, and matching it reported a module named "020100".
  const KEY = /(?<![.\w$])(?:from|import|require)\s*\(?\s*$/
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (c === '/' && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i)
      if (nl === -1) break
      i = nl
      continue
    }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2)
      i = end === -1 ? src.length : end + 2
      continue
    }
    if (c === '"' || c === "'" || c === '`') {
      const start = i
      i += 1
      while (i < src.length && src[i] !== c) {
        if (src.charCodeAt(i) === 92) i += 1 // backslash escape
        i += 1
      }
      if (KEY.test(src.slice(0, start))) out.push(src.slice(start + 1, i))
      i += 1
      continue
    }
    i += 1
  }
  return out
}

function walkReachable() {
  const roots = Object.values(pkg.exports ?? {})
    .map((e) => (typeof e === 'string' ? e : e.import))
    .filter(Boolean)
    .map((rel) => pathToFileURL(join(ROOT, rel)).href)

  const seen = new Set()
  const packages = new Set()
  const builtins = new Set()
  const queue = [...roots]

  while (queue.length) {
    const url = queue.shift()
    if (seen.has(url)) continue
    seen.add(url)

    let text
    try {
      text = readFileSync(fileURLToPath(url), 'utf8')
    } catch {
      continue
    }

    for (const spec of specifiersOf(text)) {
      if (spec.startsWith('node:')) {
        builtins.add(spec)
        continue
      }
      let resolved
      try {
        resolved = import.meta.resolve(spec, url)
      } catch {
        // An unresolvable specifier is itself worth reporting rather than
        // swallowing, because it would silently shrink the reachable set.
        findings.push({ name: `reachability:${spec}`, ok: false, detail: `could not resolve ${spec} from ${url}` })
        continue
      }
      if (resolved.startsWith('node:')) {
        builtins.add(resolved)
        continue
      }
      const path = fileURLToPath(resolved)
      const idx = path.lastIndexOf(`node_modules${sep}`)
      if (idx !== -1) {
        const rest = path.slice(idx + `node_modules${sep}`.length).split(sep)
        packages.add(rest[0].startsWith('@') ? `${rest[0]}/${rest[1]}` : rest[0])
      }
      queue.push(resolved)
    }
  }
  return { packages, builtins, filesWalked: seen.size }
}

const reach = walkReachable()

// ------------------------------------------------------------------- checks

// 1. The review covers the tree exactly. This is the check that makes the rest
//    trustworthy: without it, a new dependency would simply not be looked at.
const reviewed = new Set(review.packages.map((p) => p.name))
const inTree = new Set(treePackages.keys())
const unreviewed = [...inTree].filter((n) => !reviewed.has(n))
const departed = [...reviewed].filter((n) => !inTree.has(n))

check('every production dependency is reviewed', unreviewed.length === 0,
  `not in audit/dependency-review.json: ${unreviewed.join(', ')}`)
check('the review names no dependency that has left the tree', departed.length === 0,
  `reviewed but absent from the lockfile: ${departed.join(', ')}`)
check('the tree is within the declared ceiling', inTree.size <= review.policy.maxProductionDependencies,
  `${inTree.size} production dependencies, policy allows ${review.policy.maxProductionDependencies}`)

// 2. Direct dependencies are pinned exactly. A range is a decision to accept
//    code nobody has reviewed, taken in advance.
for (const [name, range] of Object.entries(pkg.dependencies ?? {})) {
  check(`${name} is pinned exactly`, /^\d+\.\d+\.\d+$/.test(range),
    `declared as "${range}", which accepts versions this audit has not reviewed`)
}
check('no devDependencies', Object.keys(pkg.devDependencies ?? {}).length === 0,
  'devDependencies are present and are not covered by this audit')

// 3. Per package: version, licence, install scripts, reachability.
const perPackage = []
for (const r of review.packages) {
  const actual = treePackages.get(r.name)
  if (!actual) continue

  const versionOk = check(`${r.name} is at the reviewed version`, actual.version === r.version,
    `lockfile has ${actual.version}, the review covers ${r.version}`)

  const licenceOk = check(`${r.name} licence is allowed`,
    review.policy.allowedLicences.includes(actual.licence ?? r.licence),
    `licence is ${actual.licence ?? 'undeclared'}, allowed: ${review.policy.allowedLicences.join(', ')}`)

  const scriptOk = check(`${r.name} runs no install script`,
    review.policy.allowInstallScripts || !actual.hasInstallScript,
    'the lockfile marks this package as having an install script')

  const isReachable = reach.packages.has(r.name)
  const reachOk = check(`${r.name} reachability matches the review`, isReachable === r.reachable,
    r.reachable
      ? 'the review says this is used, but no import path from the published entry points reaches it'
      : 'the review says this is unused, but it is now reachable from the published entry points')

  perPackage.push({
    ...r,
    resolvedVersion: actual.version,
    resolved: actual.resolved,
    integrity: actual.integrity,
    reachableNow: isReachable,
    checks: { versionOk, licenceOk, scriptOk, reachOk },
  })
}

// 4. Advisories and registry attestations. These need the network, so they are
//    skippable, and a skip is recorded as a skip rather than as a pass.
let advisories = null
let signatures = null
if (offline) {
  findings.push({ name: 'advisory and signature checks', ok: null, detail: 'skipped: --offline' })
} else {
  try {
    advisories = JSON.parse(npmJson(['audit', '--omit=dev', '--json'])).metadata.vulnerabilities
  } catch (e) {
    // npm audit exits non-zero when it finds something, so the body still matters.
    try {
      advisories = JSON.parse(e.stdout).metadata.vulnerabilities
    } catch {
      advisories = null
    }
  }
  if (advisories) {
    check('no known advisories', advisories.total <= review.policy.maxVulnerabilities,
      `npm audit reports ${advisories.total}: ${JSON.stringify(advisories)}`)
  } else {
    findings.push({ name: 'no known advisories', ok: null, detail: 'npm audit produced no parseable output' })
  }

  // `npm audit signatures --json` reports what failed rather than what passed:
  // { invalid: [...], missing: [...] }. Assert on those. Counting how many
  // packages npm says it audited and comparing it to our own count of the
  // production tree is a different denominator, and it failed in CI at 6 of 4
  // while nothing was actually wrong.
  try {
    const sig = JSON.parse(npmJson(['audit', 'signatures', '--json']))
    const invalid = sig.invalid ?? []
    const missing = sig.missing ?? []
    signatures = {
      invalid: invalid.length,
      missing: missing.length,
      productionTree: inTree.size,
    }
    const describe = (list) => list
      .map((e) => (typeof e === 'string' ? e : `${e.name}@${e.version}`))
      .join(', ')
    check('no package has an invalid registry signature or attestation',
      !review.policy.requireRegistrySignature || invalid.length === 0,
      `invalid: ${describe(invalid)}`)
    check('no package is missing a registry signature or attestation',
      !review.policy.requireProvenanceAttestation || missing.length === 0,
      `missing: ${describe(missing)}`)
  } catch (e) {
    findings.push({ name: 'registry signatures and attestations', ok: false, detail: `npm audit signatures failed: ${String(e.message).split('\n')[0]}` })
  }
}

// 5. The installed tree carries no install-time hook, checked against the files
//    on disk and not only the lockfile flag.
if (existsSync(join(ROOT, 'node_modules'))) {
  const HOOKS = ['preinstall', 'install', 'postinstall']
  const offenders = []
  const walk = (dir, depth = 0) => {
    if (depth > 4) return
    for (const name of readdirSync(dir)) {
      const p = join(dir, name)
      if (name === '.bin' || name === '.package-lock.json') continue
      let st
      try { st = statSync(p) } catch { continue }
      if (!st.isDirectory()) continue
      const manifest = join(p, 'package.json')
      if (existsSync(manifest)) {
        try {
          const m = JSON.parse(readFileSync(manifest, 'utf8'))
          const hit = HOOKS.filter((h) => (m.scripts ?? {})[h])
          if (hit.length) offenders.push(`${m.name}: ${hit.join(', ')}`)
        } catch { /* an unreadable manifest is not an install hook */ }
      }
      if (name.startsWith('@') || existsSync(join(p, 'node_modules'))) {
        walk(name.startsWith('@') ? p : join(p, 'node_modules'), depth + 1)
      }
    }
  }
  walk(join(ROOT, 'node_modules'))
  check('no package in the installed tree runs code at install time', offenders.length === 0,
    `install hooks found: ${offenders.join('; ')}`)
} else {
  findings.push({ name: 'install-time hooks', ok: null, detail: 'skipped: node_modules is not installed' })
}

// ------------------------------------------------------------------- output

const passed = findings.filter((f) => f.ok === true).length
const failed = findings.filter((f) => f.ok === false).length
const skipped = findings.filter((f) => f.ok === null).length

if (!quiet) {
  console.log(`Dependency audit for ${pkg.name}@${pkg.version}`)
  console.log(`reviewed ${review.reviewedAt} by ${review.reviewedBy}\n`)
  for (const f of findings) {
    const mark = f.ok === true ? 'PASS' : f.ok === false ? 'FAIL' : 'SKIP'
    console.log(`${mark}  ${f.name}${f.detail ? `\n        ${f.detail}` : ''}`)
  }
  console.log('')
  for (const p of perPackage) {
    console.log(`  ${p.name}@${p.resolvedVersion}  ${p.licence}  ${p.reachableNow ? 'reachable' : 'not reachable'}  ${p.pinning}`)
    console.log(`      external audit: ${p.externalAudit}`)
  }
  console.log(`\nwalked ${reach.filesWalked} files from ${Object.keys(pkg.exports ?? {}).length} entry points`)
  console.log(`node builtins reached: ${[...reach.builtins].sort().join(', ') || 'none'}`)
  console.log(`\n${passed} checks passed, ${failed} failed, ${skipped} skipped`)
}

if (jsonOut) {
  const out = resolvePath(ROOT, jsonOut)
  mkdirSync(dirname(out), { recursive: true })
  writeFileSync(out, JSON.stringify({
    subject: { package: pkg.name, version: pkg.version },
    review: { reviewedAt: review.reviewedAt, reviewedBy: review.reviewedBy, policy: review.policy },
    runtime: { node: process.version, platform: `${process.platform}-${process.arch}` },
    totals: { passed, failed, skipped },
    productionDependencies: inTree.size,
    devDependencies: Object.keys(pkg.devDependencies ?? {}).length,
    advisories,
    signatures,
    reachability: {
      entryPoints: Object.keys(pkg.exports ?? {}),
      filesWalked: reach.filesWalked,
      packagesReached: [...reach.packages].sort(),
      builtinsReached: [...reach.builtins].sort(),
    },
    packages: perPackage,
    findings,
  }, null, 2) + '\n')
  if (!quiet) console.log(`report written to ${jsonOut}`)
}

process.exit(failed ? 1 : 0)
