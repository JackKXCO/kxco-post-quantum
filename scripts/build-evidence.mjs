// Build dist/evidence/ — the bundle a customer's security team is handed.
//
// What this is NOT: an audit. Nobody independent has assessed this code, and a
// folder of self-generated files is not a substitute for one. The bundle says
// so, in the manifest, in the summary, and in the copied AUDIT.md, because a
// reader who mistakes it for a third-party assessment has been misled whether
// or not we intended it.
//
// What it IS: everything needed to re-run the checks and get the same answers.
// Versions, the commit, the toolchain, the backend that actually did the
// maths, the conformance output, the dependency tree, and the honest documents.
// The claim is reproducibility, not authority.
//
// Every step that fails is recorded as a failure IN the manifest rather than
// aborting the build. A bundle missing a section, with no explanation of why,
// is worse than one that says "this did not run and here is the error".
//
// Usage: node scripts/build-evidence.mjs [--out dist/evidence] [--full]

import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync, copyFileSync, readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

import { backend } from '../src/backend.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))

const args = process.argv.slice(2)
const outDir = args.includes('--out') ? args[args.indexOf('--out') + 1] : join(ROOT, 'dist', 'evidence')
const full = args.includes('--full')

mkdirSync(outDir, { recursive: true })

const steps = []

function run(name, file, argv, { optional = false } = {}) {
  const started = Date.now()
  try {
    // `npm` on Windows is a .cmd shim and needs a shell; node is a real
    // executable and MUST NOT get one, because its own path contains spaces
    // and the shell would split it.
    const needsShell = process.platform === 'win32' && file !== process.execPath
    const stdout = execFileSync(file, argv, {
      cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
      shell: needsShell,
    })
    steps.push({ name, command: [file, ...argv].join(' '), ok: true, ms: Date.now() - started })
    return stdout
  } catch (err) {
    steps.push({
      name,
      command: [file, ...argv].join(' '),
      ok: false,
      optional,
      ms: Date.now() - started,
      exitCode: err.status ?? null,
      // Both streams. npm reports a failing test suite on stdout and says
      // almost nothing on stderr, so reading only stderr records "Command
      // failed" and nothing a reader could act on — which is precisely the
      // failure this script exists to avoid.
      //
      // Tailed rather than headed: a test runner's useful output is its
      // summary and the assertion that broke, and both are at the end.
      error:
        [String(err.stderr ?? '').trim(), String(err.stdout ?? '').trim()]
          .filter(Boolean)
          .join('\n--- stdout ---\n')
          .split('\n')
          .slice(-40)
          .join('\n') || err.message,
    })
    return null
  }
}

function write(name, content) {
  const path = join(outDir, name)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content, null, 2))
  return path
}

function gitInfo() {
  const git = (argv) => {
    try {
      return execFileSync('git', argv, { cwd: ROOT, encoding: 'utf8' }).trim()
    } catch {
      return null
    }
  }
  return {
    commit: git(['rev-parse', 'HEAD']),
    shortCommit: git(['rev-parse', '--short', 'HEAD']),
    branch: git(['rev-parse', '--abbrev-ref', 'HEAD']),
    // A dirty tree means the bundle does not describe any published commit,
    // which a reader must be told rather than left to discover.
    dirty: git(['status', '--porcelain']) !== '',
    describedAt: git(['log', '-1', '--format=%cI']),
  }
}

// ── 1. identity and toolchain ───────────────────────────────────────────────

const git = gitInfo()

const identity = {
  subject: { package: pkg.name, version: pkg.version },
  git,
  toolchain: {
    node: process.version,
    openssl: process.versions.openssl,
    v8: process.versions.v8,
    platform: `${process.platform}-${process.arch}`,
  },
  // Which implementation actually did the maths on the machine that produced
  // this bundle. Two runs of the same commit on different runtimes exercise
  // different code, and a bundle that does not say which is ambiguous.
  backend: backend(),
  dependencies: pkg.dependencies,
  generatedAt: new Date().toISOString(),
}
write('01-identity.json', identity)

// ── 2. conformance ──────────────────────────────────────────────────────────
//
// The cheap sets always. SLH-DSA signature generation costs roughly two orders
// of magnitude more, so a default bundle subsamples and says so; --full does
// the whole thing.

const acvpSets = 'ML-KEM-keyGen-FIPS203,ML-KEM-encapDecap-FIPS203,ML-DSA-keyGen-FIPS204,ML-DSA-sigGen-FIPS204,ML-DSA-sigVer-FIPS204'
const acvpArgs = ['conformance/run-acvp.mjs', '--set', acvpSets, '--json', join(outDir, '02-conformance-acvp.json'), '--quiet']
if (!full) acvpArgs.push('--max-per-group', '25')
run('acvp', process.execPath, acvpArgs)

run('interop', process.execPath, [
  'conformance/interop/run-interop.mjs', '--json', join(outDir, '03-conformance-interop.json'),
], { optional: true })

// ── 3. the test suite ───────────────────────────────────────────────────────

const testOut = run('tests', 'npm', ['test'])
if (testOut !== null) write('04-tests.txt', testOut)

// ── 4. bill of materials ────────────────────────────────────────────────────
//
// CycloneDX if npm can produce it; otherwise the resolved tree, so the section
// is never simply absent.

const sbom = run('sbom', 'npm', ['sbom', '--sbom-format', 'cyclonedx', '--sbom-type', 'library'], { optional: true })
if (sbom !== null) {
  write('05-sbom.cyclonedx.json', sbom)
} else {
  const tree = run('dependency-tree', 'npm', ['ls', '--all', '--json'], { optional: true })
  if (tree !== null) write('05-dependencies.json', tree)
}

const signatures = run('npm-audit-signatures', 'npm', ['audit', 'signatures'], { optional: true })
if (signatures !== null) write('06-npm-audit-signatures.txt', signatures)

// ── 5. the honest documents ─────────────────────────────────────────────────

const docs = ['AUDIT.md', 'THREAT-MODEL.md', 'SECURITY.md', 'CONFORMANCE.md', 'DEPENDENCIES.md']
const copied = []
for (const doc of docs) {
  const from = join(ROOT, doc)
  if (existsSync(from)) {
    copyFileSync(from, join(outDir, `07-${doc}`))
    copied.push(doc)
  }
}
const productLicence = join(ROOT, 'LICENCE-PRODUCT.md')
if (existsSync(productLicence)) {
  copyFileSync(productLicence, join(outDir, '07-LICENCE-PRODUCT.md'))
  copied.push('LICENCE-PRODUCT.md')
}

// ── 6. manifest ─────────────────────────────────────────────────────────────

const files = []
for (const step of steps) void step
const { readdirSync, statSync } = await import('node:fs')
for (const name of readdirSync(outDir).sort()) {
  const path = join(outDir, name)
  if (!statSync(path).isFile() || name === '00-MANIFEST.json' || name === 'README.md') continue
  files.push({
    file: name,
    bytes: statSync(path).size,
    sha256: createHash('sha256').update(readFileSync(path)).digest('hex'),
  })
}

const failed = steps.filter((s) => !s.ok)
const manifest = {
  ...identity,
  // Said in the machine-readable part as well as the prose, because a reader
  // parsing this file may never open the README beside it.
  disclaimer:
    'This bundle is self-generated. No third party has assessed this code. ' +
    'It is evidence you can re-run, not an audit, and it must not be described as one.',
  steps,
  ok: failed.length === 0,
  failedSteps: failed.map((s) => s.name),
  sampling: full ? { full: true } : { full: false, maxPerGroup: 25, note: 'not a full-suite claim' },
  files,
}
write('00-MANIFEST.json', manifest)

// ── 7. the human summary ────────────────────────────────────────────────────

write('README.md', `# Evidence bundle — ${pkg.name} ${pkg.version}

Generated ${identity.generatedAt} from commit \`${git.shortCommit ?? 'unknown'}\`${git.dirty ? ' **with uncommitted changes**' : ''}.

## What this is not

**No third party has assessed this code.** There has been no external
cryptographic audit of this wrapper, and none of \`@noble/post-quantum\`, the
JavaScript backend, which has been self-audited by its maintainer only
(v0.6.1, April 2026).

The other Noble packages **have** been audited, but separately, at different
dates, and none of those engagements reached the post-quantum package:
\`@noble/hashes\` by Cure53 in January 2022, \`@noble/curves\` by Trail of Bits
in February 2023, Kudelski Security in September 2023 and Cure53 in September
2024, and \`@noble/ciphers\` by Cure53 in September 2024. Those dates are in
\`07-DEPENDENCIES.md\` and in the generated \`audit/dependency-review.json\`.

This bundle is not an audit and must not be described as one, by us or by
anyone quoting it.

## What this is

Everything needed to re-run the checks and get the same answers. The claim is
reproducibility, not authority. Every number here came from a command you can
run yourself, on this commit, and \`00-MANIFEST.json\` records the exact command
and its exit status.

| File | What it holds |
|---|---|
| \`00-MANIFEST.json\` | Every step, its command, whether it passed, and a SHA-256 of every file here |
| \`01-identity.json\` | Versions, commit, toolchain, and **which backend did the maths** |
| \`02-conformance-acvp.json\` | NIST ACVP vectors for FIPS 203 and 204 |
| \`03-conformance-interop.json\` | Cross-implementation matrix: OpenSSL, liboqs, Bouncy Castle, dilithium-py/kyber-py |
| \`04-tests.txt\` | Full test suite output |
| \`05-*\` | Bill of materials |
| \`06-npm-audit-signatures.txt\` | Registry signature and provenance attestation check |
| \`07-*\` | ${copied.length ? copied.join(', ') : 'no documents were found to copy'} |

## Backend

This run used **${identity.backend.kind}**${identity.backend.openssl ? ` (OpenSSL ${identity.backend.openssl})` : ''}.

That matters. The package prefers the OpenSSL 3.5 primitives where the runtime
provides them and falls back to JavaScript where it does not. The two agree on
the wire — the interop matrix checks every parameter set in both directions —
but a bundle that did not say which one ran would describe two different
implementations with one pass count.

Note that \`02-conformance-acvp.json\` drives the **JavaScript** primitives
directly, because NIST publishes vectors for parameter sets the wrapper does
not expose. The OpenSSL path is evidenced by \`03-conformance-interop.json\`.
You need both files to cover both implementations.

## Sampling

${full
  ? 'This is a full pass. No group was subsampled.'
  : 'This run subsampled ACVP groups at 25 cases each, so it is **not a full-suite claim**. Re-run with `--full` for a complete pass; SLH-DSA signature generation alone takes over an hour.'}

## Status

${failed.length === 0
  ? 'Every step completed.'
  : `**${failed.length} step(s) did not complete: ${failed.map((s) => s.name).join(', ')}.** See \`00-MANIFEST.json\` for the command and the error. A missing section is recorded rather than hidden.`}

## Reproducing it

\`\`\`bash
git checkout ${git.commit ?? '<commit>'}
npm ci
node scripts/build-evidence.mjs --full
\`\`\`

The vectors are pinned by digest in \`conformance/acvp-lock.json\` and the
interop peers in \`conformance/interop/peers-lock.json\`, so an upstream that is
silently rewritten fails the run rather than changing the answer.
`)

console.log(`evidence written to ${outDir}`)
console.log(`  backend: ${identity.backend.kind}${identity.backend.openssl ? ` (OpenSSL ${identity.backend.openssl})` : ''}`)
console.log(`  steps:   ${steps.length - failed.length}/${steps.length} completed`)
console.log(`  files:   ${files.length}`)
if (failed.length) {
  console.log(`  FAILED:  ${failed.map((s) => s.name).join(', ')}`)
}

// A step that was expected to work and did not should fail the build. Optional
// steps (peers that need a JVM, a registry that needs a token) must not.
const required = failed.filter((s) => !s.optional)
process.exit(required.length === 0 ? 0 : 1)
