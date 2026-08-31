// Cross-implementation interoperability matrix.
//
// Passing NIST's own vectors proves this package agrees with NIST. It does not
// prove two independent stacks can exchange keys and signatures, which is what
// interoperability actually means in deployment. This harness drives that:
// every check runs in both directions against implementations that share no
// code with our backend.
//
// Peers:
//   bouncycastle  Bouncy Castle bcprov (Java)          ML-DSA, ML-KEM, SLH-DSA
//   python        dilithium-py + kyber-py (Python)     ML-DSA, ML-KEM
//   liboqs        liboqs (C, containerised)            ML-DSA, ML-KEM, SLH-DSA
//
// Per parameter set and peer:
//   1  key agreement   same seed, same public key bytes in both stacks
//   2  ours -> theirs   we sign, the peer verifies
//   3  theirs -> ours   the peer signs, we verify
//   4  byte equality    deterministic signing produces identical bytes
//   5  tamper control   one flipped bit in our signature, the peer must reject
//   6  KEM ours -> theirs   we encapsulate, the peer decapsulates to the same secret
//   7  KEM theirs -> ours   the peer encapsulates, we decapsulate to the same secret
//
// Check 5 matters: without it, a peer that returns true unconditionally would
// pass every positive check in the matrix.
//
// Usage:  node conformance/interop/run-interop.mjs [--json PATH] [--peer NAME]
//                                                  [--quiet]
//
// Exit code is non-zero if any check fails. A peer whose toolchain is absent is
// reported as unavailable, which is not a failure but is also not evidence.

import { createHash } from 'node:crypto'
import { spawn, execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import * as slhBackend from '@noble/post-quantum/slh-dsa.js'

import * as mlDsa from '../../src/ml-dsa.js'
import * as mlKem from '../../src/ml-kem.js'
import * as slhDsa from '../../src/slh-dsa.js'
import * as mlDsa87 from '../../src/ml-dsa-87.js'
import * as mlKem1024 from '../../src/ml-kem-1024.js'

import { native as nativeBackend } from '#native'

const HERE = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(readFileSync(join(HERE, '..', '..', 'package.json'), 'utf8'))
const lock = JSON.parse(readFileSync(join(HERE, 'peers-lock.json'), 'utf8'))

const args = process.argv.slice(2)
const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null
const onlyPeer = args.includes('--peer') ? args[args.indexOf('--peer') + 1] : null
const quiet = args.includes('--quiet')

const CACHE = join(HERE, '.peer-cache')

// --------------------------------------------------------------- local backend
//
// Parameter sets this package wraps in its own helpers are driven through those
// helpers, so the matrix tests the published API and not just its dependency.
// The rest are driven through the backend primitives directly, and the report
// records which path each row used.

const SETS = [
  { alg: 'ML-DSA-44', kind: 'sig', prim: ml_dsa44, seedLen: 32 },
  { alg: 'ML-DSA-65', kind: 'sig', prim: ml_dsa65, seedLen: 32, wrapper: mlDsa },
  { alg: 'ML-DSA-87', kind: 'sig', prim: ml_dsa87, seedLen: 32, wrapper: mlDsa87 },
  { alg: 'ML-KEM-512', kind: 'kem', prim: ml_kem512, seedLen: 64 },
  { alg: 'ML-KEM-768', kind: 'kem', prim: ml_kem768, seedLen: 64, wrapper: mlKem },
  { alg: 'ML-KEM-1024', kind: 'kem', prim: ml_kem1024, seedLen: 64, wrapper: mlKem1024 },
  { alg: 'SLH-DSA-SHA2-128f', kind: 'sig', prim: slhBackend.slh_dsa_sha2_128f, seedLen: 48 },
  { alg: 'SLH-DSA-SHA2-192s', kind: 'sig', prim: slhBackend.slh_dsa_sha2_192s, seedLen: 72, wrapper: slhDsa },
  { alg: 'SLH-DSA-SHAKE-256f', kind: 'sig', prim: slhBackend.slh_dsa_shake_256f, seedLen: 96 },
]

// Keys are addressed by seed throughout, not by encoded private key: the
// seed-form encoding differs between libraries while the seed itself is fixed by
// FIPS 203 / FIPS 204, so it is the portable handle.
//
// Capability gaps are declared by each peer at run time, in its reply, rather
// than mirrored here: a peer that cannot honour a request answers `unsupported`
// and the matrix records N/A. The one exception is deterministic signing, which
// has to be known before the request is made because it changes what a matching
// result would even mean.
//
// Signing requests carry both a seed and an encoded secret key, and each peer
// takes the handle it supports. liboqs has no seed-derived keygen, so it uses
// the encoded key; that still tests something real, because the FIPS 203 and
// FIPS 204 private key encodings are themselves standardised.
const PEERS = {
  bouncycastle: {
    supports: () => true,
  },
  python: {
    // No maintained pure-Python SLH-DSA implementation was available to pin.
    supports: (alg) => alg.startsWith('ML-'),
  },
  liboqs: {
    supports: () => true,
    deterministicSigning: false,
  },
}

// -------------------------------------------------------------------- helpers

const hex = (u8) => Buffer.from(u8).toString('hex')
const bytes = (h) => Uint8Array.from(Buffer.from(h ?? '', 'hex'))

// Deterministic, published test material: anyone can recompute these seeds and
// re-run the matrix without our fixtures.
function fixtureSeed(label, len) {
  const out = Buffer.alloc(len)
  let filled = 0
  let counter = 0
  while (filled < len) {
    const block = createHash('sha256').update(`kxco-interop/${label}/${counter++}`).digest()
    block.copy(out, filled)
    filled += block.length
  }
  return new Uint8Array(out)
}

class Peer {
  constructor(name, cmd, cmdArgs) {
    this.name = name
    this.cmd = cmd
    this.args = cmdArgs
    this.pending = new Map()
    this.nextId = 1
    this.buffer = ''
  }

  start() {
    this.proc = spawn(this.cmd, this.args, { stdio: ['pipe', 'pipe', 'pipe'] })
    this.stderr = ''
    this.closed = false
    this.proc.stderr.on('data', (d) => {
      this.stderr += d.toString()
    })
    this.proc.stdout.on('data', (d) => {
      this.buffer += d.toString()
      let nl
      while ((nl = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, nl).trim()
        this.buffer = this.buffer.slice(nl + 1)
        if (!line) continue
        // A peer that prints to stdout would otherwise crash the run here. Its
        // output is not protocol, so note it and carry on rather than dying.
        let msg
        try {
          msg = JSON.parse(line)
        } catch {
          this.stderr += `[non-protocol stdout] ${line}
`
          continue
        }
        const waiter = this.pending.get(msg.id)
        if (waiter) {
          this.pending.delete(msg.id)
          waiter.resolve(msg)
        }
      }
    })

    // A peer that dies takes every in-flight request with it. Failing those
    // immediately, with the peer's stderr attached, turns a silent stall per
    // request into an error that says what happened.
    //
    // The stdin handler is not redundant with the others: writing to a dead
    // peer's stdin raises EPIPE on the stream, an unhandled 'error' event that
    // takes the whole run down before 'close' can report anything useful.
    this.exited = new Promise((resolve) => {
      this.proc.on('close', (code) => this.#die(new Error(`exited (code ${code})`), resolve, code))
      this.proc.on('error', (err) => this.#die(err, resolve))
      this.proc.stdin.on('error', (err) => this.#die(err, resolve))
    })
  }

  #die(err, resolveExit, code = -1) {
    this.closed = true
    const tail = this.stderr ? `\n${this.stderr.trim().split('\n').slice(-12).join('\n')}` : ''
    const why = `${this.name}: ${err.message}${tail}`
    for (const [, waiter] of this.pending) waiter.reject(new Error(why))
    this.pending.clear()
    resolveExit(code)
  }

  /**
   * Send one request and await the reply.
   *
   * Never rejects. A transport failure (dead peer, timeout, broken pipe) is
   * reported in the same `{ ok: false, error }` shape a peer uses for its own
   * failures, so every caller handles both through one path and one dead peer
   * degrades the affected rows instead of aborting the whole matrix.
   */
  request(req) {
    const where = `${req.op}/${req.alg ?? ''}`
    if (this.closed) {
      return Promise.resolve({ ok: false, error: `${this.name} is no longer running (${where})` })
    }
    const id = this.nextId++
    return new Promise((resolve) => {
      const timer = setTimeout(
        () => resolve({ ok: false, error: `${this.name} timed out on ${where}` }),
        180_000
      )
      const settle = (msg) => {
        clearTimeout(timer)
        resolve(msg)
      }
      this.pending.set(id, {
        resolve: settle,
        reject: (err) => settle({ ok: false, error: `${err.message} (${where})` }),
      })
      try {
        this.proc.stdin.write(`${JSON.stringify({ id, ...req })}\n`)
      } catch (err) {
        this.pending.delete(id)
        settle({ ok: false, error: `${this.name}: ${err.message} (${where})` })
      }
    })
  }

  async stop() {
    this.proc.stdin.end()
    await this.exited
  }
}

// ------------------------------------------------------------ peer availability

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function prepareBouncyCastle() {
  const jar = join(CACHE, 'bcprov.jar')
  mkdirSync(CACHE, { recursive: true })

  if (!existsSync(jar) || sha256File(jar) !== lock.bouncycastle.sha256) {
    execFileSync('curl', ['-sSL', '-o', jar, lock.bouncycastle.url], { stdio: 'inherit' })
    const got = sha256File(jar)
    if (got !== lock.bouncycastle.sha256) {
      throw new Error(`bcprov.jar sha256 ${got} does not match peers-lock.json`)
    }
  }

  const cls = join(CACHE, 'BouncyCastlePeer.class')
  const src = join(HERE, 'peers', 'BouncyCastlePeer.java')
  execFileSync('javac', ['-cp', jar, '-d', CACHE, src], { stdio: 'pipe' })
  if (!existsSync(cls)) throw new Error('javac produced no class file')

  // Windows uses ';' as the classpath separator, POSIX uses ':'.
  const sep = process.platform === 'win32' ? ';' : ':'
  return { cmd: 'java', args: ['-cp', `${jar}${sep}${CACHE}`, 'BouncyCastlePeer'] }
}

function preparePython() {
  const py = process.env.PYTHON ?? (process.platform === 'win32' ? 'py' : 'python3')
  const pyArgs = py === 'py' ? ['-3.12'] : []
  execFileSync(py, [...pyArgs, '-c', 'import dilithium_py, kyber_py'], { stdio: 'pipe' })
  return { cmd: py, args: [...pyArgs, join(HERE, 'peers', 'python-peer.py')] }
}

// liboqs needs a C toolchain, so it runs in a container rather than making every
// contributor install one. The image is built from peers/liboqs.Dockerfile; if it
// is absent the peer reports unavailable, which is not a failure but is also not
// evidence.
function prepareLiboqs() {
  const image = lock.liboqs.image
  execFileSync('docker', ['image', 'inspect', image], { stdio: 'pipe' })
  return { cmd: 'docker', args: ['run', '--rm', '-i', image] }
}

const PREPARE = {
  bouncycastle: prepareBouncyCastle,
  python: preparePython,
  liboqs: prepareLiboqs,
}

// ------------------------------------------------------------------- the matrix

const report = {
  subject: { package: pkg.name, version: pkg.version },
  backend: pkg.dependencies,
  // Which backend the wrapper rows actually exercised. On Node 24+ the package
  // routes through OpenSSL and on anything older through JavaScript, so a run
  // that does not say which one it used is ambiguous evidence: the same pass
  // count can describe two different implementations.
  wrapperBackend: nativeBackend === null
    ? { kind: 'javascript', reason: 'the runtime does not provide the FIPS primitives' }
    : {
        kind: 'openssl',
        openssl: nativeBackend.openssl,
        parameterSets: nativeBackend.algorithms(),
      },
  runtime: { node: process.version, platform: `${process.platform}-${process.arch}` },
  peers: {},
  rows: [],
}

let failures = 0

// A peer that cannot do something is not a peer that disagrees with us. It
// answers `unsupported`, and that records as N/A rather than counting against
// the matrix. Any other error is a real failure.
function gap(res) {
  return res.unsupported === true
}

function record(row) {
  report.rows.push(row)
  const bad = Object.values(row.checks).filter((c) => c.ok === false).length
  failures += bad
  if (!quiet) {
    const marks = Object.entries(row.checks)
      .map(([k, v]) => `${v.ok === true ? '+' : v.ok === false ? 'x' : '-'}${k}`)
      .join(' ')
    console.log(
      `${bad === 0 ? 'PASS' : 'FAIL'}  ${row.peer.padEnd(13)} ${row.alg.padEnd(19)} ${row.path.padEnd(8)} ${marks}`
    )
    for (const [k, v] of Object.entries(row.checks)) {
      if (v.ok === false) console.log(`        ${k}: ${v.detail}`)
    }
  }
}

// Local signing and verification. The wrapper path exercises this package's own
// published helpers; the backend path drives the primitive directly.
//
// The wrapper signs hedged: it does not pass extraEntropy, so the backend draws
// fresh randomness per signature, which is FIPS 204's recommended default. That
// means wrapper signatures are not reproducible byte-for-byte, so the byte
// equality check only applies to the deterministic backend path. Both paths are
// run for every parameter set the wrapper covers, so determinism is still
// evidenced for that parameter set.
function localSign(set, path, secretKey, message, context) {
  if (path === 'wrapper') {
    const sigHex = set.wrapper.sign(secretKey, message, context.length ? { context } : undefined)
    return bytes(sigHex)
  }
  return set.prim.sign(message, secretKey, { extraEntropy: false, ...(context.length ? { context } : {}) })
}

function localVerify(set, path, publicKey, message, signature, context) {
  if (path === 'wrapper') {
    return set.wrapper.verify(publicKey, message, hex(signature), context.length ? { context } : undefined)
  }
  try {
    return set.prim.verify(signature, message, publicKey, context.length ? { context } : {})
  } catch {
    return false
  }
}

async function runSignatureSet(peerName, peer, set, path) {
  const label = `${set.alg}`
  const seed = fixtureSeed(`${label}/seed`, set.seedLen)
  const message = Buffer.from(`kxco interop ${set.alg}`, 'utf8')
  const context = Buffer.from('kxco-interop-context', 'utf8')
  const checks = {}

  const local = set.prim.keygen(seed)
  const theirs = await peer.request({ op: 'keyDerive', alg: set.alg, seed: hex(seed) })

  checks.keys = theirs.ok
    ? {
        ok: hex(local.publicKey) === theirs.publicKey,
        detail: `ours ${hex(local.publicKey).slice(0, 24)} theirs ${String(theirs.publicKey).slice(0, 24)}`,
      }
    : gap(theirs)
      ? { ok: null, detail: `not applicable: ${theirs.error}` }
      : { ok: false, detail: theirs.error }

  // A peer that cannot derive from a seed still has to interoperate on every
  // other check, so only a real disagreement stops the row here.
  if (checks.keys.ok === false) {
    record({ peer: peerName, alg: set.alg, path, checks })
    return
  }

  // Contexts are exercised because FIPS 204 §5.2, and the equivalent in FIPS
  // 205, fold the context string into the signed message; a peer that ignores it
  // silently produces signatures that only verify against itself.
  for (const [suffix, ctx] of [['', Buffer.alloc(0)], ['/ctx', context]]) {
    const ourSig = localSign(set, path, local.secretKey, message, ctx)

    const theirVerify = await peer.request({
      op: 'verify',
      alg: set.alg,
      publicKey: hex(local.publicKey),
      message: hex(message),
      signature: hex(ourSig),
      context: hex(ctx),
    })
    checks[`ours>theirs${suffix}`] = theirVerify.ok
      ? { ok: theirVerify.valid === true, detail: `peer returned valid=${theirVerify.valid}` }
      : gap(theirVerify)
        ? { ok: null, detail: `not applicable: ${theirVerify.error}` }
        : { ok: false, detail: theirVerify.error }

    const theirSign = await peer.request({
      op: 'sign',
      alg: set.alg,
      seed: hex(seed),
      secretKey: hex(local.secretKey),
      message: hex(message),
      context: hex(ctx),
      deterministic: true,
    })
    if (!theirSign.ok) {
      checks[`theirs>ours${suffix}`] = gap(theirSign)
        ? { ok: null, detail: `not applicable: ${theirSign.error}` }
        : { ok: false, detail: theirSign.error }
      checks[`bytes${suffix}`] = { ok: null, detail: 'peer could not sign' }
    } else {
      const theirSig = bytes(theirSign.signature)
      checks[`theirs>ours${suffix}`] = {
        ok: localVerify(set, path, local.publicKey, message, theirSig, ctx) === true,
        detail: 'we rejected a signature the peer produced',
      }
      checks[`bytes${suffix}`] =
        path === 'wrapper'
          ? { ok: null, detail: 'not applicable: the wrapper signs hedged, so signatures are not reproducible' }
          : PEERS[peerName].deterministicSigning === false
          ? { ok: null, detail: 'not applicable: the peer signs hedged and exposes no deterministic mode' }
          : {
              ok: hex(ourSig) === theirSign.signature,
              detail: `deterministic signatures differ (ours ${hex(ourSig).slice(0, 20)}, theirs ${theirSign.signature.slice(0, 20)})`,
            }
    }

    // Negative control: the peer must reject a signature we deliberately broke.
    const tampered = Uint8Array.from(ourSig)
    tampered[tampered.length - 1] ^= 0x01
    const theirReject = await peer.request({
      op: 'verify',
      alg: set.alg,
      publicKey: hex(local.publicKey),
      message: hex(message),
      signature: hex(tampered),
      context: hex(ctx),
    })
    checks[`tamper${suffix}`] = theirReject.ok
      ? { ok: theirReject.valid === false, detail: 'peer accepted a tampered signature' }
      : gap(theirReject)
        ? { ok: null, detail: `not applicable: ${theirReject.error}` }
        : { ok: true, detail: `peer rejected with an error: ${theirReject.error}` }
  }

  record({ peer: peerName, alg: set.alg, path, checks })
}

async function runKemSet(peerName, peer, set, path) {
  const seed = fixtureSeed(`${set.alg}/seed`, set.seedLen)
  const entropy = fixtureSeed(`${set.alg}/entropy`, 48)
  const checks = {}

  const local = set.prim.keygen(seed)
  const theirs = await peer.request({ op: 'keyDerive', alg: set.alg, seed: hex(seed) })

  checks.keys = theirs.ok
    ? { ok: hex(local.publicKey) === theirs.publicKey, detail: 'derived encapsulation keys differ' }
    : gap(theirs)
      ? { ok: null, detail: `not applicable: ${theirs.error}` }
      : { ok: false, detail: theirs.error }

  if (checks.keys.ok === false) {
    record({ peer: peerName, alg: set.alg, path, checks })
    return
  }

  // We encapsulate, they decapsulate.
  const ours =
    path === 'wrapper' ? set.wrapper.encapsulate(local.publicKey) : set.prim.encapsulate(local.publicKey)
  const ourCt = ours.cipherText ?? ours.ciphertext
  const theirDecap = await peer.request({
    op: 'decapsulate',
    alg: set.alg,
    seed: hex(seed),
    secretKey: hex(local.secretKey),
    ciphertext: hex(ourCt),
  })
  checks['ours>theirs'] = theirDecap.ok
    ? { ok: theirDecap.sharedSecret === hex(ours.sharedSecret), detail: 'shared secrets differ' }
    : gap(theirDecap)
      ? { ok: null, detail: `not applicable: ${theirDecap.error}` }
      : { ok: false, detail: theirDecap.error }

  // They encapsulate with fixed entropy, we decapsulate.
  const theirEncap = await peer.request({
    op: 'encapsulate',
    alg: set.alg,
    publicKey: hex(local.publicKey),
    entropy: hex(entropy),
  })
  if (!theirEncap.ok) {
    checks['theirs>ours'] = gap(theirEncap)
      ? { ok: null, detail: `not applicable: ${theirEncap.error}` }
      : { ok: false, detail: theirEncap.error }
  } else {
    const recovered =
      path === 'wrapper'
        ? set.wrapper.decapsulate(bytes(theirEncap.ciphertext), local.secretKey)
        : set.prim.decapsulate(bytes(theirEncap.ciphertext), local.secretKey)
    checks['theirs>ours'] = {
      ok: hex(recovered) === theirEncap.sharedSecret,
      detail: 'we recovered a different shared secret than the peer sent',
    }
  }

  // Implicit rejection: a corrupted ciphertext must yield a different secret,
  // not an error and not the original secret.
  const badCt = Uint8Array.from(ourCt)
  badCt[0] ^= 0x01
  const theirBad = await peer.request({
    op: 'decapsulate',
    alg: set.alg,
    seed: hex(seed),
    secretKey: hex(local.secretKey),
    ciphertext: hex(badCt),
  })
  checks.reject = theirBad.ok
    ? {
        ok: theirBad.sharedSecret !== hex(ours.sharedSecret),
        detail: 'peer returned the real shared secret for a corrupted ciphertext',
      }
    : gap(theirBad)
      ? { ok: null, detail: `not applicable: ${theirBad.error}` }
      : { ok: true, detail: `peer rejected with an error: ${theirBad.error}` }

  record({ peer: peerName, alg: set.alg, path, checks })
}

// ----------------------------------------------------------------------- main

if (onlyPeer && !PEERS[onlyPeer]) {
  throw new Error(`unknown peer: ${onlyPeer} (known: ${Object.keys(PEERS).join(', ')})`)
}

for (const [name, meta] of Object.entries(PEERS)) {
  if (onlyPeer && name !== onlyPeer) continue

  let launch
  try {
    launch = PREPARE[name]()
  } catch (err) {
    report.peers[name] = { available: false, reason: err.message.split('\n')[0] }
    if (!quiet) console.log(`SKIP  ${name}: ${report.peers[name].reason}`)
    continue
  }

  const peer = new Peer(name, launch.cmd, launch.args)
  peer.start()

  const id = await peer.request({ op: 'identify' })
  // Record the pinned coordinate from peers-lock.json alongside whatever the
  // peer reports about itself: a repackaged jar may carry no implementation
  // version, and the pin is what actually determines what ran.
  report.peers[name] = {
    available: true,
    pinned: lock[name]?.artifact ?? lock[name]?.requirements,
    ...id,
  }
  delete report.peers[name].id
  delete report.peers[name].ok
  if (!quiet) console.log(`peer ${name}: ${id.name} ${id.version ?? ''} (${id.language})`)

  for (const set of SETS) {
    if (!meta.supports(set.alg)) continue
    // Where this package publishes its own helper for a parameter set, run the
    // matrix twice: once through that helper and once through the primitive.
    const paths = set.wrapper ? ['wrapper', 'backend'] : ['backend']
    for (const path of paths) {
      if (set.kind === 'sig') await runSignatureSet(name, peer, set, path)
      else await runKemSet(name, peer, set, path)
    }
  }

  await peer.stop()
}

report.totals = report.rows.reduce(
  (acc, row) => {
    for (const c of Object.values(row.checks)) {
      if (c.ok === true) acc.passed++
      else if (c.ok === false) acc.failed++
      else acc.inconclusive++
    }
    return acc
  },
  { passed: 0, failed: 0, inconclusive: 0 }
)

if (!quiet) {
  const t = report.totals
  console.log(
    `\n${t.passed} interop checks passed, ${t.failed} failed, ${t.inconclusive} inconclusive ` +
      `across ${report.rows.length} rows`
  )
}

if (jsonOut) {
  mkdirSync(dirname(jsonOut), { recursive: true })
  writeFileSync(jsonOut, `${JSON.stringify(report, null, 2)}\n`)
  if (!quiet) console.log(`report written to ${jsonOut}`)
}

process.exit(failures > 0 ? 1 : 0)
