// Fetch the NIST ACVP test vectors this package is validated against.
//
// The vectors are pulled from usnistgov/ACVP-Server at the commit pinned in
// acvp-lock.json, via git transport with a blobless sparse checkout so only the
// eight vector directories we use are materialised. Every file is then hashed
// and compared against the digests in the lockfile, so a silently rewritten
// upstream vector set fails the fetch instead of quietly changing the result.
//
// Usage:  node conformance/fetch-vectors.mjs [--write-lock]
//
// --write-lock regenerates the digests in acvp-lock.json. Only use it when
// deliberately moving to a newer ACVP commit, and commit the diff.

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const LOCK_PATH = join(HERE, 'acvp-lock.json')
const CACHE = process.env.ACVP_CACHE_DIR
  ? resolve(process.env.ACVP_CACHE_DIR)
  : join(HERE, '.acvp-cache')

const lock = JSON.parse(readFileSync(LOCK_PATH, 'utf8'))
const writeLock = process.argv.includes('--write-lock')

function git(args, cwd) {
  return execFileSync('git', args, {
    cwd,
    stdio: ['ignore', 'pipe', 'inherit'],
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
}

function sparseClone() {
  rmSync(CACHE, { recursive: true, force: true })
  mkdirSync(CACHE, { recursive: true })

  git(['init', '--quiet'], CACHE)
  git(['remote', 'add', 'origin', `https://github.com/${lock.source.repo}.git`], CACHE)
  git(['config', 'core.sparseCheckout', 'true'], CACHE)
  git(['sparse-checkout', 'init', '--cone'], CACHE)
  git(['sparse-checkout', 'set', ...lock.sets.map((s) => `${lock.source.path}/${s}`)], CACHE)

  // `git clone --filter` records these two settings; hand-rolling init + remote
  // add + fetch does not, and without them a checkout of a blobless commit has
  // no registered promisor to fetch missing blobs from. Setting them explicitly
  // is what makes the partial fetch below safe to check out.
  git(['config', 'remote.origin.promisor', 'true'], CACHE)
  git(['config', 'remote.origin.partialclonefilter', 'blob:none'], CACHE)

  // Blobless partial fetch of the single pinned commit: no history, no other
  // paths. Falls back to a plain shallow fetch if the server or the local git
  // will not do a partial one, because the vectors matter and the transfer
  // saving does not.
  try {
    git(['fetch', '--depth', '1', '--filter=blob:none', 'origin', lock.source.commit], CACHE)
  } catch {
    console.warn('partial fetch failed, retrying without --filter')
    git(['config', '--unset', 'remote.origin.promisor'], CACHE)
    git(['config', '--unset', 'remote.origin.partialclonefilter'], CACHE)
    git(['fetch', '--depth', '1', 'origin', lock.source.commit], CACHE)
  }

  git(['checkout', '--quiet', 'FETCH_HEAD'], CACHE)

  const head = git(['rev-parse', 'HEAD'], CACHE).trim()
  if (head !== lock.source.commit) {
    throw new Error(`checked out ${head}, expected ${lock.source.commit}`)
  }
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

export function vectorPath(set, file) {
  return join(CACHE, lock.source.path, set, `${file}.json`)
}

export function acvpSource() {
  return lock.source
}

function verify() {
  const digests = {}
  let mismatches = 0

  for (const set of lock.sets) {
    for (const file of ['prompt', 'expectedResults']) {
      const path = vectorPath(set, file)
      if (!existsSync(path)) throw new Error(`missing vector file: ${set}/${file}.json`)
      const got = sha256(path)
      digests[`${set}/${file}.json`] = got

      const want = lock.digests?.[`${set}/${file}.json`]
      if (!writeLock && want && want !== got) {
        console.error(`DIGEST MISMATCH ${set}/${file}.json\n  expected ${want}\n  got      ${got}`)
        mismatches++
      }
    }
  }

  if (writeLock) {
    lock.digests = digests
    writeFileSync(LOCK_PATH, `${JSON.stringify(lock, null, 2)}\n`)
    console.log(`wrote ${Object.keys(digests).length} digests to acvp-lock.json`)
    return
  }

  if (mismatches) {
    throw new Error(`${mismatches} vector file(s) do not match the pinned digests`)
  }
  if (!lock.digests || Object.keys(lock.digests).length === 0) {
    console.warn('acvp-lock.json carries no digests yet; run with --write-lock to pin them')
  } else {
    console.log(`verified ${Object.keys(digests).length} vector files against acvp-lock.json`)
  }
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))

if (invokedDirectly) {
  const alreadyThere =
    existsSync(join(CACHE, '.git')) &&
    lock.sets.every((s) => existsSync(vectorPath(s, 'prompt')))

  if (alreadyThere && !process.env.ACVP_FORCE_FETCH) {
    console.log(`vectors already present in ${CACHE}`)
  } else {
    console.log(`fetching ${lock.source.repo}@${lock.source.commit.slice(0, 12)} into ${CACHE}`)
    sparseClone()
  }
  verify()
}
