// Headless proof that the WebAssembly build runs the same guests the native one
// does. Node only for the harness -- the emulator is the same code, and the guest
// files go into MEMFS exactly as a page would put them there.
//
//   node web/test_node.mjs
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const createA64Emu = require(path.join(here, 'aarch64emu.js'));

let out = '';
const dec = new TextDecoder();
globalThis.a64emuOutput = (fd, bytes) => { out += dec.decode(bytes, { stream: true }); };
globalThis.a64emuLog = () => {};

const M = await createA64Emu();

// Copy a host file into MEMFS, creating the directories on the way.
function put(guestPath, hostPath) {
  const parts = guestPath.split('/').slice(1, -1);
  let acc = '';
  for (const p of parts) { acc += '/' + p; try { M.FS.mkdir(acc); } catch {} }
  M.FS.writeFile(guestPath, new Uint8Array(fs.readFileSync(hostPath)));
}

// argv is a NUL-separated, double-NUL-terminated block: no JSON parser in the C.
function argz(list) {
  const s = list.join('\0') + '\0\0';
  const n = M.lengthBytesUTF8(s) + 1;
  const p = M._malloc(n);
  M.stringToUTF8(s, p, n);
  return p;
}

function run(guestPath, args, guestRoot = '') {
  out = '';
  const pp = argz([guestPath, ...args]);
  const cp = M.allocateUTF8 ? M.allocateUTF8(guestPath) : (() => {
    const n = M.lengthBytesUTF8(guestPath) + 1, q = M._malloc(n);
    M.stringToUTF8(guestPath, q, n); return q;
  })();
  const rp = (() => {
    const n = M.lengthBytesUTF8(guestRoot) + 1, q = M._malloc(n);
    M.stringToUTF8(guestRoot, q, n); return q;
  })();
  const rc = M._emu_run(cp, pp, rp, 0);
  M._free(pp); M._free(cp); M._free(rp);
  return { rc, out, insns: M._emu_instructions() };
}

let pass = 0, fail = 0;
const check = (name, want, got) => {
  if (want === got) { console.log(`ok   ${name}`); pass++; }
  else { console.log(`FAIL ${name}\n     want: ${JSON.stringify(want)}\n     got:  ${JSON.stringify(got)}`); fail++; }
};

// ---- the freestanding hello, which needs nothing but the ELF
put('/hello.elf', path.join(root, 'tests/hello.elf'));
check('wasm: hello.elf', 'hello from aarch64\n', run('/hello.elf', []).out);

// ---- the same program as an arm64 Mach-O, which exercises the Darwin personality:
// a different loader, a different initial stack, and `svc #0x80` with BSD numbering.
const macho = path.join(root, 'tests/hello.macho');
if (fs.existsSync(macho)) {
  put('/hello.macho', macho);
  check('wasm: hello.macho (Darwin)', 'hello from aarch64\n', run('/hello.macho', []).out);
} else {
  console.log('skip mach-o (run tests/run_macho.sh first)');
}

// ---- busybox, if it has been fetched
const bb = path.join(root, 'guests/busybox');
if (fs.existsSync(bb)) {
  put('/bin/busybox', bb);
  put('/README.md', path.join(root, 'README.md'));
  check('wasm: busybox echo', 'hi there\n', run('/bin/busybox', ['echo', 'hi', 'there']).out);
  check('wasm: busybox uname', 'aarch64\n', run('/bin/busybox', ['uname', '-m']).out);
  // The same cross-check the native suite makes: the guest's digest must equal the
  // host's digest of the same bytes.
  const { createHash } = await import('node:crypto');
  const want = createHash('sha256').update(fs.readFileSync(path.join(root, 'README.md'))).digest('hex');
  const got = (run('/bin/busybox', ['sha256sum', '/README.md']).out || '').split(' ')[0];
  check('wasm: busybox sha256sum', want, got);
} else {
  console.log('skip busybox (guests/busybox not present)');
}

// ---- CPython, if the sysroot has been built.
//
// 45 MB goes into MEMFS, which is the honest cost of a dynamically linked guest
// with a standard library: the page has to supply every file the loader and the
// interpreter will open. A shipped demo would trim the stdlib rather than pretend
// this is free.
const pyRoot = path.join(root, 'guests/sysroot');
if (fs.existsSync(path.join(pyRoot, 'opt/python/bin/python3.13'))) {
  const mkdirp = (p) => {
    let acc = '';
    for (const part of p.split('/').filter(Boolean)) { acc += '/' + part; try { M.FS.mkdir(acc); } catch {} }
  };
  const copyTree = (rel) => {
    for (const e of fs.readdirSync(path.join(pyRoot, rel), { withFileTypes: true })) {
      const r = rel + '/' + e.name;
      if (e.isDirectory()) { mkdirp(r); copyTree(r); }
      else if (e.isFile()) M.FS.writeFile('/' + r, new Uint8Array(fs.readFileSync(path.join(pyRoot, r))));
    }
  };
  mkdirp('lib'); copyTree('lib');
  mkdirp('opt/python/bin'); copyTree('opt/python/bin');
  mkdirp('opt/python/lib'); copyTree('opt/python/lib');
  const r = run('/opt/python/bin/python3.13',
                ['-c', 'import sys,platform;print(sys.version.split()[0],platform.machine())']);
  if (r.rc !== 0) console.log('     (emulator said: ' + M.UTF8ToString(M._emu_error()) + ')');
  check('wasm: cpython', '3.13.14 aarch64\n', r.out);
} else {
  console.log('skip cpython (guests/sysroot not built)');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
