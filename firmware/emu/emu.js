// Прошивка pmtoken в эмуляторе RP2040 (rp2040js) с мостом USB CDC <-> TCP.
//
//   npm ci && node emu.js ../../build-fw/pmtoken.uf2 [порт]
//   pmhwtest tcp:<порт>
//
// Кадры по TCP те же, что по USB CDC, поэтому клиент работает с эмулятором как
// с симулятором, а в прошивке исполняется настоящий ARM-код с TinyUSB. Запись
// flash rp2040js не эмулирует — перехватываем ROM-функции flash_range_erase/program.
// По каждому запросу печатается число тактов: время на плате = такты / 125 МГц.
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const net = require('net');
const path = require('path');
const { Simulator, USBCDC, ConsoleLogger, LogLevel } = require('rp2040js');

const BOOTROM_URL = 'https://raw.githubusercontent.com/wokwi/rp2040js/v1.1.1/demo/bootrom.ts';
const BOOTROM_SHA256 = '99f8a1f813ce3aa9415884de3fb6c5b962d3c6fa0394b05413ad3c7b3c39ec62';
const MHZ = 125;

const [uf2Path, portArg] = process.argv.slice(2);
if (!uf2Path) { console.error('node emu.js pmtoken.uf2 [порт]'); process.exit(2); }
const port = Number(portArg || 47300);

// Bootrom RP2040 (B1, BSD-3, Raspberry Pi) — скачиваем один раз и сверяем хэш
async function bootrom() {
  const file = path.join(__dirname, 'bootrom.ts');
  if (!fs.existsSync(file)) {
    const body = await new Promise((ok, fail) => https.get(BOOTROM_URL, (r) => {
      if (r.statusCode !== 200) return fail(new Error('bootrom: HTTP ' + r.statusCode));
      const parts = [];
      r.on('data', (d) => parts.push(d)).on('end', () => ok(Buffer.concat(parts)));
    }).on('error', fail));
    fs.writeFileSync(file, body);
  }
  const src = fs.readFileSync(file);
  if (crypto.createHash('sha256').update(src).digest('hex') !== BOOTROM_SHA256) throw new Error('bootrom: хэш не совпал');
  const text = src.toString('utf8');
  return new Uint32Array(text.slice(text.indexOf('[') + 1, text.lastIndexOf(']'))
    .split(',').map((s) => s.trim()).filter(Boolean).map(Number));
}

async function main() {
  const sim = new Simulator();
  const mcu = sim.rp2040;
  mcu.logger = new ConsoleLogger(LogLevel.Error);
  mcu.loadBootrom(await bootrom());
  mcu.flash.fill(0xff);                       // чистая NOR-flash

  const uf2 = fs.readFileSync(uf2Path);
  for (let off = 0; off + 512 <= uf2.length; off += 512) {
    if (uf2.readUInt32LE(off) !== 0x0a324655) throw new Error('не UF2');
    const addr = uf2.readUInt32LE(off + 12), size = uf2.readUInt32LE(off + 16);
    uf2.copy(mcu.flash, addr - 0x10000000, off + 32, off + 32 + size);
  }

  // таблица функций ROM: по адресу 0x14 — u16-указатель на пары (код, адрес)
  const rd16 = (a) => mcu.readUint8(a) | (mcu.readUint8(a + 1) << 8);
  const rom = {};
  for (let p = rd16(0x14); rd16(p); p += 4) rom[rd16(p)] = rd16(p + 2) & ~1;
  const fn = (name) => rom[name.charCodeAt(0) | (name.charCodeAt(1) << 8)];
  const hooks = new Map();
  hooks.set(fn('RE'), (r) => mcu.flash.fill(0xff, r[0], r[0] + r[1]));
  hooks.set(fn('RP'), (r) => { for (let i = 0; i < r[2]; i++) mcu.flash[r[0] + i] &= mcu.readUint8(r[1] + i); });
  for (const n of ['IF', 'EX', 'FC', 'CX']) hooks.set(fn(n), () => {});

  const cdc = new USBCDC(mcu.usbCtrl);
  let sock = null, cycles = 0, dtrUpAt = 0, reqAt = -1, lastOut = 0;
  const pending = [];
  const report = () => {
    if (reqAt < 0) return;
    const c = lastOut - reqAt;
    console.log(`[emu] запрос: ${(c / 1e6).toFixed(2)} млн тактов ≈ ${(c / MHZ / 1000).toFixed(0)} мс на ${MHZ} МГц`);
    reqAt = -1;
  };
  cdc.onDeviceConnected = () => console.log('[emu] USB CDC готов');
  cdc.onSerialData = (buf) => { lastOut = cycles; if (sock) sock.write(Buffer.from(buf)); };

  net.createServer((s) => {
    if (sock) sock.destroy();
    sock = s;
    s.setNoDelay(true);
    pending.length = 0;
    // закрытие прошлого клиента доходит до прошивки сбросом DTR, затем новый DTR
    cdc.cdcSetControlLineState(0);
    dtrUpAt = cycles + 2e6;
    s.on('data', (d) => { report(); reqAt = cycles; for (const b of d) pending.push(b); });
    s.on('close', () => { if (sock === s) { sock = null; pending.length = 0; cdc.cdcSetControlLineState(0); } });
    s.on('error', () => {});
  }).listen(port, '127.0.0.1', () => console.log(`[emu] 127.0.0.1:${port}`));

  const core = mcu.core, clock = sim.clock, ns = 1e9 / (MHZ * 1e6);
  const run = () => {
    for (let i = 0; i < 400000; i++) {
      const h = hooks.get(core.PC);
      if (h) { h(core.registers); core.PC = core.registers[14] & ~1; continue; }
      if (core.waiting) { clock.tick(clock.nanosToNextAlarm); continue; }
      const c = core.executeInstruction();
      cycles += c;
      clock.tick(c * ns);
    }
    if (dtrUpAt && cycles >= dtrUpAt) { cdc.cdcSetControlLineState(3); dtrUpAt = 0; }
    if (!dtrUpAt) while (pending.length && !cdc.txFIFO.full) cdc.sendSerialByte(pending.shift());
    setImmediate(run);
  };
  core.PC = 0x10000000;
  run();
}

main().catch((e) => { console.error(e.message); process.exit(1); });
