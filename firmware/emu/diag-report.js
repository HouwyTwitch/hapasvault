// SPDX-License-Identifier: GPL-3.0-or-later
// Прочитать отчёт pmdiag из моста CDC эмулятора (emu.js) до строки «Конец отчёта.».
//
//   node emu.js ../../build-fw/pmtoken.uf2,../../build-fw/pmdiag.uf2 47303 &
//   node diag-report.js 47303
'use strict';
const net = require('net');

const port = Number(process.argv[2] || 47303);
const sock = net.connect(port, '127.0.0.1');
let buf = Buffer.alloc(0);
sock.on('data', (d) => {
  buf = Buffer.concat([buf, d]);
  if (buf.toString('utf8').includes('Конец отчёта.')) {
    process.stdout.write(buf.toString('utf8'));
    sock.destroy();
    process.exit(0);
  }
});
sock.on('error', (e) => { console.error(e.message); process.exit(1); });
setTimeout(() => {
  process.stdout.write(buf.toString('utf8'));
  console.error('\nнет конца отчёта за 150 с');
  process.exit(1);
}, 150000);
