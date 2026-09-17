/* AetherVPN — web UI controller.
 * Talks to the local webbridge over fetch + SSE. Every control below drives a
 * real backend action: connect/disconnect, protocol switch, node pinning and
 * latency sweeps, split rules, Windows proxy take-over, core management. */
(() => {
'use strict';

// ── i18n ────────────────────────────────────────────────────────
const STRINGS = {
  'zh-CN': {
    home: '首页', nodes: '节点', split: '分流', rules: '规则', settings: '设置', logs: '日志', about: '关于',
    coreReady: '核心就绪', coreRunning: '核心运行中', coreMissing: '核心未找到', coreUnknown: '检测核心…',
    coreIncompatible: '核心不兼容', coreStopped: '核心已停止',
    disconnected: '未连接', connecting: '连接中…', connected: '已连接', reconnecting: '重连中…',
    failed: '连接失败', testing: '测速中…', live: '实时速率', localIP: '本地 IP', exitIP: '出口 IP',
    autoNode: '自动最佳节点', hintOff: '点击下方按钮开始安全加速', hintOn: '隧道已建立，流量正在通过 Aether Core',
    hintConnecting: '正在发现并验证网关…', totalDown: '下载流量', totalUp: '上传流量', duration: '在线时长',
    sysProxyOn: '已接管', sysProxyOff: '未接管', lanOn: '放行', lanOff: '阻断', ksOn: '已启用', ksOff: '未启用',
    available: '可用', nodesTesting: '测速中', unavailable: '不可用', nodeConnected: '当前节点',
    select: '选用', selected: '已选用', neverTested: '未测速',
    saved: '设置已保存', rulesSaved: '规则已保存', copied: '已复制到剪贴板', cleared: '日志已清空',
    testingStarted: '开始测速全部节点', rescanning: '已清除网关缓存，重新扫描中…',
    protocolSwitched: '协议已切换', needCore: '未找到 Aether Core：请在设置页指定核心路径后重试',
  },
  'en-US': {
    home: 'Home', nodes: 'Nodes', split: 'Split', rules: 'Rules', settings: 'Settings', logs: 'Logs', about: 'About',
    coreReady: 'Core ready', coreRunning: 'Core running', coreMissing: 'Core not found', coreUnknown: 'Detecting core…',
    coreIncompatible: 'Core incompatible', coreStopped: 'Core stopped',
    disconnected: 'Disconnected', connecting: 'Connecting…', connected: 'Connected', reconnecting: 'Reconnecting…',
    failed: 'Failed', testing: 'Testing…', live: 'Live speed', localIP: 'Local IP', exitIP: 'Exit IP',
    autoNode: 'Auto (best node)', hintOff: 'Press the button below to start a secure tunnel',
    hintOn: 'Tunnel is up — traffic flows through Aether Core',
    hintConnecting: 'Discovering and validating gateways…', totalDown: 'Downloaded', totalUp: 'Uploaded', duration: 'Uptime',
    sysProxyOn: 'Taken over', sysProxyOff: 'Released', lanOn: 'Allowed', lanOff: 'Blocked', ksOn: 'Enabled', ksOff: 'Disabled',
    available: 'Available', nodesTesting: 'Testing', unavailable: 'Unavailable', nodeConnected: 'Active',
    select: 'Select', selected: 'Selected', neverTested: 'Not measured',
    saved: 'Settings saved', rulesSaved: 'Rules saved', copied: 'Copied to clipboard', cleared: 'Log cleared',
    testingStarted: 'Latency sweep started', rescanning: 'Gateway cache cleared — rescanning…',
    protocolSwitched: 'Protocol switched', needCore: 'Aether Core not found — set the core path in Settings',
  },
};
let lang = 'zh-CN';
const tx = (k) => (STRINGS[lang] && STRINGS[lang][k]) || STRINGS['zh-CN'][k] || k;

// pick reads a bilingual field (… / …_en) for the active language.
const pick = (obj, key) => (lang === 'en-US' ? (obj[key + '_en'] || obj[key]) : obj[key]);

// ── app state ───────────────────────────────────────────────────
const NAV = [
  { id: 'home', icon: 'i-home' },
  { id: 'nodes', icon: 'i-nodes' },
  { id: 'split', icon: 'i-split' },
  { id: 'rules', icon: 'i-rules' },
  { id: 'settings', icon: 'i-settings' },
  { id: 'logs', icon: 'i-logs' },
];
const PAGE_ICON = { home: 'i-home', nodes: 'i-nodes', split: 'i-split', rules: 'i-rules', settings: 'i-settings', logs: 'i-logs', about: 'i-about' };

let S = null;
let logs = [];
let logFilter = 'all';
let logQuery = '';
let range = '1m';
let page = 'home';
let series = [];
let seriesTimer = null;
let connectedAtMs = 0;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const el = (tag, cls, html) => { const n = document.createElement(tag); if (cls) n.className = cls; if (html != null) n.innerHTML = html; return n; };
const icon = (id, cls = 'mini') => `<svg class="${cls}"><use href="#${id}"/></svg>`;

// ── formatting ──────────────────────────────────────────────────
function fmtBytes(b) {
  b = Number(b) || 0;
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
  return b + ' B';
}
function fmtSpeed(b) {
  b = Number(b) || 0;
  if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB/s';
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KB/s';
  return Math.round(b) + ' B/s';
}
function fmtDur(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
}
function clockTime(ms) {
  const d = new Date(ms);
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}
function hhmmss(ms) {
  const d = new Date(ms);
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') + ':' + String(d.getSeconds()).padStart(2, '0');
}
function quality(ms) {
  if (!ms || ms <= 0) return 0;
  if (ms <= 100) return 1;
  if (ms <= 200) return 2;
  if (ms <= 400) return 3;
  return 4;
}
function barClass(ms) {
  const q = quality(ms);
  let c = 'bars';
  if (q > 0) { c += ' on'; if (q === 3) c += ' l3'; if (q === 2) c += ' l2'; if (q === 1) c += ' l1'; }
  return c;
}

// ── country flags ───────────────────────────────────────────────
// Windows' Segoe UI Emoji deliberately does not render regional-indicator
// (flag) emoji, so the flag emoji the core reports is decoded back to its ISO
// 3166-1 alpha-2 code and drawn as inline SVG instead.
const FLAGS = {
  // horizontal tricolours
  NL: ['h', '#AE1C28', '#FFFFFF', '#21468B'], DE: ['h', '#000000', '#DD0000', '#FFCE00'],
  RU: ['h', '#FFFFFF', '#0039A6', '#D52B1E'], AT: ['h', '#ED2939', '#FFFFFF', '#ED2939'],
  HU: ['h', '#CD2A3E', '#FFFFFF', '#436F4D'], BG: ['h', '#FFFFFF', '#00966E', '#D62612'],
  LU: ['h', '#ED2939', '#FFFFFF', '#00A1DE'], LI: ['h', '#002B7F', '#CE1126', '#FFD100'],
  IR: ['h', '#239F40', '#FFFFFF', '#DA0000'], IQ: ['h', '#CE1126', '#FFFFFF', '#000000'],
  EG: ['h', '#CE1126', '#FFFFFF', '#000000'], YE: ['h', '#CE1126', '#FFFFFF', '#000000'],
  SY: ['h', '#CE1126', '#FFFFFF', '#000000'], OM: ['h', '#D21034', '#FFFFFF', '#007A3D'],
  KW: ['h', '#007A3D', '#FFFFFF', '#CE1126'], JO: ['h', '#007A3D', '#FFFFFF', '#000000'],
  AE: ['h', '#FF0000', '#FFFFFF', '#000000'], LB: ['h', '#ED1C24', '#FFFFFF', '#ED1C24'],
  AM: ['h', '#D90012', '#0033A0', '#F2A800'], AZ: ['h', '#0092BC', '#E8112D', '#EF3340'],
  KZ: ['h', '#00AFCA', '#FEC50C'], LT: ['h', '#FDB913', '#006A44', '#EF1B23'],
  EE: ['h', '#0072CE', '#000000', '#FFFFFF'], LV: ['h', '#9E1B34', '#FFFFFF', '#9E1B34'],
  RS: ['h', '#C6363C', '#0C4076', '#FFFFFF'], HR: ['h', '#FF0000', '#FFFFFF', '#171796'],
  SI: ['h', '#FFFFFF', '#005DA4', '#ED1C24'], SK: ['h', '#EE1C25', '#0B4EA2', '#FFFFFF'],
  CZ: ['h', '#11457E', '#FFFFFF', '#D7141A'], KP: ['h', '#024FA2', '#FFFFFF', '#ED1C24'],
  LA: ['h', '#CE1126', '#002868', '#FFFFFF'], ID: ['h', '#CE1126', '#FFFFFF'],
  PL: ['h', '#FFFFFF', '#DC143C'], UA: ['h', '#0057B7', '#FFDD00'], MT: ['h', '#FFFFFF', '#CF142B'],
  MC: ['h', '#CE1126', '#FFFFFF'], MA: ['h', '#C1272D', '#006233'], DZ: ['h', '#006233', '#FFFFFF', '#D21034'],
  TN: ['h', '#E70013', '#FFFFFF'], LY: ['h', '#CE1126', '#000000', '#009739'],
  SD: ['h', '#D21034', '#FFFFFF', '#000000'], SN: ['h', '#00853F', '#FDEF42', '#E31B23'],
  CI: ['h', '#F77F00', '#FFFFFF', '#009E60'], CM: ['h', '#007A5E', '#CE1126', '#FCD116'],
  CG: ['h', '#009543', '#FCD116', '#DC241F'], CD: ['h', '#007FFF', '#FCD116', '#CE1021'],
  GH: ['h', '#CE1126', '#FCD116', '#006B3F'], KE: ['h', '#000000', '#BB0000', '#006600'],
  TZ: ['h', '#1EB53A', '#FCD116', '#00A3DD'], UG: ['h', '#000000', '#FCDC04', '#D90000'],
  ET: ['h', '#009639', '#FCDC04', '#DA121A'], NG: ['h', '#008751', '#FFFFFF', '#008751'],
  MZ: ['h', '#00913F', '#000000', '#FDC70A'], ZM: ['h', '#198A00', '#DE2010', '#000000'],
  BW: ['h', '#6DA9E4', '#FFFFFF', '#000000'], NA: ['h', '#003580', '#FFFFFF', '#009543'],
  ZW: ['h', '#319208', '#FFD200', '#D40000'], SC: ['h', '#003F87', '#FCD116', '#D62828'],
  HT: ['h', '#00209F', '#D21034'], HN: ['h', '#0073CF', '#FFFFFF'], NI: ['h', '#0067B1', '#FFFFFF', '#0067B1'],
  CR: ['h', '#002B7F', '#FFFFFF', '#CE1126'], PA: ['h', '#DA121A', '#FFFFFF', '#005293'],
  CU: ['h', '#002A8F', '#FFFFFF', '#CF142B'], DO: ['h', '#002D62', '#FFFFFF', '#CE1126'],
  JM: ['h', '#009B3A', '#FFB915', '#000000'], TT: ['h', '#CE1126', '#FFFFFF', '#000000'],
  AR: ['h', '#74ACDF', '#FFFFFF', '#74ACDF'], PE: ['h', '#D91023', '#FFFFFF'],
  EC: ['h', '#FFDD00', '#0072CF', '#EF3340'], BO: ['h', '#007934', '#FCD116', '#CE1126'],
  PY: ['h', '#D52B1E', '#FFFFFF', '#003893'], GY: ['h', '#009E49', '#FFFFFF', '#FFD100'],
  GT: ['h', '#4997D0', '#FFFFFF', '#4997D0'], BZ: ['h', '#0072C6', '#FFFFFF', '#CE1126'],
  MM: ['h', '#FECB00', '#34B233', '#EA2839'], LK: ['h', '#FFB700', '#8D153A', '#00534E'],
  BD: ['h', '#006A4E', '#F42A41'], PK: ['h', '#01411A', '#FFFFFF'],
  MN: ['h', '#C4272F', '#0159AD', '#FFD100'], QA: ['h', '#8A1538', '#FFFFFF'],
  BH: ['h', '#CE1126', '#FFFFFF'],
  AL: ['h', '#E41E20', '#000000'], MK: ['h', '#D20000', '#FFE600'], ME: ['h', '#C40308', '#FFD700'],
  XK: ['h', '#1C3F94', '#FFFFFF', '#C8102E'], CY: ['h', '#FFFFFF', '#D57800'],
  TH: ['h', '#ED1C24', '#F4F5F0', '#2D2A4A', '#F4F5F0', '#ED1C24'],
  SA: ['h', '#006C35', '#FFFFFF'],
  VE: ['h', '#F8D31D', '#003893', '#CE1126'], UY: ['h', '#FFFFFF', '#0038A8'],
  KH: ['h', '#032EA1', '#E00025', '#032EA1'], BY: ['h', '#FFFFFF', '#CE1126', '#FFFFFF'],
  AO: ['h', '#CE1126', '#000000'], SV: ['h', '#0F47AF', '#FFFFFF', '#0F47AF'],
  MO: ['h', '#00693E', '#FFFFFF'], GE: ['cross', '#FFFFFF', '#E8112D'],
  FJ: ['ensign', '#6FBFE8', '#FFFFFF'],

  // vertical tricolours
  FR: ['v', '#002395', '#FFFFFF', '#ED2939'], IT: ['v', '#008C45', '#F4F5F0', '#CD212A'],
  IE: ['v', '#169B62', '#FFFFFF', '#FF883E'], BE: ['v', '#000000', '#FAE042', '#ED2939'],
  RO: ['v', '#002B7F', '#FCD116', '#CE1126'], MD: ['v', '#0033A0', '#FFCC00', '#D20000'],
  AD: ['v', '#0018A8', '#FEDF00', '#D0103A'], MX: ['mx'],

  // nordic crosses
  DK: ['nordic', '#C60C30', '#FFFFFF'], FI: ['nordic', '#FFFFFF', '#003580'],
  SE: ['nordic', '#006AA7', '#FECC00'], NO: ['nordic', '#BA0C2F', '#FFFFFF', '#00205B'],
  IS: ['nordic', '#0065BD', '#FFFFFF', '#DC1E35'], FO: ['nordic', '#FFFFFF', '#0065BD', '#ED2939'],

  // bespoke
  US: ['us'], GB: ['gb'], JP: ['dot', '#FFFFFF', '#BC002D'], GL: ['dot', '#FFFFFF', '#C8102E'],
  CN: ['cn'], VN: ['star', '#DA251D', '#FFFF00'], KR: ['kr'], BR: ['br'], CA: ['ca'],
  IN: ['in'], SG: ['sg'], TR: ['tr'], IL: ['il'], PH: ['ph'], MY: ['my'],
  HK: ['hk'], TW: ['tw'], CL: ['cl'], CO: ['co'], PT: ['pt'], ES: ['es'],
  ZA: ['za'], GR: ['gr'], CH: ['cross', '#FF0000', '#FFFFFF'], AU: ['ensign', '#00247D', '#FFFFFF'],
  NZ: ['ensign', '#00247D', '#CC142B'],
};

function emojiToCode(s) {
  if (!s) return '';
  const cps = Array.from(String(s)).map((c) => c.codePointAt(0));
  if (cps.length < 2) return '';
  if (cps[0] < 0x1f1e6 || cps[0] > 0x1f1ff || cps[1] < 0x1f1e6 || cps[1] > 0x1f1ff) return '';
  return String.fromCharCode(cps[0] - 0x1f1e6 + 65, cps[1] - 0x1f1e6 + 65);
}

const rect = (x, y, w, h, c) => `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${c}"/>`;

function starPath(cx, cy, r, points) {
  let d = '';
  for (let i = 0; i < points * 2; i++) {
    const rr = i % 2 ? r * 0.42 : r;
    const a = (Math.PI * 2 * i) / (points * 2) - Math.PI / 2;
    d += (i ? 'L' : 'M') + (cx + rr * Math.cos(a)).toFixed(2) + ' ' + (cy + rr * Math.sin(a)).toFixed(2);
  }
  return d + 'Z';
}

// British flag geometry, reused by the ensigns (AU / NZ).
const gbInner = `<path d="M0 0 24 16M24 0 0 16" stroke="#FFFFFF" stroke-width="3.4" fill="none"/>` +
  `<path d="M0 0 24 16M24 0 0 16" stroke="#C8102E" stroke-width="1.9" fill="none"/>` +
  rect(0, 6, 24, 4, '#FFFFFF') + rect(9, 0, 6, 16, '#FFFFFF') +
  rect(0, 6.6, 24, 2.8, '#C8102E') + rect(9.6, 0, 4.8, 16, '#C8102E');

const FLAG_FN = {
  h: (f) => f.slice(1).map((c, i, a) => rect(0, (16 * i / a.length).toFixed(2), 24, (16 / a.length).toFixed(2), c)).join(''),
  v: (f) => f.slice(1).map((c, i, a) => rect((24 * i / a.length).toFixed(2), 0, (24 / a.length).toFixed(2), 16, c)).join(''),
  nordic: (f) => {
    const [bg, cross, inner] = f.slice(1);
    let s = rect(0, 0, 24, 16, bg) + rect(0, 6, 24, 4, cross) + rect(7.5, 0, 4, 16, cross);
    if (inner) s += rect(0, 6.9, 24, 2.2, inner) + rect(8.4, 0, 2.2, 16, inner);
    return s;
  },
  dot: (f) => rect(0, 0, 24, 16, f[1]) + `<circle cx="12" cy="8" r="4.4" fill="${f[2]}"/>`,
  star: (f) => rect(0, 0, 24, 16, f[1]) + `<path d="${starPath(12, 8, 4.6)}" fill="${f[2]}"/>`,
  cross: (f) => rect(0, 0, 24, 16, f[1]) + rect(10.2, 3, 3.6, 10, f[2]) + rect(6, 6.2, 12, 3.6, f[2]),
  us: () => `<rect width="24" height="16" fill="#FFFFFF"/>` +
    [0, 2.46, 4.92, 7.38, 9.85, 12.31, 14.77].map((y) => rect(0, y.toFixed(2), 24, 1.23, '#B22234')).join('') +
    rect(0, 0, 9.6, 8.62, '#3C3B6E') +
    [1.6, 4.8, 8.0, 3.2, 6.4].map((x, i) => `<circle cx="${x}" cy="${i < 3 ? 2.2 : 4.4}" r="0.75" fill="#FFFFFF"/>`).join('') +
    [2.4, 5.6, 9.0].map((x, i) => `<circle cx="${x}" cy="${i < 2 ? 6.4 : 8.6 - 1.6}" r="0.75" fill="#FFFFFF"/>`).join(''),
  gb: () => rect(0, 0, 24, 16, '#012169') + gbInner,
  ensign: (f) => rect(0, 0, 24, 16, f[1]) + `<g transform="scale(0.5)">${gbInner}</g>` +
    [16.5, 20].map((x, i) => `<circle cx="${x}" cy="${i ? 5 : 11.5}" r="1.6" fill="${f[2] || '#FFFFFF'}"/>`).join('') +
    `<circle cx="18.2" cy="8.4" r="1.9" fill="${f[2] || '#FFFFFF'}"/>`,
  cn: () => rect(0, 0, 24, 16, '#DE2910') + `<path d="${starPath(5.6, 4.4, 2.7)}" fill="#FFDE00"/>` +
    [[8.4, 1.9], [10, 3.4], [10, 5.6], [8.4, 7]].map((p) => `<path d="${starPath(p[0], p[1], 0.95)}" fill="#FFDE00"/>`).join(''),
  kr: () => rect(0, 0, 24, 16, '#FFFFFF') +
    `<path d="M8 8a4 4 0 0 1 8 0z" fill="#CD2E3A"/><path d="M8 8a4 4 0 0 0 8 0z" fill="#0047A0"/>` +
    `<path d="M8 8a2 2 0 0 1 4 0z" fill="#0047A0"/><path d="M16 8a2 2 0 0 1-4 0z" fill="#CD2E3A"/>` +
    rect(1.6, 2.4, 6.4, 1.1, '#000000') + rect(1.6, 12.5, 6.4, 1.1, '#000000') +
    rect(16, 2.4, 6.4, 1.1, '#000000') + rect(16, 12.5, 6.4, 1.1, '#000000'),
  br: () => rect(0, 0, 24, 16, '#009B3A') + `<path d="M12 1.4 22 8 12 14.6 2 8Z" fill="#FEDF00"/>` +
    `<circle cx="12" cy="8" r="3.3" fill="#002776"/><path d="M8.5 6.4Q12 9.6 15.5 6.4" stroke="#FFFFFF" stroke-width="0.7" fill="none"/>`,
  ca: () => rect(0, 0, 24, 16, '#FFFFFF') + rect(0, 0, 6, 16, '#D80621') + rect(18, 0, 6, 16, '#D80621') +
    `<path d="M12 3.1l1.15 2.25 2.5.35-1.8 1.75.42 2.47L12 8.72l-2.27 1.2.42-2.47-1.8-1.75 2.5-.35z" fill="#D80621"/>`,
  in: () => rect(0, 0, 24, 5.34, '#FF9933') + rect(0, 5.34, 24, 5.33, '#FFFFFF') + rect(0, 10.67, 24, 5.33, '#138808') +
    `<circle cx="12" cy="8" r="2.6" fill="none" stroke="#000080" stroke-width="0.65"/><circle cx="12" cy="8" r="0.5" fill="#000080"/>`,
  sg: () => rect(0, 0, 24, 8, '#EF3340') + rect(0, 8, 24, 8, '#FFFFFF') +
    `<circle cx="5.2" cy="4" r="3.1" fill="#FFFFFF"/><circle cx="6.6" cy="4" r="2.5" fill="#EF3340"/>` +
    [[9.2, 1.9], [11, 2.6], [10.6, 4.6], [8.6, 4.6], [8.2, 2.6]].map((p) => `<circle cx="${p[0]}" cy="${p[1]}" r="0.7" fill="#FFFFFF"/>`).join(''),
  tr: () => rect(0, 0, 24, 16, '#E30A17') + `<circle cx="9.4" cy="8" r="4.3" fill="#FFFFFF"/>` +
    `<circle cx="11.3" cy="8" r="3.4" fill="#E30A17"/><path d="${starPath(15, 8, 2)}" fill="#FFFFFF"/>`,
  il: () => rect(0, 0, 24, 16, '#FFFFFF') + rect(0, 1.4, 24, 2.6, '#0038B8') + rect(0, 12, 24, 2.6, '#0038B8') +
    `<path d="M12 4.4 14.6 9.6 9.4 9.6Z" fill="none" stroke="#0038B8" stroke-width="0.8"/>` +
    `<path d="M12 11.6 9.4 6.4 14.6 6.4Z" fill="none" stroke="#0038B8" stroke-width="0.8"/>`,
  ph: () => rect(0, 0, 24, 8, '#0038A8') + rect(0, 8, 24, 8, '#CE1126') +
    `<path d="M0 0h11L0 8Z" fill="#FFFFFF"/><circle cx="3.4" cy="4" r="0.9" fill="#FCD116"/>`,
  my: () => rect(0, 0, 24, 16, '#FFFFFF') + [0, 3, 6, 9, 12].map((y) => rect(0, y, 24, 1.5, '#CC0000')).join('') +
    rect(0, 0, 11, 8, '#010066') + `<circle cx="6.4" cy="4" r="2.2" fill="#FFCC00"/><path d="${starPath(6.4, 4, 1.3)}" fill="#FFCC00"/>`,
  hk: () => rect(0, 0, 24, 16, '#EE1C25') +
    [[12, 4], [14.6, 6.4], [13.4, 9.6], [10.6, 9.6], [9.4, 6.4]].map((p) => `<circle cx="${p[0]}" cy="${p[1]}" r="2.1" fill="#FFFFFF"/>`).join('') +
    `<circle cx="12" cy="4" r="0.9" fill="#EE1C25"/><circle cx="14.6" cy="6.4" r="0.9" fill="#EE1C25"/>` +
    `<circle cx="13.4" cy="9.6" r="0.9" fill="#EE1C25"/><circle cx="10.6" cy="9.6" r="0.9" fill="#EE1C25"/>` +
    `<circle cx="9.4" cy="6.4" r="0.9" fill="#EE1C25"/>`,
  tw: () => rect(0, 0, 24, 16, '#FE0000') + rect(0, 0, 12, 8, '#000095') +
    `<circle cx="6" cy="4" r="2.2" fill="#FFFFFF"/><circle cx="6" cy="4" r="1.6" fill="#000095"/>`,
  cl: () => rect(0, 0, 24, 8, '#FFFFFF') + rect(0, 8, 24, 8, '#D52B1E') + rect(0, 0, 8, 8, '#0039A6') +
    `<path d="${starPath(4, 4, 2.2)}" fill="#FFFFFF"/>`,
  co: () => rect(0, 0, 24, 8, '#FCD116') + rect(0, 8, 24, 4, '#003893') + rect(0, 12, 24, 4, '#CE1126'),
  pt: () => rect(0, 0, 10, 16, '#006600') + rect(10, 0, 14, 16, '#FF0000') +
    `<circle cx="10" cy="8" r="3.2" fill="#FFE900" stroke="#FFE900" stroke-width="0.6"/>`,
  es: () => rect(0, 0, 24, 4, '#AA151B') + rect(0, 4, 24, 8, '#F1BF00') + rect(0, 12, 24, 4, '#AA151B'),
  za: () => rect(0, 0, 24, 8, '#E03C31') + rect(0, 8, 24, 8, '#001489') +
    `<path d="M0 1.4 11 8 0 14.6Z" fill="#007A4D"/><path d="M0 3.2 8.4 8 0 12.8Z" fill="#FFB81C"/>`,
  gr: () => rect(0, 0, 24, 16, '#FFFFFF') + [0, 3, 6, 9, 12].map((y) => rect(0, y, 24, 1.6, '#0D5EAF')).join('') +
    rect(0, 0, 10, 8.6, '#0D5EAF') + rect(0, 3, 10, 1.6, '#FFFFFF') + rect(3.5, 0, 1.6, 8.6, '#FFFFFF'),
  mx: () => rect(0, 0, 24, 16, '#FFFFFF') + rect(0, 0, 5.6, 16, '#006847') + rect(18.4, 0, 5.6, 16, '#CE1126') +
    `<circle cx="12" cy="8" r="1.9" fill="#8C6239"/>`,
};

// flagHTML renders the flag for a flag-emoji; unknown codes fall back to a
// neutral globe badge so the layout never breaks.
function flagHTML(emoji) {
  const code = emojiToCode(emoji);
  const f = code && FLAGS[code];
  let inner;
  if (f && FLAG_FN[f[0]]) {
    inner = FLAG_FN[f[0]](f);
  } else if (f) {
    inner = rect(0, 0, 24, 16, '#DCE6F4');
  } else {
    inner = rect(0, 0, 24, 16, '#DCE6F4') +
      `<circle cx="12" cy="8" r="4.4" fill="none" stroke="#9FB0CA" stroke-width="1"/>` +
      `<path d="M7.6 8h8.8M12 3.6c1.5 2.3 1.5 6.5 0 8.8-1.5-2.3-1.5-6.5 0-8.8" fill="none" stroke="#9FB0CA" stroke-width="0.9"/>`;
  }
  return `<svg class="flag-svg" viewBox="0 0 24 16" preserveAspectRatio="xMidYMid meet" title="${code || ''}">${inner}</svg>`;
}

// ── transport ───────────────────────────────────────────────────
async function api(path, body) {
  try {
    const res = await fetch(path, body === undefined
      ? { credentials: 'same-origin' }
      : { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    const text = await res.text();
    if (!res.ok) throw new Error(text);
    return text ? JSON.parse(text) : null;
  } catch (e) {
    toast('请求失败：' + String(e.message || e).slice(0, 120), 'err');
    return null;
  }
}

function connectSSE() {
  const src = new EventSource('/api/stream', { withCredentials: true });
  src.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (_) { return; }
    if (msg.type === 'snapshot') applySnapshot(msg.data);
    else if (msg.type === 'log') { pushLog(msg.data); renderLogs(); renderRecent(); }
  };
  src.onerror = () => { setTimeout(connectSSE, 1500); };
}

function applySnapshot(next) {
  const prevStatus = S && S.vpn ? S.vpn.status : null;
  S = next;
  if (next.settings) lang = next.settings.language || 'zh-CN';
  document.documentElement.dataset.theme = (next.settings && next.settings.theme === 'dark') ? 'dark' : 'light';
  document.documentElement.lang = lang;
  if (next.vpn.status === 'Connected' && prevStatus !== 'Connected') connectedAtMs = Date.now();
  if (next.vpn.status !== 'Connected' && next.vpn.status !== 'Connecting' && next.vpn.status !== 'Reconnecting') connectedAtMs = 0;
  render();
}

// ── rendering ───────────────────────────────────────────────────
// Only the active page is rebuilt in full: the one-second tick must not reset
// another page's scroll position or selection.
function render() {
  if (!S) return;
  renderNav();
  renderTop();
  renderCoreBadges();
  switch (page) {
    case 'home': renderHome(); break;
    case 'nodes': renderNodes(); break;
    case 'split': renderSplit(); break;
    case 'rules': renderRules(); break;
    case 'settings': renderSettingsOnce(); break;
    case 'logs': renderLogs(); break;
    case 'about': renderAbout(); break;
  }
  renderRecent();
  if (page === 'home') renderProtocols();
}

function renderNav() {
  const nav = $('#nav');
  if (nav.childElementCount !== NAV.length) {
    nav.innerHTML = '';
    for (const item of NAV) {
      const b = el('button', 'nav-item');
      b.type = 'button';
      b.dataset.page = item.id;
      b.innerHTML = icon(item.icon) + '<span>' + tx(item.id) + '</span>';
      b.onclick = () => go(item.id);
      nav.appendChild(b);
    }
  } else {
    let i = 0;
    for (const b of nav.children) { b.querySelector('span').textContent = tx(NAV[i].id); i++; }
  }
  for (const b of nav.children) b.classList.toggle('active', b.dataset.page === page);
}

function go(id) {
  page = id;
  $$('.page').forEach((p) => p.classList.toggle('active', p.dataset.page === id));
  renderNav();
  renderTop();
  if (id === 'home') startSeriesTimer(); else stopSeriesTimer();
  render();
  if (id === 'home') drawChart();
}

function renderTop() {
  $('#pageTitle').textContent = tx(page);
  const v = S.vpn;
  const sub = v.status === 'Connected'
    ? tx('connected') + ' · ' + v.protocolName + (v.exitCountry ? ' · ' + v.exitCountry : '')
    : (v.error ? v.error : coreLabel() + ' · ' + tx(page === 'home' ? 'home' : page));
  $('#pageSub').textContent = sub;
}

function coreLabel() {
  const v = S.version;
  if (v.coreRunning) return tx('coreRunning');
  switch (v.coreHealth) {
    case 'Ready': return tx('coreReady');
    case 'Missing': return tx('coreMissing');
    case 'Incompatible': return tx('coreIncompatible');
    default: return tx('coreUnknown');
  }
}

function coreClass() {
  const v = S.version;
  if (v.coreRunning) return 'ok';
  if (v.coreHealth === 'Missing' || v.coreHealth === 'Incompatible') return 'bad';
  if (v.coreHealth === 'Ready') return 'ok';
  return 'warn';
}

function renderHome() {
  const v = S.vpn, t = S.traffic;
  const cls = { Connected: 'is-connected', Connecting: 'is-connecting', Reconnecting: 'is-connecting', Testing: 'is-connected', Failed: 'is-failed' }[v.status] || '';
  document.body.className = cls;

  const word = { Connected: tx('connected'), Connecting: tx('connecting'), Reconnecting: tx('reconnecting'), Failed: tx('failed'), Testing: tx('testing') }[v.status] || tx('disconnected');
  $('#heroWord').textContent = word;
  $('#heroTime').textContent = fmtDur(v.durationSec);
  $('#heroHint').textContent = v.status === 'Connected' ? tx('hintOn')
    : (v.status === 'Connecting' || v.status === 'Reconnecting') ? tx('hintConnecting')
      : v.status === 'Failed' ? (v.error || tx('failed')) : tx('hintOff');

  const connected = v.status === 'Connected';
  $('#ipLabel').textContent = connected ? tx('exitIP') : tx('localIP');
  $('#ipVal').textContent = connected ? (v.exitIP || v.localIP || '—') : (v.localIP || '—');
  $('#protoVal').textContent = v.protocolName;
  $('#latVal').textContent = v.latencyMs > 0 ? v.latencyMs + ' ms' : '—';
  $('#latVal').style.color = quality(v.latencyMs) === 1 ? 'var(--ok)' : '';
  $('#upVal').textContent = (t.downBps >= 0 || t.upBps >= 0) ? fmtSpeed(t.upBps) : '0 B/s';
  $('#downVal').textContent = fmtSpeed(t.downBps);

  const hasExit = connected && (v.exitCountry || v.exitIP);
  $('#nodeFlag').innerHTML = flagHTML(hasExit ? v.exitFlag : '');
  $('#nodeName').textContent = hasExit ? (v.exitCountry || v.exitIP || tx('autoNode')) : tx('autoNode');
  $('#nodeProto').textContent = hasExit ? v.protocolName : (v.gateway ? v.gatewayName || v.gateway : '—');
  $('#nodeMs').textContent = v.latencyMs > 0 ? v.latencyMs + ' ms' : '—';
  $('#nodeMs').className = 'node-ms q' + quality(v.latencyMs);
  const nb = $('#nodeBars');
  nb.className = barClass(v.latencyMs);
  if (!nb.childElementCount) nb.innerHTML = '<i></i><i></i><i></i><i></i>';

  $('#lgDown').textContent = fmtSpeed(t.downBps);
  $('#lgUp').textContent = fmtSpeed(t.upBps);
  $('#stTotal').textContent = fmtBytes((t.downTotal || 0) + (t.upTotal || 0));
  $('#stDown').textContent = fmtBytes(t.downTotal);
  $('#stUp').textContent = fmtBytes(t.upTotal);
  $('#stDuration').textContent = fmtDur(connected || v.durationSec ? v.durationSec : 0);

  if (page === 'home') drawChart();
}

// Sidebar + topbar core badges mirror coremgr health on every page.
function renderCoreBadges() {
  const ver = (S.version.core || '—').split('\n')[0];
  const cls = coreClass();
  $('#coreState').textContent = coreLabel();
  $('#coreVer').textContent = ver;
  $('#coreDot').className = 'core-dot ' + cls;
  $('#topCoreVer').textContent = ver;
  $('#topCore').querySelector('.dot').className = 'dot ' + cls;
}

// ── protocol switcher ───────────────────────────────────────────
const PROTO_ICON = { wg: 'i-shield', h2: 'i-split', h3: 'i-wifi', mim: 'i-server', gool: 'i-nodes', auto: 'i-bolt' };
function renderProtocols() {
  const sel = $('#protoSelect');
  const list = S.protocols;
  if (sel.dataset.built !== '1') {
    sel.innerHTML = list.map((p) => `<option value="${p.key}">${p.label}</option>`).join('');
    sel.dataset.built = '1';
    sel.onchange = () => switchProtocol(sel.value);
  }
  sel.value = S.activeProtocol;

  const grid = $('#protoGrid');
  if (!grid.dataset.ready) {
    grid.innerHTML = '';
    for (const p of list) {
      const b = el('button', 'proto-btn ' + p.key);
      b.type = 'button';
      b.innerHTML = `<span class="pb-ico">${icon(PROTO_ICON[p.key] || 'i-wifi')}</span><span class="txt">${p.label}</span>`;
      b.onclick = () => switchProtocol(p.key);
      grid.appendChild(b);
    }
    grid.dataset.ready = '1';
  }
  Array.from(grid.children).forEach((b, i) => b.classList.toggle('on', list[i].key === S.activeProtocol));
}

async function switchProtocol(key) {
  if (key === S.activeProtocol) return;
  const tag = $('#protoApplying');
  if (tag) tag.hidden = false;
  if (S.version.coreHealth === 'Missing') toast(tx('needCore'), 'err');
  const r = await api('/api/protocol', { key });
  if (tag) tag.hidden = true;
  if (r && r.ok) toast(tx('protocolSwitched') + ': ' + (S.protocols.find((p) => p.key === key) || {}).label, 'ok');
}

// ── chart ───────────────────────────────────────────────────────
async function loadSeries() {
  const r = await api('/api/traffic/series?range=' + range);
  if (r && Array.isArray(r.points)) { series = r.points; drawChart(); }
}
function startSeriesTimer() {
  loadSeries();
  stopSeriesTimer();
  seriesTimer = setInterval(loadSeries, 3000);
}
function stopSeriesTimer() { if (seriesTimer) { clearInterval(seriesTimer); seriesTimer = null; } }

let chartCacheKey = '';
function drawChart() {
  const cv = $('#chart');
  if (!cv) return;
  const rect = cv.getBoundingClientRect();
  if (!rect.width) return;
  const dpr = window.devicePixelRatio || 1;
  if (cv.width !== Math.round(rect.width * dpr) || cv.height !== Math.round(rect.height * dpr)) {
    cv.width = Math.round(rect.width * dpr);
    cv.height = Math.round(rect.height * dpr);
  }
  const ctx = cv.getContext('2d');
  const W = cv.width, H = cv.height;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, W, H);

  const cs = getComputedStyle(document.documentElement);
  const accent = (cs.getPropertyValue('--accent') || '#2f6df6').trim();
  const violet = (cs.getPropertyValue('--violet') || '#8b5cf6').trim();
  const lineC = (cs.getPropertyValue('--line') || '#e2eaf7').trim();
  const faint = (cs.getPropertyValue('--text-faint') || '#93a3bb').trim();
  const s = dpr;

  const padL = 52 * s, padR = 10 * s, padT = 12 * s, padB = 24 * s;
  const pw = W - padL - padR, ph = H - padT - padB;

  let max = 1;
  for (const p of series) { if (p.down > max) max = p.down; if (p.up > max) max = p.up; }
  max = max > 1024 ? max * 1.28 : 1024;

  // grid + y labels
  ctx.font = `${10.5 * s}px system-ui, sans-serif`;
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  const rows = 4;
  for (let i = 0; i <= rows; i++) {
    const y = padT + (ph * i) / rows;
    ctx.strokeStyle = lineC;
    ctx.lineWidth = 1 * s;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(padL + pw, y);
    ctx.stroke();
    ctx.fillStyle = faint;
    ctx.fillText(fmtSpeed((max * (rows - i)) / rows).replace(/ /g, ' '), padL - 8 * s, y);
  }

  if (!series.length) {
    ctx.fillStyle = faint;
    ctx.textAlign = 'center';
    ctx.font = `${12 * s}px system-ui, sans-serif`;
    ctx.fillText('暂无数据 — 连接后开始采样', padL + pw / 2, padT + ph / 2);
    return;
  }

  const n = series.length;
  const xOf = (i) => padL + (pw * i) / Math.max(1, n - 1);
  const yOf = (v) => padT + ph - (Math.min(v, max) / max) * ph;

  const curve = (key, color, fillAlpha) => {
    ctx.beginPath();
    ctx.moveTo(xOf(0), yOf(series[0][key]));
    for (let i = 1; i < n; i++) {
      const cx = (xOf(i - 1) + xOf(i)) / 2;
      ctx.bezierCurveTo(cx, yOf(series[i - 1][key]), cx, yOf(series[i][key]), xOf(i), yOf(series[i][key]));
    }
    ctx.lineWidth = 2 * s;
    ctx.strokeStyle = color;
    ctx.lineJoin = 'round';
    ctx.stroke();

    ctx.lineTo(xOf(n - 1), padT + ph);
    ctx.lineTo(xOf(0), padT + ph);
    ctx.closePath();
    const g = ctx.createLinearGradient(0, padT, 0, padT + ph);
    g.addColorStop(0, hexA(color, fillAlpha));
    g.addColorStop(1, hexA(color, 0));
    ctx.fillStyle = g;
    ctx.fill();
  };
  curve('up', violet, 0.20);
  curve('down', accent, 0.24);

  // x labels
  ctx.fillStyle = faint;
  ctx.textBaseline = 'top';
  const ticks = Math.min(5, n);
  for (let i = 0; i < ticks; i++) {
    const idx = Math.round((n - 1) * (i / Math.max(1, ticks - 1)));
    ctx.textAlign = i === 0 ? 'left' : (i === ticks - 1 ? 'right' : 'center');
    ctx.fillText(clockTime(series[idx].t), xOf(idx), padT + ph + 8 * s);
  }
  chartCacheKey = '';
}

function hexA(hex, a) {
  const h = hex.replace('#', '');
  const v = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
  const r = parseInt(v.slice(0, 2), 16), g = parseInt(v.slice(2, 4), 16), b = parseInt(v.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${a})`;
}

// ── nodes ───────────────────────────────────────────────────────
function renderNodes() {
  const tb = $('#nodeTable tbody');
  if (!tb) return;
  const nodes = S.nodes || [];
  $('#nodeHint').textContent = S.testing ? tx('nodesTesting') + '…' : (lang === 'zh-CN'
    ? '节点来自核心探测的 Cloudflare 边缘池；测速包含 TCP 延迟与下载速度，完成后自动固定最佳节点。'
    : 'Gateways from the core-scanned Cloudflare edge pool. The sweep measures TCP latency and download speed, then pins the best node.');
  $('#nodeTest').disabled = S.testing;
  tb.innerHTML = '';
  if (!nodes.length) { tb.innerHTML = `<tr><td colspan="8" class="empty">${lang === 'zh-CN' ? '暂无节点' : 'No nodes'}</td></tr>`; return; }
  for (const n of nodes) {
    const tr = el('tr');
    if (S.activeNode === n.id) tr.className = 'sel';
    const q = quality(n.latencyMs);
    const name = n.country || n.label || ('Edge ' + n.ip);
    tr.innerHTML =
      `<td><div class="cell-main">${flagHTML(n.flag)}<div><b>${esc(name)}</b><small class="mono">${n.status === 'Connected' ? tx('nodeConnected') : esc(n.colo || n.label || '')}</small></div></div></td>` +
      `<td class="mono">${n.ip}</td>` +
      `<td class="mono">${n.port}</td>` +
      `<td class="ms q${q}">${n.latencyMs > 0 ? n.latencyMs + ' ms' : '—'}</td>` +
      `<td class="mono">${n.speedBps > 0 ? fmtSpeed(n.speedBps) : '—'}</td>` +
      `<td class="mono">${n.exitIP ? esc(n.exitCountry || '') + ' ' + n.exitIP : '—'}</td>` +
      `<td><span class="badge ${n.status === 'Available' ? 'ok' : n.status === 'Connected' ? 'live' : n.status === 'Testing' ? 'warn' : 'bad'}">${badgeText(n.status)}</span></td>` +
      `<td><button class="row-act" data-id="${n.id}">${S.activeNode === n.id ? tx('selected') : tx('select')}</button></td>`;
    tr.querySelector('.row-act').onclick = () => selectNode(n.id);
    tb.appendChild(tr);
  }
}
function badgeText(st) {
  return { Available: tx('available'), Connected: tx('nodeConnected'), Testing: tx('nodesTesting'), Unavailable: tx('unavailable') }[st] || st;
}

async function selectNode(id) {
  const r = await api('/api/nodes/select', { id, connect: true });
  if (r && r.ok) toast(tx('selected'), 'ok');
}

// ── split ───────────────────────────────────────────────────────
const MODES = [
  { id: 'full_vpn', icon: 'i-shield', name: '全局 VPN', name_en: 'Global VPN', desc: '接管系统代理，所有流量走隧道', desc_en: 'Takes over the system proxy; all traffic goes through the tunnel' },
  { id: 'proxy', icon: 'i-wifi', name: '全局代理', name_en: 'Global proxy', desc: '仅本机代理端口（127.0.0.1）走隧道', desc_en: 'Only apps pointed at 127.0.0.1 use the tunnel' },
  { id: 'split', icon: 'i-split', name: '规则分流', name_en: 'Rule-based split', desc: '按 PAC 规则分流，直连/屏蔽由你掌控', desc_en: 'PAC rules decide what is direct or blocked' },
  { id: 'direct', icon: 'i-stop', name: '直连', name_en: 'Direct', desc: '关闭隧道，直连网络', desc_en: 'Tunnel off — plain internet' },
];
function renderSplit() {
  const grid = $('#modeGrid');
  if (!grid) return;
  if (!grid.dataset.built || grid.dataset.lang !== lang) {
    grid.innerHTML = '';
    for (const m of MODES) {
      const b = el('button', 'mode-card');
      b.type = 'button';
      b.innerHTML = `<span class="mode-ico">${icon(m.icon)}</span><span class="mode-body"><b>${pick(m, 'name')}</b><small>${pick(m, 'desc')}</small></span>`;
      b.onclick = () => api('/api/mode', { mode: m.id });
      grid.appendChild(b);
    }
    grid.dataset.built = '1';
    grid.dataset.lang = lang;
  }
  Array.from(grid.children).forEach((b, i) => b.classList.toggle('on', MODES[i].id === S.settings.mode));

  const st = S.system;
  $('#sysProxyVal').innerHTML = st.sysProxy ? `<span class="badge ok">${tx('sysProxyOn')}</span>` : `<span class="badge">${tx('sysProxyOff')}</span>`;
  $('#ksVal').innerHTML = st.killSwitch ? `<span class="badge ok">${tx('ksOn')}</span>` : `<span class="badge">${tx('ksOff')}</span>`;
  $('#lanVal').innerHTML = S.settings.lan_access ? `<span class="badge ok">${tx('lanOn')}</span>` : `<span class="badge">${tx('lanOff')}</span>`;
  $('#pacVal').textContent = 'aether-split.pac';
  $('#btnKsToggle').textContent = st.killSwitch ? (lang === 'zh-CN' ? '关闭 Kill Switch' : 'Disable Kill Switch') : (lang === 'zh-CN' ? '启用 Kill Switch' : 'Enable Kill Switch');
}

// ── rules ───────────────────────────────────────────────────────
let rulesDirty = false;
function renderRules() {
  const b = $('#editBlock'), d = $('#editDirect');
  if (!b || !d) return;
  if (document.activeElement !== b) b.value = (S.settings.split_block || []).join('\n');
  if (document.activeElement !== d) d.value = (S.settings.split_direct || []).join('\n');
}

// ── settings ────────────────────────────────────────────────────
const SCHEMA = [
  {
    name: '通用', name_en: 'General', icon: 'i-settings', rows: [
      { k: 'language', type: 'select', label: '界面语言', label_en: 'Language', options: [['zh-CN', '简体中文'], ['en-US', 'English']] },
      { k: 'theme', type: 'select', label: '主题', label_en: 'Theme', options: [['light', '浅色'], ['dark', '深色']] },
      { k: 'auto_start', type: 'switch', label: '开机自启动', label_en: 'Start with Windows', hint: '写入 HKCU Run 项', hint_en: 'Writes the HKCU Run entry' },
      { k: 'auto_connect', type: 'switch', label: '启动后自动连接', label_en: 'Auto-connect on launch', hint: '随自启动一起连上隧道', hint_en: 'Connects together with autostart' },
      { k: 'auto_reconnect', type: 'switch', label: '自动重连', label_en: 'Auto-reconnect', hint: '网络变化或隧道断开时重连', hint_en: 'Reconnects after network changes or a dead tunnel' },
      { k: 'kill_switch', type: 'switch', label: 'Kill Switch（防泄漏）', label_en: 'Kill Switch (leak guard)', hint: '未走隧道的出站流量将被阻断', hint_en: 'Blocks egress that would bypass the tunnel' },
      { k: 'lan_access', type: 'switch', label: '允许局域网访问', label_en: 'Allow LAN access', hint: '私有地址直连', hint_en: 'Private addresses stay direct' },
    ],
  },
  {
    name: '网络', name_en: 'Network', icon: 'i-wifi', rows: [
      { k: 'mode', type: 'select', label: '连接方式', label_en: 'Routing mode', options: [['full_vpn', '全局 VPN'], ['proxy', '全局代理'], ['split', '规则分流'], ['direct', '直连']] },
      { k: 'ip_stack', type: 'select', label: 'IP 协议栈', label_en: 'IP stack', hint: 'IPv4/IPv6 扫描策略', hint_en: 'IPv4/IPv6 scanning policy', options: [['ipv4', '仅 IPv4'], ['ipv6', '仅 IPv6'], ['dual', 'IPv4 + IPv6']] },
      { k: 'socks_port', type: 'number', label: '本地 SOCKS5 端口', label_en: 'Local SOCKS5 port' },
      { k: 'http_proxy_port', type: 'number', label: '本地 HTTP 代理端口', label_en: 'Local HTTP proxy port', hint: '0 = 关闭', hint_en: '0 = disabled' },
    ],
  },
  {
    name: 'DNS 与网关', name_en: 'DNS & gateway', icon: 'i-server', rows: [
      { k: 'dns_leak_guard', type: 'switch', label: 'DNS 防泄漏', label_en: 'DNS leak guard', hint: '连接期间强制隧道内解析', hint_en: 'Forces in-tunnel resolution while connected' },
      { k: 'dns_servers', type: 'text', label: '自定义 DNS', label_en: 'Custom DNS servers', hint: '逗号分隔，经隧道转发', hint_en: 'Comma separated, tunneled' },
      { k: 'auto_scan', type: 'switch', label: '自动扫描网关', label_en: 'Auto-scan gateways', hint: '取消勾选则使用固定网关', hint_en: 'Uncheck to honor the pinned gateway' },
      { k: 'auto_failover', type: 'switch', label: '自动故障转移', label_en: 'Auto-failover' },
      { k: 'cached_gateway', type: 'text', label: '固定网关 (ip:port)', label_en: 'Pinned gateway (ip:port)', hint: '留空则由核心扫描', hint_en: 'Empty = the core scans' },
      { k: 'scan_mode', type: 'select', label: '扫描模式', label_en: 'Scan mode', options: [['turbo', 'Turbo'], ['balanced', 'Balanced'], ['thorough', 'Thorough'], ['stealth', 'Stealth'], ['ironclad', 'Ironclad']] },
    ],
  },
  {
    name: '高级', name_en: 'Advanced', icon: 'i-bolt', rows: [
      { k: 'ech', type: 'switch', label: '加密 Client Hello (ECH)', label_en: 'Encrypted Client Hello (ECH)' },
      { k: 'connect_timeout', type: 'number', label: '连接超时（秒）', label_en: 'Connect timeout (s)' },
      { k: 'reconnect_delay', type: 'number', label: '重连延时（秒）', label_en: 'Reconnect delay (s)' },
      { k: 'keepalive', type: 'number', label: 'WireGuard Keepalive（秒）', label_en: 'WireGuard keepalive (s)' },
      { k: 'mtu', type: 'number', label: 'MTU', hint: '0 = 核心默认', hint_en: '0 = core default' },
      { k: 'log_level', type: 'select', label: '日志级别', label_en: 'Log level', options: [['error', 'Error'], ['warn', 'Warn'], ['info', 'Info'], ['debug', 'Debug'], ['trace', 'Trace']] },
    ],
  },
  {
    name: 'Aether 核心', name_en: 'Aether Core', icon: 'i-lock', rows: [
      { k: 'core_path', type: 'text', label: '核心路径', label_en: 'Core path', hint: '留空 = 在 exe 同目录 / core-bin / PATH 中查找（不联网）', hint_en: 'Empty = search beside the exe, core-bin, PATH (never online)' },
    ],
  },
];

let settingsLang = '';
function renderSettingsOnce() {
  const host = $('#settingsPage');
  if (!host || settingsLang === lang) return;
  settingsLang = lang;
  if (!host.dataset.started) host.dataset.started = '1';
  host.innerHTML = '';

  for (const g of SCHEMA) {
    const card = el('div', 'card');
    card.innerHTML = `<div class="card-head"><span class="title">${icon(g.icon, 'mini accent')}${pick(g, 'name')}</span></div>`;
    const wrap = el('div', 'set-grid');
    for (const r of g.rows) wrap.appendChild(settingRow(r));
    card.appendChild(wrap);
    host.appendChild(card);
  }

  const card = el('div', 'card');
  card.innerHTML = `<div class="card-head"><span class="title">${icon('i-lock', 'mini accent')}${lang === 'zh-CN' ? '核心操作' : 'Core operations'}</span></div>`;
  const acts = el('div', 'head-actions');
  const mk = (label, cls, fn) => { const b = el('button', 'btn ' + cls, label); b.type = 'button'; b.onclick = fn; return b; };
  acts.appendChild(mk('检测核心', 'primary', detectCore));
  acts.appendChild(mk('重启核心', '', () => api('/api/core/restart')));
  acts.appendChild(mk('停止核心', 'danger', () => api('/api/core/stop')));
  acts.appendChild(mk('重新扫描网关', '', () => { api('/api/nodes/rescan'); toast(tx('rescanning'), 'info'); }));
  card.appendChild(acts);
  card.appendChild(el('p', 'hint', lang === 'zh-CN'
    ? '关闭窗口即退出程序，并自动停止核心、还原系统代理。核心二进制不做自动更新：手动替换 core-bin/aether.exe 后点“检测核心”。'
    : 'Closing the window exits the client: the core stops and the system proxy is restored. No auto-update: replace core-bin/aether.exe, then press Detect.'));
  host.appendChild(card);
  syncSettingsUI();
}

function settingRow(r) {
  const row = el('div', 'set-row');
  const hint = pick(r, 'hint');
  row.innerHTML = `<div class="set-info"><b>${pick(r, 'label')}</b>${hint ? `<small>${hint}</small>` : ''}</div>`;
  const ctl = el('div', 'set-ctl');
  if (r.type === 'switch') {
    const lb = el('label', 'switch');
    lb.innerHTML = '<input type="checkbox"><i></i>';
    lb.querySelector('input').onchange = (e) => patch({ [r.k]: e.target.checked });
    ctl.appendChild(lb);
    row.dataset.kind = 'switch';
  } else if (r.type === 'select') {
    const s = el('select');
    s.innerHTML = r.options.map((o) => `<option value="${o[0]}">${o[1]}</option>`).join('');
    s.onchange = (e) => patch({ [r.k]: e.target.value });
    ctl.appendChild(s);
    row.dataset.kind = 'select';
  } else {
    const i = el('input');
    i.type = 'text';
    i.spellcheck = false;
    if (r.type === 'number') { i.inputMode = 'numeric'; i.style.minWidth = '92px'; i.style.textAlign = 'right'; }
    i.onchange = (e) => patch({ [r.k]: r.type === 'number' ? (parseInt(e.target.value, 10) || 0) : e.target.value });
    ctl.appendChild(i);
    row.dataset.kind = 'input';
  }
  row.dataset.k = r.k;
  row.appendChild(ctl);
  return row;
}

function syncSettingsUI() {
  if (!S) return;
  const st = S.settings;
  for (const row of $$('.set-row')) {
    const k = row.dataset.k;
    const v = st[k];
    const input = row.querySelector('input[type=checkbox], select, input');
    if (!input) continue;
    if (input.type === 'checkbox') input.checked = !!v;
    else input.value = Array.isArray(v) ? v.join(',') : (v == null ? '' : String(v));
  }
}

async function patch(obj) {
  const r = await api('/api/settings', obj);
  if (r) { S.settings = r; toast(tx('saved'), 'ok'); syncSettingsUI(); }
}

async function detectCore() {
  const row = $$('.set-row').find((r) => r.dataset.k === 'core_path');
  const p = row ? row.querySelector('input').value.trim() : '';
  await api('/api/core/detect', { path: p });
}

// ── logs ────────────────────────────────────────────────────────
function pushLog(e) {
  logs.push(e);
  if (logs.length > 1500) logs = logs.slice(-1500);
}
function visibleLogs() {
  let out = logs;
  if (logFilter !== 'all') out = out.filter((e) => e.level === logFilter);
  if (logQuery) { const q = logQuery.toLowerCase(); out = out.filter((e) => (e.msg || '').toLowerCase().includes(q)); }
  return out;
}
function renderLogs() {
  const host = $('#logScroll');
  if (!host) return;
  const list = visibleLogs();
  if (!host.dataset.sticky) host.dataset.sticky = '1';
  const atBottom = host.scrollHeight - host.scrollTop - host.clientHeight < 40;
  host.innerHTML = list.map((e) =>
    `<div class="log-line lv-${e.level}"><span class="lg-t">${hhmmss(new Date(e.when).getTime())}</span><span class="lg-l">${e.level}</span><span class="lg-m">${esc(e.msg)}</span></div>`
  ).join('') || `<div class="empty">${lang === 'zh-CN' ? '暂无日志' : 'No entries'}</div>`;
  if (atBottom) host.scrollTop = host.scrollHeight;
}
function renderRecent() {
  const ul = $('#recentLogs');
  if (!ul) return;
  const list = logs.slice(-7).reverse();
  ul.innerHTML = list.map((e) => {
    const c = e.level === 'ERROR' ? 'error' : e.level === 'WARN' ? 'warn' : e.level === 'DEBUG' ? 'debug' : '';
    return `<li><i class="log-ico ${c}"></i><span class="lt">${hhmmss(new Date(e.when).getTime())}</span><span class="lm">${esc(e.msg)}</span></li>`;
  }).join('') || `<li><span class="lm">${lang === 'zh-CN' ? '暂无日志' : 'No entries'}</span></li>`;
}

// ── about ───────────────────────────────────────────────────────
function renderAbout() {
  if (!$('#abGui')) return;
  const v = S.version;
  $('#abGui').textContent = 'v' + v.gui;
  $('#abCore').textContent = (v.core || '—').split('\n')[0];
  $('#abBackend').textContent = v.backend || '—';
  const lic = $('#abExpiry');
  if (lic) {
    if (!licState) lic.textContent = '检查中…';
    else if (licState.expired) lic.textContent = '已到期';
    else if (licState.offline) lic.textContent = '未检查（离线）';
    else if (licState.days_left >= 0) lic.textContent = licState.expiry_at + '（剩 ' + licState.days_left + ' 天）';
    else lic.textContent = '无限制';
  }
}

// ── updates & license ────────────────────────────────────────────
// Both the license window and the update feed live in version.json in the
// publishing repo, so they can be retuned without shipping a new build.
let licState = null;
let updState = null;

const guiVer = () => 'v' + (S.version.gui || '');
const coreVer = () => (S.version.core || '—').split('\n')[0];

function closeModal() {
  $('#modalMask').hidden = true;
  $('#modalBox').innerHTML = '';
}

function showModal(html, cls) {
  const box = $('#modalBox');
  box.className = 'modal' + (cls ? ' ' + cls : '');
  box.innerHTML = html;
  $('#modalMask').hidden = false;
}

// An expired build offers exactly one button: acknowledging it stops the
// tunnel and exits, as agreed.
function showExpired(lic) {
  showModal(`
    <h3>软件已到期</h3>
    <p class="m-warn">${esc(lic.message || '软件已到期，请联系作者续期')}</p>
    <p class="m-contact">${esc(lic.contact || 'Telegram: @xiaoheok\nEmail: hezhanleiok@gmail.com').replace(/\n/g, '<br>')}</p>
    <div class="modal-act"><button class="btn primary" id="expOk" type="button">确定</button></div>
  `, 'expired');
  $('#expOk').onclick = async () => {
    $('#expOk').disabled = true;
    await api('/api/disconnect');
    await api('/api/window/quit');
  };
}

// Updates are applied in place — the download never leaves the app.
function showUpdateDialog(u) {
  const row = (name, cur, next, has) => `
    <div class="up-row">
      <span class="up-info"><b>${name}</b><small>${cur}${has ? ' → ' + next : ''}</small></span>
      <span class="up-badge ${has ? 'new' : ''}">${has ? '有新版本' : '已是最新'}</span>
    </div>`;
  const notes = [u.gui_notes, u.core_notes].filter(Boolean).join('\n');
  showModal(`
    <h3>检查更新</h3>
    ${row('GUI 客户端', guiVer(), u.gui_version || '', u.gui_has)}
    ${row('Aether 核心', coreVer(), u.core_version || '', u.core_has)}
    ${notes ? `<div class="up-notes">${esc(notes)}</div>` : ''}
    <div class="modal-act">
      <button class="btn" id="upClose" type="button">关闭</button>
      ${u.gui_has || u.core_has ? '<button class="btn primary" id="upApply" type="button">立即更新</button>' : ''}
    </div>
  `);
  $('#upClose').onclick = closeModal;
  const apply = $('#upApply');
  if (apply) {
    apply.onclick = async () => {
      apply.disabled = true;
      apply.textContent = '正在下载并更新…';
      if (u.gui_has) await api('/api/update/gui');
      else if (u.core_has) await api('/api/update/core');
    };
  }
}

async function checkUpdates(manual) {
  const r = await api('/api/update/check');
  if (!r) {
    if (manual) toast('检查更新失败，请检查网络连接', 'err');
    return;
  }
  licState = r.license || null;
  updState = r.update || null;
  if (page === 'about') renderAbout();
  // The license window always wins over an update offer.
  if (licState && licState.expired) { showExpired(licState); return; }
  if (manual) {
    if (updState && (updState.gui_has || updState.core_has)) showUpdateDialog(updState);
    else toast('已是最新版本', 'ok');
  } else if (updState && (updState.gui_has || updState.core_has)) {
    toast('发现新版本，可在「关于」页更新', 'info');
  }
}

// ── misc ────────────────────────────────────────────────────────
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

let toastTimer = [];
function toast(msg, kind) {
  const host = $('#toasts');
  const n = el('div', 'toast ' + (kind || 'info'), `<span>${esc(msg)}</span>`);
  host.appendChild(n);
  const t = setTimeout(() => n.remove(), 3200);
  toastTimer.push(t);
  while (host.children.length > 4) host.firstChild.remove();
}

// ── wiring ──────────────────────────────────────────────────────
function bind() {
  $('#powerBtn').onclick = async () => {
    const st = S.vpn.status;
    if (st === 'Connected' || st === 'Connecting' || st === 'Reconnecting') await api('/api/disconnect');
    else {
      if (!S.version.core || S.version.coreHealth === 'Missing') toast(tx('needCore'), 'err');
      await api('/api/connect');
    }
  };

  $('#coreCard').onclick = () => go('settings');
  $('#btnSettings').onclick = () => go('settings');
  $('#btnTheme').onclick = () => patch({ theme: S.settings.theme === 'dark' ? 'light' : 'dark' });
  $$('button[data-page], .card.stat[data-page]').forEach((b) => { b.onclick = () => go(b.dataset.page); });

  $('#rangeSeg').onclick = (e) => {
    const b = e.target.closest('button[data-range]');
    if (!b) return;
    range = b.dataset.range;
    $$('#rangeSeg button').forEach((x) => x.classList.toggle('on', x === b));
    loadSeries();
  };

  $('#qaNodes').onclick = () => go('nodes');
  $('#qaRefresh').onclick = async () => {
    const b = $('#qaRefresh');
    b.disabled = true;
    if (S.vpn.status === 'Connected') await api('/api/exit/refresh');
    else await api('/api/nodes/test');
    setTimeout(() => { b.disabled = false; }, 1200);
  };
  $('#qaLogs').onclick = () => go('logs');
  $$('#stats .stat').forEach((s) => { s.onclick = () => go(s.dataset.page); });

  $('#nodeTest').onclick = () => { api('/api/nodes/test'); toast(tx('testingStarted'), 'info'); };
  $('#nodeAuto').onclick = () => api('/api/nodes/auto');
  $('#nodeRescan').onclick = () => { api('/api/nodes/rescan'); toast(tx('rescanning'), 'info'); };

  $('#saveRules').onclick = async () => {
    const r = await api('/api/settings', {
      split_block: $('#editBlock').value.split('\n').map((s) => s.trim()).filter(Boolean),
      split_direct: $('#editDirect').value.split('\n').map((s) => s.trim()).filter(Boolean),
    });
    if (r) { S.settings = r; toast(tx('rulesSaved'), 'ok'); }
  };
  const COMMON = ['private', 'baidu.com', 'qq.com', 'taobao.com', 'jd.com', 'bilibili.com', 'weibo.com', 'zhihu.com', 'douban.com', '163.com', 'aliyun.com', 'ximalaya.com'];
  $('#addCommon').onclick = () => {
    const cur = $('#editDirect').value.split('\n').map((s) => s.trim()).filter(Boolean);
    const set = new Set(cur);
    COMMON.forEach((c) => set.add(c));
    $('#editDirect').value = Array.from(set).join('\n');
  };

  $('#btnSysProxyOff').onclick = () => api('/api/disconnect');
  $('#btnKsToggle').onclick = () => patch({ kill_switch: !S.system.killSwitch });

  $('#logLevelSeg').onclick = (e) => {
    const b = e.target.closest('button[data-level]');
    if (!b) return;
    logFilter = b.dataset.level;
    $$('#logLevelSeg button').forEach((x) => x.classList.toggle('on', x === b));
    renderLogs();
  };
  $('#logSearch').oninput = (e) => { logQuery = e.target.value.trim(); renderLogs(); };
  $('#logClear').onclick = async () => { await api('/api/logs/clear'); logs = []; renderLogs(); renderRecent(); toast(tx('cleared'), 'ok'); };
  $('#logCopy').onclick = async () => {
    const text = visibleLogs().map((e) => `${hhmmss(new Date(e.when).getTime())} [${e.level}] ${e.msg}`).join('\n');
    try { await navigator.clipboard.writeText(text); toast(tx('copied'), 'ok'); } catch (_) { toast('clipboard blocked', 'err'); }
  };

  $('#abCheckUpdate').onclick = () => checkUpdates(true);
  $$('[data-url]').forEach((b) => { b.onclick = () => api('/api/system/open', { url: b.dataset.url }); });

  window.addEventListener('resize', () => drawChart());
  document.addEventListener('keydown', (e) => {
    if (e.key === 'F5' || (e.ctrlKey && e.key === 'r')) { e.preventDefault(); return; }
    if (e.key === 'Escape' && page !== 'home') go('home');
  });
}

// ── diagnostics ─────────────────────────────────────────────────
// Front-end facts and uncaught errors go to the same log file as the Go side,
// so a blank or broken window can be diagnosed without a debugger.
function sendDiag(kind, data) {
  try {
    fetch('/api/client-log', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, data }),
    }).catch(() => {});
  } catch (_) { /* logging must never break the UI */ }
}

window.addEventListener('error', (e) => {
  sendDiag('error', { msg: String(e.message), src: String(e.filename), line: e.lineno });
});
window.addEventListener('unhandledrejection', (e) => {
  sendDiag('error', { msg: 'unhandledrejection: ' + String(e.reason) });
});

// ── boot ────────────────────────────────────────────────────────
(async function boot() {
  bind();
  sendDiag('diag', {
    viewport: window.innerWidth + 'x' + window.innerHeight,
    screen: window.screen.width + 'x' + window.screen.height,
    dpr: window.devicePixelRatio,
    ua: navigator.userAgent.replace(/^.*(Edg\/[\d.]+).*$/, '$1'),
  });
  const snap = await api('/api/snapshot');
  if (!snap) { document.body.innerHTML = '<div style="padding:40px;font:14px system-ui">无法连接到本地服务 /api/snapshot</div>'; return; }
  const hist = await api('/api/logs?limit=600');
  if (hist && hist.entries) logs = hist.entries;
  applySnapshot(snap);
  go('home');
  connectSSE();
  checkUpdates(false); // start-up probe: license window first, then updates
})();

})();
