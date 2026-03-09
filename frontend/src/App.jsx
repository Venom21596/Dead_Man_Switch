import { useState, useEffect } from "react";
import { ethers } from "ethers";

// ── ABI ───────────────────────────────────────────────────────────────────────
const ABI = [
  "function createVault(string,string,uint256,uint8,address,string) returns (uint256)",
  "function addTrustee(uint256,address,string,bytes32)",
  "function confirmDeath(uint256)",
  "function submitShare(uint256,string)",
  "function cancelVault(uint256)",
  "function getVault(uint256) view returns (tuple(address owner,string encryptedDataHash,string encryptedDataURI,uint256 timelockExpiry,uint8 threshold,uint8 totalShares,uint8 sharesSubmitted,uint8 status,address beneficiary,uint256 createdAt,string description))",
  "function getTrustees(uint256) view returns (tuple(address addr,string name,bool hasSubmittedShare,bool hasConfirmedDeath,bytes32 shareCommitment)[])",
  "function getShareSubmissions(uint256) view returns (tuple(address trustee,string encryptedShare,uint256 submittedAt)[])",
  "function getDeathConfirmations(uint256) view returns (uint8)",
  "function isTimelockExpired(uint256) view returns (bool)",
  "function vaultCount() view returns (uint256)",
];

// ── Shamir GF(2^8) ────────────────────────────────────────────────────────────
const P=0x11b;
const gm=(a,b)=>{let r=0;while(b){if(b&1)r^=a;a<<=1;if(a&0x100)a^=P;b>>=1;}return r&0xff};
const gp=(b,e)=>{let r=1;while(e>0){if(e&1)r=gm(r,b);b=gm(b,b);e>>=1;}return r};
const gi=a=>gp(a,254);
const ep=(c,x)=>{let r=0;for(let i=c.length-1;i>=0;i--)r=gm(r,x)^c[i];return r};
const lg=pts=>{let r=0;for(let i=0;i<pts.length;i++){let[xi,yi]=pts[i],n=1,d=1;for(let j=0;j<pts.length;j++)if(i!==j){n=gm(n,pts[j][0]);d=gm(d,xi^pts[j][0]);}r^=gm(yi,gm(n,gi(d)));}return r};
function splitSecret(sb,t,n){const sh=Array.from({length:n},(_,i)=>[i+1,[]]);for(const b of sb){const c=[b,...Array.from({length:t-1},()=>Math.floor(Math.random()*256))];sh.forEach(([x,d])=>d.push(ep(c,x)));}return sh.map(([x,d])=>[x,new Uint8Array(d)])}
function reconstructSecret(sh){const len=sh[0][1].length;const o=new Uint8Array(len);for(let i=0;i<len;i++)o[i]=lg(sh.map(([x,d])=>[x,d[i]]));return o}
function s2h(sh){return sh.map(([x,d])=>`${x.toString(16).padStart(2,'0')}:${Array.from(d).map(b=>b.toString(16).padStart(2,'0')).join('')}`)}
function h2s(hs){return hs.map(s=>{const[xh,dh]=s.split(':');return[parseInt(xh,16),new Uint8Array(dh.match(/.{2}/g).map(b=>parseInt(b,16)))]})}

// ── AES-GCM ───────────────────────────────────────────────────────────────────
const genKey=()=>crypto.subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"]);
const expKey=k=>crypto.subtle.exportKey("raw",k).then(r=>new Uint8Array(r));
const impKey=r=>crypto.subtle.importKey("raw",r,{name:"AES-GCM"},true,["encrypt","decrypt"]);
async function encData(data,key){const iv=crypto.getRandomValues(new Uint8Array(12));const e=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,data);return{ct:Array.from(new Uint8Array(e)).map(b=>b.toString(16).padStart(2,'0')).join(''),iv:Array.from(iv).map(b=>b.toString(16).padStart(2,'0')).join('')}}
async function decData(ctHex,ivHex,key){const ct=new Uint8Array(ctHex.match(/.{2}/g).map(b=>parseInt(b,16)));const iv=new Uint8Array(ivHex.match(/.{2}/g).map(b=>parseInt(b,16)));return crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct)}

// ── IPFS sim ──────────────────────────────────────────────────────────────────
// ── IPFS simulation (persistent) ─────────────────────────────────────────────
const ipfsUp = (data) => {

  const hash =
    "Qm" +
    Array.from(crypto.getRandomValues(new Uint8Array(20)))
      .map(b => b.toString(36))
      .join("")
      .slice(0, 44);

  localStorage.setItem("ipfs_" + hash, data);

  return hash;
};

const ipfsFetch = (hash) => {
  return localStorage.getItem("ipfs_" + hash);
};

// ── STYLES ────────────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f8f7ff;
  --bg2:#f0eff9;
  --white:#ffffff;
  --border:#e4e2f5;
  --border2:#d0cdef;
  --primary:#5b4fcf;
  --primary-light:#7c6fdf;
  --primary-dim:rgba(91,79,207,0.1);
  --primary-dim2:rgba(91,79,207,0.06);
  --secondary:#0ea5e9;
  --success:#10b981;
  --success-dim:rgba(16,185,129,0.1);
  --warn:#f59e0b;
  --warn-dim:rgba(245,158,11,0.1);
  --danger:#ef4444;
  --danger-dim:rgba(239,68,68,0.1);
  --text:#1a1638;
  --text2:#4a4570;
  --text3:#7a759e;
  --font:'Plus Jakarta Sans',sans-serif;
  --mono:'JetBrains Mono',monospace;
  --r:12px;
  --r-sm:8px;
  --shadow:0 1px 3px rgba(91,79,207,0.08),0 4px 16px rgba(91,79,207,0.06);
  --shadow-lg:0 8px 40px rgba(91,79,207,0.15);
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh;line-height:1.5}

/* ── HEADER ── */
.hdr{position:sticky;top:0;z-index:200;background:rgba(248,247,255,0.92);backdrop-filter:blur(16px);border-bottom:1px solid var(--border);padding:0 32px;height:60px;display:flex;align-items:center;justify-content:space-between}
.hdr-logo{display:flex;align-items:center;gap:10px;cursor:pointer}
.hdr-logo-icon{width:34px;height:34px;background:var(--primary);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:17px;box-shadow:0 4px 12px rgba(91,79,207,0.35)}
.hdr-logo-text{font-weight:800;font-size:1rem;color:var(--text);letter-spacing:-0.02em}
.hdr-logo-text span{color:var(--primary)}
.hdr-right{display:flex;align-items:center;gap:10px}
.net-badge{display:flex;align-items:center;gap:6px;background:var(--white);border:1px solid var(--border);border-radius:20px;padding:5px 12px;font-family:var(--mono);font-size:0.65rem;color:var(--text3)}
.net-dot{width:7px;height:7px;border-radius:50%;background:var(--success);box-shadow:0 0 6px var(--success)}
.net-dot.off{background:var(--text3);box-shadow:none}
.wallet-btn{background:var(--primary);color:#fff;border:none;padding:8px 18px;border-radius:var(--r-sm);font-family:var(--font);font-size:0.82rem;font-weight:600;cursor:pointer;transition:all .2s;box-shadow:0 4px 12px rgba(91,79,207,0.3)}
.wallet-btn:hover{background:var(--primary-light);transform:translateY(-1px)}
.wallet-btn.conn{background:var(--white);border:1px solid var(--border);color:var(--text2);box-shadow:none;font-family:var(--mono);font-size:0.72rem}

/* ── NAV TABS ── */
.nav-tabs{display:flex;gap:4px;padding:0 32px;background:var(--white);border-bottom:1px solid var(--border)}
.nav-tab{padding:12px 18px;font-size:0.82rem;font-weight:600;cursor:pointer;border:none;background:none;color:var(--text3);border-bottom:2px solid transparent;transition:all .15s;display:flex;align-items:center;gap:7px}
.nav-tab:hover{color:var(--text2)}
.nav-tab.active{color:var(--primary);border-bottom-color:var(--primary)}
.tab-badge{background:var(--primary-dim);color:var(--primary);border-radius:20px;padding:1px 7px;font-size:0.62rem;font-weight:700}

/* ── LAYOUT ── */
.page{max-width:900px;margin:0 auto;padding:36px 24px}
.page-wide{max-width:1100px;margin:0 auto;padding:36px 24px}

/* ── LANDING ── */
.land-hero{text-align:center;padding:64px 24px 48px;max-width:680px;margin:0 auto}
.land-eyebrow{display:inline-flex;align-items:center;gap:8px;background:var(--primary-dim);color:var(--primary);border-radius:20px;padding:6px 14px;font-size:0.72rem;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;margin-bottom:20px}
.land-title{font-size:3rem;font-weight:800;letter-spacing:-0.04em;line-height:1.1;color:var(--text);margin-bottom:16px}
.land-title span{color:var(--primary)}
.land-sub{font-size:1.05rem;color:var(--text2);line-height:1.7;margin-bottom:36px;max-width:540px;margin-left:auto;margin-right:auto}
.land-btns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.land-btn-primary{background:var(--primary);color:#fff;border:none;padding:14px 32px;border-radius:var(--r);font-family:var(--font);font-size:0.95rem;font-weight:700;cursor:pointer;transition:all .2s;box-shadow:0 8px 24px rgba(91,79,207,0.35)}
.land-btn-primary:hover{transform:translateY(-2px);box-shadow:0 12px 32px rgba(91,79,207,0.45)}
.land-btn-ghost{background:var(--white);color:var(--primary);border:2px solid var(--border2);padding:14px 32px;border-radius:var(--r);font-family:var(--font);font-size:0.95rem;font-weight:700;cursor:pointer;transition:all .2s}
.land-btn-ghost:hover{border-color:var(--primary);transform:translateY(-2px)}

/* ── HOW IT WORKS ── */
.how-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:48px 0}
.how-card{background:var(--white);border:1px solid var(--border);border-radius:var(--r);padding:28px 24px;position:relative;transition:all .2s}
.how-card:hover{border-color:var(--primary);box-shadow:var(--shadow-lg);transform:translateY(-3px)}
.how-num{width:36px;height:36px;background:var(--primary-dim);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:0.75rem;font-weight:800;color:var(--primary);margin-bottom:14px}
.how-icon{font-size:1.6rem;margin-bottom:10px}
.how-title{font-size:0.95rem;font-weight:700;color:var(--text);margin-bottom:8px}
.how-desc{font-size:0.8rem;color:var(--text3);line-height:1.6}

/* ── ROLE CARDS ── */
.role-section{margin:48px 0}
.section-title{font-size:1.4rem;font-weight:800;letter-spacing:-0.02em;margin-bottom:6px}
.section-sub{color:var(--text3);font-size:0.85rem;margin-bottom:24px}
.role-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.role-card{background:var(--white);border:2px solid var(--border);border-radius:var(--r);padding:24px;cursor:pointer;transition:all .2s;text-align:center}
.role-card:hover,.role-card.sel{border-color:var(--primary);background:var(--primary-dim2)}
.role-icon{font-size:2.2rem;margin-bottom:12px}
.role-name{font-size:1rem;font-weight:700;margin-bottom:6px}
.role-desc{font-size:0.75rem;color:var(--text3);line-height:1.5}
.role-tag{display:inline-block;background:var(--primary-dim);color:var(--primary);border-radius:20px;padding:3px 10px;font-size:0.65rem;font-weight:700;margin-top:10px}

/* ── ONBOARDING ── */
.onboard-wrap{max-width:680px;margin:0 auto}
.ob-header{text-align:center;margin-bottom:36px}
.ob-steps{display:flex;align-items:center;justify-content:center;gap:0;margin-bottom:40px}
.ob-step{display:flex;align-items:center;gap:8px}
.ob-step-circle{width:32px;height:32px;border-radius:50%;border:2px solid var(--border2);display:flex;align-items:center;justify-content:center;font-size:0.75rem;font-weight:700;color:var(--text3);background:var(--white);transition:all .3s;flex-shrink:0}
.ob-step-circle.active{border-color:var(--primary);background:var(--primary);color:#fff}
.ob-step-circle.done{border-color:var(--success);background:var(--success);color:#fff}
.ob-step-label{font-size:0.7rem;font-weight:600;color:var(--text3)}
.ob-step-label.active{color:var(--primary)}
.ob-step-label.done{color:var(--success)}
.ob-connector{width:40px;height:2px;background:var(--border2);margin:0 4px}
.ob-connector.done{background:var(--success)}
.ob-card{background:var(--white);border:1px solid var(--border);border-radius:var(--r);padding:32px;box-shadow:var(--shadow)}

/* ── CARDS / COMMON ── */
.card{background:var(--white);border:1px solid var(--border);border-radius:var(--r);padding:24px;margin-bottom:14px;box-shadow:var(--shadow)}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.card-title{font-size:0.72rem;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--text3)}
.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.stat-box{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-sm);padding:16px}
.stat-n{font-size:1.8rem;font-weight:800;letter-spacing:-0.04em;line-height:1}
.stat-n.purple{color:var(--primary)}
.stat-n.green{color:var(--success)}
.stat-n.gold{color:var(--warn)}
.stat-l{font-size:0.65rem;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;margin-top:4px;font-weight:600}

/* ── VAULT CARDS ── */
.vault-item{background:var(--white);border:1px solid var(--border);border-radius:var(--r);padding:18px 22px;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:10px}
.vault-item:hover{border-color:var(--primary);box-shadow:var(--shadow);transform:translateX(3px)}
.vault-id{font-family:var(--mono);font-size:0.6rem;color:var(--text3);margin-bottom:3px}
.vault-name{font-size:0.95rem;font-weight:700;color:var(--text);margin-bottom:6px}
.vault-meta{display:flex;gap:16px;font-size:0.72rem;color:var(--text3)}
.v-meta-item{display:flex;align-items:center;gap:4px}
.progress-bar{height:4px;background:var(--bg2);border-radius:4px;overflow:hidden;margin-top:8px}
.progress-fill{height:100%;border-radius:4px;transition:width .5s}
.fill-full{background:var(--success)}
.fill-part{background:var(--primary)}
.fill-none{width:0}

/* ── BADGES ── */
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em}
.badge::before{content:'';width:5px;height:5px;border-radius:50%;flex-shrink:0}
.b-active{background:var(--primary-dim);color:var(--primary)}.b-active::before{background:var(--primary)}
.b-death{background:var(--warn-dim);color:var(--warn)}.b-death::before{background:var(--warn)}
.b-released{background:var(--success-dim);color:var(--success)}.b-released::before{background:var(--success)}
.b-cancelled{background:var(--danger-dim);color:var(--danger)}.b-cancelled::before{background:var(--danger)}

/* ── FORMS ── */
.field{margin-bottom:16px}
.label{display:block;font-size:0.72rem;font-weight:600;color:var(--text2);margin-bottom:7px}
.label-hint{font-weight:400;color:var(--text3);margin-left:6px}
.input,.textarea,.select{width:100%;background:var(--bg);border:1.5px solid var(--border2);color:var(--text);padding:10px 14px;border-radius:var(--r-sm);font-family:var(--font);font-size:0.85rem;outline:none;transition:border-color .2s}
.input:focus,.textarea:focus,.select:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(91,79,207,0.1)}
.textarea{resize:vertical;min-height:110px;line-height:1.6}
.input-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.input-help{font-size:0.7rem;color:var(--text3);margin-top:5px;line-height:1.5}

/* ── BUTTONS ── */
.btn{padding:10px 22px;border-radius:var(--r-sm);font-family:var(--font);font-size:0.85rem;font-weight:700;cursor:pointer;border:none;transition:all .2s;display:inline-flex;align-items:center;gap:8px}
.btn-primary{background:var(--primary);color:#fff;box-shadow:0 4px 12px rgba(91,79,207,0.25)}
.btn-primary:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 20px rgba(91,79,207,0.35)}
.btn-success{background:var(--success);color:#fff}
.btn-danger{background:var(--danger);color:#fff}
.btn-ghost{background:var(--white);border:1.5px solid var(--border2);color:var(--text2)}
.btn-ghost:hover:not(:disabled){border-color:var(--primary);color:var(--primary)}
.btn:disabled{opacity:.45;cursor:not-allowed;transform:none!important}
.btn-sm{padding:7px 14px;font-size:0.78rem}
.btn-row{display:flex;gap:10px;flex-wrap:wrap}

/* ── ALERTS ── */
.alert{padding:12px 16px;border-radius:var(--r-sm);font-size:0.8rem;margin-bottom:16px;border:1.5px solid;line-height:1.6;display:flex;gap:10px;align-items:flex-start}
.alert-icon{flex-shrink:0;font-size:1rem;margin-top:1px}
.alert-info{background:rgba(14,165,233,0.07);border-color:rgba(14,165,233,0.25);color:#0369a1}
.alert-success{background:var(--success-dim);border-color:rgba(16,185,129,0.3);color:#065f46}
.alert-warn{background:var(--warn-dim);border-color:rgba(245,158,11,0.3);color:#92400e}
.alert-danger{background:var(--danger-dim);border-color:rgba(239,68,68,0.3);color:#991b1b}

/* ── TIMELINE ── */
.timeline{padding:4px 0}
.tl-item{display:flex;gap:14px;padding-bottom:22px;position:relative}
.tl-item:not(:last-child)::before{content:'';position:absolute;left:9px;top:20px;bottom:0;width:2px;background:var(--border)}
.tl-dot{width:20px;height:20px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:10px;border:2px solid;margin-top:1px}
.tl-dot.done{background:var(--success);border-color:var(--success);color:#fff}
.tl-dot.active{background:var(--primary);border-color:var(--primary);color:#fff}
.tl-dot.pending{background:var(--white);border-color:var(--border2);color:var(--text3)}
.tl-label{font-size:0.85rem;font-weight:600;color:var(--text);margin-bottom:2px}
.tl-sub{font-size:0.72rem;color:var(--text3);line-height:1.5}

/* ── TABS ── */
.tabs{display:flex;gap:4px;border-bottom:2px solid var(--border);margin-bottom:22px}
.tab{padding:8px 16px;font-size:0.8rem;font-weight:600;cursor:pointer;border:none;background:none;color:var(--text3);border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .15s}
.tab:hover{color:var(--text2)}
.tab.active{color:var(--primary);border-bottom-color:var(--primary)}

/* ── TABLE ── */
.tbl-wrap{border:1px solid var(--border);border-radius:var(--r-sm);overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:0.8rem}
th{padding:10px 14px;background:var(--bg2);color:var(--text3);font-size:0.65rem;letter-spacing:0.08em;text-transform:uppercase;text-align:left;font-weight:700}
td{padding:12px 14px;border-top:1px solid var(--border);color:var(--text2)}
tr:hover td{background:var(--bg2)}

/* ── INFO ROWS ── */
.info-row{display:flex;justify-content:space-between;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--border);gap:20px}
.info-row:last-child{border:none}
.info-key{font-size:0.75rem;color:var(--text3);font-weight:500;flex-shrink:0}
.info-val{font-size:0.75rem;color:var(--text);font-family:var(--mono);text-align:right;word-break:break-all}

/* ── HASH BOX ── */
.hash-box{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-sm);padding:10px 14px;font-family:var(--mono);font-size:0.7rem;color:var(--text2);word-break:break-all;line-height:1.6;margin-bottom:8px}

/* ── HELP TOOLTIP ── */
.help-tip{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;background:var(--bg2);border:1px solid var(--border2);font-size:0.6rem;color:var(--text3);cursor:help;margin-left:5px;flex-shrink:0;font-weight:700}

/* ── STEP WIZARD ── */
.wizard{display:flex;gap:0;border:1px solid var(--border);border-radius:var(--r-sm);overflow:hidden;margin-bottom:28px}
.wiz-step{flex:1;padding:11px 8px;text-align:center;font-size:0.68rem;font-weight:600;color:var(--text3);background:var(--white);border-right:1px solid var(--border);transition:all .2s}
.wiz-step:last-child{border-right:none}
.wiz-step.active{background:var(--primary);color:#fff}
.wiz-step.done{background:var(--success-dim);color:var(--success)}

/* ── SPINNER ── */
.spin{width:15px;height:15px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:sp .7s linear infinite;flex-shrink:0}
@keyframes sp{to{transform:rotate(360deg)}}

/* ── TOAST ── */
.toast{position:fixed;bottom:24px;right:24px;z-index:999;background:var(--white);border:1.5px solid var(--border);border-radius:var(--r);padding:14px 18px;min-width:300px;box-shadow:var(--shadow-lg);animation:su .3s ease}
.toast-title{font-size:0.85rem;font-weight:700;margin-bottom:3px}
.toast-sub{font-size:0.72rem;color:var(--text3)}
@keyframes su{from{transform:translateY(16px);opacity:0}to{transform:translateY(0);opacity:1}}

/* ── EMPTY ── */
.empty{text-align:center;padding:48px 20px;color:var(--text3)}
.empty-ico{font-size:3rem;margin-bottom:12px}
.empty-title{font-size:1rem;font-weight:700;color:var(--text2);margin-bottom:6px}
.empty-sub{font-size:0.8rem;line-height:1.6}

/* ── FEATURE STRIP ── */
.feat-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:40px 0}
.feat-box{background:var(--white);border:1px solid var(--border);border-radius:var(--r);padding:20px 16px;text-align:center}
.feat-icon{font-size:1.8rem;margin-bottom:8px}
.feat-title{font-size:0.82rem;font-weight:700;color:var(--text);margin-bottom:4px}
.feat-desc{font-size:0.72rem;color:var(--text3);line-height:1.5}

/* ── DIVIDER ── */
.divider{border:none;border-top:1px solid var(--border);margin:32px 0}

/* ── ANIM ── */
@keyframes fi{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.fi{animation:fi .35s ease forwards}

/* ── TRUSTEE SHARE BOX ── */
.share-item{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-sm);padding:14px 16px;margin-bottom:10px}
.share-label{font-size:0.7rem;font-weight:700;color:var(--text2);margin-bottom:6px;display:flex;align-items:center;gap:8px}
.share-val{font-family:var(--mono);font-size:0.68rem;color:var(--text3);word-break:break-all;line-height:1.6}
`;

// ── Helpers ───────────────────────────────────────────────────────────────────
const STATUS=["Active","Death Reported","Released","Cancelled"];
const S_CLASS=["b-active","b-death","b-released","b-cancelled"];
function Badge({s}){const i=typeof s==="number"?s:STATUS.findIndex(x=>x===s||x.replace(" ","")===s);return <span className={`badge ${S_CLASS[Math.max(0,i)]}`}>{STATUS[Math.max(0,i)]||s}</span>}
function Alert({type="info",icon,children}){const icons={info:"ℹ️",success:"✅",warn:"⚠️",danger:"❌"};return <div className={`alert alert-${type}`}><span className="alert-icon">{icon||icons[type]}</span><div>{children}</div></div>}
function Toast({t,clear}){useEffect(()=>{if(t?.done||t?.err){const id=setTimeout(clear,4000);return()=>clearTimeout(id)}},[t]);if(!t)return null;return <div className="toast"><div className="toast-title" style={{color:t.done?"var(--success)":t.err?"var(--danger)":"var(--text)"}}>{t.done?"✓ ":t.err?"✗ ":""}{t.title}</div><div className="toast-sub">{t.sub}</div></div>}
const dLeft=exp=>Math.max(0,Math.floor((exp-Date.now()/1000)/86400));

// ── APP ───────────────────────────────────────────────────────────────────────
export default function App(){
  const[page,setPage]=useState("landing");
  const[tab,setTab]=useState("dashboard");
  const[selVault,setSelVault]=useState(null);
  const[acct,setAcct]=useState(null);
  const[chainId,setChainId]=useState(null);
  const[contract,setContract]=useState(null);
  const[vaults,setVaults]=useState([]);
  const[dep,setDep]=useState(null);
  const[tx,setTx]=useState(null);
  const showTx=(title,sub)=>setTx({title,sub});
  const doneTx=(title,sub)=>setTx({title,sub,done:true});
  const errTx=(title,sub)=>setTx({title,sub,err:true});

  useEffect(()=>{
    fetch("/deployment.json").then(r=>r.json()).then(d=>{
      setDep(d);
      // Auto-connect if MetaMask already has permission
      if(window.ethereum){
        window.ethereum.request({method:"eth_accounts"}).then(async accounts=>{
          if(accounts.length>0){
            const p=new ethers.BrowserProvider(window.ethereum);
            const s=await p.getSigner();
            const a=await s.getAddress();
            const n=await p.getNetwork();
            setAcct(a);setChainId(Number(n.chainId));
            const c=new ethers.Contract(d.contractAddress,ABI,s);
            setContract(c);
            await loadVaults(c);
          }
        });
      }
    }).catch(()=>{});
  },[]);
  
  const connect=async()=>{
    if(!window.ethereum){alert("Please install MetaMask first!\nGo to metamask.io");return}
    try{
      const p=new ethers.BrowserProvider(window.ethereum);
      await p.send("eth_requestAccounts",[]);
      const s=await p.getSigner();
      const a=await s.getAddress();
      const n=await p.getNetwork();
      setAcct(a);setChainId(Number(n.chainId));
      if(dep){const c=new ethers.Contract(dep.contractAddress,ABI,s);setContract(c);await loadVaults(c);}
    }catch(e){console.error(e)}
  };

  useEffect(()=>{if(!window.ethereum)return;window.ethereum.on("accountsChanged",connect);window.ethereum.on("chainChanged",()=>window.location.reload());},[dep]);

  const loadVaults=async(c)=>{
    try{
      const count=Number(await c.vaultCount());
      const list=[];
      for(let i=0;i<count;i++){
        try{
          const v=await c.getVault(i);
          const tr=await c.getTrustees(i);
          const d=Number(await c.getDeathConfirmations(i));
          list.push({id:i,description:v.description,status:Number(v.status),threshold:Number(v.threshold),totalShares:Number(v.totalShares),sharesSubmitted:Number(v.sharesSubmitted),timelockExpiry:Number(v.timelockExpiry),beneficiary:v.beneficiary,owner:v.owner,dataHash:v.encryptedDataHash,dataURI:v.encryptedDataURI,createdAt:new Date(Number(v.createdAt)*1000).toLocaleDateString(),trustees:tr,deaths:d});
        }catch{}
      }
      setVaults(list);
    }catch(e){console.error(e)}
  };

  const goApp=(t)=>{setPage("app");setTab(t||"dashboard")};

  return(
    <>
      <style>{CSS}</style>
      {/* HEADER */}
      <header className="hdr">
        <div className="hdr-logo" onClick={()=>setPage("landing")}>
          <div className="hdr-logo-icon">🔐</div>
          <div><div className="hdr-logo-text">Posthumous<span>Release</span></div></div>
        </div>
        <div className="hdr-right">
          {acct&&<div className="net-badge"><div className={`net-dot${chainId===31337?"":" off"}`}/>{chainId===31337?"Hardhat Local":chainId?`Chain ${chainId}`:"Wrong Network"}</div>}
          <button className={`wallet-btn${acct?" conn":""}`} onClick={acct?()=>{}:connect}>
            {acct?`${acct.slice(0,6)}...${acct.slice(-4)}`:"Connect Wallet"}
          </button>
          {page==="landing"&&<button className="btn-ghost btn btn-sm" onClick={()=>goApp()}>Open App →</button>}
        </div>
      </header>

      {/* PAGES */}
      {page==="landing"&&<LandingPage onStart={()=>goApp()} onRole={r=>{setPage("app");setTab(r)}} connect={connect} acct={acct}/>}
      {page==="app"&&(
        <>
          <nav className="nav-tabs">
            {[["dashboard","🗄 Dashboard"],["create","＋ Create Vault"],["trustee","◈ Trustee Portal"],["beneficiary","◇ Beneficiary Portal"],["guide","📖 How It Works"]].map(([t,label])=>(
              <button key={t} className={`nav-tab${tab===t?" active":""}`} onClick={()=>{setTab(t);setSelVault(null)}}>{label}</button>
            ))}
          </nav>
          <div className="page-wide fi">
            {!acct&&<div style={{marginBottom:16}}><Alert type="warn" icon="🦊">Connect your MetaMask wallet to interact with the blockchain. <button className="btn btn-primary btn-sm" style={{marginLeft:8}} onClick={connect}>Connect Now</button></Alert></div>}
            {tab==="dashboard"&&!selVault&&<DashboardPage vaults={vaults} onSelect={setSelVault} onRefresh={()=>contract&&loadVaults(contract)} acct={acct}/>}
            {tab==="dashboard"&&selVault&&<VaultDetail vault={selVault} onBack={()=>setSelVault(null)} contract={contract} acct={acct} showTx={showTx} doneTx={doneTx} errTx={errTx} onRefresh={()=>contract&&loadVaults(contract)}/>}
            {tab==="create"&&<CreatePage contract={contract} acct={acct} showTx={showTx} doneTx={doneTx} errTx={errTx} onDone={()=>{contract&&loadVaults(contract);setTab("dashboard")}}/>}
            {tab==="trustee"&&<TrusteePage contract={contract} acct={acct} showTx={showTx} doneTx={doneTx} errTx={errTx} onRefresh={()=>contract&&loadVaults(contract)}/>}
            {tab==="beneficiary"&&<BeneficiaryPage contract={contract} acct={acct} showTx={showTx} doneTx={doneTx} errTx={errTx}/>}
            {tab==="guide"&&<GuidePage onRole={r=>setTab(r)}/>}
          </div>
        </>
      )}
      <Toast t={tx} clear={()=>setTx(null)}/>
    </>
  );
}

// ── LANDING PAGE ──────────────────────────────────────────────────────────────
function LandingPage({onStart,onRole,connect,acct}){
  return(
    <div>
      {/* Hero */}
      <div className="land-hero fi">
        <div className="land-eyebrow">🔐 Blockchain-Powered Digital Legacy</div>
        <h1 className="land-title">Your secrets survive.<br/><span>Even when you don't.</span></h1>
        <p className="land-sub">PosthumousRelease lets you securely encrypt your most sensitive data — passwords, crypto seeds, final messages — and automatically release it to your loved ones only after you pass away. No single point of failure. No trust required.</p>
        <div className="land-btns">
          <button className="land-btn-primary" onClick={onStart}>Get Started →</button>
          <button className="land-btn-ghost" onClick={()=>{onStart();onRole("guide")}}>See How It Works</button>
        </div>
      </div>

      {/* Feature strip */}
      <div className="page-wide">
        <div className="feat-strip fi">
          <div className="feat-box"><div className="feat-icon">🔒</div><div className="feat-title">AES-256 Encrypted</div><div className="feat-desc">Military-grade encryption. Data never leaves your browser unencrypted.</div></div>
          <div className="feat-box"><div className="feat-icon">🔑</div><div className="feat-title">Threshold Cryptography</div><div className="feat-desc">Shamir's Secret Sharing splits your key — no single trustee can act alone.</div></div>
          <div className="feat-box"><div className="feat-icon">⛓</div><div className="feat-title">Blockchain Timelock</div><div className="feat-desc">Smart contract enforces rules. No company, no middleman, no single point of failure.</div></div>
          <div className="feat-box"><div className="feat-icon">⏱</div><div className="feat-title">Auto Dead-Man Switch</div><div className="feat-desc">Data releases automatically after a set time if trustees don't act.</div></div>
        </div>

        {/* How it works */}
        <div style={{textAlign:"center",marginBottom:8}}><h2 style={{fontSize:"1.8rem",fontWeight:800,letterSpacing:"-0.03em"}}>How It Works</h2><p style={{color:"var(--text3)",marginTop:6,fontSize:"0.9rem"}}>Three roles, one secure system</p></div>
        <div className="how-grid">
          <div className="how-card"><div className="how-num">01</div><div className="how-icon">👤</div><div className="how-title">Owner — You</div><div className="how-desc">Encrypt your sensitive data, split your encryption key across trusted people, and set a timelock. You're in full control.</div></div>
          <div className="how-card"><div className="how-num">02</div><div className="how-icon">👥</div><div className="how-title">Trustees — Your Trusted Circle</div><div className="how-desc">Each trustee holds one piece of your encryption key. When you pass, they confirm it and submit their piece to the blockchain.</div></div>
          <div className="how-card"><div className="how-num">03</div><div className="how-icon">🎁</div><div className="how-title">Beneficiary — Your Loved Ones</div><div className="how-desc">Once enough trustees confirm and submit shares, the vault unlocks. The beneficiary reconstructs the key and reads your data.</div></div>
        </div>

        {/* Role picker */}
        <div className="role-section">
          <div style={{textAlign:"center"}}><h2 className="section-title">Who are you?</h2><p className="section-sub">Choose your role to jump straight to the right section</p></div>
          <div className="role-grid">
            <div className="role-card" onClick={()=>{onRole("create")}}>
              <div className="role-icon">🏛</div><div className="role-name">I'm the Owner</div>
              <div className="role-desc">I want to protect my digital assets and leave them for someone I love.</div>
              <div className="role-tag">Create a Vault →</div>
            </div>
            <div className="role-card" onClick={()=>onRole("trustee")}>
              <div className="role-icon">🤝</div><div className="role-name">I'm a Trustee</div>
              <div className="role-desc">Someone I trust has given me a secret share. I need to submit it after they pass.</div>
              <div className="role-tag">Trustee Portal →</div>
            </div>
            <div className="role-card" onClick={()=>onRole("beneficiary")}>
              <div className="role-icon">💌</div><div className="role-name">I'm the Beneficiary</div>
              <div className="role-desc">Someone left something for me. I want to access my inherited data.</div>
              <div className="role-tag">Beneficiary Portal →</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── GUIDE PAGE ────────────────────────────────────────────────────────────────
function GuidePage({onRole}){
  const[open,setOpen]=useState(0);
  const sections=[
    {title:"What is this system?",icon:"❓",content:"PosthumousRelease is a decentralized system that lets you securely encrypt important data (passwords, crypto seed phrases, bank details, final messages) and automatically release it to a chosen person after you die — using blockchain technology and advanced cryptography. No company stores your data. No single person can access it early. It's completely trustless."},
    {title:"What is Shamir's Secret Sharing?",icon:"🔑",content:"Your encryption key is split into N pieces (called shares) using a mathematical technique called Shamir's Secret Sharing (over Galois Field GF(2^8)). Any T shares can reconstruct the original key, but fewer than T shares reveal absolutely nothing. For example, in a 3-of-5 setup: 5 trustees each hold 1 share. Any 3 can unlock the vault. Even if 2 trustees disappear or refuse — the other 3 can still release the data."},
    {title:"What is a blockchain timelock?",icon:"⏱",content:"A smart contract on the blockchain enforces the release rules. The timelock means: if no trustee acts within a set number of days (e.g. 365 days), the vault automatically unlocks — a 'dead man's switch'. This prevents data from being locked forever if trustees are unreachable. The blockchain is trustless — no company or person controls it."},
    {title:"How is my data encrypted?",icon:"🔒",content:"Your data is encrypted in your browser using AES-256-GCM — the same encryption used by banks and governments. A random 256-bit key is generated, your data is encrypted with it, then the key itself is split using Shamir's Secret Sharing. Only the encrypted blob is stored (on IPFS). The key never exists in one place."},
    {title:"Step-by-step: Owner",icon:"👤",content:"1. Go to 'Create Vault'\n2. Type your sensitive data (passwords, messages, seed phrases)\n3. Add your trustees (wallet addresses of people you trust)\n4. Set a threshold (e.g. 3-of-5) and a timelock (e.g. 365 days)\n5. Add your beneficiary's wallet address\n6. Click Deploy — your data is encrypted and the vault is created on the blockchain\n7. Send each trustee their secret share privately (shown after creation)"},
    {title:"Step-by-step: Trustee",icon:"👥",content:"1. The vault owner sends you a hex share privately (e.g. via encrypted message)\n2. Store it safely — this is your piece of the encryption key\n3. When the owner passes away, go to 'Trustee Portal'\n4. Enter the Vault ID\n5. Click 'Confirm Death' — this is recorded on the blockchain\n6. Once enough trustees confirm, paste your share and click 'Submit Share'\n7. When enough shares are submitted, the vault automatically releases"},
    {title:"Step-by-step: Beneficiary",icon:"💌",content:"1. You'll be notified (or check the dashboard) when a vault is Released\n2. Go to 'Beneficiary Portal'\n3. Enter the Vault ID\n4. Collect the hex shares from trustees who submitted them\n5. Paste all shares (one per line) into the box\n6. Click 'Decrypt & Recover Data'\n7. Your inherited data appears — decrypted in your browser"},
  ];
  return(
    <div className="page fi">
      <div className="page-header" style={{marginBottom:28}}>
        <h1 style={{fontSize:"1.8rem",fontWeight:800,letterSpacing:"-0.03em",marginBottom:4}}>📖 How It Works</h1>
        <p style={{color:"var(--text3)",fontSize:"0.85rem"}}>Everything you need to understand this system</p>
      </div>
      <div style={{display:"grid",grid:"auto-flow/1fr 1fr",gap:12,marginBottom:32}}>
        {[["Owner","create","🏛","Create and manage your vault"],["Trustee","trustee","🤝","Confirm death & submit share"],["Beneficiary","beneficiary","💌","Access your inherited data"]].map(([n,r,ic,d])=>(
          <div key={r} className="card" style={{cursor:"pointer",border:"1.5px solid var(--border2)"}} onClick={()=>onRole(r)}>
            <div style={{display:"flex",gap:12,alignItems:"center"}}>
              <div style={{fontSize:"1.8rem"}}>{ic}</div>
              <div><div style={{fontWeight:700,fontSize:"0.9rem"}}>{n}</div><div style={{fontSize:"0.75rem",color:"var(--text3)"}}>{d}</div></div>
              <div style={{marginLeft:"auto",color:"var(--primary)",fontWeight:700,fontSize:"0.8rem"}}>Go →</div>
            </div>
          </div>
        ))}
      </div>
      {sections.map((s,i)=>(
        <div key={i} className="card" style={{marginBottom:8,cursor:"pointer"}} onClick={()=>setOpen(open===i?-1:i)}>
          <div style={{display:"flex",alignItems:"center",gap:12,justifyContent:"space-between"}}>
            <div style={{display:"flex",gap:10,alignItems:"center"}}>
              <span style={{fontSize:"1.2rem"}}>{s.icon}</span>
              <span style={{fontWeight:700,fontSize:"0.9rem"}}>{s.title}</span>
            </div>
            <span style={{color:"var(--text3)",fontSize:"1.1rem"}}>{open===i?"▲":"▼"}</span>
          </div>
          {open===i&&<div style={{marginTop:14,fontSize:"0.82rem",color:"var(--text2)",lineHeight:1.8,whiteSpace:"pre-line",borderTop:"1px solid var(--border)",paddingTop:14}}>{s.content}</div>}
        </div>
      ))}
    </div>
  );
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
function DashboardPage({vaults,onSelect,onRefresh,acct}){
  return(
    <div className="page fi">
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:24}}>
        <div><h1 style={{fontSize:"1.6rem",fontWeight:800,letterSpacing:"-0.03em"}}>Vault Dashboard</h1><p style={{color:"var(--text3)",fontSize:"0.82rem",marginTop:2}}>All posthumous data vaults on the blockchain</p></div>
        <button className="btn btn-ghost btn-sm" onClick={onRefresh}>↻ Refresh</button>
      </div>
      <div className="stats-row">
        <div className="stat-box"><div className="stat-n">{vaults.length}</div><div className="stat-l">Total Vaults</div></div>
        <div className="stat-box"><div className="stat-n purple">{vaults.filter(v=>v.status===0).length}</div><div className="stat-l">Active</div></div>
        <div className="stat-box"><div className="stat-n green">{vaults.filter(v=>v.status===2).length}</div><div className="stat-l">Released</div></div>
      </div>
      <div className="card">
        <div className="card-hd"><span className="card-title">All Vaults</span></div>
        {vaults.length===0?(
          <div className="empty">
            <div className="empty-ico">🔒</div>
            <div className="empty-title">No vaults yet</div>
            <div className="empty-sub">{acct?"Create your first vault to protect your digital legacy.":"Connect your wallet to see vaults."}</div>
          </div>
        ):vaults.map(v=>{
          const pct=v.threshold>0?Math.min(100,(v.sharesSubmitted/v.threshold)*100):0;
          return(
            <div key={v.id} className="vault-item" onClick={()=>onSelect(v)}>
              <div style={{flex:1}}>
                <div className="vault-id">VAULT #{String(v.id).padStart(4,"0")} · Created {v.createdAt}</div>
                <div className="vault-name">{v.description}</div>
                <div className="vault-meta">
                  <span className="v-meta-item">🔑 {v.threshold}/{v.totalShares} threshold</span>
                  <span className="v-meta-item">⏱ {dLeft(v.timelockExpiry)} days left</span>
                  <span className="v-meta-item">👤 {v.owner.slice(0,8)}...</span>
                </div>
                <div className="progress-bar"><div className={`progress-fill ${pct===100?"fill-full":pct>0?"fill-part":"fill-none"}`} style={{width:`${pct}%`}}/></div>
                <div style={{fontSize:"0.65rem",color:"var(--text3)",marginTop:3}}>{v.sharesSubmitted}/{v.threshold} shares collected</div>
              </div>
              <Badge s={v.status}/>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── VAULT DETAIL ──────────────────────────────────────────────────────────────
function VaultDetail({vault,onBack,contract,acct,showTx,doneTx,errTx,onRefresh}){
  const[tab,setTab]=useState("overview");
  const[subs,setSubs]=useState([]);
  useEffect(()=>{if(contract&&vault.status===2)contract.getShareSubmissions(vault.id).then(setSubs).catch(()=>{});},[vault]);
  return(
    <div className="page fi">
      <div style={{display:"flex",alignItems:"center",gap:14,marginBottom:24}}>
        <button className="btn btn-ghost btn-sm" onClick={onBack}>← Back</button>
        <div style={{flex:1}}><div style={{fontWeight:800,fontSize:"1.2rem",letterSpacing:"-0.02em"}}>{vault.description}</div><div style={{fontSize:"0.72rem",color:"var(--text3)",marginTop:2}}>Vault #{vault.id}</div></div>
        <Badge s={vault.status}/>
      </div>
      <div className="stats-row">
        <div className="stat-box"><div className="stat-n purple">{vault.threshold}/{vault.totalShares}</div><div className="stat-l">Threshold</div></div>
        <div className="stat-box"><div className="stat-n gold">{vault.deaths}</div><div className="stat-l">Death Confirmations</div></div>
        <div className="stat-box"><div className="stat-n green">{vault.sharesSubmitted}</div><div className="stat-l">Shares Submitted</div></div>
      </div>
      <div className="tabs">{["overview","trustees","timeline","shares"].map(t=><button key={t} className={`tab${tab===t?" active":""}`} onClick={()=>setTab(t)}>{t.charAt(0).toUpperCase()+t.slice(1)}</button>)}</div>
      {tab==="overview"&&<div className="card"><div className="card-title" style={{marginBottom:14}}>Vault Information</div><div className="info-row"><span className="info-key">Owner</span><span className="info-val">{vault.owner}</span></div><div className="info-row"><span className="info-key">Beneficiary</span><span className="info-val">{vault.beneficiary}</span></div><div className="info-row"><span className="info-key">Created</span><span className="info-val">{vault.createdAt}</span></div><div className="info-row"><span className="info-key">Timelock Expiry</span><span className="info-val">{new Date(vault.timelockExpiry*1000).toLocaleDateString()} ({dLeft(vault.timelockExpiry)} days remaining)</span></div><div className="info-row"><span className="info-key">Data Hash (IPFS)</span><span className="info-val">{vault.dataHash}</span></div><div className="info-row"><span className="info-key">Encryption</span><span className="info-val">AES-256-GCM + Shamir SSS ({vault.threshold}-of-{vault.totalShares})</span></div></div>}
      {tab==="trustees"&&<div className="card"><div className="card-title" style={{marginBottom:14}}>Trustees ({vault.trustees?.length||0})</div><div className="tbl-wrap"><table><thead><tr><th>Name</th><th>Address</th><th>Confirmed Death</th><th>Submitted Share</th></tr></thead><tbody>{vault.trustees?.map((t,i)=><tr key={i}><td style={{fontWeight:600,color:"var(--text)"}}>{t.name}</td><td>{t.addr.slice(0,12)}...</td><td>{t.hasConfirmedDeath?<span style={{color:"var(--success)",fontWeight:700}}>✓ Yes</span>:<span style={{color:"var(--text3)"}}>Pending</span>}</td><td>{t.hasSubmittedShare?<span style={{color:"var(--success)",fontWeight:700}}>✓ Yes</span>:<span style={{color:"var(--text3)"}}>Pending</span>}</td></tr>)}</tbody></table></div></div>}
      {tab==="timeline"&&<div className="card"><div className="card-title" style={{marginBottom:16}}>Event Timeline</div><div className="timeline"><div className="tl-item"><div className="tl-dot done">✓</div><div><div className="tl-label">Vault Created</div><div className="tl-sub">{vault.createdAt} — Deployed to blockchain</div></div></div>{vault.trustees?.filter(t=>t.hasConfirmedDeath).map((t,i)=><div key={i} className="tl-item"><div className="tl-dot done">✓</div><div><div className="tl-label">Death Confirmed by {t.name}</div><div className="tl-sub">On-chain confirmation submitted</div></div></div>)}{(vault.status===1||vault.status===2)&&<div className="tl-item"><div className="tl-dot active">!</div><div><div className="tl-label">Status → Death Reported</div><div className="tl-sub">Threshold of {vault.threshold} confirmations reached — shares can now be submitted</div></div></div>}{vault.trustees?.filter(t=>t.hasSubmittedShare).map((t,i)=><div key={i} className="tl-item"><div className="tl-dot done">✓</div><div><div className="tl-label">Share Submitted by {t.name}</div><div className="tl-sub">Encrypted Shamir share stored on blockchain</div></div></div>)}{vault.status===2&&<div className="tl-item"><div className="tl-dot done" style={{background:"var(--success)"}}>🔓</div><div><div className="tl-label" style={{color:"var(--success)"}}>Vault Released!</div><div className="tl-sub">Beneficiary can now reconstruct the key and decrypt the data</div></div></div>}<div className="tl-item"><div className="tl-dot pending">⏱</div><div><div className="tl-label" style={{color:"var(--text3)"}}>Timelock Fallback: {new Date(vault.timelockExpiry*1000).toLocaleDateString()}</div><div className="tl-sub">Auto-releases if no trustee action before this date</div></div></div></div></div>}
      {tab==="shares"&&<div className="card"><div className="card-title" style={{marginBottom:14}}>Submitted Shares</div>{vault.status!==2?<Alert type="info">Shares are only visible to the beneficiary after the vault is Released.</Alert>:subs.length===0?<div className="empty"><div className="empty-ico">🔑</div><div className="empty-title">No shares visible</div><div className="empty-sub">Only the vault beneficiary can view submitted shares.</div></div>:subs.map((s,i)=><div key={i}><div style={{fontSize:"0.7rem",fontWeight:600,color:"var(--text2)",marginBottom:5}}>From {s.trustee.slice(0,14)}...:</div><div className="hash-box">{s.encryptedShare}</div></div>)}</div>}
    </div>
  );
}

// ── CREATE PAGE ───────────────────────────────────────────────────────────────
function CreatePage({contract,acct,showTx,doneTx,errTx,onDone}){
  const[step,setStep]=useState(0);
  const[busy,setBusy]=useState(false);
  const[result,setResult]=useState(null);
  const[form,setForm]=useState({desc:"",data:"",threshold:"3",days:"365",beneficiary:"",trustees:[{n:"",a:""},{n:"",a:""},{n:"",a:""},{n:"",a:""},{n:"",a:""}]});
  const sf=(k,v)=>setForm(f=>({...f,[k]:v}));
  const st=(i,k,v)=>{const t=[...form.trustees];t[i]={...t[i],[k]:v};sf("trustees",t)};
  const valid=form.trustees.filter(t=>t.a&&t.n);

  const deploy = async () => {
  if (!contract) {
    alert("Connect MetaMask first!");
    return;
  }

  setBusy(true);

  try {

    showTx("Encrypting data...", "AES-256-GCM key generation");

    const key = await genKey();
    const raw = await expKey(key);

    const bytes = new TextEncoder().encode(form.data);
    const { ct, iv } = await encData(bytes, key);

    const n = valid.length;
    const t = parseInt(form.threshold);

    showTx("Splitting key...", "Shamir Secret Sharing");

    const shares = splitSecret(raw, t, n);
    const hexShares = s2h(shares);

    showTx("Uploading to IPFS...", "Storing encrypted payload");

    const hash = ipfsUp(JSON.stringify({ ct, iv, algo: "AES-256-GCM" }));


    /* ---------------- CREATE VAULT ---------------- */

    showTx("Creating vault...", "Blockchain transaction");

    const tx1 = await contract.createVault(
      hash,
      `ipfs://${hash}`,
      parseInt(form.days),
      t,
      form.beneficiary,
      form.desc
    );

    await tx1.wait();


    /* ---------- FIXED VAULT ID EXTRACTION ---------- */

    const vid = Number(await contract.vaultCount()) - 1;


    /* ---------------- ADD TRUSTEES ---------------- */

    for (let i = 0; i < valid.length; i++) {

      showTx(`Adding trustee ${i + 1}/${valid.length}...`, valid[i].n);

      const tx2 = await contract.addTrustee(
        vid,
        valid[i].a,
        valid[i].n,
        ethers.keccak256(ethers.toUtf8Bytes(hexShares[i]))
      );

      await tx2.wait();
    }


    /* ---------------- SUCCESS ---------------- */

    doneTx("Vault created!", `Vault #${vid} is live on the blockchain`);

    setResult({
      vid,
      hexShares,
      trustees: valid,
      hash
    });

  } catch (e) {

    console.error(e);

    errTx(
      "Failed",
      e.reason || e.message?.slice(0, 70) || "Unknown error"
    );

  }

  setBusy(false);
};

  if(result) return(
    <div className="page fi">
      <Alert type="success" icon="🎉">Vault #{result.vid} successfully created on the blockchain!</Alert>
      <div className="card">
        <div className="card-hd"><span className="card-title">IPFS Storage</span></div>
        <div className="info-row"><span className="info-key">IPFS Hash</span><span className="info-val">{result.hash}</span></div>
        <Alert type="info" icon="ℹ️">Your encrypted data is stored at this IPFS hash. The blockchain only holds the hash — your actual data is never on-chain.</Alert>
      </div>
      <div className="card">
        <div className="card-hd"><span className="card-title">🔑 Shamir Shares — Send to Each Trustee Privately</span></div>
        <Alert type="warn" icon="⚠️">Send each share ONLY to its corresponding trustee via a secure channel (encrypted email, Signal, etc.). Never store all shares in the same place.</Alert>
        {result.hexShares.map((s,i)=>(
          <div key={i} className="share-item">
            <div className="share-label">Share for <strong>{result.trustees[i]?.n}</strong> <span style={{color:"var(--text3)",fontWeight:400}}>(Trustee {i+1})</span></div>
            <div className="share-val">{s}</div>
          </div>
        ))}
      </div>
      <button className="btn btn-primary" onClick={onDone}>← Back to Dashboard</button>
    </div>
  );

  const steps=["Your Data","Trustees","Settings","Deploy"];
  return(
    <div className="page fi">
      <h1 style={{fontSize:"1.6rem",fontWeight:800,letterSpacing:"-0.03em",marginBottom:4}}>Create a Vault</h1>
      <p style={{color:"var(--text3)",fontSize:"0.82rem",marginBottom:24}}>Protect your digital legacy in 4 simple steps</p>
      <div className="wizard">{steps.map((s,i)=><div key={i} className={`wiz-step${i===step?" active":i<step?" done":""}`}>{i<step?"✓ ":""}{s}</div>)}</div>

      {step===0&&<div className="ob-card fi">
        <h2 style={{fontSize:"1.1rem",fontWeight:800,marginBottom:4}}>What do you want to protect?</h2>
        <p style={{fontSize:"0.8rem",color:"var(--text3)",marginBottom:20,lineHeight:1.6}}>This data will be AES-256-GCM encrypted in your browser before anything is stored. Nobody can read it — not even us.</p>
        <div className="field"><label className="label">Vault Name <span className="label-hint">What is this vault for?</span></label><input className="input" placeholder="e.g. My Digital Legacy — Crypto seeds & final wishes" value={form.desc} onChange={e=>sf("desc",e.target.value)}/></div>
        <div className="field"><label className="label">Your Sensitive Data</label><textarea className="textarea" placeholder="Type anything here:&#10;• Bitcoin / crypto seed phrases&#10;• Passwords and account credentials&#10;• Final messages to loved ones&#10;• Bank account details&#10;• Important documents or instructions" value={form.data} onChange={e=>sf("data",e.target.value)} rows={8}/><div className="input-help">✓ Encrypted with AES-256-GCM in your browser &nbsp;·&nbsp; ✓ Stored on IPFS &nbsp;·&nbsp; ✓ Never transmitted unencrypted</div></div>
        <button className="btn btn-primary" onClick={()=>setStep(1)} disabled={!form.desc||!form.data}>Next: Add Trustees →</button>
      </div>}

      {step===1&&<div className="ob-card fi">
        <h2 style={{fontSize:"1.1rem",fontWeight:800,marginBottom:4}}>Who are your trustees?</h2>
        <p style={{fontSize:"0.8rem",color:"var(--text3)",marginBottom:8,lineHeight:1.6}}>Trustees each hold one piece of your encryption key. Choose people you deeply trust — family members, close friends, a lawyer. You need at least {form.threshold} of them to agree before data is released.</p>
        <Alert type="info" icon="💡">You need at least 3 trustees for a 3-of-5 setup. Add wallet addresses — if someone doesn't have MetaMask yet, they can create a free wallet at metamask.io</Alert>
        {form.trustees.map((t,i)=>(
          <div key={i} style={{background:"var(--bg2)",border:"1px solid var(--border)",borderRadius:"var(--r-sm)",padding:"14px 16px",marginBottom:10}}>
            <div style={{fontSize:"0.72rem",fontWeight:700,color:"var(--text3)",marginBottom:8}}>Trustee {i+1} {i<3&&<span style={{color:"var(--danger)"}}>*</span>}</div>
            <div className="input-row">
              <div className="field" style={{margin:0}}><label className="label">Name</label><input className="input" placeholder="Full name" value={t.n} onChange={e=>st(i,"n",e.target.value)}/></div>
              <div className="field" style={{margin:0}}><label className="label">Wallet Address (0x...)</label><input className="input" placeholder="0x..." value={t.a} onChange={e=>st(i,"a",e.target.value)}/></div>
            </div>
          </div>
        ))}
        <div className="btn-row" style={{marginTop:16}}>
          <button className="btn btn-ghost" onClick={()=>setStep(0)}>← Back</button>
          <button className="btn btn-primary" onClick={()=>setStep(2)} disabled={valid.length<2}>Next: Settings →</button>
        </div>
      </div>}

      {step===2&&<div className="ob-card fi">
        <h2 style={{fontSize:"1.1rem",fontWeight:800,marginBottom:4}}>Threshold & Timelock</h2>
        <p style={{fontSize:"0.8rem",color:"var(--text3)",marginBottom:20,lineHeight:1.6}}>Set how many trustees must agree, and how long until auto-release.</p>
        <div className="input-row">
          <div className="field"><label className="label">Threshold <span className="help-tip" title="Minimum number of trustees needed to release">?</span></label>
            <select className="select" value={form.threshold} onChange={e=>sf("threshold",e.target.value)}>
              {[2,3,4,5].filter(n=>n<=valid.length).map(n=><option key={n} value={n}>{n} of {valid.length} trustees must agree</option>)}
            </select>
            <div className="input-help">Higher = more secure. Recommended: at least half your trustees.</div>
          </div>
          <div className="field"><label className="label">Timelock <span className="help-tip" title="If no trustee acts, data auto-releases after this many days">?</span></label>
            <select className="select" value={form.days} onChange={e=>sf("days",e.target.value)}>
              <option value="180">180 days (6 months)</option>
              <option value="365">365 days (1 year) — Recommended</option>
              <option value="730">730 days (2 years)</option>
              <option value="1825">1825 days (5 years)</option>
            </select>
            <div className="input-help">A "dead-man's switch". If no trustee acts, data releases automatically.</div>
          </div>
        </div>
        <div className="field"><label className="label">Beneficiary Wallet Address <span className="label-hint">Who receives your data?</span></label>
          <input className="input" placeholder="0x..." value={form.beneficiary} onChange={e=>sf("beneficiary",e.target.value)}/>
          <div className="input-help">This person will be able to collect and decrypt your data after the vault is released.</div>
        </div>
        <Alert type="info" icon="💡">With <strong>{form.threshold}-of-{valid.length}</strong>: even if {valid.length-parseInt(form.threshold)} trustees are unavailable, your data can still be released.</Alert>
        <div className="btn-row">
          <button className="btn btn-ghost" onClick={()=>setStep(1)}>← Back</button>
          <button className="btn btn-primary" onClick={()=>setStep(3)} disabled={!form.beneficiary||valid.length<2}>Next: Review →</button>
        </div>
      </div>}

      {step===3&&<div className="ob-card fi">
        <h2 style={{fontSize:"1.1rem",fontWeight:800,marginBottom:4}}>Review & Deploy</h2>
        <p style={{fontSize:"0.8rem",color:"var(--text3)",marginBottom:20,lineHeight:1.6}}>Check everything before deploying to the blockchain.</p>
        <div className="info-row"><span className="info-key">Vault Name</span><span className="info-val">{form.desc}</span></div>
        <div className="info-row"><span className="info-key">Data Size</span><span className="info-val">{form.data.length} characters</span></div>
        <div className="info-row"><span className="info-key">Trustees</span><span className="info-val">{valid.map(t=>t.n).join(", ")}</span></div>
        <div className="info-row"><span className="info-key">Threshold</span><span className="info-val">{form.threshold} of {valid.length} trustees</span></div>
        <div className="info-row"><span className="info-key">Timelock</span><span className="info-val">{form.days} days</span></div>
        <div className="info-row"><span className="info-key">Beneficiary</span><span className="info-val">{form.beneficiary.slice(0,20)}...</span></div>
        <div className="info-row"><span className="info-key">Encryption</span><span className="info-val">AES-256-GCM + Shamir {form.threshold}-of-{valid.length}</span></div>
        <Alert type="warn" icon="⚠️">Deploying to the blockchain is permanent. You can cancel the vault later but cannot change trustees or threshold after creation.</Alert>
        <div className="btn-row" style={{marginTop:8}}>
          <button className="btn btn-ghost" onClick={()=>setStep(2)}>← Back</button>
          <button className="btn btn-primary" onClick={deploy} disabled={busy||!contract}>
            {busy?<><div className="spin"/>Deploying...</>:"🔒 Deploy Vault to Blockchain"}
          </button>
        </div>
        {!contract&&<div style={{marginTop:12}}><Alert type="danger" icon="🦊">Connect MetaMask to deploy.</Alert></div>}
      </div>}
    </div>
  );
}

// ── TRUSTEE PAGE ──────────────────────────────────────────────────────────────
function TrusteePage({contract,acct,showTx,doneTx,errTx,onRefresh}){
  const[vid,setVid]=useState("");const[vault,setVault]=useState(null);const[busy,setBusy]=useState(false);const[share,setShare]=useState("");
  const load=async()=>{if(!contract){alert("Connect wallet first");return}try{const v=await contract.getVault(parseInt(vid));const tr=await contract.getTrustees(parseInt(vid));const d=Number(await contract.getDeathConfirmations(parseInt(vid)));setVault({id:parseInt(vid),description:v.description,status:Number(v.status),threshold:Number(v.threshold),totalShares:Number(v.totalShares),sharesSubmitted:Number(v.sharesSubmitted),timelockExpiry:Number(v.timelockExpiry),trustees:tr,deaths:d})}catch(e){alert("Vault not found: "+(e.reason||e.message))}};
  const confirmDeath=async()=>{setBusy(true);try{showTx("Confirming death...","Sending on-chain transaction");const tx=await contract.confirmDeath(vault.id);await tx.wait();doneTx("Confirmed ✓","Your confirmation is recorded on the blockchain");onRefresh();load()}catch(e){errTx("Failed",e.reason||e.message?.slice(0,60))}setBusy(false)};
  const submitShare=async()=>{if(!share.trim()){alert("Paste your share first");return}setBusy(true);try{showTx("Submitting share...","Sending to blockchain");const tx=await contract.submitShare(vault.id,share.trim());await tx.wait();doneTx("Share submitted ✓","Your share is now on-chain");onRefresh();load()}catch(e){errTx("Failed",e.reason||e.message?.slice(0,60))}setBusy(false)};
  return(
    <div className="page fi">
      <h1 style={{fontSize:"1.6rem",fontWeight:800,letterSpacing:"-0.03em",marginBottom:4}}>Trustee Portal</h1>
      <p style={{color:"var(--text3)",fontSize:"0.82rem",marginBottom:24}}>You've been trusted with a secret share. Use this portal when the time comes.</p>
      <Alert type="info" icon="🤝">As a trustee, you hold one piece of the vault owner's encryption key. You have two jobs: confirm their death, then submit your share. Both are required.</Alert>
      <div className="card">
        <div className="field" style={{display:"flex",gap:10,margin:0}}>
          <div style={{flex:1}}><label className="label">Vault ID <span className="label-hint">The owner should have given you this number</span></label><input className="input" placeholder="e.g. 0" value={vid} onChange={e=>setVid(e.target.value)}/></div>
          <div style={{alignSelf:"flex-end"}}><button className="btn btn-primary" onClick={load}>Load Vault</button></div>
        </div>
      </div>
      {vault&&<div className="fi">
        <div className="card">
          <div className="card-hd"><span style={{fontWeight:700}}>{vault.description}</span><Badge s={vault.status}/></div>
          <div className="stats-row">
            <div className="stat-box"><div className="stat-n gold">{vault.deaths}/{vault.threshold}</div><div className="stat-l">Confirmations</div></div>
            <div className="stat-box"><div className="stat-n purple">{vault.sharesSubmitted}/{vault.threshold}</div><div className="stat-l">Shares In</div></div>
            <div className="stat-box"><div className="stat-n">{dLeft(vault.timelockExpiry)}</div><div className="stat-l">Days to Timelock</div></div>
          </div>
        </div>
        <div className="card">
          <div className="card-hd"><span className="card-title">Step 1 — Confirm the Owner Has Passed Away</span></div>
          <p style={{fontSize:"0.82rem",color:"var(--text2)",marginBottom:16,lineHeight:1.6}}>Only do this if you have confirmed the owner has died. This is a permanent, public action recorded on the blockchain. Once {vault.threshold} trustees confirm, shares can be submitted.</p>
          <button className="btn btn-danger" onClick={confirmDeath} disabled={busy||!contract}>
            {busy?<><div className="spin"/>Processing...</>:"☠ Confirm Owner's Death"}
          </button>
        </div>
        <div className="card">
          <div className="card-hd"><span className="card-title">Step 2 — Submit Your Secret Share</span></div>
          {vault.status===0&&<Alert type="warn" icon="🔒">Share submission is locked until {vault.threshold} trustees confirm death, or the timelock expires on {new Date(vault.timelockExpiry*1000).toLocaleDateString()}.</Alert>}
          <div className="field"><label className="label">Your Shamir Share <span className="label-hint">The hex string the owner sent you privately</span></label><textarea className="textarea" placeholder="Paste your share here, e.g:&#10;01:a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6..." value={share} onChange={e=>setShare(e.target.value)} rows={4}/></div>
          <button className="btn btn-primary" onClick={submitShare} disabled={busy||vault.status===0||!contract}>
            {busy?<><div className="spin"/>Submitting...</>:"🔑 Submit Share to Blockchain"}
          </button>
        </div>
      </div>}
    </div>
  );
}

// ── BENEFICIARY PAGE ──────────────────────────────────────────────────────────
function BeneficiaryPage({contract,acct,showTx,doneTx,errTx}){
  const[vid,setVid]=useState("");const[vault,setVault]=useState(null);const[subs,setSubs]=useState([]);const[shares,setShares]=useState("");const[dec,setDec]=useState(null);const[busy,setBusy]=useState(false);
  const load=async()=>{if(!contract){alert("Connect wallet first");return}try{const v=await contract.getVault(parseInt(vid));setVault({id:parseInt(vid),description:v.description,status:Number(v.status),threshold:Number(v.threshold),sharesSubmitted:Number(v.sharesSubmitted)});if(Number(v.status)===2){const s=await contract.getShareSubmissions(parseInt(vid));setSubs(s)}}catch(e){alert("Error: "+(e.reason||e.message))}};
  const reconstruct=async()=>{setBusy(true);try{showTx("Reconstructing key...","Shamir Secret Sharing");const hexShares=shares.trim().split("\n").map(s=>s.trim()).filter(Boolean);if(hexShares.length<vault.threshold){alert(`Need at least ${vault.threshold} shares, got ${hexShares.length}`);setBusy(false);return}const shareData=h2s(hexShares);const raw=reconstructSecret(shareData);showTx("Fetching from IPFS...","Retrieving encrypted payload");const v=await contract.getVault(vault.id);const data=ipfsFetch(v.encryptedDataHash);if(!data){alert("Could not fetch from IPFS. The vault must be created in this browser session for the simulation to work.");setBusy(false);return}const{ct,iv}=JSON.parse(data);showTx("Decrypting...","AES-256-GCM");const key=await impKey(raw);const buf=await decData(ct,iv,key);const text=new TextDecoder().decode(buf);doneTx("Data recovered ✓","Successfully decrypted");setDec(text)}catch(e){errTx("Failed",e.message?.slice(0,70)||"Invalid shares or data")}setBusy(false)};
  return(
    <div className="page fi">
      <h1 style={{fontSize:"1.6rem",fontWeight:800,letterSpacing:"-0.03em",marginBottom:4}}>Beneficiary Portal</h1>
      <p style={{color:"var(--text3)",fontSize:"0.82rem",marginBottom:24}}>Access data that was left for you by collecting trustee shares and decrypting.</p>
      <Alert type="info" icon="💌">Someone has left data for you. Once the vault is Released and you have collected shares from trustees, paste them below to decrypt your inherited data.</Alert>
      <div className="card">
        <div className="field" style={{display:"flex",gap:10,margin:0}}>
          <div style={{flex:1}}><label className="label">Vault ID <span className="label-hint">Ask the trustees or check the dashboard</span></label><input className="input" placeholder="e.g. 0" value={vid} onChange={e=>setVid(e.target.value)}/></div>
          <div style={{alignSelf:"flex-end"}}><button className="btn btn-primary" onClick={load}>Load Vault</button></div>
        </div>
      </div>
      {vault&&vault.status!==2&&<Alert type="warn" icon="⏳">Vault #{vault.id} is not yet released. Status: <Badge s={vault.status}/> — Waiting for {vault.threshold-vault.sharesSubmitted} more shares.</Alert>}
      {vault&&vault.status===2&&<div className="fi">
        <Alert type="success" icon="🔓">Vault Released! {vault.sharesSubmitted} shares are on the blockchain. Collect the hex shares from your trustees and paste them below.</Alert>
        {subs.length>0&&<div className="card"><div className="card-hd"><span className="card-title">Shares on Blockchain</span></div>{subs.map((s,i)=><div key={i} className="share-item"><div className="share-label">From trustee {s.trustee.slice(0,14)}...</div><div className="share-val">{s.encryptedShare}</div></div>)}</div>}
        <div className="card">
          <div className="card-hd"><span className="card-title">Reconstruct & Decrypt</span></div>
          <p style={{fontSize:"0.8rem",color:"var(--text2)",marginBottom:16,lineHeight:1.6}}>Paste the hex shares you've collected from trustees — one per line. You need at least {vault.threshold} shares.</p>
          <div className="field"><label className="label">Shamir Shares (one per line)</label><textarea className="textarea" placeholder={"01:a3f2b1c4d5e6...\n02:b7c8d9e0f1a2...\n03:c3d4e5f6a7b8..."} value={shares} onChange={e=>setShares(e.target.value)} rows={6}/><div className="input-help">These are the hex strings each trustee received from the vault owner and submitted to the blockchain.</div></div>
          <button className="btn btn-primary" onClick={reconstruct} disabled={busy||!shares.trim()}>
            {busy?<><div className="spin"/>Decrypting...</>:"🔓 Decrypt & Recover My Data"}
          </button>
        </div>
        {dec&&<div className="card fi" style={{border:"2px solid var(--success)"}}>
          <div className="card-hd"><span className="card-title" style={{color:"var(--success)"}}>✓ Data Successfully Decrypted</span></div>
          <Alert type="success" icon="✅">Your data has been decrypted and verified. It was encrypted with AES-256-GCM — only you can read this.</Alert>
          <div className="hash-box" style={{color:"var(--text)",whiteSpace:"pre-wrap",lineHeight:1.8,fontSize:"0.82rem",background:"var(--success-dim)",borderColor:"rgba(16,185,129,0.3)"}}>{dec}</div>
        </div>}
      </div>}
    </div>
  );
}