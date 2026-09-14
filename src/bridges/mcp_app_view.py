"""The AgentAvow MCP Apps "View" — a self-contained interactive trust card.

Rendered natively by a host that supports MCP Apps (SEP-1865, spec 2026-01-26) in a
sandboxed iframe, instead of the model paraphrasing our text card. Speaks the ui/*
postMessage protocol directly (no bundler / external deps) so it renders under the
host's strict default CSP (script-src 'self' 'unsafe-inline'; img-src 'self' data:;
connect-src 'none'). It needs NO network: the scan result arrives via
ui/notifications/tool-result and it reads our stable structuredContent contract.

This is the render SPIKE card — real, but the full locked dual-mark polish comes after
we confirm it renders in Claude web + Desktop. Kept as a plain string (not an f-string)
so the JS braces are literal.
"""

TRUST_CARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light dark">
<title>AgentAvow trust card</title>
<style>
  :root { --bg: light-dark(#ffffff,#0b0f17); --fg: light-dark(#0b0f17,#e6edf3);
          --muted: light-dark(#5b6673,#9aa7b6); --line: light-dark(#e5e9ef,#1e2733);
          --green:#22c55e; --amber:#f59e0b; --neutral: light-dark(#64748b,#94a3b8);
          --track: light-dark(#e5e9ef,#1e2733); --teal:#2dd4bf; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .card { padding:16px 18px; }
  .top { display:flex; align-items:baseline; justify-content:space-between; gap:12px; }
  .brand { font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); }
  .target { font-weight:700; font-size:15px; margin:2px 0 12px; word-break:break-all; }
  .pill { font-size:11px; font-weight:700; padding:3px 9px; border-radius:999px; white-space:nowrap; }
  .row { display:flex; align-items:center; gap:10px; margin:8px 0; }
  .rowlabel { width:74px; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }
  .bar { flex:1; height:8px; border-radius:99px; background:var(--track); overflow:hidden; }
  .fill { height:100%; border-radius:99px; }
  .val { width:104px; text-align:right; font-variant-numeric:tabular-nums; font-size:12.5px; color:var(--muted); }
  .score { font-size:26px; font-weight:800; }
  .why { color:var(--muted); font-size:12.5px; margin:10px 0 0; }
  .foot { display:flex; align-items:center; justify-content:space-between; gap:12px;
          margin-top:14px; padding-top:12px; border-top:1px solid var(--line); }
  .signed { font-size:11px; color:var(--muted); }
  button { font:inherit; font-weight:600; font-size:12.5px; color:#04201c; background:var(--teal);
           border:0; border-radius:8px; padding:7px 12px; cursor:pointer; }
</style>
</head>
<body>
  <div class="card" id="card">
    <div class="top"><span class="brand">◇ AgentAvow</span><span class="pill" id="pill">…</span></div>
    <div class="target" id="target">Loading trust card…</div>
    <div class="row"><span class="rowlabel">Trust</span>
      <span class="bar"><span class="fill" id="tfill" style="width:0%"></span></span>
      <span class="val"><span class="score" id="score">–</span>/100</span></div>
    <div class="row"><span class="rowlabel">Adoption</span>
      <span class="bar"><span class="fill" id="afill" style="width:0%;background:var(--teal)"></span></span>
      <span class="val" id="adopt">–</span></div>
    <div class="why" id="why"></div>
    <div class="foot"><span class="signed" id="signed"></span>
      <button id="report" style="display:none">View full report ↗</button></div>
  </div>
<script>
(function () {
  var PROTO = "2026-01-26";
  var target = window.parent, nextId = 1, pending = {};
  function send(m){ target.postMessage(m, "*"); }
  function notify(method, params){ send({ jsonrpc:"2.0", method:method, params:params||{} }); }
  function request(method, params){
    var id = nextId++; send({ jsonrpc:"2.0", id:id, method:method, params:params||{} });
    return new Promise(function(res, rej){ pending[id] = { res:res, rej:rej }; });
  }
  function compact(n){
    if(!n) return "";
    n = +n;
    var u = [[1e9,"B"],[1e6,"M"],[1e3,"k"]];
    for(var i=0;i<u.length;i++){ if(n>=u[i][0]){ return (n/u[i][0]).toFixed(1).replace(/\.0$/,"")+u[i][1]; } }
    return ""+n;
  }
  function reportSize(){
    try { notify("ui/notifications/size-changed",
      { width: document.body.scrollWidth, height: document.getElementById("card").scrollHeight + 8 }); } catch(e){}
  }
  var reportUrl = null;
  function render(sc){
    if(!sc){ return; }
    var score = +(sc.trust_score||0);
    var reason = sc.verdict_reason;  // clean|blocking_findings|thin_coverage|low_signals
    var mode = (sc.verdict === "safe") ? "safe" : (reason === "blocking_findings" ? "risk" : "limited");
    var conf = {
      safe:    { label:"✓ SAFE",    color:"var(--green)" },
      risk:    { label:"⚠ REVIEW",  color:"var(--amber)" },
      limited: { label:"◍ LIMITED", color:"var(--neutral)" }
    }[mode];
    document.getElementById("target").textContent = sc.target + (sc.target_type ? " · " + sc.target_type : "");
    var pill = document.getElementById("pill");
    pill.textContent = conf.label; pill.style.color = conf.color;
    pill.style.background = "color-mix(in srgb, " + conf.color + " 15%, transparent)";
    document.getElementById("score").textContent = score;
    var tf = document.getElementById("tfill"); tf.style.width = score + "%"; tf.style.background = conf.color;
    var ad = sc.adoption;
    document.getElementById("afill").style.width = (ad ? (ad.score_0_100||0) : 0) + "%";
    document.getElementById("adopt").textContent = ad ? (compact(ad.count) + " " + (ad.unit||"")) : "new";
    var whys = {
      clean: "No blocking issues found.",
      blocking_findings: (sc.critical||0) + " critical, " + (sc.high||0) + " high — review before you connect.",
      thin_coverage: "No risks found; score capped by limited coverage, not detected risk.",
      low_signals: "No risks found; below the bar on non-finding signals, not detected risk."
    };
    document.getElementById("why").textContent = whys[reason] || "";
    document.getElementById("signed").textContent = sc.signed ? "signed ✔ Ed25519 · recomputable offline" : "";
    reportUrl = sc.report_url || null;
    if(reportUrl){ document.getElementById("report").style.display = "inline-block"; }
    reportSize();
  }
  document.getElementById("report").addEventListener("click", function(){
    if(reportUrl){ request("ui/open-link", { url: reportUrl }); }
  });
  window.addEventListener("message", function(ev){
    if(ev.source !== target) return;
    var m = ev.data; if(!m || m.jsonrpc !== "2.0") return;
    if(m.id !== undefined && (("result" in m) || ("error" in m))){
      var p = pending[m.id]; if(p){ delete pending[m.id]; m.error ? p.rej(m.error) : p.res(m.result); } return;
    }
    if(m.method === "ui/notifications/tool-result"){
      var r = m.params || {};
      render(r.structuredContent || (function(){ try { return JSON.parse(r.content && r.content[0] && r.content[0].text); } catch(e){ return null; } })());
    }
  });
  request("ui/initialize", {
    appInfo: { name:"AgentAvow trust card", version:"0.1.0" },
    appCapabilities: { availableDisplayModes:["inline"] },
    protocolVersion: PROTO
  }).then(function(){ notify("ui/notifications/initialized", {}); reportSize(); })
    .catch(function(){ /* host without MCP Apps: text fallback already shown by the model */ });
})();
</script>
</body>
</html>
"""
