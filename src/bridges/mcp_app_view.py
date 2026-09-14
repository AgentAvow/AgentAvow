"""The AgentAvow MCP Apps "View" — the interactive trust card.

Rendered natively by an MCP-Apps host (SEP-1865, spec 2026-01-26) in a sandboxed
iframe. Speaks the ui/* postMessage protocol directly (no bundler/deps) so it renders
under the host's strict default CSP (script-src 'self' 'unsafe-inline'; img-src 'self'
data:; connect-src 'none'). No network: the scan result arrives via
ui/notifications/tool-result and it reads our stable structuredContent contract.

The artwork MATCHES the live site's locked dual mark (web/src/rebrand/components/
TrustMark.tsx): a vertical 10-segment trust bar tinted by trust tier, and an adoption
VU needle (teal->magenta) that fills to the adoption level. Kept as a plain string
(not an f-string) so the JS/SVG braces are literal.
"""

TRUST_CARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light dark">
<title>AgentAvow trust card</title>
<style>
  :root { --bg:#0b0f17; --fg:#e6edf3; --muted:#9aa7b6; --track:#1e2733; --line:#1e2733; --teal:#2dd4bf; }
  @media (prefers-color-scheme: light){ :root{ --bg:#ffffff; --fg:#0b0f17; --muted:#5b6673; --track:#e5e9ef; --line:#e5e9ef; } }
  :root[data-theme="light"]{ --bg:#ffffff; --fg:#0b0f17; --muted:#5b6673; --track:#e5e9ef; --line:#e5e9ef; }
  :root[data-theme="dark"]{ --bg:#0b0f17; --fg:#e6edf3; --muted:#9aa7b6; --track:#1e2733; --line:#1e2733; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .card { padding:16px 18px; }
  .hdr { display:flex; align-items:center; justify-content:space-between; gap:12px; }
  .brand { font-size:11px; letter-spacing:.14em; text-transform:uppercase; color:var(--muted); }
  .pill { font-size:11px; font-weight:800; padding:3px 10px; border-radius:999px; white-space:nowrap; }
  .target { font-weight:700; font-size:15px; margin:3px 0 14px; word-break:break-all; }
  .inst { display:flex; gap:26px; align-items:flex-end; justify-content:center; padding:2px 0 4px; }
  .col { display:flex; flex-direction:column; align-items:center; }
  .segs { display:flex; flex-direction:column-reverse; gap:2.5px; }
  .seg { width:14px; height:6px; border-radius:1px; }
  .num { font-weight:800; line-height:1; font-size:22px; margin-top:6px; font-variant-numeric:tabular-nums; }
  .unit { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:10px; color:var(--muted); margin-left:2px; }
  .tw { font-weight:700; font-size:10px; margin-top:3px; }
  .mut { color:var(--muted); }
  .grad { background:linear-gradient(100deg,#2dd4bf,#e879f9); -webkit-background-clip:text; background-clip:text; color:transparent; }
  .why { color:var(--muted); font-size:12.5px; margin:12px 0 0; text-align:center; }
  .foot { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-top:14px; padding-top:12px; border-top:1px solid var(--line); }
  .signed { font-size:11px; color:var(--muted); }
  button { font:inherit; font-weight:700; font-size:12px; color:#04201c; background:var(--teal); border:0; border-radius:8px; padding:7px 12px; cursor:pointer; }
</style>
</head>
<body>
  <div class="card" id="card">
    <div class="hdr"><span class="brand">◇ AgentAvow</span><span class="pill" id="pill" style="display:none"></span></div>
    <div class="target" id="target">Loading trust card…</div>
    <div class="inst">
      <div class="col"><div id="trust"></div><div class="tw mut" style="margin-top:4px">TRUST</div></div>
      <div class="col"><div id="adopt"></div><div class="tw mut" style="margin-top:4px">ADOPTION</div></div>
    </div>
    <div class="why" id="why"></div>
    <div class="foot"><span class="signed" id="signed"></span><button id="report" style="display:none">View full report ↗</button></div>
  </div>
<script>
(function () {
  var PROTO = "2026-01-26", target = window.parent, nextId = 1, pending = {}, initialized = false;
  function send(m){ target.postMessage(m, "*"); }
  function notify(method, params){ send({ jsonrpc:"2.0", method:method, params:params||{} }); }
  function request(method, params){ var id=nextId++; send({jsonrpc:"2.0",id:id,method:method,params:params||{}}); return new Promise(function(res,rej){pending[id]={res:res,rej:rej};}); }
  function markInitialized(){ if(initialized) return; initialized=true; notify("ui/notifications/initialized", {}); }
  function reportSize(){ try{ notify("ui/notifications/size-changed",{width:document.body.scrollWidth,height:document.getElementById("card").scrollHeight+8}); }catch(e){} }

  function compact(n){ n=+n||0; var u=[[1e9,"B"],[1e6,"M"],[1e3,"k"]]; for(var i=0;i<u.length;i++){ if(n>=u[i][0]) return (n/u[i][0]).toFixed(1).replace(/\.0$/,"")+u[i][1]; } return ""+n; }
  function tier(s){ var T=[["Trusted",80,"#22C55E"],["Standard",60,"#5BBF3A"],["Caution",40,"#F59E0B"],["Restricted",20,"#F97316"],["Blocked",0,"#EF4444"]]; for(var i=0;i<T.length;i++){ if(s>=T[i][1]) return {name:T[i][0],color:T[i][2]}; } return {name:"Blocked",color:"#EF4444"}; }
  function P(cx,cy,r,d){ var a=d*Math.PI/180; return [cx+r*Math.cos(a), cy+r*Math.sin(a)]; }
  function ARC(cx,cy,r,a0,a1){ var s=P(cx,cy,r,a0),e=P(cx,cy,r,a1),lg=(a1-a0>180)?1:0; return "M"+s[0].toFixed(1)+" "+s[1].toFixed(1)+" A"+r+" "+r+" 0 "+lg+" 1 "+e[0].toFixed(1)+" "+e[1].toFixed(1); }
  function adoptionPct(c){ c=c||0; return c>0?Math.min(100,Math.round(Math.log10(c+1)/9*100)):0; }
  function adoptTier(p){ return p>=88?"Load-bearing":p>=65?"Widely relied":p>=40?"Established":p>=15?"Rising":"New"; }

  function renderTrust(score){
    var t=tier(score), lv=Math.round(score/10), segs="";
    for(var i=9;i>=0;i--){ segs+='<div class="seg" style="background:'+(i<lv?t.color:"var(--track)")+'"></div>'; }
    document.getElementById("trust").innerHTML =
      '<div class="segs">'+segs+'</div>'
      +'<div class="num" style="color:'+t.color+'">'+score+'<span class="unit">/100</span></div>'
      +'<div class="tw" style="color:'+t.color+'">'+t.name+'</div>';
  }
  function renderAdopt(ad){
    var c=ad?(ad.count||0):0, pct=ad?(ad.score_0_100!=null?ad.score_0_100:adoptionPct(c)):0, has=(pct>0||c>0);
    var cx=100,cy=88,r=74,a0=180,a1=360, ang=a0+pct/100*180, n=P(cx,cy,r-16,ang), ticks="";
    for(var i=0;i<9;i++){ var ta=a0+180*((i+1)/10),p0=P(cx,cy,r-6,ta),p1=P(cx,cy,r-((i+1===5)?14:10),ta);
      ticks+='<line x1="'+p0[0].toFixed(1)+'" y1="'+p0[1].toFixed(1)+'" x2="'+p1[0].toFixed(1)+'" y2="'+p1[1].toFixed(1)+'" stroke="var(--muted)" stroke-width="'+((i+1===5)?1.6:1)+'" opacity="0.4"/>'; }
    var fill=(has&&ang>a0+1.5)?'<path d="'+ARC(cx,cy,r,a0,ang)+'" fill="none" stroke="url(#agrad)" stroke-width="8"/>':'';
    var tr='<path d="'+ARC(cx,cy,r,Math.max(ang,a0+0.5),a1)+'" fill="none" stroke="var(--track)" stroke-width="8"/>';
    var nd=has?('<line x1="'+cx+'" y1="'+cy+'" x2="'+n[0].toFixed(1)+'" y2="'+n[1].toFixed(1)+'" stroke="#2dd4bf" stroke-width="3.4" stroke-linecap="round"/><circle cx="'+cx+'" cy="'+cy+'" r="5.5" fill="#2dd4bf"/>')
                :('<circle cx="'+cx+'" cy="'+cy+'" r="5.5" fill="var(--muted)" opacity="0.3"/>');
    document.getElementById("adopt").innerHTML =
      '<svg width="118" viewBox="0 0 200 94" style="overflow:visible"><defs><linearGradient id="agrad" gradientUnits="userSpaceOnUse" x1="26" y1="0" x2="174" y2="0"><stop stop-color="#2dd4bf"/><stop offset="1" stop-color="#e879f9"/></linearGradient></defs>'+fill+tr+ticks+nd+'</svg>'
      +'<div class="num">'+(has?compact(c):'<span class="mut">New</span>')+(has&&ad&&ad.unit?'<span class="unit">'+ad.unit+'</span>':'')+'</div>'
      +'<div class="tw">'+(has?'<span class="grad">'+adoptTier(pct)+'</span>':'<span class="mut">no signal yet</span>')+'</div>';
  }

  var reportUrl=null;
  function render(sc){
    if(!sc){ return; }
    var score=+(sc.trust_score||0), reason=sc.verdict_reason;
    var mode=(sc.verdict==="safe")?"safe":(reason==="blocking_findings"?"risk":"limited");
    var conf={ safe:{label:"✓ SAFE",color:"#22C55E"}, risk:{label:"⚠ REVIEW",color:"#F59E0B"}, limited:{label:"◍ LIMITED",color:"#94A3B8"} }[mode];
    document.getElementById("target").textContent = sc.target + (sc.target_type?" · "+sc.target_type:"");
    var pill=document.getElementById("pill"); pill.textContent=conf.label; pill.style.color=conf.color; pill.style.background=conf.color+"22"; pill.style.display="inline-block";
    renderTrust(score); renderAdopt(sc.adoption);
    var whys={ clean:"No blocking issues found.", blocking_findings:(sc.critical||0)+" critical, "+(sc.high||0)+" high — review before you connect.",
               thin_coverage:"No risks found; score capped by limited coverage, not detected risk.", low_signals:"No risks found; below the bar on non-finding signals, not detected risk." };
    document.getElementById("why").textContent = whys[reason]||"";
    document.getElementById("signed").textContent = sc.signed?"signed ✔ Ed25519 · recomputable":"";
    reportUrl=sc.report_url||null;
    if(reportUrl){ document.getElementById("report").style.display="inline-block"; }
    reportSize();
  }
  function fromResult(r){ if(!r) return; var sc=r.structuredContent; if(!sc){ try{ sc=JSON.parse(r.content&&r.content[0]&&r.content[0].text); }catch(e){} } render(sc); }

  document.getElementById("report").addEventListener("click", function(){ if(reportUrl) request("ui/open-link",{url:reportUrl}); });
  window.addEventListener("message", function(ev){
    if(ev.source!==target) return;
    var m=ev.data; if(!m||m.jsonrpc!=="2.0") return;
    if(m.id!==undefined && (("result" in m)||("error" in m))){ var p=pending[m.id]; if(p){ delete pending[m.id]; m.error?p.rej(m.error):p.res(m.result); } return; }
    switch(m.method){
      case "ui/notifications/tool-result": markInitialized(); fromResult(m.params); break;
      case "ui/notifications/host-context-changed": if(m.params&&m.params.theme){ document.documentElement.dataset.theme=m.params.theme; } break;
    }
  });

  request("ui/initialize", { appInfo:{name:"AgentAvow trust card",version:"0.2.0"}, appCapabilities:{availableDisplayModes:["inline"]}, protocolVersion:PROTO })
    .then(function(init){ if(init&&init.hostContext&&init.hostContext.theme){ document.documentElement.dataset.theme=init.hostContext.theme; } markInitialized(); reportSize(); })
    .catch(function(){ markInitialized(); });   // even if the init response isn't matched, signal ready so tool-result flows
  // Belt-and-suspenders: never let a finicky init-response block the data.
  setTimeout(markInitialized, 700);
})();
</script>
</body>
</html>
"""
