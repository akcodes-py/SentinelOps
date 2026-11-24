"""Minimal web UI for the copilot (PDR 5: 'clients: API clients and a simple web UI').

Reason codes are deliberately not displayed to end users (PDR 6.3.2); they stay
in the logs and reviewer views.
"""

UI_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelOps Copilot</title>
<style>
  body { font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; }
  main { max-width:820px; margin:40px auto; padding:0 20px; }
  h1 { font-size:1.6rem; }
  .card { background:#1e293b; border:1px solid #334155; border-radius:12px; padding:20px; margin-bottom:16px; }
  label { display:block; font-size:.85rem; margin-top:10px; color:#94a3b8; }
  input, textarea, button { width:100%; box-sizing:border-box; margin-top:4px; padding:10px; border-radius:8px; border:1px solid #475569; background:#0f172a; color:#e2e8f0; font:inherit; }
  textarea { min-height:90px; resize:vertical; }
  button { margin-top:14px; background:#2563eb; border:none; cursor:pointer; font-weight:600; }
  button:hover { background:#1d4ed8; }
  #out { white-space:pre-wrap; min-height:60px; }
  .blocked { color:#fca5a5; }
  .ok { color:#86efac; }
  code { color:#93c5fd; }
</style>
</head>
<body>
<main>
  <h1>SentinelOps — AI Ops Copilot</h1>
  <p>Secure control plane demo. All data is synthetic. Reason codes stay in the logs.</p>
  <div class="card">
    <label>Session token (leave empty to fetch one automatically)</label>
    <input id="token" placeholder="Bearer token">
    <label>Message</label>
    <textarea id="msg">Show me the pickup schedule for today</textarea>
    <label>Session ID</label>
    <input id="session" value="web-demo">
    <button onclick="send()">Send</button>
  </div>
  <div class="card">
    <strong>Response</strong>
    <div id="out">—</div>
    <div id="meta"></div>
  </div>
</main>
<script>
async function getToken() {
  let t = document.getElementById('token').value.trim();
  if (t) return t;
  const r = await fetch('/auth/token', {method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({tenant_id:1, username:'admin1', role:'admin'})});
  const j = await r.json();
  t = j.access_token;
  document.getElementById('token').value = t;
  return t;
}
async function send() {
  const out = document.getElementById('out');
  const meta = document.getElementById('meta');
  out.textContent = 'Working…'; meta.textContent = '';
  try {
    const token = await getToken();
    const r = await fetch('/copilot', {method:'POST', headers:{'Content-Type':'application/json',
      'Authorization':'Bearer ' + token, 'x-api-key':'web-demo'},
      body:JSON.stringify({message:document.getElementById('msg').value,
                           session_id:document.getElementById('session').value})});
    const j = await r.json();
    out.textContent = j.text;
    out.className = j.blocked ? 'blocked' : 'ok';
    meta.innerHTML = 'Status <code>' + r.status + '</code> · blocked=<code>' + j.blocked +
      '</code> · safe_mode=<code>' + j.safe_mode + '</code> · tool_calls=<code>' + j.tool_calls.length + '</code>';
  } catch (e) { out.textContent = 'Error: ' + e; out.className='blocked'; }
}
</script>
</body>
</html>
"""
