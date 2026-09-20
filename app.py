"""
Web dashboard for the Email Forensics Prototype — SIH 2026, PS ID 26106, Team Tech Titans

Wraps email_forensics.py (same engine, unchanged) in a Flask web UI so the demo
looks like an actual analyst dashboard instead of raw JSON in a terminal.
<title>Email Threat Detection Platform</title>
Run:  python app.py
Then open: http://127.0.0.1:5000 in your browser
*{
  margin:0;
  padding:0;
  box-sizing:border-box;
}

body{
  font-family:'Segoe UI',sans-serif;
  background:#0f1420;
  color:white;
  min-height:100vh;
}

header{
  padding:25px 60px;
  border-bottom:1px solid #22304d;
  display:flex;
  justify-content:space-between;
  align-items:center;
}

.logo{
  font-size:24px;
  font-weight:700;
}

.logo span{
  color:#2f7cff;
}

.hero{
  min-height:85vh;
  display:flex;
  align-items:center;
  justify-content:center;
  text-align:center;
  padding:40px;
}

.hero-content{
  max-width:900px;
}

.hero h1{
  font-size:56px;
  line-height:1.2;
  margin-bottom:20px;
}

.hero p{
  font-size:20px;
  color:#9eb2d4;
  margin-bottom:40px;
}

.upload-card{
  background:#161d2e;
  border:1px solid #253150;
  padding:35px;
  border-radius:16px;
  max-width:650px;
  margin:auto;
}

input[type=file]{
  width:100%;
  padding:14px;
  border:2px dashed #3a4a75;
  border-radius:8px;
  background:#0f1420;
  color:white;
  margin-bottom:20px;
}

button{
  background:#2f7cff;
  color:white;
  border:none;
  padding:14px 30px;
  border-radius:8px;
  font-size:16px;
  font-weight:600;
  cursor:pointer;
}

button:hover{
  background:#1d66e7;
}

.features{
  display:flex;
  justify-content:center;
  gap:20px;
  margin-top:40px;
  flex-wrap:wrap;
}

.feature{
  background:#161d2e;
  padding:16px 22px;
  border-radius:10px;
  border:1px solid #253150;
}

footer{
  text-align:center;
  padding:20px;
  color:#6f82a5;
}
import json
from flask import Flask, request, render_template_string, send_file

<body>
<header>
  <div class="logo">
    🛡️ Email<span>Forensics AI</span>
  </div>
  <div>
    SIH 2026 • Team Tech Titans
  </div>
</header>
<section class="hero">
  <div class="hero-content">
    <h1>
      AI-Powered Email Threat Detection,
      Geolocation & Forensic Intelligence
    </h1>
    <p>
      Upload an email (.eml) file and instantly uncover phishing attempts,
      sender infrastructure, geolocation intelligence, authentication failures,
      IOC indicators, and forensic evidence.
    </p>
    <div class="upload-card">
      <form action="/upload" method="post" enctype="multipart/form-data">
        <input
          type="file"
          name="emlfile"
          accept=".eml"
          required>
        <button type="submit">
          Analyze Email
        </button>
      </form>
    </div>
    <div class="features">
      <div class="feature">📧 Email Analysis</div>
      <div class="feature">🌍 Geolocation Mapping</div>
      <div class="feature">🔍 IOC Detection</div>
      <div class="feature">📄 Forensic Reports</div>
    </div>
  </div>
</section>
<footer>
  Smart India Hackathon 2026 • PS ID 26106
</footer>
@media(max-width:900px){.shell{grid-template-columns:1fr}.sidebar{display:none}.main{padding:22px 16px}.grid{grid-template-columns:1fr}.full{grid-column:auto}.distribution{grid-template-columns:1fr}.analysis-list{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="shell"><aside class="sidebar"><div class="brand">Mail<span>Trace</span><small>Forensic intelligence</small></div><div class="nav-label">Workspace</div><nav class="nav"><a class="active" href="/">Overview</a><a href="/results#email-summary">Analyze email</a><a href="/results#mail-path">Cases</a><a href="/download-report">Reports</a><a href="/results#graph">Settings</a></nav><div class="analyst">ACTIVE ANALYST<strong>A. Brooks</strong>Mail Security Operations</div></aside>
<main class="main"><div class="topbar"><div><div class="eyebrow">Security operations / Home</div><h1 class="title">Threat assessment workspace</h1></div><div class="status">● Monitoring live</div></div>
{% if report %}
<div class="grid"><section class="card"><h2>Analyze uploaded email</h2><p class="subtle">{{ filename }} · Last analyzed just now</p><div class="upload"><form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="emlfile" accept=".eml" required><button class="button" type="submit">Analyze new email</button></form></div></section>
<section class="card"><h2>Threat assessment</h2><div class="score-row"><div class="score"><span>{{ report.threat_assessment.fraud_score }}</span></div><div><span class="badge">{{ report.threat_assessment.verdict }}</span><ul class="reasons">{% for r in report.threat_assessment.reasons[:3] %}<li>{{ r }}</li>{% endfor %}</ul></div></div><div style="margin-top:16px"><div style="display:flex;justify-content:space-between;color:#8096ae;font-size:11px;margin-bottom:7px"><span>Risk confidence</span><b style="color:#fff">{{ report.threat_assessment.fraud_score }} / 100</b></div><div class="meter"><i style="width:{{ report.threat_assessment.fraud_score }}%"></i></div></div></section>
<section class="card"><h2>AI classification</h2><div class="distribution"><div class="legend">{% for category in report.threat_assessment.classification %}<div><span><i class="dot" style="background:{{ classification_colors[loop.index0] }}"></i>{{ category.label }}</span><b>{{ category.percentage }}%</b></div>{% endfor %}</div></div></section>
<section class="card"><h2>Why this category?</h2><p class="subtle">The classifier selected <strong style="color:#ff9b91">{{ report.threat_assessment.verdict }}</strong> because the message signals are explainable and auditable:</p><ul class="reasons">{% for r in report.threat_assessment.reasons %}<li>{{ r }}</li>{% endfor %}</ul></section>
<section class="card full"><h2>Uploaded email preview</h2><div class="preview">From: {{ report.email_summary.from }}
To: {{ report.email_summary.to or '—' }}
Reply-To: {{ report.email_summary.reply_to or '—' }}
Subject: {{ report.email_summary.subject }}
Message-ID: {{ report.email_summary.message_id }}

{{ report.email_summary.body or 'Message body unavailable.' }}{% for image in report.email_summary.inline_images %}
<img class="email-inline-image" src="{{ image.data_uri }}" alt="{{ image.filename }}">{% endfor %}{% for attachment in report.email_summary.attachments %}
\n[Attachment: {{ attachment.filename }} ({{ attachment.content_type }}, {{ attachment.size }} bytes)]{% endfor %}</div></section>
<section class="card full"><h2>Forensic intelligence</h2><div class="analysis-list"><a class="analysis-link" href="/results#authentication"><strong>Authentication Check</strong><span>SPF / DKIM / DMARC validation</span></a><a class="analysis-link" href="/results#mail-path"><strong>Origin & geolocation</strong><span>Mail path reconstruction and server hops</span></a><a class="analysis-link" href="/results#routing"><strong>Routing / IP intelligence</strong><span>ISP, ASN, proxy and hosting signals</span></a><a class="analysis-link" href="/results#ioc"><strong>Indicators of Compromise</strong><span>URLs, sender IP and domain evidence</span></a><a class="analysis-link" href="/results#graph"><strong>Graph-based attribution</strong><span>Sender domain ↔ reply-to ↔ origin IPs</span></a><a class="analysis-link" href="/results#conclusion"><strong>Forensic conclusion</strong><span>Recommended response actions</span></a></div></section>
<section class="card full"><div style="display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap"><div><h2 style="margin-bottom:5px">Forensic report ready</h2><p class="subtle">Export the complete evidence package with chain-of-custody metadata.</p></div><a class="button" href="/download-report">Download forensics report</a></div></section></div>
{% else %}
<div class="card"><h2>Start an email investigation</h2><p class="subtle">Upload an .eml file to generate the threat score, explanation, mail path, authentication checks, and downloadable forensic report.</p><div class="upload" style="margin-top:20px"><form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="emlfile" accept=".eml" required><button class="button" type="submit">Analyze email</button></form></div></div>
{% endif %}<div class="footer">MailTrace · Evidence-led email security analysis · Prototype data stays local to this analyst session</div></main></div>
</body>
</html>
"""


PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Email Forensic Intelligence Platform — Tech Titans</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<script src="https://unpkg.com/leaflet-polylinedecorator@1.6.0/dist/leaflet.polylineDecorator.js"></script>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #0f1420;
    color: #e6e9f0;
    margin: 0;
    padding: 0;
  }
  header {
    background: linear-gradient(90deg, #14213d, #1b2a4a);
    padding: 22px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 3px solid #2f7cff;
  }
  header h1 { font-size: 20px; margin: 0; }
  header span { color: #8fa2c7; font-size: 13px; }
  .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
  .card {
    background: #161d2e;
    border: 1px solid #253150;
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 20px;
  }
  .card h2 {
    font-size: 15px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #7ea0ff;
    margin-top: 0;
    border-bottom: 1px solid #253150;
    padding-bottom: 10px;
  }
  form { display: flex; gap: 12px; align-items: center; }
  input[type=file] {
    background: #0f1420; border: 1px dashed #3a4a75; padding: 10px;
    border-radius: 6px; color: #e6e9f0; flex: 1;
  }
  button {
    background: #2f7cff; color: white; border: none; padding: 12px 22px;
    border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px;
  }
  button:hover { background: #1c63e0; }
  .score-wrap { display: flex; align-items: center; gap: 30px; }
  .score-circle {
    width: 120px; height: 120px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 30px; font-weight: 700; flex-shrink: 0;
    border: 6px solid {{ score_color }};
    color: {{ score_color }};
  }
  .verdict-badge {
    display: inline-block; padding: 6px 16px; border-radius: 20px;
    font-weight: 700; font-size: 13px; background: {{ score_color }}22;
    color: {{ score_color }}; border: 1px solid {{ score_color }};
  }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  td { padding: 8px 4px; border-bottom: 1px solid #253150; vertical-align: top; }
  td.label { color: #8fa2c7; width: 180px; }
  ul.reasons { margin: 0; padding-left: 20px; }
  ul.reasons li { margin-bottom: 8px; line-height: 1.4; }
  .pass { color: #35d07f; font-weight: 600; }
  .fail { color: #ff5c5c; font-weight: 600; }
  .footer-note { color: #5d6b8f; font-size: 12px; text-align: center; margin-top: 10px; }
  #hop-map { height: 380px; border-radius: 8px; margin-top: 10px; }
  .leaflet-popup-content-wrapper { background: #161d2e; color: #e6e9f0; }
  .leaflet-popup-tip { background: #161d2e; }
  .map-legend { display: flex; gap: 18px; font-size: 12px; margin-top: 8px; color: #8fa2c7; }
  .map-legend span { display: inline-flex; align-items: center; gap: 6px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
  .map-legend-box {
    background: rgba(22,29,46,0.92); color: #e6e9f0; padding: 10px 14px;
    border-radius: 6px; font-size: 12px; line-height: 1.8; box-shadow: 0 2px 8px rgba(0,0,0,0.4);
  }
  .map-legend-box i {
    display: inline-block; width: 10px; height: 10px; border-radius: 50%;
    margin-right: 6px; vertical-align: middle;
  }
  .graph-node {
    padding: 10px 14px; border-radius: 8px; color: white; font-weight: 600;
    white-space: normal; overflow-wrap: anywhere; word-break: break-word;
    text-align: center; font-size: 13px; line-height: 1.35;
    box-shadow: 0 2px 6px rgba(0,0,0,0.3);
  }
  .graph-edge-label {
    fill: #8fa2c7; font-size: 11px;
  }
  .correlation-columns { position: relative; z-index: 1; display: grid; grid-template-columns: minmax(150px, 1fr) minmax(220px, 1.4fr) minmax(150px, 1fr); gap: clamp(24px, 6vw, 90px); min-height: 500px; align-items: stretch; padding: 20px 28px; }
  .correlation-column { display: flex; flex-direction: column; justify-content: space-around; align-items: center; gap: 12px; min-width: 0; }
  .correlation-column .graph-node { width: min(100%, 230px); min-height: 42px; display: flex; align-items: center; justify-content: center; }
  .graph-email { flex-direction: column; gap: 5px; }
  .graph-email small { color: #b7c5d8; font-size: 10px; line-height: 1.35; font-weight: 400; }
  .graph-column-label { color: #8fa2c7; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
  .correlation-campaign-column { justify-content: center; }
  @media (max-width: 760px) { .correlation-columns { grid-template-columns: minmax(100px, 1fr) minmax(130px, 1.2fr) minmax(100px, 1fr); gap: 12px; padding: 12px 4px; } .graph-node { font-size: 11px; padding: 8px 10px; } }
  .ip-chip { display: inline-flex; align-items: center; gap: 8px; background: #0f1420; border: 1px solid #253150; border-radius: 6px; padding: 8px 12px; margin: 4px 6px 4px 0; font-size: 13px; }
  .ip-badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 10px; }
  .ip-badge.public { background: #1e8449; color: #d4f5e0; }
  .ip-badge.private { background: #555b6e; color: #d8d8d8; }
  body {
    background-color: #f5f2ee;
    background-image: url('/static/email-bg.png');
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
    color: #1f2937;
  }
  header {
    background: rgba(255, 255, 255, 0.86);
    border-bottom-color: #d97706;
    box-shadow: 0 12px 28px rgba(120, 53, 15, 0.1);
  }
  header span, .footer-note, .map-legend { color: #5b6472; }
  .card {
    background: rgba(255, 255, 255, 0.88);
    border-color: rgba(217, 119, 6, 0.22);
    border-radius: 18px;
    box-shadow: 0 14px 32px rgba(120, 53, 15, 0.08);
    backdrop-filter: blur(10px);
  }
  .card h2 { color: #78350f; border-bottom-color: rgba(146, 64, 14, 0.18); }
  td { border-bottom-color: rgba(146, 64, 14, 0.14); }
  td.label { color: #5b6472; }
  .pass { color: #15803d; }
  .fail { color: #b91c1c; }
  input[type=file] { background: rgba(255, 255, 255, 0.7); border-color: rgba(146, 64, 14, 0.5); color: #1f2937; }
  button { background: linear-gradient(180deg, #ea580c, #b45309); border-radius: 10px; }
  button:hover { background: #9a3412; }
  .ip-chip { background: rgba(255, 255, 255, 0.72); border-color: rgba(146, 64, 14, 0.2); }
  .map-legend-box { background: rgba(255, 255, 255, 0.94); color: #1f2937; }
  .classification-bars { display: grid; gap: 14px; margin-top: 18px; }
  .classification-row { display: grid; grid-template-columns: 125px 1fr 48px; align-items: center; gap: 12px; font-size: 13px; }
  .classification-track { height: 12px; border-radius: 999px; background: rgba(146, 64, 14, 0.1); overflow: hidden; }
  .classification-fill { height: 100%; border-radius: inherit; background: linear-gradient(90deg, #ea580c, #d97706); }
  .classification-row strong { color: #78350f; text-align: right; }
  @media (max-width: 640px) { .classification-row { grid-template-columns: 105px 1fr 42px; gap: 8px; } }
  .page-title {
    margin: 34px 0 18px;
    color: #78350f;
    font-size: clamp(2.5rem, 5vw, 4.7rem);
    line-height: 0.95;
    letter-spacing: -0.07em;
    font-weight: 800;
  }
  .report-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
  .report-grid .card { margin-bottom: 0; }
  .wide-card { grid-column: 1 / -1; }
  .threat-dashboard { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
  .threat-dashboard .card { margin-bottom: 0; }
  .threat-dashboard .threat-card { grid-area: threat; }
  .threat-dashboard .auth-card { grid-area: auth; }
  .threat-dashboard .summary-card { grid-area: summary; }
  .threat-dashboard .confidence-card { grid-area: confidence; }
  .threat-dashboard .classification-card { grid-area: classification; }
  .threat-dashboard { grid-template-areas: 'threat auth' 'summary confidence' 'classification classification'; }
  .geo-dashboard { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
  .geo-dashboard .card { margin-bottom: 0; }
  .geo-dashboard .mail-card { grid-column: 1 / -1; }
  .geo-dashboard .techniques-card { grid-column: 1 / -1; }
  .section-title {
    margin: 54px 0 18px;
    color: #78350f;
    font-size: clamp(2.5rem, 5vw, 4.7rem);
    line-height: 0.95;
    letter-spacing: -0.07em;
    font-weight: 800;
  }
  .flow-card { width: 100%; max-width: 100%; box-sizing: border-box; overflow: hidden; }
  .soc-flow { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; align-items: stretch; width: 100%; max-width: 100%; box-sizing: border-box; }
  .soc-step { position: relative; padding: 16px; border: 1px solid rgba(217,119,6,.25); border-radius: 14px; background: rgba(255,255,255,.72); flex: 1 1 0; min-width: 0; width: 100%; max-width: 100%; box-sizing: border-box; overflow: hidden; }
  .soc-step:not(:last-child)::after { content: '→'; position: absolute; right: -18px; top: 50%; color: #d97706; font-size: 1.8rem; font-weight: 800; z-index: 2; }
  .soc-step strong { display: block; color: #78350f; margin-bottom: 8px; }
  .soc-step span { color: #5b6472; font-size: .9rem; line-height: 1.45; overflow-wrap: anywhere; }
  .flow-step-image { display: block; width: auto; max-width: 100%; max-height: 70px; object-fit: contain; margin: 0 auto 14px; }
  @media (max-width: 760px) {
    .report-grid, .geo-dashboard, .soc-flow { grid-template-columns: 1fr; }
    .threat-dashboard { grid-template-columns: 1fr; grid-template-areas: 'threat' 'auth' 'summary' 'confidence' 'classification'; }
    .wide-card { grid-column: auto; }
    .soc-step:not(:last-child)::after { content: '↓'; right: auto; top: auto; bottom: -24px; left: 50%; }
  }
</style>
</head>
<body>
<header>
  <h1>🛡️ AI-Powered Email Threat Detection, Geolocation &amp; Forensic Intelligence Platform</h1>
  <span>PS ID 26106 &nbsp;•&nbsp; Team Tech Titans &nbsp;•&nbsp; SIH 2026</span>
</header>

<div class="container">

  <div class="card">
    <h2>Email file name: {{ filename }}</h2>
    {% if report %}
    <details>
      <summary class="email-preview-toggle">See email preview</summary>
      <div class="email-preview-body">{{ report.email_summary.body or 'Message body unavailable.' }}{% for image in report.email_summary.inline_images %}<img class="email-inline-image" src="{{ image.data_uri }}" alt="{{ image.filename }}">{% endfor %}{% for attachment in report.email_summary.attachments %}
    [Attachment: {{ attachment.filename }} ({{ attachment.content_type }}, {{ attachment.size }} bytes)]{% endfor %}</div>
    </details>
    {% endif %}
  </div>

  {% if report %}

  <h1 class="page-title">AI-Powered Threat Detection</h1>
  <div class="threat-dashboard">

  <div class="card threat-card">
    <h2>Threat Assessment</h2>
    <div class="score-wrap">
      <div class="score-circle">{{ report.threat_assessment.fraud_score }}</div>
      <div>
        <div class="verdict-badge">{{ report.threat_assessment.verdict }}</div>
        <ul class="reasons" style="margin-top:14px;">
          {% for r in report.threat_assessment.reasons %}
            <li>{{ r }}</li>
          {% endfor %}
        </ul>
        {% if report.threat_assessment.model_available %}
          <p class="footer-note" style="text-align:left; margin-top:12px;">ML spam probability: {{ (report.threat_assessment.model_probability * 100)|round(1) }}%</p>
        {% endif %}
      </div>
    </div>
  </div>

  <div class="card summary-card" id="email-summary">
    <h2>Email Summary</h2>
    <table>
      <tr><td class="label">From</td><td>{{ report.email_summary.from }}</td></tr>
      <tr><td class="label">Reply-To</td><td>{{ report.email_summary.reply_to or "—" }}</td></tr>
      <tr><td class="label">Subject</td><td>{{ report.email_summary.subject }}</td></tr>
      <tr><td class="label">Message-ID</td><td>{{ report.email_summary.message_id }}</td></tr>
    </table>
  </div>

  <div class="card classification-card">
    <h2>AI Classification</h2>
    <div class="classification-bars">
      {% for category in report.threat_assessment.classification %}
      <div class="classification-row"><span>{{ category.label }}</span><div class="classification-track"><div class="classification-fill" style="width:{{ category.percentage }}%"></div></div><strong>{{ category.percentage }}%</strong></div>
      {% endfor %}
    </div>
  </div>

  <div class="card auth-card" id="authentication">
    <h2>Authentication Check (SPF / DKIM / DMARC)</h2>
    <table>
      <tr><td class="label">Sending Domain</td><td>{{ report.authentication_check.from_domain }}</td></tr>
      <tr><td class="label">SPF</td><td class="{{ 'pass' if report.authentication_check.spf.found else 'fail' }}">
        {{ "VALID" if report.authentication_check.spf.found else "MISSING / NOT FOUND" }}
      </td></tr>
      <tr><td class="label">DMARC</td><td class="{{ 'pass' if report.authentication_check.dmarc.found else 'fail' }}">
        {{ "VALID" if report.authentication_check.dmarc.found else "MISSING / NOT FOUND" }}
      </td></tr>
      <tr><td class="label">DKIM Signature</td><td class="{{ 'pass' if report.authentication_check.dkim_signature_present else 'fail' }}">
        {{ "PRESENT" if report.authentication_check.dkim_signature_present else "ABSENT" }}
      </td></tr>
    </table>
  </div>

  <div class="card confidence-card">
    <h2>Origin Attribution Confidence</h2>
    <table>
      <tr><td class="label">Confidence Score</td><td style="font-weight:700; color:{{ score_color }};">{{ report.attribution_confidence.confidence_percent }}%</td></tr>
    </table>
    <ul class="reasons" style="margin-top:10px;">
      {% for evidence_text, ok in report.attribution_confidence.evidence %}
        <li class="{{ 'pass' if ok else 'fail' }}">{{ "✓" if ok else "✗" }} {{ evidence_text }}</li>
      {% endfor %}
    </ul>
  </div>

  </div>

  <h1 class="section-title">AI-Powered Geolocation</h1>
  <div class="geo-dashboard">

  <div class="card ip-card">
    <h2>IP Addresses Found</h2>
    <div>
      {% for entry in report.origin_trace.all_ips_tagged %}
      <div class="ip-chip">
        {{ entry.ip }}
        <span class="ip-badge {{ 'public' if entry.tag == 'PUBLIC' else 'private' }}">{{ entry.tag }}</span>
      </div>
      {% endfor %}
      {% if not report.origin_trace.all_ips_tagged %}
        <p style="color:#8fa2c7;">No IP addresses found in header chain.</p>
      {% endif %}
    </div>
    <p class="footer-note" style="text-align:left; margin-top:8px;">Extracted from Received routing headers.</p>
  </div>

  <div class="card mail-card" id="mail-path">
    <h2>Mail Path Reconstruction</h2>
    <div id="hop-map"></div>

    <h2 id="routing" style="margin-top:20px;">Routing / IP Intelligence</h2>
    <table>
      <tr>
        <td class="label" style="font-weight:700;">Hop</td>
        <td style="font-weight:700;">IP</td>
        <td style="font-weight:700;">Country / City</td>
        <td style="font-weight:700;">ISP</td>
        <td style="font-weight:700;">ASN</td>
        <td style="font-weight:700;">Reverse DNS</td>
        <td style="font-weight:700;">Proxy/TOR/VPN</td>
        <td style="font-weight:700;">Hosting</td>
      </tr>
      {% for hop in report.mail_path %}
      <tr>
        <td class="label">{{ loop.index }} — {{ hop.role }}</td>
        <td>{{ hop.ip }}</td>
        <td>{{ hop.city ~ ", " ~ hop.country if hop.country else "Unavailable" }}</td>
        <td>{{ hop.isp or "Unavailable" }}</td>
        <td>{{ hop.asn or "Unavailable" }}</td>
        <td>{{ hop.reverse_dns or "Unavailable" }}</td>
        <td class="{{ 'fail' if hop.proxy else 'pass' if hop.proxy is not none else '' }}">
          {{ "YES" if hop.proxy else ("No" if hop.proxy is not none else "Unavailable") }}
        </td>
        <td class="{{ 'fail' if hop.hosting else 'pass' if hop.hosting is not none else '' }}">
          {{ "YES" if hop.hosting else ("No" if hop.hosting is not none else "Unavailable") }}
        </td>
      </tr>
      {% endfor %}
      {% if not report.mail_path %}
      <tr><td colspan="8">No public IP hops found in the header chain.</td></tr>
      {% endif %}
    </table>
    <p class="footer-note" style="text-align:left; margin-top:8px;">Total hops: {{ report.mail_path|length }}</p>
  </div>

  <div class="card techniques-card">
    <h2>Threat Actor Techniques Observed</h2>
    <ul class="reasons">
      {% for technique, flagged in report.threat_techniques.items() %}
        <li class="{{ 'fail' if flagged else 'pass' }}">{{ "✓" if flagged else "✗" }} {{ technique }}</li>
      {% endfor %}
    </ul>
  </div>

  </div>

  <h1 class="section-title">AI-Powered Forensic Intelligence</h1>
  <div class="report-grid">

  <div class="card" id="ioc">
    <h2>Indicators of Compromise (IOC)</h2>
    <table>
      <tr><td class="label">Sender IP</td><td>{{ report.iocs.sender_ip or "—" }}</td></tr>
      <tr><td class="label">Sender Domain</td><td>{{ report.iocs.sender_domain or "—" }}</td></tr>
      <tr><td class="label">URLs in body</td><td>
        {% if report.iocs.suspicious_urls %}{% for u in report.iocs.suspicious_urls %}{{ u }}<br>{% endfor %}{% else %}None found{% endif %}
      </td></tr>
      <tr><td class="label">Attachment Hash</td><td>Not analyzed — this prototype does not process attachments (see limitations)</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Recommended Actions</h2>
    <ul class="reasons">
      {% for action in report.recommended_actions %}
        <li>{{ action }}</li>
      {% endfor %}
    </ul>
  </div>

  <div class="card" id="conclusion">
    <h2>Forensic Conclusion</h2>
    <p style="line-height:1.6;">{{ report.forensic_conclusion }}</p>
  </div>

  <div class="card wide-card">
    <h2>Forensic Report</h2>
    <a href="/download-report" style="text-decoration:none;"><button type="button">⬇ Download Forensic Report (PDF)</button></a>
  </div>

  <div class="card wide-card flow-card">
    <h2>IOC to SOC Incident Response Flow</h2>
    <div class="soc-flow">
      <div class="soc-step"><strong>1. IOC Extracted</strong><img class="flow-step-image" src="/static/flow-ioc-extracted.png" alt="IOC extracted"><span>URLs, IPs, sender domains, and authentication signals (SPF/DKIM) extracted automatically from the uploaded .eml file.</span></div>
      <div class="soc-step"><strong>2. SOC Triages</strong><img class="flow-step-image" src="/static/flow-soc-triages.png" alt="SOC triages"><span>Analysts validate threat intelligence, correlate campaign evidence, and set priority.</span></div>
      <div class="soc-step"><strong>3. Infrastructure Blocked</strong><img class="flow-step-image" src="/static/flow-infra-blocked.png" alt="Infrastructure blocked"><span>Malicious domains and IPs blocked at Firewall, Email Gateway, and DNS servers to neutralize active threats.</span></div>
    </div>
  </div>

  <div class="card wide-card">
    <h2>Campaign Correlation</h2>
    {% set correlation_graph = report.email_correlation_graph|default({'nodes': [], 'edges': [], 'matches': []}) %}
    {% set sender_domain = correlation_graph.current_sender_domain or report.authentication_check.from_domain or "No sender domain present" %}
    {% set origin_ip = correlation_graph.current_origin_ip or report.origin_trace.originating_ip or "No originating IP present" %}
    {% set reply_domain = correlation_graph.current_reply_domain or "No Reply-To domain present" %}
    <div id="graph-wrap" class="correlation-graph" style="position:relative; min-height:500px; margin-top:10px;">
      <svg id="graph-svg" style="position:absolute; top:0; left:0; width:100%; height:100%; pointer-events:none;"></svg>
      <div class="correlation-columns">
        <div class="correlation-column">
          <div class="graph-column-label">Emails</div>
          <div class="graph-node graph-email" id="node-sender" data-edge-keys="current" style="background:#1b3a5c;">
            {{ report.email_summary.filename or "Uploaded email" }}
          </div>
          {% for edge in correlation_graph.edges[:5] %}
          {% set related = (correlation_graph.nodes|selectattr('id', 'equalto', edge.target)|list|first) %}
          <div class="graph-node graph-email" data-edge-keys="{{ loop.index0 }}" style="background:#252d3a;">
            {{ related.filename if related else edge.target }}
          </div>
          {% endfor %}
        </div>
        <div class="correlation-column">
          <div class="graph-column-label">Shared indicators</div>
          {% for indicator in correlation_graph.graph_indicators|default([]) %}
          <div class="graph-node graph-indicator" data-edge-keys="{{ indicator.edge_keys|join(',') }}" style="background:#252d3a;">{{ indicator.label }}</div>
          {% endfor %}
        </div>
        <div class="correlation-column correlation-campaign-column">
          <div class="graph-column-label">Campaign</div>
          <div class="graph-node graph-campaign" id="node-campaign" style="background:#252d3a;">{{ report.campaign_graph.campaign_id }}</div>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Domain Intelligence</h2>
    <table>
      {% if report.domain_intelligence.lookalike %}
      <tr><td class="label">Lookalike Domain</td><td class="fail">
        FLAGGED — mimics "{{ report.domain_intelligence.lookalike.impersonating }}" (edit distance {{ report.domain_intelligence.lookalike.edit_distance }})
      </td></tr>
      {% else %}
      <tr><td class="label">Lookalike Domain</td><td class="pass">No known brand impersonation detected</td></tr>
      {% endif %}
      <tr><td class="label">MX Records</td><td class="{{ 'pass' if report.domain_intelligence.mx_records else 'fail' }}">
        {{ report.domain_intelligence.mx_records|join(', ') if report.domain_intelligence.mx_records else "None found" }}
      </td></tr>
      {% if report.domain_intelligence.registration.available %}
      <tr><td class="label">Registration Date</td><td>{{ report.domain_intelligence.registration.registration_date or "Unknown" }}</td></tr>
      <tr><td class="label">Registrar</td><td>{{ report.domain_intelligence.registration.registrar or "Unknown" }}</td></tr>
      {% else %}
      <tr><td class="label">WHOIS/RDAP</td><td>Unavailable for this domain</td></tr>
      {% endif %}
    </table>
  </div>

  <div class="card">
    <h2>Origin Trace &amp; Geolocation</h2>
    <table>
      <tr><td class="label">Originating IP</td><td>{{ report.origin_trace.originating_ip or "Not found" }}</td></tr>
      {% if report.geolocation.status == "success" %}
      <tr><td class="label">Country</td><td>{{ report.geolocation.country }}</td></tr>
      <tr><td class="label">City / Region</td><td>{{ report.geolocation.city }}, {{ report.geolocation.regionName }}</td></tr>
      <tr><td class="label">ISP / Org</td><td>{{ report.geolocation.isp }}</td></tr>
      <tr><td class="label">Proxy / TOR / VPN</td><td class="{{ 'fail' if report.geolocation.proxy else 'pass' }}">
        {{ "YES — FLAGGED" if report.geolocation.proxy else "No" }}
      </td></tr>
      <tr><td class="label">Hosting/Cloud IP</td><td class="{{ 'fail' if report.geolocation.hosting else 'pass' }}">
        {{ "YES" if report.geolocation.hosting else "No" }}
      </td></tr>
      {% else %}
      <tr><td class="label">Geolocation</td><td class="fail">{{ report.geolocation.error }}</td></tr>
      {% endif %}
    </table>
  </div>

  </div>

  {% endif %}

  <p class="footer-note">Prototype scope: rule-based scoring stands in for the production NLP/BERT model;
  Neo4j graph correlation is the planned phase-2 addition for multi-email campaign clustering.</p>

</div>

{% if report %}
<script>
(function() {
  var hops = {{ hops_json|safe }};
  var hopsWithCoords = hops.filter(function(h) { return h.lat !== null && h.lon !== null && h.lat !== undefined && h.lon !== undefined; });

  if (hopsWithCoords.length === 0) {
    document.getElementById('hop-map').innerHTML =
      '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#5d6b8f;">No geolocated hops available to plot (network/API unavailable for this run).</div>';
    return;
  }

  var map = L.map('hop-map');
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors',
    maxZoom: 18
  }).addTo(map);

  var colors = { "Probable Origin": "#e74c3c", "Intermediate Relay": "#f1c40f", "Final Visible Mail Server": "#2ecc71" };
  var latlngs = [];

  hopsWithCoords.forEach(function(h) {
    var color = colors[h.role] || "#3498db";
    var marker = L.circleMarker([h.lat, h.lon], {
      radius: 8, color: color, fillColor: color, fillOpacity: 0.9, weight: 2
    }).addTo(map);
    marker.bindPopup(
      "<b>" + h.role + "</b><br>IP: " + h.ip +
      (h.reverse_dns ? "<br>Reverse DNS: " + h.reverse_dns : "") +
      (h.city ? "<br>" + h.city + ", " + h.country : "") +
      (h.isp ? "<br>ISP: " + h.isp : "") +
      (h.asn ? "<br>ASN: " + h.asn : "")
    );
    latlngs.push([h.lat, h.lon]);
  });

  if (latlngs.length > 1) {
    var line = L.polyline(latlngs, { color: "#2f7cff", weight: 3, opacity: 0.85 }).addTo(map);
    if (typeof L.polylineDecorator === "function") {
      L.polylineDecorator(line, {
        patterns: [
          { offset: 0, repeat: 30, symbol: L.Symbol.arrowHead({
              pixelSize: 10, polygon: false, pathOptions: { stroke: true, color: "#2f7cff", weight: 3 }
          }) }
        ]
      }).addTo(map);
    }
  }

  if (latlngs.length === 1) {
    map.setView(latlngs[0], 6);
  } else {
    map.fitBounds(latlngs, { padding: [30, 30] });
  }

  L.control.scale({ imperial: true, metric: false, position: "bottomleft" }).addTo(map);

  var legend = L.control({ position: "bottomleft" });
  legend.onAdd = function() {
    var div = L.DomUtil.create('div', 'map-legend-box');
    div.innerHTML =
      '<b>Email Routing Trace</b><br>' +
      '<span><i style="background:#e74c3c"></i> Probable Origin</span><br>' +
      '<span><i style="background:#f1c40f"></i> Intermediate Relay</span><br>' +
      '<span><i style="background:#2ecc71"></i> Final Visible Mail Server</span><br>' +
      '<span><i style="background:#2f7cff; height:2px; width:14px; border-radius:0;"></i> Routing Path</span>';
    return div;
  };
  legend.addTo(map);
})();
</script>

<script>
(function() {
  var wrap = document.getElementById('graph-wrap');
  var svg = document.getElementById('graph-svg');
  var campaign = document.getElementById('node-campaign');
  var indicators = document.querySelectorAll('.graph-indicator');
  var emails = document.querySelectorAll('.graph-email');
  if (!wrap || !svg || !campaign || indicators.length === 0) return;

  var svgns = "http://www.w3.org/2000/svg";
  var wrapRect = wrap.getBoundingClientRect();

  function center(element) {
    var rect = element.getBoundingClientRect();
    return { x: rect.left + rect.width / 2 - wrapRect.left, y: rect.top + rect.height / 2 - wrapRect.top };
  }

  function curve(from, to, color) {
    var path = document.createElementNS(svgns, "path");
    var bend = Math.max(35, Math.abs(to.x - from.x) * 0.42);
    path.setAttribute("d", "M " + from.x + " " + from.y + " C " + (from.x + bend) + " " + from.y + ", " + (to.x - bend) + " " + to.y + ", " + to.x + " " + to.y);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", color);
    path.setAttribute("stroke-width", "1.4");
    path.setAttribute("marker-end", "url(#graph-arrow)");
    svg.appendChild(path);
  }

  var defs = document.createElementNS(svgns, "defs");
  defs.innerHTML = '<marker id="graph-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#247da8"></path></marker>';
  svg.appendChild(defs);

  indicators.forEach(function(indicator) {
    var keys = (indicator.getAttribute('data-edge-keys') || '').split(',');
    var target = center(indicator);
    emails.forEach(function(email) {
      var emailKeys = (email.getAttribute('data-edge-keys') || '').split(',');
      if (keys.some(function(key) { return emailKeys.indexOf(key) !== -1; })) {
        curve(center(email), target, '#247da8');
      }
    });
    curve(target, center(campaign), '#247da8');
  });
})();
</script>
{% endif %}

</body>
</html>
"""

import os
import json
import tempfile
from flask import Flask, request, render_template_string, send_file, redirect, jsonify
from werkzeug.utils import secure_filename

from email_forensics import build_report
from pdf_report import generate_pdf_report
import uuid

app = Flask(__name__)
RUNTIME_FOLDER = tempfile.gettempdir() if os.environ.get("VERCEL") else os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(RUNTIME_FOLDER, "emailforensics-uploads")
REPORT_FOLDER = os.path.join(RUNTIME_FOLDER, "emailforensics-reports")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# Global or persistent store for mapping Case IDs to generated reports
REPORTS_STORE = {}

# Secret API key for Google Apps Script integration
ANALYTICS_API_KEY = os.environ.get("ANALYTICS_API_KEY", "24001103844-g3istkphaa2d9r4v5h9j9ho4gr3oalqf.apps.googleusercontent.com")

THEME_CSS = """
  :root {
    --bg: #f4efe9;
    --bg-strong: #f8f4f1;
    --surface: rgba(255, 255, 255, 0.85);
    --surface-strong: rgba(255, 255, 255, 0.96);
    --border: rgba(217, 119, 6, 0.22);
    --border-strong: rgba(146, 64, 14, 0.45);
    --accent: #ea580c;
    --accent-strong: #d97706;
    --brown: #78350f;
    --brown-soft: #92400e;
    --text: #1f2937;
    --muted: #5b6472;
    --success: #16a34a;
    --warning: #f59e0b;
    --danger: #dc2626;
    --shadow: 0 18px 40px rgba(120, 53, 15, 0.08);
  }

  * { box-sizing: border-box; }

  html, body {
    margin: 0;
    min-height: 100%;
    font-family: 'Segoe UI', Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
  }

  body.landing-page {
    background-color: #f5f2ee !important;
    background-image: linear-gradient(rgba(255, 252, 247, 0.34), rgba(255, 252, 247, 0.34)), url('/static/1st-bg.png') !important;
    background-size: cover !important;
    background-position: center !important;
    background-repeat: no-repeat !important;
    background-attachment: fixed !important;
  }

  body.landing-page .app-shell {
    background: transparent !important;
  }

  body {
    background-color: #f5f2ee;
    background-image: url('/static/email-bg.png');
    background-size: cover;
    background-position: center center;
    background-attachment: fixed;
    background-repeat: no-repeat;
    min-height: 100vh;
    color: var(--text);
  }

  a { color: inherit; text-decoration: none; }

  .app-shell {
    max-width: 1280px;
    margin: 0 auto;
    padding: 24px 20px 60px;
  }

  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
    padding: 18px 20px;
    border: 1px solid var(--border);
    background: rgba(255, 255, 255, 0.82);
    backdrop-filter: blur(10px);
    border-radius: 18px;
    box-shadow: var(--shadow);
    margin-bottom: 28px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 800;
    letter-spacing: -0.04em;
    font-size: 1.8rem;
    color: var(--brown);
  }

  .brand-mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 42px;
    height: 42px;
    border-radius: 12px;
    background: linear-gradient(180deg, #f8d3a6, #e7b06c);
    color: var(--brown);
    font-size: 1.2rem;
  }

  .nav-links {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .nav-link {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 9px 14px;
    border-radius: 10px;
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--muted);
    border: 1px solid transparent;
  }

  .nav-link.active {
    color: var(--brown);
    background: rgba(234, 88, 12, 0.08);
    border-color: rgba(234, 88, 12, 0.2);
  }

  .top-actions {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .btn,
  .ghost-btn,
  .chip {
    border: 1px solid rgba(120, 53, 15, 0.25);
    border-radius: 12px;
    cursor: pointer;
    font-weight: 700;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
  }

  .btn:hover,
  .ghost-btn:hover,
  .chip:hover {
    transform: translateY(-1px);
  }

  .btn {
    padding: 12px 22px;
    background: linear-gradient(180deg, var(--accent) 0%, var(--accent-strong) 100%);
    border-color: rgba(120, 53, 15, 0.25);
    color: white;
    box-shadow: 0 12px 22px rgba(234, 88, 12, 0.18);
  }

  .ghost-btn {
    padding: 10px 16px;
    background: rgba(255, 255, 255, 0.7);
    color: var(--brown);
  }

  .hero-card {
    text-align: center;
    padding: 72px 18px 30px;
  }

  .hero-title {
    margin: 0;
    font-size: clamp(3.2rem, 5vw, 6rem);
    line-height: 0.95;
    letter-spacing: -0.07em;
    color: rgba(31, 41, 55, 0.94);
    font-weight: 800;
  }

  .hero-sub {
    max-width: 920px;
    margin: 22px auto 0;
    font-size: clamp(1.1rem, 1.5vw, 1.5rem);
    color: var(--muted);
    line-height: 1.5;
  }

  .upload-panel {
    width: min(760px, 100%);
    margin: 30px auto 0;
    padding: 18px;
    border-radius: 18px;
    background: rgba(255, 255, 255, 0.72);
    border: 1px solid var(--border);
    backdrop-filter: blur(10px);
    box-shadow: var(--shadow);
  }

  .file-input-wrap {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: flex-start;
    min-height: 58px;
    padding: 6px 10px;
    border-radius: 12px;
    border: 1px dashed rgba(146, 64, 14, 0.75);
    background: rgba(255,255,255,0.18);
    box-shadow: inset 0 0 0 1px rgba(167,128,92,0.12);
  }

  .file-input-wrap input[type="file"] {
    display: none;
  }

  .file-label {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 14px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--text);
    cursor: pointer;
  }
  .email-preview-toggle { cursor: pointer; list-style: none; }
  .email-preview-toggle::-webkit-details-marker { display: none; }
  .email-preview-toggle::before { content: '▸'; display: inline-block; margin-right: 8px; color: #d97706; }
  details[open] .email-preview-toggle::before { content: '▾'; }
  .email-preview-body { max-height: 320px; overflow: auto; margin-top: 16px; white-space: pre-wrap; text-align: left; font: .88rem/1.7 Consolas, 'Segoe UI', monospace; color: #1f2937; background: rgba(255,255,255,.55); border: 1px solid rgba(146,64,14,.18); border-radius: 10px; padding: 14px; }
  .email-inline-image { display: block; max-width: 100%; max-height: 360px; object-fit: contain; margin: 14px 0; border: 1px solid rgba(146,64,14,.18); border-radius: 8px; background: #fff; }
  .flow-card { padding: 20px; background: rgba(255,255,255,.88); backdrop-filter: blur(10px); border: 1px solid rgba(217,119,6,.2); border-radius: 12px; }
  .flow-card h2 { color: #92400e; }
  .flow-step-image { display: block; width: auto; max-width: 100%; max-height: 70px; object-fit: contain; margin: 0 auto 14px; }

  .choose-file {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 18px;
    min-height: 38px;
    border-radius: 10px;
    background: linear-gradient(180deg, #a6673d 0%, #8d5a34 100%);
    border: 1px solid rgba(99, 58, 31, 0.8);
    color: white;
    font-weight: 700;
    box-shadow: 0 8px 18px rgba(120, 53, 15, 0.12);
    flex-shrink: 0;
  }

  .filename {
    overflow: hidden;
    text-overflow: ellipsis;
    color: rgba(31, 41, 55, 0.9);
    font-weight: 500;
  }

  .upload-actions {
    display: flex;
    justify-content: center;
    margin-top: 18px;
  }

  .submit-btn {
    min-width: 220px;
    padding: 15px 28px;
    border: none;
    border-radius: 12px;
    background: linear-gradient(180deg, #b06b3d 0%, #8b5b30 100%);
    color: white;
    font-size: 1.05rem;
    font-weight: 800;
    cursor: pointer;
    box-shadow: 0 10px 20px rgba(120, 53, 15, 0.15);
  }

  .feature-row {
    display: flex;
    justify-content: center;
    flex-wrap: wrap;
    gap: 14px;
    margin-top: 30px;
  }

  .feature-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    min-width: 200px;
    padding: 14px 18px;
    border: 1px solid var(--border);
    border-radius: 12px;
    background: rgba(255,255,255,0.7);
    backdrop-filter: blur(10px);
    color: var(--text);
    font-weight: 600;
  }

  .feature-icon {
    width: 20px;
    height: 20px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--brown-soft);
  }

  .feature-icon svg {
    width: 20px;
    height: 20px;
    fill: none;
    stroke: currentColor;
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
  }

  .overview-grid {
    display: grid;
    grid-template-columns: repeat(12, minmax(0, 1fr));
    gap: 18px;
  }

  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    backdrop-filter: blur(10px);
    box-shadow: var(--shadow);
    padding: 22px;
  }

  .threat-panel { grid-column: span 4; }
  .class-panel { grid-column: span 4; }
  .why-panel { grid-column: span 4; }
  .preview-panel { grid-column: span 7; }
  .intel-panel { grid-column: span 5; }
  .report-panel { grid-column: span 12; }

  .panel h2 {
    margin: 0 0 8px;
    font-size: 1.2rem;
    color: var(--brown);
    letter-spacing: -0.03em;
  }

  .subtle {
    margin: 0;
    color: var(--muted);
    font-size: 0.92rem;
  }

  .score-wrap {
    display: flex;
    align-items: center;
    gap: 18px;
    margin-top: 18px;
  }

  .score-ring {
    width: 105px;
    height: 105px;
    border-radius: 50%;
    position: relative;
    background: conic-gradient(var(--accent) 0deg 245deg, #edcaa2 245deg 360deg);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .score-ring::before {
    content: "";
    position: absolute;
    inset: 12px;
    background: rgba(255,255,255,0.9);
    border-radius: 50%;
  }

  .score-ring strong {
    position: relative;
    font-size: 1.6rem;
    color: var(--brown);
    z-index: 1;
  }

  .risk-tag {
    display: inline-block;
    margin-top: 8px;
    padding: 6px 10px;
    border-radius: 999px;
    background: rgba(22, 163, 74, 0.08);
    border: 1px solid rgba(22, 163, 74, 0.2);
    color: var(--success);
    font-size: 0.7rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .confidence {
    margin-top: 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    color: var(--muted);
    font-size: 0.82rem;
    font-weight: 700;
  }

  .meter {
    width: 100%;
    height: 10px;
    border-radius: 999px;
    background: rgba(146, 64, 14, 0.08);
    overflow: hidden;
    margin-top: 8px;
  }

  .meter > span {
    display: block;
    height: 100%;
    border-radius: inherit;
    background: linear-gradient(90deg, var(--accent) 0%, var(--accent-strong) 100%);
  }

  .chart-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    margin-top: 18px;
  }

  .donut {
    width: 170px;
    height: 170px;
    border-radius: 50%;
    background: var(--accent);
    position: relative;
  }

  .donut::before {
    content: "";
    position: absolute;
    inset: 24px;
    background: rgba(255,255,255,0.95);
    border-radius: 50%;
  }

  .legend {
    display: grid;
    gap: 8px;
    margin-top: 18px;
  }

  .legend-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    color: var(--text);
    font-size: 0.9rem;
  }

  .legend-left {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
  }

  .why-list,
  .detail-list,
  .mini-list {
    list-style: none;
    padding: 0;
    margin: 18px 0 0;
    display: grid;
    gap: 10px;
  }

  .why-list li,
  .detail-list li,
  .mini-list li {
    position: relative;
    padding-left: 18px;
    color: var(--text);
    line-height: 1.5;
  }

  .why-list li::before,
  .detail-list li::before,
  .mini-list li::before {
    content: "•";
    position: absolute;
    left: 0;
    color: var(--accent-strong);
    font-size: 1.2rem;
    line-height: 1;
  }

  .preview-box {
    margin-top: 18px;
    max-height: 280px;
    overflow: auto;
    border: 1px solid rgba(146, 64, 14, 0.2);
    border-radius: 12px;
    background: rgba(255,255,255,0.5);
    padding: 16px;
    font-family: 'Consolas', 'Segoe UI', monospace;
    font-size: 0.88rem;
    line-height: 1.7;
    color: var(--text);
    white-space: pre-wrap;
  }

  .intel-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-top: 18px;
  }

  .intel-card {
    display: block;
    border: 1px solid var(--border);
    background: rgba(255,255,255,0.72);
    border-radius: 14px;
    padding: 16px;
    min-height: 112px;
  }

  .intel-card strong {
    display: block;
    color: var(--brown);
    margin-bottom: 4px;
  }

  .intel-card span {
    color: var(--muted);
    font-size: 0.9rem;
  }

  .report-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    flex-wrap: wrap;
    margin-top: 10px;
  }

  .report-banner .btn {
    min-width: 230px;
  }

  .detail-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
  }

  .detail-layout {
    display: grid;
    grid-template-columns: 1.3fr 0.7fr;
    gap: 18px;
  }

  .detail-card {
    background: rgba(255,255,255,0.85);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 20px;
    backdrop-filter: blur(10px);
    box-shadow: var(--shadow);
  }

  .detail-card h3 {
    margin: 0 0 12px;
    color: var(--brown);
    letter-spacing: -0.03em;
  }

  .table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
    color: var(--text);
  }

  .table th,
  .table td {
    text-align: left;
    padding: 10px 8px;
    border-bottom: 1px solid rgba(146, 64, 14, 0.12);
  }

  .table th {
    color: var(--brown);
    font-weight: 800;
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 7px 10px;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    background: rgba(234, 88, 12, 0.08);
    border: 1px solid rgba(234, 88, 12, 0.2);
    color: var(--brown);
  }

  @media (max-width: 980px) {
    .threat-panel, .class-panel, .why-panel, .preview-panel, .intel-panel, .report-panel {
      grid-column: span 12;
    }

    .detail-layout {
      grid-template-columns: 1fr;
    }
  }

  @media (max-width: 760px) {
    .topbar {
      flex-direction: column;
      align-items: flex-start;
    }

    .nav-links {
      width: 100%;
      justify-content: flex-start;
    }

    .brand {
      font-size: 1.5rem;
    }

    .hero-card {
      padding-top: 40px;
    }

    .feature-pill {
      min-width: 150px;
      flex: 1 1 42%;
    }

    .file-label {
      white-space: normal;
      flex-wrap: wrap;
    }

    .intel-grid {
      grid-template-columns: 1fr;
    }
  }
"""

HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Threat Detection Platform</title>
  <style>{{ theme_css }}</style>
</head>
<body class="landing-page">
  <div class="app-shell">
    <div class="hero-card">
      <h1 class="hero-title">AI-Powered Email Threat<br>Detection,<br>Geolocation &amp; Forensic<br>Intelligence</h1>
      <p class="hero-sub">Upload an email (.eml) file and instantly uncover phishing attempts, sender infrastructure, geolocation intelligence, authentication failures, IOC indicators, and forensic evidence.</p>

      <div class="upload-panel">
        <form action="/upload" method="post" enctype="multipart/form-data">
          <div class="file-input-wrap">
            <label for="emlfile" class="file-label">
              <span id="choose-file-button" class="choose-file" role="button" tabindex="0">Choose File</span>
              <span class="filename">No file selected</span>
            </label>
            <input id="emlfile" type="file" name="emlfile" accept=".eml" required style="display: none !important;">
          </div>
          <div class="upload-actions">
            <button class="submit-btn" type="submit">Analyze Email</button>
          </div>
        </form>
      </div>

      <div class="feature-row">
        <div class="feature-pill"><span class="feature-icon"><svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="M3 7.5L12 13l9-5.5"></path></svg></span>Email Analysis</div>
        <div class="feature-pill"><span class="feature-icon"><svg viewBox="0 0 24 24"><path d="M12 21s6-4.5 6-10a6 6 0 1 0-12 0c0 5.5 6 10 6 10Z"></path><circle cx="12" cy="11" r="2.4"></circle></svg></span>Geolocation Mapping</div>
        <div class="feature-pill"><span class="feature-icon"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="5.5"></circle><path d="M16 16l4.5 4.5"></path></svg></span>IOC Detection</div>
        <div class="feature-pill"><span class="feature-icon"><svg viewBox="0 0 24 24"><path d="M7 3.5h10a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5.5a2 2 0 0 1 2-2Z"></path><path d="M8 8.5h8M8 12h8M8 15.5h6"></path></svg></span>Forensic Reports</div>
      </div>
    </div>
  </div>
  <script>
    (function () {
      var input = document.getElementById('emlfile');
      var chooseButton = document.getElementById('choose-file-button');
      var filename = document.querySelector('.filename');
      chooseButton.addEventListener('click', function (event) {
        event.preventDefault();
        input.click();
      });
      chooseButton.addEventListener('keydown', function (event) {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          input.click();
        }
      });
      input.addEventListener('change', function () {
        filename.textContent = this.files.length ? this.files[0].name : 'No file selected';
      });
    }());
  </script>
</body>
</html>
"""

OVERVIEW_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Threat Assessment Workspace</title>
  <style>{{ theme_css }}</style>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand"><span class="brand-mark">✉</span> MailTrace</div>
      <nav class="nav-links">
        <a class="nav-link active" href="/overview">Overview</a>
        <a class="nav-link" href="/detail/authentication">Authentication</a>
        <a class="nav-link" href="/detail/geolocation">Geolocation</a>
        <a class="nav-link" href="/detail/ioc">IOC</a>
        <a class="nav-link" href="/detail/forensics">Forensics</a>
      </nav>
      <div class="top-actions">
        <a class="ghost-btn" href="/">New Upload</a>
      </div>
    </header>

    <main class="overview-grid">
      <section class="panel threat-panel">
        <h2>Threat Assessment</h2>
        <p class="subtle">{{ filename }} · Last analyzed just now</p>
        <div class="score-wrap">
          <div class="score-ring"><strong>{{ report.threat_assessment.fraud_score }}</strong></div>
          <div>
            <div class="risk-tag">{{ report.threat_assessment.verdict }}</div>
            <div class="confidence"><span>Risk confidence</span><strong>{{ report.threat_assessment.fraud_score }} / 100</strong></div>
            <div class="meter"><span style="width: {{ report.threat_assessment.fraud_score }}%;"></span></div>
          </div>
        </div>
      </section>

      <section class="panel class-panel">
        <h2>AI Classification</h2>
        <div class="chart-wrap">
          <div class="donut" style="background: conic-gradient({{ classification_gradient }});"></div>
        </div>
        <div class="legend">
          {% for category in report.threat_assessment.classification %}
          <div class="legend-row"><div class="legend-left"><span class="dot" style="background:{{ classification_colors[loop.index0] }}"></span>{{ category.label }}</div><strong>{{ category.percentage }}%</strong></div>
          {% endfor %}
        </div>
      </section>

      <section class="panel why-panel">
        <h2>Why this category?</h2>
        <p class="subtle">The classifier selected <strong>{{ report.threat_assessment.verdict }}</strong> because the message is high-risk and clearly shows chain-of-custody signals.</p>
        <ul class="why-list">
          {% for reason in report.threat_assessment.reasons %}
          <li>{{ reason }}</li>
          {% endfor %}
        </ul>
      </section>

      <section class="panel preview-panel">
        <h2>Uploaded Email Preview</h2>
        <p class="subtle">Subject: {{ report.email_summary.subject or 'No subject provided' }}</p>
        <div class="preview-box">From: {{ report.email_summary.from }}
To: {{ report.email_summary.to or '—' }}
Reply-To: {{ report.email_summary.reply_to or '—' }}
Subject: {{ report.email_summary.subject or '—' }}
Message-ID: {{ report.email_summary.message_id or '—' }}

{{ report.email_summary.body or 'Message body unavailable.' }}{% for image in report.email_summary.inline_images %}
<img class="email-inline-image" src="{{ image.data_uri }}" alt="{{ image.filename }}">{% endfor %}{% for attachment in report.email_summary.attachments %}
[Attachment: {{ attachment.filename }} ({{ attachment.content_type }}, {{ attachment.size }} bytes)]{% endfor %}</div>
      </section>

      <section class="panel intel-panel">
        <h2>Forensic Intelligence</h2>
        <div class="intel-grid">
          <a class="intel-card" href="/detail/authentication"><strong>Authentication Check</strong><span>SPF / DKIM / DMARC validation</span></a>
          <a class="intel-card" href="/detail/geolocation"><strong>Origin &amp; Geolocation</strong><span>Mail path reconstruction and server hops</span></a>
          <a class="intel-card" href="/detail/routing"><strong>Routing / IP Intelligence</strong><span>ISP, ASN, proxy and hosting signals</span></a>
          <a class="intel-card" href="/detail/ioc"><strong>Indicators of Compromise</strong><span>URLs, sender IP and domain evidence</span></a>
          <a class="intel-card" href="/detail/graph"><strong>Graph-based Attribution</strong><span>Sender domain ↔ reply-to ↔ origin IPs</span></a>
          <a class="intel-card" href="/detail/forensics"><strong>Forensic Conclusion</strong><span>Recommended response actions</span></a>
        </div>
      </section>

      <section class="panel report-panel">
        <div class="report-banner">
          <div>
            <h2 style="margin-bottom: 4px;">Forensic report ready</h2>
            <p class="subtle">Export the complete evidence package with chain-of-custody metadata.</p>
          </div>
          <a class="btn" href="/download-report">Download Forensic Report (PDF)</a>
        </div>
      </section>
    </main>
  </div>
</body>
</html>
"""

DETAIL_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ section_title }}</title>
  <style>{{ theme_css }}</style>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand"><span class="brand-mark">✉</span> MailTrace</div>
      <nav class="nav-links">
        <a class="nav-link" href="/overview">Overview</a>
        <a class="nav-link active" href="/detail/{{ section_key }}">{{ section_title }}</a>
      </nav>
      <div class="top-actions">
        <a class="ghost-btn" href="/overview">← Back to Overview</a>
      </div>
    </header>

    <div class="detail-header">
      <div>
        <h2 style="margin:0 0 6px; color: var(--brown); font-size: 2rem; letter-spacing: -0.05em;">{{ section_title }}</h2>
        <p class="subtle">{{ section_excerpt }}</p>
      </div>
      <span class="status-pill">Live analysis</span>
    </div>

    <div class="detail-layout">
      <div class="detail-card">
        <h3>Analysis details</h3>
        {{ section_body | safe }}
      </div>
      <div class="detail-card">
        <h3>Quick facts</h3>
        <ul class="mini-list">
          <li>Threat verdict: {{ report.threat_assessment.verdict }}</li>
          <li>Fraud score: {{ report.threat_assessment.fraud_score }} / 100</li>
          <li>Filename: {{ filename }}</li>
          <li>Sender: {{ report.email_summary.from or 'Not available' }}</li>
        </ul>
      </div>
    </div>
  </div>
</body>
</html>
"""


def score_color(score):
    if score >= 60:
        return "#ff5c5c"
    elif score >= 30:
        return "#ffb020"
    return "#35d07f"


def classification_gradient(categories):
  colors = ["#d97706", "#f59e0b", "#f3ca8c", "#fef3c7", "#a16207"]
  stops = []
  position = 0
  for color, category in zip(colors, categories):
    next_position = position + category["percentage"]
    stops.append(f"{color} {position}% {next_position}%")
    position = next_position
  return ", ".join(stops)


@app.route("/", methods=["GET"])
def home():
  return render_template_string(HOME_PAGE, theme_css=THEME_CSS)


@app.route("/overview", methods=["GET"])
def overview():
  return redirect("/results")


@app.route("/detail/<section_key>", methods=["GET"])
def detail(section_key):
  return redirect("/results")

  report = app.config.get("LAST_REPORT")
  filename = app.config.get("LAST_FILENAME", "Unknown")

  sections = {
    "authentication": {
      "title": "Authentication",
      "excerpt": "Email sender validation, DKIM signature presence, and DMARC/SPF alignment.",
      "body": """
      <ul class="detail-list">
        <li>SPF status: {spf}</li>
        <li>DKIM signature: {dkim}</li>
        <li>DMARC status: {dmarc}</li>
        <li>Sending domain: {domain}</li>
      </ul>
      """.format(
        spf="Valid" if report.get("authentication_check", {}).get("spf", {}).get("found") else "Missing / invalid",
        dkim="Present" if report.get("authentication_check", {}).get("dkim_signature_present") else "Absent",
        dmarc="Valid" if report.get("authentication_check", {}).get("dmarc", {}).get("found") else "Missing / invalid",
        domain=report.get("authentication_check", {}).get("from_domain", "Unknown")
      )
    },
    "geolocation": {
      "title": "Geolocation",
      "excerpt": "Origin analysis and network location indicators from the routing chain.",
      "body": """
      <ul class="detail-list">
        <li>Originating IP: {origin}</li>
        <li>Country: {country}</li>
        <li>City: {city}</li>
        <li>ISP: {isp}</li>
      </ul>
      """.format(
        origin=report.get("origin_trace", {}).get("originating_ip", "Not found"),
        country=report.get("geolocation", {}).get("country", "Unknown"),
        city=report.get("geolocation", {}).get("city", "Unknown"),
        isp=report.get("geolocation", {}).get("isp", "Unknown")
      )
    },
    "ioc": {
      "title": "Indicators of Compromise",
      "excerpt": "URLs, sender infrastructure, and malicious artefacts detected in the message.",
      "body": """
      <ul class="detail-list">
        <li>Sender IP: {sender_ip}</li>
        <li>Sender domain: {sender_domain}</li>
        <li>Suspicious URLs: {urls}</li>
        <li>Threat verdict: {verdict}</li>
      </ul>
      """.format(
        sender_ip=report.get("iocs", {}).get("sender_ip", "—"),
        sender_domain=report.get("iocs", {}).get("sender_domain", "—"),
        urls=", ".join(report.get("iocs", {}).get("suspicious_urls", [])) if report.get("iocs", {}).get("suspicious_urls") else "None detected",
        verdict=report.get("threat_assessment", {}).get("verdict", "Unknown")
      )
    },
    "forensics": {
      "title": "Forensics",
      "excerpt": "Chain-of-custody evidence summary and recommended response actions.",
      "body": """
      <ul class="detail-list">
        <li>Verdict: {verdict}</li>
        <li>Fraud score: {score}</li>
        <li>Recommendation: {action}</li>
        <li>Conclusion: {conclusion}</li>
      </ul>
      """.format(
        verdict=report.get("threat_assessment", {}).get("verdict", "Unknown"),
        score=report.get("threat_assessment", {}).get("fraud_score", 0),
        action=report.get("recommended_actions", ["No action available"])[0],
        conclusion=report.get("forensic_conclusion", "No conclusion available")
      )
    },
  }

  section = sections.get(section_key, sections["authentication"])

  return render_template_string(
    DETAIL_PAGE,
    section_key=section_key,
    section_title=section["title"],
    section_excerpt=section["excerpt"],
    section_body=section["body"],
    report=report,
    filename=filename,
    theme_css=THEME_CSS
  )

# @app.route("/", methods=["GET", "POST"])
# def index():
#     report = None
#     color = "#35d07f"
#     hops_json = "[]"
#     if request.method == "POST":
#         f = request.files["emlfile"]
#         path = os.path.join(UPLOAD_FOLDER, f.filename)
#         f.save(path)
#         report = build_report(path)
#         color = score_color(report["threat_assessment"]["fraud_score"])
#         app.config["LAST_REPORT"] = report
#         hops_json = json.dumps(report.get("mail_path", []))
#     return render_template_string(PAGE, report=report, score_color=color, hops_json=hops_json)

# Global or persistent store for mapping Case IDs to generated reports
REPORTS_STORE = {}

# Set your secret API key in Vercel environment variables or hardcode for testing
ANALYTICS_API_KEY = os.environ.get("ANALYTICS_API_KEY", "your_secret_key_123")

@app.route("/results", methods=["GET"])
def results():
    case_id = request.args.get("caseId")
    
    # Fetch report from specific caseId if provided, otherwise fallback to LAST_REPORT
    if case_id and case_id in REPORTS_STORE:
        report = REPORTS_STORE[case_id]
        filename = report.get("email_summary", {}).get("filename", "api-upload.eml")
    else:
        report = app.config.get("LAST_REPORT")
        filename = app.config.get("LAST_FILENAME", "Unknown")

    if not report:
        return redirect("/")

    return render_template_string(
        PAGE,
        report=report,
        filename=filename,
        score_color=score_color(report["threat_assessment"]["fraud_score"]),
        classification_colors=["#d97706", "#f59e0b", "#f3ca8c", "#fef3c7", "#a16207"],
        classification_gradient=classification_gradient(report["threat_assessment"].get("classification", [])),
        hops_json=json.dumps(report.get("mail_path", []))
    )

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("emlfile")
    if not f or not f.filename:
        return "Please select an .eml file before analyzing.", 400

    filename = secure_filename(f.filename)
    if not filename.lower().endswith(".eml"):
        return "Only .eml files are supported.", 400

    path = os.path.join(UPLOAD_FOLDER, filename)
    f.save(path)

    report = build_report(path)
    case_id = report.get("campaign_graph", {}).get("campaign_id") or f"CASE-{uuid.uuid4().hex[:8].upper()}"

    # Save to case store and config
    REPORTS_STORE[case_id] = report
    app.config["LAST_REPORT"] = report
    app.config["LAST_FILENAME"] = filename

    return redirect(f"/results?caseId={case_id}")


@app.route("/download-report")
def download_report():
    case_id = request.args.get("caseId")
    
    # 1. Look up report by caseId or fallback to LAST_REPORT
    if case_id and case_id in REPORTS_STORE:
        report = REPORTS_STORE[case_id]
    else:
        report = app.config.get("LAST_REPORT")

    if not report:
        return "No report available yet — analyze an email first.", 400

    out_path = os.path.join(REPORT_FOLDER, "forensic_report.pdf")
    generated_case_id = generate_pdf_report(report, out_path)
    return send_file(out_path, as_attachment=True, download_name=f"{generated_case_id}.pdf")

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    api_key = request.headers.get('x-api-key')
    if api_key != ANALYTICS_API_KEY:
        return jsonify({"error": "Unauthorized: Invalid API Key"}), 401

    temp_path = None
    try:
        data = request.get_json()
        if not isinstance(data, dict) or not isinstance(data.get('rawEmail'), str):
            return jsonify({"error": "Bad Request: Missing rawEmail parameter"}), 400

        raw_email_text = data['rawEmail']
        if not raw_email_text.strip():
            return jsonify({"error": "Bad Request: rawEmail cannot be empty"}), 400

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".eml", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(raw_email_text)
            temp_path = temp_file.name
        
        report = build_report(temp_path)
        filename = secure_filename(data.get("filename") or "api-upload.eml") or "api-upload.eml"
        report["email_summary"]["filename"] = filename

        # -------------------------------------------------------------
        # FIX: Generate a strictly UNIQUE Case ID for every single scan
        # -------------------------------------------------------------
        unique_suffix = uuid.uuid4().hex[:8].upper()
        
        # If your analysis module returns a campaign ID, append a unique hash:
        # e.g., "CAM-9141D266-A1B2C3D4"
        raw_campaign_id = report.get("campaign_graph", {}).get("campaign_id")
        if raw_campaign_id:
            case_id = f"{raw_campaign_id}-{unique_suffix}"
        else:
            case_id = f"CASE-{unique_suffix}"

        # Update the report payload with the unique case ID
        if "campaign_graph" in report and isinstance(report["campaign_graph"], dict):
            report["campaign_graph"]["campaign_id"] = case_id

        # Save to memory store using the unique key
        REPORTS_STORE[case_id] = report

        # Fallbacks for legacy state
        app.config["LAST_REPORT"] = report
        app.config["LAST_FILENAME"] = filename

        host_url = request.host_url.rstrip('/')
        report_url = f"{host_url}/results?caseId={case_id}"

        threat = report["threat_assessment"]
        return jsonify({
            "status": "success",
            "verdict": threat["verdict"],
            "category": threat.get("predicted_category"),
            "fraudScore": threat["fraud_score"],
            "caseId": case_id,
            "reportUrl": report_url,
            "originIP": report["origin_trace"].get("originating_ip"),
            "senderDomain": report["authentication_check"].get("from_domain"),
            "replyToDomain": report["email_correlation_graph"].get("current_reply_domain"),
            "classification": threat.get("classification", []),
            "reasons": threat.get("reasons", []),
            "report": report,
        }), 200

    except Exception:
        app.logger.exception("Email analysis API failed")
        return jsonify({"error": "Internal Error: email analysis failed"}), 500
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)