/**
 * GHSA-39q2-94rc-95cp — Vulnerable CMS Preview Server
 *
 * Simulates a CMS with a /preview endpoint that accepts:
 *   ?allowTags=tag1,tag2   — comma-separated list of "safe" custom tags
 *   ?content=<html>        — HTML content to sanitize and render
 *
 * The server uses DOMPurify 3.3.3 with ADD_TAGS as a function
 * and FORBID_TAGS as a blocklist. Due to the short-circuit bug,
 * passing a forbidden tag name in allowTags bypasses FORBID_TAGS.
 */

const express = require("express");
const { JSDOM } = require("jsdom");
const createDOMPurify = require("dompurify");

const app = express();
const PORT = 3000;

// ─── DOMPurify setup (server-side via jsdom) ─────────────────────────────────
const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);

// ─── Tags that are ALWAYS forbidden, regardless of allowTags ─────────────────
const FORBIDDEN = ["script", "iframe", "object", "embed", "base", "form", "input", "meta"];

// ─── HTML shell ──────────────────────────────────────────────────────────────
const page = (title, body, extra = "") => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0 }
    body { font-family: system-ui, sans-serif; background: #f8f9fa; color: #1a1a2e; padding: 2rem }
    h1 { font-size: 1.4rem; font-weight: 600; margin-bottom: .25rem }
    .sub { font-size: .85rem; color: #666; margin-bottom: 1.5rem }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 1.25rem; margin-bottom: 1rem }
    .card h2 { font-size: .75rem; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; color: #888; margin-bottom: .75rem }
    pre, code { font-family: 'Fira Code', monospace; font-size: .8rem }
    pre { background: #1e1e2e; color: #cdd6f4; padding: 1rem; border-radius: 8px; overflow-x: auto; line-height: 1.7 }
    .red { color: #f38ba8 }
    .green { color: #a6e3a1 }
    .amber { color: #fab387 }
    .dim { color: #6c7086 }
    label { font-size: .8rem; color: #555; display: block; margin-bottom: .3rem }
    input[type=text], textarea { width: 100%; padding: .5rem .75rem; border: 1px solid #e2e8f0; border-radius: 6px; font-family: monospace; font-size: .8rem; margin-bottom: .75rem }
    textarea { height: 80px; resize: vertical }
    button { padding: .5rem 1.25rem; border-radius: 6px; border: none; cursor: pointer; font-size: .85rem; font-weight: 500 }
    .btn-red { background: #f38ba8; color: #1e1e2e }
    .btn-gray { background: #e2e8f0; color: #1a1a2e; margin-left: .5rem }
    .badge { display: inline-block; font-size: .7rem; padding: 2px 8px; border-radius: 20px; font-weight: 600 }
    .badge-red { background: #fce4ec; color: #c62828 }
    .badge-green { background: #e8f5e9; color: #2e7d32 }
    .render-box { background: #fffde7; border: 1px solid #f9a825; border-radius: 8px; padding: 1rem; min-height: 40px }
    .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem }
    @media(max-width:640px){ .grid2 { grid-template-columns: 1fr } }
    .tag-pill { display: inline-block; background: #e0e7ff; color: #3730a3; border-radius: 4px; padding: 1px 7px; font-size: .75rem; font-family: monospace; margin: 2px }
  </style>
  ${extra}
</head>
<body>${body}</body>
</html>`;

// ─── Home — explain the setup ─────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.send(page("DOMPurify CVE Demo", `
<h1>GHSA-39q2-94rc-95cp — DOMPurify 3.3.3</h1>
<p class="sub">
  <span class="badge badge-red">Vulnerable</span> &nbsp;
  <code>ADD_TAGS</code> as function + <code>FORBID_TAGS</code> — short-circuit bypass
</p>

<div class="card">
  <h2>How this server works</h2>
  <pre><span class="dim">// server.js — the vulnerable sanitizer</span>

<span class="dim">const FORBIDDEN = ['script','iframe','object','embed','base','form','input','meta']</span>

app.get('/preview', (req, res) => {
  const allowTags = req.query.allowTags?.split(',') ?? []
  const content   = req.query.content ?? ''

  const clean = DOMPurify.sanitize(content, {
    <span class="amber">ADD_TAGS:    (tag) => allowTags.includes(tag),</span>  <span class="dim">// ← function form</span>
    <span class="green">FORBID_TAGS: FORBIDDEN,</span>                          <span class="dim">// ← supposed safety net</span>
  })

  res.send(renderPage(clean))   <span class="dim">// output goes straight to innerHTML</span>
})</pre>
  <p style="font-size:.85rem;color:#555;margin-top:.75rem">
    The developer believes <code>FORBID_TAGS</code> is an unconditional blocklist. 
    Due to the DOMPurify bug, when <code>ADD_TAGS</code> is a function and 
    <code>tagCheck(tagName)</code> returns <code>true</code>, 
    the <code>&amp;&amp;</code> short-circuits and <code>FORBID_TAGS</code> is never evaluated.
  </p>
</div>

<div class="card">
  <h2>Try it yourself</h2>
  <form action="/preview" method="get">
    <label>allowTags (comma-separated — try adding "script")</label>
    <input type="text" name="allowTags" value="x-card" />
    <label>content (HTML)</label>
    <textarea name="content"><p>Hello world</p><script>alert('xss')<\/script></textarea>
    <button type="submit" class="btn-red">Send to /preview</button>
  </form>
</div>
`));
});

// ─── Preview endpoint — the vulnerable one ────────────────────────────────────
app.get("/preview", (req, res) => {
  const allowTags = (req.query.allowTags ?? "")
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);

  const content = req.query.content ?? "";

  // ── VULNERABLE sanitization ───────────────────────────────────────────────
  const clean = DOMPurify.sanitize(content, {
    ADD_TAGS: (tag) => allowTags.includes(tag),  // ← function form
    FORBID_TAGS: FORBIDDEN,                       // ← supposed safety net, bypassed
  });

  // ── Detect bypass ─────────────────────────────────────────────────────────
  const bypassed = /<script/i.test(clean);
  const hasAllowed = allowTags.some((t) => FORBIDDEN.includes(t));

  res.send(page("Preview — GHSA-39q2-94rc-95cp", `
<h1>CMS Preview</h1>
<p class="sub">
  allowTags: ${allowTags.map((t) => `<span class="tag-pill">${t}</span>`).join(" ") || "<em>none</em>"}
  &nbsp;·&nbsp;
  ${hasAllowed
    ? `<span class="badge badge-red">&#9888; forbidden tag in allowTags: ${allowTags.filter(t => FORBIDDEN.includes(t)).join(", ")}</span>`
    : `<span class="badge badge-green">allowTags look safe</span>`
  }
</p>

${bypassed ? `
<div style="background:#fce4ec;border:1px solid #f48fb1;border-radius:8px;padding:1rem;margin-bottom:1rem">
  <strong style="color:#c62828">FORBID_TAGS bypassed!</strong>
  <span id="pwned" style="display:none;margin-left:.5rem;color:#c62828;font-weight:600">
    script ran in your browser
  </span>
  <p style="font-size:.85rem;color:#c62828;margin-top:.25rem">
    tagCheck('script') returned true &rarr; short-circuit &rarr; FORBID_TAGS never evaluated &rarr; &lt;script&gt; passed through.
  </p>
</div>` : ""}

<div class="card">
  <h2>Sanitized output <span class="badge badge-red">DOMPurify 3.3.3 &mdash; ADD_TAGS: function</span></h2>
  <pre style="margin-bottom:.75rem">${escHtml(clean) || "<em style='color:#888'>(empty)</em>"}</pre>
  <div class="render-box">
    ${clean}
    <span id="pwned" style="display:none;font-weight:600;color:#c62828">Script executed!</span>
  </div>
</div>

<div class="card">
  <h2>Condition trace</h2>
  <pre>${evalTrace(content, allowTags)}</pre>
</div>

<p style="margin-top:1rem"><a href="/" style="font-size:.85rem;color:#6366f1">&larr; Back to home</a></p>
`));
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function evalTrace(html, allowTags) {
  try {
    const dom = new JSDOM(html);
    const tags = [...new Set(
      [...dom.window.document.body.querySelectorAll("*")]
        .map((el) => el.tagName.toLowerCase())
    )];

    return tags.map((tag) => {
      const tagCheckResult = allowTags.includes(tag);
      const isForbidden = FORBIDDEN.includes(tag);
      const condA = !tagCheckResult;           // !(tagCheck(tag))
      const shortCircuited = tagCheckResult;   // condA is false → && stops here

      if (shortCircuited) {
        return `<span class="amber">&lt;${tag}&gt;</span>  tagCheck=true  !(true)=false  <span class="red">→ SHORT-CIRCUIT — FORBID_TAGS[${tag}]=${isForbidden} never checked → TAG PASSES</span>`;
      }
      const condB = !false || isForbidden;     // simplified
      return `<span class="green">&lt;${tag}&gt;</span>  tagCheck=false  !(false)=true  FORBID=${isForbidden}  → ${isForbidden ? "removed" : "kept (allowed)"}`;
    }).join("\n");
  } catch {
    return "(could not parse)";
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║  GHSA-39q2-94rc-95cp — DOMPurify 3.3.3 Demo              ║
╠══════════════════════════════════════════════════════════╣
║  Server:  http://localhost:${PORT}                          ║
║                                                          ║            
╚══════════════════════════════════════════════════════════╝
`);
});
