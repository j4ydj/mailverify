#!/usr/bin/env python3
import os
import uuid
import threading
from datetime import datetime
from flask import Flask, request, render_template_string, send_file, jsonify

from mailverify import verify_email, read_emails, write_results_csv, DEFAULT_DISPOSABLE

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
RESULT_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)

jobs = {}
lock = threading.Lock()

HTML = """
<!doctype html>
<title>MailVerify</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; }
  .card { max-width: 680px; padding: 20px; border: 1px solid #ddd; border-radius: 12px; }
  label { display:block; margin-top:10px; }
  input, button { padding:8px; margin-top:6px; }
  button { cursor:pointer; }
  .small { color:#666; font-size: 12px; }
</style>
<div class="card">
  <h2>MailVerify</h2>
  <p class="small">Upload a CSV (with <b>email</b> header or first column). Safe default rate: 1/sec.</p>
  <form action="/start" method="post" enctype="multipart/form-data">
    <label>CSV File <input type="file" name="file" required></label>
    <label>MAIL FROM <input type="text" name="mail_from" value="verify@localhost"></label>
    <label>Global rate (checks/sec) <input type="number" name="rate" value="1" step="0.1"></label>
    <label>Per-domain delay (sec) <input type="number" name="per_domain" value="3" step="0.1"></label>
    <label>Concurrency <input type="number" name="concurrency" value="4"></label>
    <label><input type="checkbox" name="catch_all" checked> Detect catch-all domains</label>
    <button type="submit">Start Verification</button>
  </form>
  <div id="status"></div>
</div>
<script>
  const params = new URLSearchParams(window.location.search);
  const job = params.get('job');
  const statusDiv = document.getElementById('status');
  if (job) {
    const poll = async () => {
      const r = await fetch(`/status/${job}`);
      const data = await r.json();
      statusDiv.innerHTML = `<p><b>Status:</b> ${data.status}</p>` +
        (data.progress ? `<p>${data.progress}</p>` : '') +
        (data.download ? `<p><a href="${data.download}">Download results</a></p>` : '');
      if (data.status !== 'done' && data.status !== 'error') setTimeout(poll, 2000);
    };
    poll();
  }
</script>
"""


def run_job(job_id, path, params):
    try:
        emails = read_emails(path)
        total = len(emails)
        results = []
        summary = {}
        for i, email in enumerate(emails, 1):
            res = verify_email(
                email,
                params['mail_from'],
                params['timeout'],
                params['catch_all'],
                params['rate'],
                params['per_domain'],
                DEFAULT_DISPOSABLE,
            )
            results.append(res)
            status = res.get("status", "unknown")
            summary[status] = summary.get(status, 0) + 1
            with lock:
                jobs[job_id]['progress'] = f"{i}/{total} processed"
        out_path = os.path.join(RESULT_DIR, f"{job_id}.csv")
        write_results_csv(out_path, results, append=False)
        with lock:
            jobs[job_id]['status'] = 'done'
            jobs[job_id]['download'] = f"/download/{job_id}"
            jobs[job_id]['summary'] = summary
    except Exception as e:
        with lock:
            jobs[job_id]['status'] = 'error'
            jobs[job_id]['error'] = str(e)


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/start", methods=["POST"])
def start():
    f = request.files.get('file')
    if not f:
        return "No file", 400
    job_id = uuid.uuid4().hex
    in_path = os.path.join(UPLOAD_DIR, f"{job_id}.csv")
    f.save(in_path)

    params = {
        'mail_from': request.form.get('mail_from', 'verify@localhost'),
        'timeout': 10,
        'rate': float(request.form.get('rate', 1)),
        'per_domain': float(request.form.get('per_domain', 3)),
        'concurrency': int(request.form.get('concurrency', 4)),
        'catch_all': True if request.form.get('catch_all') else False,
    }

    with lock:
        jobs[job_id] = {
            'status': 'running',
            'created': datetime.utcnow().isoformat(),
            'progress': '0/0',
        }

    t = threading.Thread(target=run_job, args=(job_id, in_path, params), daemon=True)
    t.start()
    return ("", 302, {"Location": f"/?job={job_id}"})


@app.route("/status/<job_id>")
def status(job_id):
    with lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({'status': 'not_found'})
        return jsonify(job)


@app.route("/download/<job_id>")
def download(job_id):
    path = os.path.join(RESULT_DIR, f"{job_id}.csv")
    if not os.path.exists(path):
        return "Not found", 404
    return send_file(path, as_attachment=True, download_name=f"verified-{job_id}.csv")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)
