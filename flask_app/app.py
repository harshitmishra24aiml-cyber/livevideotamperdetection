import os,json,uuid,secrets,time
from pathlib import Path
from flask import Flask,render_template,request,redirect,url_for,flash,send_file,jsonify
from werkzeug.utils import secure_filename
from config import UPLOADS,EVIDENCE
from modules.db import init,conn,query
from modules.pipeline import record_video,verify_video
from modules.crypto import keypair,verify
app=Flask(__name__); app.secret_key=os.environ.get("FLASK_SECRET_KEY","local-demo-change-before-deploy"); app.config["MAX_CONTENT_LENGTH"]=250*1024*1024; init()
CHALLENGES={}
@app.get("/")
def home(): return render_template("index.html",sessions=query("SELECT * FROM sessions ORDER BY created DESC"),alerts=query("SELECT * FROM alerts ORDER BY id DESC LIMIT 15"),cameras=query("SELECT id,name,active FROM cameras"))
@app.post("/upload")
def upload():
 f=request.files.get("video")
 if not f or not f.filename: flash("Select a video"); return redirect(url_for("home"))
 p=UPLOADS/(uuid.uuid4().hex+secure_filename(f.filename)); f.save(p)
 try:
  ref,alerts=record_video(p,request.form.get("source","uploaded"))
  with conn() as c:
   c.execute("INSERT INTO sessions(id,source,frames,root) VALUES(?,?,?,?)",(ref["session_id"],ref["source"],len(ref["records"]),ref["final_chain"]))
   for r in ref["records"]: c.execute("INSERT INTO frame_records VALUES(?,?,?,?,?,?)",(ref["session_id"],r["sequence"],r["timestamp"],r["frame_hash"],r["chain_hash"],json.dumps(r["scene"])))
   for a in alerts: c.execute("INSERT INTO alerts(session,kind,severity,message) VALUES(?,?,?,?)",(ref["session_id"],a["kind"],a["severity"],a["message"]))
  return render_template("result.html",ref=ref,alerts=alerts)
 except Exception as e: flash(str(e)); return redirect(url_for("home"))
@app.post("/verify")
def verify_route():
 f=request.files.get("video"); r=request.files.get("reference")
 if not f or not r: flash("Both video and original reference JSON are required"); return redirect(url_for("home"))
 vp=UPLOADS/(uuid.uuid4().hex+secure_filename(f.filename)); rp=UPLOADS/(uuid.uuid4().hex+secure_filename(r.filename)); f.save(vp); r.save(rp)
 try: return render_template("verify.html",result=verify_video(vp,json.loads(rp.read_text())))
 except Exception as e: flash(str(e)); return redirect(url_for("home"))
@app.post("/camera/register")
def camera_register():
 name=request.form.get("name","").strip()
 if not name: flash("Camera name required"); return redirect(url_for("home"))
 cid="CAM-"+uuid.uuid4().hex[:10].upper(); private,public=keypair()
 with conn() as c: c.execute("INSERT INTO cameras(id,name,public_key) VALUES(?,?,?)",(cid,name,public))
 return render_template("key.html",cid=cid,private=private,public=public)
@app.post("/camera/challenge")
def challenge():
 cid=request.form.get("camera_id"); cam=query("SELECT * FROM cameras WHERE id=? AND active=1",(cid,))
 if not cam: return jsonify(error="Unknown camera"),404
 nonce=secrets.token_urlsafe(32); CHALLENGES[nonce]=(cid,time.time()+60)
 return jsonify(camera_id=cid,nonce=nonce,warning="Software nonce proves key possession only, not physical scene freshness.")
@app.post("/camera/challenge/verify")
def challenge_verify():
 d=request.get_json(force=True); item=CHALLENGES.pop(d.get("nonce"),None); cam=query("SELECT * FROM cameras WHERE id=? AND active=1",(d.get("camera_id"),))
 ok=bool(item and item[0]==d.get("camera_id") and item[1]>time.time() and cam and verify(cam[0]["public_key"],d["nonce"],d["signature"]))
 return jsonify(valid=ok,meaning="Registered-key possession only; not camera hardware attestation.")
@app.post("/simulate")
def simulate():
 sid=request.form.get("sid"); attack=request.form.get("attack"); p=EVIDENCE/sid/"reference.json"
 if not p.exists(): flash("Evidence session not found"); return redirect(url_for("home"))
 records=json.loads(p.read_text())["records"]; changed=[dict(x) for x in records]
 if not changed: flash("No records"); return redirect(url_for("home"))
 if attack=="modify": changed[len(changed)//2]["frame_hash"]="f"*64
 elif attack=="delete": changed.pop(len(changed)//2)
 elif attack=="insert": changed.insert(1,dict(changed[0]))
 elif attack=="reorder" and len(changed)>1: changed[0],changed[1]=changed[1],changed[0]
 elif attack=="replay": changed.append(dict(changed[0]))
 elif attack=="timestamp": changed[0]["timestamp"]+=3600
 issues=[]; prev="0"*64
 from modules.crypto import link
 for i,r in enumerate(changed,1):
  if r["sequence"]!=i: issues.append("sequence anomaly")
  if link(prev,i,r["frame_hash"],r["timestamp"])!=r["chain_hash"]: issues.append("chain mismatch")
  prev=link(prev,i,r["frame_hash"],r["timestamp"])
 if len(changed)!=len(records): issues.append("record count mismatch")
 detail=json.dumps(issues or ["No anomaly detected"])
 with conn() as c: c.execute("INSERT INTO simulations(session,attack,detected,detail) VALUES(?,?,?,?)",(sid,attack,int(bool(issues)),detail))
 return render_template("simulation.html",attack=attack,issues=issues)
@app.get("/reference/<sid>")
def reference(sid):
 p=EVIDENCE/sid/"reference.json"
 return send_file(p,as_attachment=True,download_name="sentinel-reference.json") if p.exists() else ("Not found",404)
@app.get("/report/<sid>")
def report(sid):
 data={"session":query("SELECT * FROM sessions WHERE id=?",(sid,)),"frames":query("SELECT * FROM frame_records WHERE session=? ORDER BY seq",(sid,)),"alerts":query("SELECT * FROM alerts WHERE session=?",(sid,))}
 from io import BytesIO
 if not data["session"]: return "Not found",404
 b=BytesIO(json.dumps(data,indent=2).encode()); b.seek(0); return send_file(b,mimetype="application/json",as_attachment=True,download_name=f"sentinel-{sid}.json")
@app.get("/api/health")
def health(): return jsonify(status="ok",service="Crypto Sentinel Flask")
if __name__=="__main__": app.run(host="127.0.0.1",port=5000)
