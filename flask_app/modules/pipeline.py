import cv2,json,time,uuid
from config import EVIDENCE
from modules.crypto import GENESIS,digest,link
from modules.detectors import SceneDetector
def record_video(path,source="uploaded"):
 cap=cv2.VideoCapture(str(path))
 if not cap.isOpened(): raise ValueError("Video could not be opened")
 sid=uuid.uuid4().hex; out=EVIDENCE/sid; out.mkdir(parents=True); prev=GENESIS; records=[]; alerts=[]; detector=SceneDetector(); seen=set()
 try:
  while len(records)<500:
   ok,f=cap.read()
   if not ok: break
   n=len(records)+1; ts=round(time.time(),6); h=digest(f); ch=link(prev,n,h,ts); scene=detector.inspect(f)
   if h in seen: alerts.append({"kind":"duplicate_frame","severity":"warning","sequence":n,"message":"Repeated frame digest"})
   seen.add(h)
   if scene["obstruction_suspected"]: alerts.append({"kind":"obstruction_suspected","severity":"high","sequence":n,"message":"Near-black and low-detail frame; heuristic suspicion only"})
   if scene["frozen"]: alerts.append({"kind":"frozen_indicator","severity":"warning","sequence":n,"message":"Very low inter-frame visual change"})
   records.append({"sequence":n,"timestamp":ts,"frame_hash":h,"chain_hash":ch,"scene":scene}); prev=ch
 finally: cap.release()
 if not records: raise ValueError("No decodable frames")
 ref={"session_id":sid,"source":source,"records":records,"final_chain":prev}
 (out/"reference.json").write_text(json.dumps(ref,indent=2))
 return ref,alerts
def verify_video(path,ref):
 cap=cv2.VideoCapture(str(path))
 if not cap.isOpened(): raise ValueError("Video could not be opened")
 expected=ref["records"]; failures=[]; n=0; prev=GENESIS; exact=0
 try:
  while True:
   ok,f=cap.read()
   if not ok: break
   n+=1
   if n>len(expected): failures.append({"seq":n,"reason":"extra/inserted frame"}); continue
   r=expected[n-1]; h=digest(f)
   if h==r["frame_hash"]: exact+=1
   else: failures.append({"seq":n,"reason":"frame hash mismatch"})
   ch=link(prev,n,h,r["timestamp"])
   if ch!=r["chain_hash"]: failures.append({"seq":n,"reason":"chain link mismatch"})
   prev=ch
 finally: cap.release()
 if n<len(expected): failures.append({"seq":n+1,"reason":f"{len(expected)-n} missing frame(s)"})
 return {"integrity_verified":not failures and n==len(expected),"checked":n,"reference_frames":len(expected),"exact_frames":exact,"failures":failures,"note":"Requires a trusted original reference. Does not authenticate a physical camera or live scene."}
