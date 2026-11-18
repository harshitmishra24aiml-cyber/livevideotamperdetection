import cv2
class SceneDetector:
 def __init__(self): self.prev=None
 def inspect(self,f):
  g=cv2.cvtColor(f,cv2.COLOR_BGR2GRAY); mean=float(g.mean()); std=float(g.std()); sharp=float(cv2.Laplacian(g,cv2.CV_64F).var())
  delta=None if self.prev is None else float(cv2.absdiff(g,self.prev).mean()); self.prev=g.copy()
  black=mean<22 and std<12; blur=sharp<8 and std<18; frozen=delta is not None and delta<0.35
  flags=(["near-black"] if black else [])+(["low-detail"] if blur else [])+(["frozen-looking"] if frozen else [])
  return {"brightness":round(mean,2),"sharpness":round(sharp,2),"frozen":frozen,"obstruction_suspected":black and blur,"flags":flags,"score":round(min(1,(.45 if black else 0)+(.3 if blur else 0)+(.25 if frozen else 0)),3)}
