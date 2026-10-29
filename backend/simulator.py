"""Dataset-backed alert replay. All generated IPs and response actions are simulated."""
import random, threading, time
from pathlib import Path
import numpy as np
import pandas as pd
from joblib import load
from backend.db import add_alert
from backend.risk import risk_score, risk_band

ROOT=Path(__file__).resolve().parents[1]
MODEL_PATH=ROOT/"ml"/"model.joblib"
class Simulator:
    def __init__(self):
        self.model=load(MODEL_PATH) if MODEL_PATH.exists() else None
        self.rows=None; self.thread=None; self.running=False
    def samples(self):
        if self.rows is None:
            if self.model and "replay_rows" in self.model:
                self.rows=self.model["replay_rows"].copy()
                return self.rows
            paths=list((ROOT/"data").rglob("*.csv")); frames=[]
            for path in paths:
                try:
                    frame=pd.read_csv(path,encoding="latin1",low_memory=False)
                    frame.columns=[str(c).strip() for c in frame.columns]
                    if "Label" in frame:
                        frame["Label"]=frame["Label"].map(self.canonical)
                        frames.append(frame.sample(min(len(frame),2500),random_state=9))
                except Exception: continue
            self.rows=pd.concat(frames,ignore_index=True) if frames else pd.DataFrame()
        return self.rows
    @staticmethod
    def canonical(v):
        x=str(v).strip().lower()
        if x=="benign": return "BENIGN"
        if "portscan" in x: return "PortScan"
        if x.startswith("dos") or x=="ddos" or x=="heartbleed": return "DoS"
        if "patator" in x or "brute force" in x: return "BruteForce"
        if "web attack" in x or "xss" in x or "sql injection" in x: return "WebAttack"
        return v
    def _flow(self, row):
        if not self.model: raise RuntimeError("Model missing; run python ml/train.py")
        features=self.model["features"]
        values=pd.to_numeric(row.reindex(features),errors="coerce").replace([np.inf,-np.inf],np.nan)
        values=values.fillna(pd.Series(self.model["benign_median"]))
        x=values.to_frame().T.astype("float32")
        clf=self.model["classifier"]; probs=clf.predict_proba(x)[0]
        pred_idx=int(np.argmax(probs)); attack=str(clf.classes_[pred_idx]); confidence=float(probs[pred_idx])
        raw=float(self.model["anomaly"].decision_function(x)[0])
        anomaly=max(0.0,min(1.0,(0.12-raw)/0.24))
        score=risk_score(confidence,attack,anomaly)
        importance=clf.feature_importances_; median=pd.Series(self.model["benign_median"]); scale=pd.Series(self.model["benign_scale"]).replace(0,1)
        deviations=((values-median).abs()/scale).replace([np.inf,-np.inf],0).fillna(0).to_numpy()
        contribution=importance*deviations
        top=sorted([{"name":features[i],"contribution":round(float(contribution[i]),4)} for i in range(len(features))],key=lambda z:z["contribution"],reverse=True)[:5]
        if attack=="BENIGN" and anomaly<0.8: return None
        return {"src_ip":f"10.{random.randint(0,20)}.{random.randint(0,255)}.{random.randint(1,254)}",
          "dst_ip":f"192.168.{random.randint(0,20)}.{random.randint(1,254)}",
          "src_port":int(random.randint(1024,65535)),"dst_port":int(row.get(" Destination Port",row.get("Destination Port",443)) or 443),
          "protocol":"TCP","attack_type":attack,"confidence":confidence,"anomaly_score":anomaly,
          "risk_score":score,"risk_band":risk_band(score),"top_features":top}
    def one(self, attack_type=None):
        rows=self.samples()
        if rows.empty:return None
        if attack_type:
            matching=rows[rows["Label"]==attack_type]
            if matching.empty: raise ValueError(f"No dataset rows for {attack_type}")
            row=matching.sample(1).iloc[0]
        else: row=rows.sample(1).iloc[0]
        alert=self._flow(row)
        return add_alert(alert) if alert else None
    def burst_attack(self, attack_type="DoS", n=5):
        created=[]
        for _ in range(max(1,min(int(n),100))):
            aid=self.one(attack_type)
            if aid: created.append(aid)
        return created
    def start(self):
        if self.running:return
        self.running=True
        def loop():
            while self.running:
                try:self.one()
                except Exception as exc: print("Simulator:",exc)
                time.sleep(4)
        self.thread=threading.Thread(target=loop,daemon=True,name="soc-simulator"); self.thread.start()

simulator=Simulator()
