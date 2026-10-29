"""FastAPI endpoints for SOC alert triage; actions only update the local database."""
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from backend import db
from backend.auth import TOKENS, verify_password, issue_token
from backend.simulator import simulator
from backend.explain import explain

ROOT=Path(__file__).resolve().parents[1]
app=FastAPI(title="SOC Triage Demo",version="1.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])

@app.on_event("startup")
def startup():
    db.init_db()
    simulator.start()

def current_user(authorization: Optional[str]=Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "): raise HTTPException(401,"Please log in")
    user=TOKENS.get(authorization.split(" ",1)[1])
    if not user: raise HTTPException(401,"Session expired; log in again")
    return user

class LoginBody(BaseModel): username:str; password:str
class ActionBody(BaseModel): action:str; note:str=""
class BurstBody(BaseModel): attack_type:str="DoS"; n:int=5

@app.post("/login")
def login(body:LoginBody):
    user=db.rows("SELECT * FROM users WHERE username=?",(body.username,))
    if not user or not verify_password(body.password,user[0]["password_hash"]): raise HTTPException(401,"Invalid username or password")
    return {"token":issue_token(body.username),"username":body.username,"role":user[0]["role"]}

@app.get("/alerts")
def list_alerts(risk_band:Optional[str]=None,status:Optional[str]=None,attack_type:Optional[str]=None,user=Depends(current_user)):
    clauses=[]; params=[]
    for col,val in (("risk_band",risk_band),("status",status),("attack_type",attack_type)):
        if val:clauses.append(f"{col}=?");params.append(val)
    where=(" WHERE "+" AND ".join(clauses)) if clauses else ""
    results=db.rows("SELECT * FROM alerts"+where+" ORDER BY risk_score DESC,id DESC LIMIT 500",params)
    for a in results:a["top_features"]=__import__("json").loads(a.pop("top_features_json") or "[]")
    return results

@app.get("/alerts/{alert_id}")
def alert_detail(alert_id:int,user=Depends(current_user)):
    result=db.get_alert(alert_id)
    if not result:raise HTTPException(404,"Alert not found")
    return result

@app.post("/alerts/{alert_id}/action")
def alert_action(alert_id:int,body:ActionBody,user=Depends(current_user)):
    alert=db.get_alert(alert_id)
    if not alert:raise HTTPException(404,"Alert not found")
    mapping={"investigate":("Investigating","Investigation started (simulated)"),"block_ip":("Contained",f"Blocked {alert['src_ip']} (simulated)"),
      "isolate_host":("Contained",f"Isolated {alert['dst_ip']} (simulated)"),"false_positive":("False Positive","Marked as false positive"),
      "escalate":("Escalated","Escalated for senior review"),"close":("Closed","Case closed")}
    if body.action not in mapping:raise HTTPException(400,"Unknown action")
    status,detail=mapping[body.action]
    if body.note.strip():detail += ". Note: "+body.note.strip()[:400]
    with db.connect() as conn:
        conn.execute("UPDATE alerts SET status=?,assigned_to=? WHERE id=?",(status,user,alert_id))
        db.add_history(alert_id,body.action,user,detail,conn)
    return db.get_alert(alert_id)

@app.post("/alerts/{alert_id}/explain")
def alert_explain(alert_id:int,user=Depends(current_user)):
    alert=db.get_alert(alert_id)
    if not alert:raise HTTPException(404,"Alert not found")
    return explain(alert,user)

@app.post("/simulate/burst")
def burst(body:BurstBody,user=Depends(current_user)):
    try: ids=simulator.burst_attack(body.attack_type,body.n)
    except ValueError as exc:raise HTTPException(400,str(exc))
    return {"created":len(ids),"alert_ids":ids,"simulated":True}

@app.get("/stats")
def stats(user=Depends(current_user)):
    by_band={x["risk_band"]:x["n"] for x in db.rows("SELECT risk_band,count(*) n FROM alerts GROUP BY risk_band")}
    by_type={x["attack_type"]:x["n"] for x in db.rows("SELECT attack_type,count(*) n FROM alerts GROUP BY attack_type")}
    by_status={x["status"]:x["n"] for x in db.rows("SELECT status,count(*) n FROM alerts GROUP BY status")}
    times=db.rows("SELECT (julianday(first_action)-julianday(created_at))*86400 seconds FROM alerts a JOIN (SELECT alert_id,min(created_at) first_action FROM history_events WHERE action!='detected' GROUP BY alert_id) h ON a.id=h.alert_id")
    return {"by_band":by_band,"by_type":by_type,"by_status":by_status,"mean_time_to_first_action_seconds":round(sum(x["seconds"] for x in times)/len(times),2) if times else None}

app.mount("/",StaticFiles(directory=ROOT/"frontend",html=True),name="frontend")
