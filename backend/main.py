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
from backend.organization import ORGANIZATION, SCENARIOS, recent_events, run_drill
from backend.explain import explain
from backend.firewall import settings as firewall_settings, block_ip as add_firewall_block, unblock_ip as remove_firewall_block
from backend.live_monitor import live_monitor

ROOT=Path(__file__).resolve().parents[1]
app=FastAPI(title="SOC Triage Demo",version="1.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])

@app.on_event("startup")
def startup():
    db.init_db()
    if firewall_settings()["mode"] == "live":
        live_monitor.start()

def current_user(authorization: Optional[str]=Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "): raise HTTPException(401,"Please log in")
    user=TOKENS.get(authorization.split(" ",1)[1])
    if not user: raise HTTPException(401,"Session expired; log in again")
    return user

class LoginBody(BaseModel): username:str; password:str
class ActionBody(BaseModel): action:str; note:str=""
class BurstBody(BaseModel): attack_type:str="DoS"; n:int=5
class OrganizationDrillBody(BaseModel): scenario:str

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
    mapping={"investigate":("Investigating","Investigation started (simulated)"),
      "isolate_host":("Contained",f"Isolated {alert['dst_ip']} (simulated)"),"false_positive":("False Positive","Marked as false positive"),
      "escalate":("Escalated","Escalated for senior review"),"close":("Closed","Case closed")}
    cfg = firewall_settings()
    if body.action == "block_ip":
        if cfg["mode"] == "live" and not cfg["real_blocking_enabled"]:
            raise HTTPException(409,"Real blocking is disabled. Set ENABLE_REAL_BLOCKING=true and restart the app as Administrator.")
        if cfg["mode"] == "live":
            if alert.get("source") != "windows-firewall-log":
                raise HTTPException(409,"Only alerts created from live Windows Firewall logs can be blocked in live mode.")
            user_row = db.rows("SELECT role FROM users WHERE username=?", (user,))
            if not user_row or user_row[0]["role"] != "admin":
                raise HTTPException(403,"Sign in with the admin account to add real Windows Firewall rules.")
            try:
                group = add_firewall_block(alert["src_ip"], alert_id)
            except (ValueError, RuntimeError, OSError) as exc:
                db.add_history(alert_id,"block_ip_failed",user,str(exc)[:400])
                raise HTTPException(503,f"Windows Firewall rule was not added: {exc}")
            mapping["block_ip"]=("Contained",f"Blocked {alert['src_ip']} in Windows Firewall (inbound and outbound rule group: {group})")
        else:
            mapping["block_ip"]=("Contained",f"Blocked {alert['src_ip']} (simulated)")
    if body.action == "unblock_ip":
        if cfg["mode"] != "live" or not cfg["real_blocking_enabled"]:
            raise HTTPException(409,"Unblocking requires live mode and ENABLE_REAL_BLOCKING=true.")
        if alert.get("source") != "windows-firewall-log":
            raise HTTPException(409,"Only live Windows Firewall alerts have removable firewall rules.")
        user_row = db.rows("SELECT role FROM users WHERE username=?", (user,))
        if not user_row or user_row[0]["role"] != "admin":
            raise HTTPException(403,"Sign in with the admin account to remove Windows Firewall rules.")
        try:
            group = remove_firewall_block(alert_id)
        except (RuntimeError, OSError) as exc:
            db.add_history(alert_id,"unblock_ip_failed",user,str(exc)[:400])
            raise HTTPException(503,f"Windows Firewall rule was not removed: {exc}")
        mapping["unblock_ip"]=("Investigating",f"Removed Windows Firewall block rules for {alert['src_ip']} ({group})")
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
    if firewall_settings()["mode"] == "live":
        raise HTTPException(409,"Dataset burst simulation is unavailable in live mode.")
    try: ids=simulator.burst_attack(body.attack_type,body.n)
    except ValueError as exc:raise HTTPException(400,str(exc))
    return {"created":len(ids),"alert_ids":ids,"simulated":True}

@app.get("/organization")
def organization(user=Depends(current_user)):
    return {**ORGANIZATION,
            "scenarios":[{"id":key,"label":value["label"],"summary":value["summary"]} for key,value in SCENARIOS.items()],
            "recent_events":recent_events(40)}

@app.post("/organization/drill")
def organization_drill(body:OrganizationDrillBody,user=Depends(current_user)):
    try:
        result=run_drill(body.scenario)
    except ValueError as exc:
        raise HTTPException(400,str(exc))
    return {**result,"simulated":True,"organization":ORGANIZATION["name"]}

@app.get("/stats")
def stats(user=Depends(current_user)):
    by_band={x["risk_band"]:x["n"] for x in db.rows("SELECT risk_band,count(*) n FROM alerts GROUP BY risk_band")}
    by_type={x["attack_type"]:x["n"] for x in db.rows("SELECT attack_type,count(*) n FROM alerts GROUP BY attack_type")}
    by_status={x["status"]:x["n"] for x in db.rows("SELECT status,count(*) n FROM alerts GROUP BY status")}
    times=db.rows("SELECT (julianday(first_action)-julianday(created_at))*86400 seconds FROM alerts a JOIN (SELECT alert_id,min(created_at) first_action FROM history_events WHERE action!='detected' GROUP BY alert_id) h ON a.id=h.alert_id")
    return {"by_band":by_band,"by_type":by_type,"by_status":by_status,"mean_time_to_first_action_seconds":round(sum(x["seconds"] for x in times)/len(times),2) if times else None}

@app.get("/config")
def config(user=Depends(current_user)):
    cfg = firewall_settings()
    user_row = db.rows("SELECT role FROM users WHERE username=?", (user,))
    return {**cfg, "role": user_row[0]["role"] if user_row else "analyst",
            "real_blocking_available": cfg["mode"] == "live" and cfg["real_blocking_enabled"]}

app.mount("/",StaticFiles(directory=ROOT/"frontend"/"dist",html=True),name="frontend")
