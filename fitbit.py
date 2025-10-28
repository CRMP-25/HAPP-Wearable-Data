# server/fitbit.py
import base64, os, time, json, secrets, hashlib
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Request, HTTPException, Depends, Response
from fastapi.responses import RedirectResponse, JSONResponse
import httpx
from supabase import create_client, Client
from cryptography.fernet import Fernet   # simple at-rest encryption
# add at the top of the file:
from urllib.parse import quote
from fastapi.responses import PlainTextResponse
import traceback

router = APIRouter()
SUPABASE: Client = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE"])
ENC = Fernet(base64.urlsafe_b64encode(os.environ["APP_ENCRYPTION_KEY"].encode()[:32]))  # 32 bytes

FITBIT_CLIENT_ID     = os.environ["FITBIT_CLIENT_ID"]
FITBIT_CLIENT_SECRET = os.environ["FITBIT_CLIENT_SECRET"]
FITBIT_REDIRECT_URL  = os.environ["FITBIT_REDIRECT_URL"]
print("USING FITBIT_REDIRECT_URL =", FITBIT_REDIRECT_URL)

FITBIT_AUTH_URL  = "https://www.fitbit.com/oauth2/authorize"
FITBIT_TOKEN_URL = "https://api.fitbit.com/oauth2/token"
FITBIT_API_BASE  = "https://api.fitbit.com"

def enc(s: str) -> str: return ENC.encrypt(s.encode()).decode()
def dec(s: str) -> str: return ENC.decrypt(s.encode()).decode()

def make_pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge

@router.get("/auth/fitbit/start")
async def fitbit_start(user_id: str | None = None, response: Response = None):
    if not user_id:
        # if FE forgets to pass it, fail loudly so you see it fast
        return PlainTextResponse("Missing user_id", status_code=400)

    code_verifier, code_challenge = make_pkce()
    state = secrets.token_urlsafe(24) + f".{user_id}"

    # URL-encode the redirect before adding to the query string
    ru = quote(FITBIT_REDIRECT_URL, safe="")

    url = (
        f"{FITBIT_AUTH_URL}"
        f"?response_type=code"
        f"&client_id={FITBIT_CLIENT_ID}"
        f"&redirect_uri={ru}"                       # <— encoded
        f"&scope=activity%20heartrate%20sleep%20profile"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&state={state}"
    )

    response = RedirectResponse(url=url, status_code=302)
    response.set_cookie(
        "fitbit_pkce",
        json.dumps({"v": code_verifier, "s": state}),
        max_age=600,
        httponly=True,
        secure=False,      # ok for http://127.0.0.1
        samesite="lax"     # 🔒 explicitly allow top-level redirect back from Fitbit
    )

    return response


# @router.get("/auth/fitbit/callback")
# async def fitbit_cb(request: Request, code: str, state: str):
#     # read and validate cookie
#     cookie = request.cookies.get("fitbit_pkce")
#     if not cookie:
#         raise HTTPException(400, "missing pkce cookie")
#     pk = json.loads(cookie)
#     if pk.get("s") != state:
#         raise HTTPException(400, "state mismatch")
#     # extract user_id we encoded into state
#     try:
#         user_id = state.split(".")[-1]
#     except:
#         raise HTTPException(400, "bad state")

#     # exchange code for tokens
#     basic = base64.b64encode(f"{FITBIT_CLIENT_ID}:{FITBIT_CLIENT_SECRET}".encode()).decode()
#     data = {
#         "client_id": FITBIT_CLIENT_ID,
#         "grant_type": "authorization_code",
#         "redirect_uri": FITBIT_REDIRECT_URL,
#         "code": code,
#         "code_verifier": pk["v"],
#     }
#     async with httpx.AsyncClient() as x:
#         r = await x.post(FITBIT_TOKEN_URL, data=data, headers={"Authorization": f"Basic {basic}"})
#     if r.status_code != 200:
#         raise HTTPException(400, f"token exchange failed: {r.text}")
#     tok = r.json()
#     access_token  = tok["access_token"]
#     refresh_token = tok["refresh_token"]
#     expires_in    = int(tok.get("expires_in", 28800))
#     scope         = tok.get("scope")
#     # fitbit user id (encoded id)
#     fitbit_user_id = tok.get("user_id") or tok.get("encoded_user_id")

#     # upsert connection
#     expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
#     payload = {
#         "user_id": user_id, "provider": "fitbit",
#         "provider_user_id": fitbit_user_id,
#         "access_token": enc(access_token),
#         "refresh_token": enc(refresh_token),
#         "expires_at": expires_at.isoformat(),
#         "scope": scope,
#         "updated_at": datetime.now(timezone.utc).isoformat()
#     }
#     SUPABASE.table("wearable_connections").upsert(payload, on_conflict="user_id,provider").execute()

#     # small UX: bounce back to your dashboard
#     # Production
#     # return RedirectResponse("/H37/dashboard.html?fitbit=connected", status_code=302)
#     return RedirectResponse("http://127.0.0.1:5500/H37/dashboard.html?fitbit=connected", status_code=302)



@router.get("/auth/fitbit/callback")
async def fitbit_cb(request: Request, code: str, state: str):
    try:
        # --- validate PKCE cookie/state ---
        cookie = request.cookies.get("fitbit_pkce")
        if not cookie:
            return PlainTextResponse("OAuth error: missing PKCE cookie from /auth/fitbit/start", status_code=400)
        pk = json.loads(cookie)
        if pk.get("s") != state:
            return PlainTextResponse("OAuth error: state mismatch", status_code=400)

        # extract user_id we encoded into state ("<random>.<user_id>")
        try:
            user_id = state.split(".")[-1]
        except Exception:
            return PlainTextResponse("OAuth error: bad state format (no user_id)", status_code=400)

        # --- exchange code for tokens ---
        basic = base64.b64encode(f"{FITBIT_CLIENT_ID}:{FITBIT_CLIENT_SECRET}".encode()).decode()
        data = {
            "client_id": FITBIT_CLIENT_ID,
            "grant_type": "authorization_code",
            "redirect_uri": FITBIT_REDIRECT_URL,   # must match exactly
            "code": code,
            "code_verifier": pk["v"],
        }
        async with httpx.AsyncClient() as x:
            r = await x.post(FITBIT_TOKEN_URL, data=data, headers={"Authorization": f"Basic {basic}"})

        if r.status_code != 200:
            # Show Fitbit’s exact error text so we can see what's wrong
            return PlainTextResponse(f"Token exchange failed {r.status_code}:\n{r.text}", status_code=400)

        tok = r.json()
        access_token  = tok["access_token"]
        refresh_token = tok["refresh_token"]
        expires_in    = int(tok.get("expires_in", 28800))
        scope         = tok.get("scope")
        fitbit_user_id = tok.get("user_id") or tok.get("encoded_user_id")

        # --- upsert connection in Supabase ---
        try:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            payload = {
                "user_id": user_id, "provider": "fitbit",
                "provider_user_id": fitbit_user_id,
                "access_token": enc(access_token),
                "refresh_token": enc(refresh_token),
                "expires_at": expires_at.isoformat(),
                "scope": scope,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            SUPABASE.table("wearable_connections").upsert(
                payload, on_conflict="user_id,provider"
            ).execute()
        except Exception as db_err:
            # Most common cause: table/columns don’t exist, or RLS blocks insert
            tb = traceback.format_exc()
            return PlainTextResponse(
                "Database error while saving Fitbit tokens:\n"
                f"{db_err}\n\n{tb}",
                status_code=500
            )

        # --- success: go back to your UI ---
       
        # return RedirectResponse(
        #     "http://127.0.0.1:5500/H37/dashboard.html?targetTab=tab-wearable&autoSync=1",
        #     status_code=302
        # )
        # return RedirectResponse(
        #     "http://127.0.0.1:5500/H37/dashboard.html?targetTab=tab-wearable&autoSync=1&provider=fitbit",
        #     status_code=302
        # )

        resp = RedirectResponse(
            "http://127.0.0.1:5500/HAPP-wearable-google-fit-pixel-V43/H43/dashboard.html?targetTab=tab-wearable&autoSync=1&provider=fitbit",
            status_code=302
        )
        # 🚿 clear the one-time PKCE cookie so it can’t clash later
        resp.delete_cookie("fitbit_pkce")
        return resp


    except Exception as e:
        tb = traceback.format_exc()
        return PlainTextResponse(f"Unhandled error in callback:\n{e}\n\n{tb}", status_code=500)


async def get_fitbit_tokens(user_id: str):
    # read row
    res = SUPABASE.table("wearable_connections").select("*").eq("user_id", user_id).eq("provider", "fitbit").single().execute()
    row = (res.data or {})
    if not row:
        raise HTTPException(404, "no fitbit connection")
    access = dec(row["access_token"])
    refresh = dec(row["refresh_token"])
    exp = datetime.fromisoformat(row["expires_at"].replace("Z","")).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) < exp - timedelta(seconds=60):
        return access, refresh

    # refresh
    basic = base64.b64encode(f"{FITBIT_CLIENT_ID}:{FITBIT_CLIENT_SECRET}".encode()).decode()
    async with httpx.AsyncClient() as x:
        r = await x.post(FITBIT_TOKEN_URL,
                         data={"grant_type":"refresh_token","refresh_token":refresh},
                         headers={"Authorization": f"Basic {basic}"})
    if r.status_code != 200:
        raise HTTPException(401, f"token refresh failed: {r.text}")
    tok = r.json()
    access = tok["access_token"]; refresh = tok["refresh_token"]
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(tok.get("expires_in", 28800)))
    SUPABASE.table("wearable_connections").update({
        "access_token": enc(access), "refresh_token": enc(refresh),
        "expires_at": expires_at.isoformat(), "updated_at": datetime.now(timezone.utc).isoformat()
    }).eq("user_id", user_id).eq("provider", "fitbit").execute()
    return access, refresh

# --- public status used by the UI label
@router.get("/api/wearables/status")
async def status(req: Request):
    # if you use Supabase Auth JWT on the request, extract user_id; else pass ?user_id=...
    user_id = req.query_params.get("user_id")
    if not user_id:
        return JSONResponse({"fitbit": {"connected": False}})
    res = SUPABASE.table("wearable_connections").select("last_sync_at, expires_at").eq("user_id", user_id).eq("provider","fitbit").execute()
    rows = res.data or []
    connected = len(rows) > 0
    last = rows[0]["last_sync_at"] if connected else None
    return JSONResponse({"fitbit": {"connected": connected, "lastSync": last}})

# --- daily sync: write into wearable_data (preserve manual fields)
@router.post("/sync/fitbit/daily")
async def sync_fitbit_day(payload: dict):
    """
    payload = {"user_id":"...", "date":"YYYY-MM-DD"}
    """
    user_id = payload["user_id"]
    day = payload["date"]
    
    print(f"\n{'='*60}")
    print(f"🔄 SYNCING FITBIT DATA FOR USER: {user_id}, DATE: {day}")
    print(f"{'='*60}")
    
    access, _ = await get_fitbit_tokens(user_id)

    # 1) Fetch activities, sleep, and heart rate
    async with httpx.AsyncClient() as x:
        act = await x.get(
            f"{FITBIT_API_BASE}/1/user/-/activities/date/{day}.json",
            headers={"Authorization": f"Bearer {access}"}
        )
        slp = await x.get(
            f"{FITBIT_API_BASE}/1.2/user/-/sleep/date/{day}.json",
            headers={"Authorization": f"Bearer {access}"}
        )
        hr = await x.get(
            f"{FITBIT_API_BASE}/1/user/-/activities/heart/date/{day}/1d.json",
            headers={"Authorization": f"Bearer {access}"}
        )
    
    # Check if activities API call succeeded
    # if act.status_code != 200:
    #     print(f"❌ Activities API failed: {act.status_code} - {act.text}")
    #     raise HTTPException(400, f"Fitbit API error: {act.text}")
    if act.status_code != 200:
        print(f"❌ Activities API failed: {act.status_code} - {act.text}")
        raise HTTPException(status_code=act.status_code, detail=f"Fitbit API error: {act.text}")
    
    act_data = act.json()
    print(f"\n📊 RAW FITBIT RESPONSE:")
    print(f"Full response: {json.dumps(act_data, indent=2)}")
    
    # Extract steps (ensure it's an integer)
    summary = act_data.get("summary", {})
    steps = summary.get("steps", 0)
    
    # Ensure steps is an integer
    if isinstance(steps, str):
        steps = int(steps) if steps.isdigit() else 0
    elif steps is None:
        steps = 0
    else:
        steps = int(steps)
    
    print(f"👣 Extracted steps: {steps}")
    
    # Extract distance (convert to km if needed)
    distance_km = 0.0
    distances = summary.get("distances", [])
    
    for d in distances:
        if d.get("activity") == "total":
            dist_value = float(d.get("distance", 0))
            distance_km = round(dist_value, 2)
            print(f"📏 Extracted distance: {distance_km} km")
            break
    
    # Extract calories
    calories = summary.get("caloriesOut")
    if calories:
        calories = int(float(calories))
    print(f"🔥 Extracted calories: {calories}")
    
    # Extract sleep data
    sleep_minutes = None
    if slp.status_code == 200:
        slp_data = slp.json()
        print(f"\n😴 Sleep API response: {json.dumps(slp_data.get('summary', {}), indent=2)}")
        totals = slp_data.get("summary", {}).get("totalMinutesAsleep")
        if totals is not None:
            sleep_minutes = int(totals)
            print(f"😴 Extracted sleep: {sleep_minutes} minutes")
    
    # Extract heart rate data
    hr_avg = hr_min = hr_max = None
    if hr.status_code == 200:
        hr_data = hr.json()
        print(f"\n❤️ Heart rate API response: {json.dumps(hr_data, indent=2)}")
        
        activities_heart = hr_data.get("activities-heart", [])
        if activities_heart:
            value = activities_heart[0].get("value", {})
            hr_avg = value.get("restingHeartRate")
            
            # Try to get min/max from heart rate zones
            zones = value.get("heartRateZones", [])
            if zones:
                # Extract min/max from zones (approximation)
                all_mins = [z.get("min", 0) for z in zones if z.get("min")]
                all_maxs = [z.get("max", 0) for z in zones if z.get("max")]
                if all_mins:
                    hr_min = min(all_mins)
                if all_maxs:
                    hr_max = max(all_maxs)
            
            print(f"❤️ Extracted HR - Avg: {hr_avg}, Min: {hr_min}, Max: {hr_max}")
    
    # 2) Fetch existing manual data to preserve
    exist = SUPABASE.table("wearable_data").select("""
        bp_sys, bp_dia, oxygen_level, oxygen_min, oxygen_max, oxygen_avg,
        stress_level, stress_score, nutrition_kcal, nutrition_protein_g, 
        nutrition_carbs_g, nutrition_fat_g, workout_name, workout_duration_min,
        workout_distance_km, workout_calories
    """).eq("user_id", user_id).eq("date", day).eq("source", "fitbit").execute()
    
    ex = exist.data[0] if exist.data else {}
    
    # 3) Build upsert payload
    up = {
        "user_id": user_id,
        "date": day,
        "steps": steps,  # ✅ Now correctly extracted
        "distance": distance_km,
        "calories": calories,
        "sleep_minutes": sleep_minutes,
        "heart_rate_avg": hr_avg,
        "heart_rate_min": hr_min,
        "heart_rate_max": hr_max,
        # Preserve manual fields
        "bp_sys": ex.get("bp_sys"),
        "bp_dia": ex.get("bp_dia"),
        "oxygen_level": ex.get("oxygen_level"),
        "oxygen_min": ex.get("oxygen_min"),
        "oxygen_max": ex.get("oxygen_max"),
        "oxygen_avg": ex.get("oxygen_avg"),
        "stress_level": ex.get("stress_level"),
        "stress_score": ex.get("stress_score"),
        "nutrition_kcal": ex.get("nutrition_kcal"),
        "nutrition_protein_g": ex.get("nutrition_protein_g"),
        "nutrition_carbs_g": ex.get("nutrition_carbs_g"),
        "nutrition_fat_g": ex.get("nutrition_fat_g"),
        "workout_name": ex.get("workout_name"),
        "workout_duration_min": ex.get("workout_duration_min"),
        "workout_distance_km": ex.get("workout_distance_km"),
        "workout_calories": ex.get("workout_calories"),
        "source": "fitbit",
        "synced_at": datetime.now(timezone.utc).isoformat()
    }
    
    print(f"\n💾 UPSERT PAYLOAD:")
    print(f"Steps: {up['steps']}, Distance: {up['distance']}, Calories: {up['calories']}")
    print(f"Sleep: {up['sleep_minutes']} min, HR: {up['heart_rate_avg']}")
    
    # Upsert to database
    result = SUPABASE.table("wearable_data").upsert(
        up, on_conflict="user_id,date,source"
    ).execute()
    
    print(f"✅ Database upsert complete for {day}")
    print(f"{'='*60}\n")
    
    # Update last sync timestamp
    SUPABASE.table("wearable_connections").update({
        "last_sync_at": datetime.now(timezone.utc).isoformat()
    }).eq("user_id", user_id).eq("provider", "fitbit").execute()
    
    return {"ok": True, "date": day, "steps": steps, "calories": calories}