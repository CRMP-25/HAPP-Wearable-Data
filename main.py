# main.py
from fastapi import FastAPI
from dotenv import load_dotenv
from pathlib import Path

# Load .env that sits next to main.py (important if you start uvicorn from another folder)
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

from fastapi.middleware.cors import CORSMiddleware
from fitbit import router as fitbit_router  # local file import

app = FastAPI()

# CORS: allow your file-server (127.0.0.1:5500)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "https://happ.instituteofanalytics.com",
    ],
    allow_origin_regex=r"http://(127\.0\.0\.1|localhost):\d+",

    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from os import getenv

@app.get("/__debug/env")
def debug_env():
    return {"FITBIT_REDIRECT_URL": getenv("FITBIT_REDIRECT_URL")}


app.include_router(fitbit_router)




# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["https://happ.instituteofanalytics.com", "http://127.0.0.1:5500"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )



# app = FastAPI()
# app.include_router(fitbit_router)
