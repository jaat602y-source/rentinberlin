# rent_site/config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///rent.db")
    DEBUG = os.getenv("DEBUG", "1") == "1"
