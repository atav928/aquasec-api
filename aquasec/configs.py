"""Configurations"""
import os

class Config:
    API_KEY = os.getenv("AQUA_API_KEY", "")
    API_SECRET = os.getenv("AQUA_API_SECRET", "")
    API_URL =  "https://api.cloudsploit.com/v2"
    