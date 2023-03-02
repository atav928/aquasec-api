"""Configurations"""
import os

class Config:
    API_KEY = os.getenv("AQUA_API_KEY", "")
    _API_SECRET = os.getenv("AQUA_API_SECRET", "")
    API_URL =  "https://api.cloudsploit.com/v2"
    API_VERSION = os.getenv("AQUA_API_VERSION", 'v2')
