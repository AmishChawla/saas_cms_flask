import os
from flask.cli import load_dotenv


# MY ROOT URL
# MY_ROOT_URL = 'http://127.0.0.1:5000'
MY_ROOT_URL = 'http://35.154.190.245:5000'



# FOR API
BASE_URL = 'http://127.0.0.1:8000/api'
ROOT_URL = 'http://127.0.0.1:8000'

# ROOT_URL = 'http://35.154.190.245:8000'
# BASE_URL = 'http://35.154.190.245:8000/api'




load_dotenv('secrets.env')


GEMINI_APIKEY = os.getenv("GOOGLE_GEMINI_APIKEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = 'http://127.0.0.1:5000/callback'
AUTHORIZATION_BASE_URL = 'https://accounts.google.com/o/oauth2/auth'
TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'





