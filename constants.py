import os

from flask.cli import load_dotenv

load_dotenv('secrets')
# BASE_URL = 'http://127.0.0.1:8000/api'
# ROOT_URL = 'http://127.0.0.1:8000'


ROOT_URL = 'http://35.154.190.245:8000'
BASE_URL = 'http://35.154.190.245:8000/api'

GEMINI_APIKEY = os.getenv("GOOGLE_GEMINI_APIKEY")





