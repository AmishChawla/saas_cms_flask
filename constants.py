import os
from flask.cli import load_dotenv


# MY ROOT URL
MY_ROOT_URL = 'http://127.0.0.1:5000/'
# MY_ROOT_URL = 'http://35.154.190.245:5000/'



# FOR API
BASE_URL = 'http://127.0.0.1:8000/api'
ROOT_URL = 'http://127.0.0.1:8000'

# ROOT_URL = 'http://35.154.190.245:8000'
# BASE_URL = 'http://35.154.190.245:8000/api'



load_dotenv('secrets')


GEMINI_APIKEY = os.getenv("GOOGLE_GEMINI_APIKEY")





