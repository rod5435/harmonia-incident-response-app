import os
from dotenv import load_dotenv
load_dotenv()

BASEDIR = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASEDIR, 'incident_response.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', 'your_openai_api_key_here')
