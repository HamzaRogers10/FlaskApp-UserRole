import os
from pathlib import Path

from dotenv import load_dotenv

# handy to have - makes referencing files on local system easier
basedir = Path(__file__).parent
load_dotenv(basedir / '.env')


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
