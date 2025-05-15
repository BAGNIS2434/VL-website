import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Set base directory
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Instance path configuration
    INSTANCE_PATH = os.path.join(BASE_DIR, 'instance')
    if not os.path.exists(INSTANCE_PATH):
        os.makedirs(INSTANCE_PATH, exist_ok=True)
    
    # Database configuration
    DB_PATH = os.path.join(INSTANCE_PATH, "database.db")
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DB_PATH}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    
    # JWT and application secret keys
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev-jwt-key')
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')

    # JWT configuration
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_ACCESS_COOKIE_NAME = 'access_token_cookie'
    JWT_COOKIE_CSRF_PROTECT = False
    JWT_ACCESS_TOKEN_EXPIRES = 86400  # 24 hours
    JWT_COOKIE_SECURE = False  # Set to True in production
    JWT_COOKIE_SAMESITE = 'Lax'
    JWT_ACCESS_COOKIE_PATH = '/'
    JWT_REFRESH_COOKIE_PATH = '/'
    JWT_REFRESH_TOKEN_EXPIRES = 2592000  # 30 days
    JWT_COOKIE_DOMAIN = None
    JWT_JSON_KEY = 'access_token'  # Add this
    JWT_IDENTITY_CLAIM = 'sub'     # Add this
    JWT_ACCESS_CSRF_HEADER_NAME = 'X-CSRF-TOKEN'  # Add this
    JWT_ACCESS_TOKEN_EXPIRES_REFRESH = False  # Add this

    # Mail settings
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')
    MAIL_MAX_EMAILS = None
    MAIL_ASCII_ATTACHMENTS = False

    # Debug mode (set to False in production)
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'