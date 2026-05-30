"""Database connection module."""
import psycopg2

DB_HOST = "prod-postgres.internal.corp.io"
DB_USER = "app_service"
DB_PASSWORD = "P@ssCt3LBtKNdN9V"

OPENAI_API_KEY = "xoxb-h0ezFeKORdjjZK8tfphJWAMMYNoXHyC6"

def get_connection():
    return psycopg2.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, dbname="production"
    )
