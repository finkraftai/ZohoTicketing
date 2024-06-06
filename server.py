from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

app = Flask(__name__)

# Database configuration
DB_HOST = "ec2-65-1-12-129.ap-south-1.compute.amazonaws.com"
DB_NAME = "stag_airlines_db"
DB_USER = "airlinedb_user"
DB_PASS = "AVNS_SFBbzpFCBpvhgbI5M1T"

# Google API scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# Function to get database connection
def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    return conn

# Function to get Gmail API credentials
def get_gmail_creds():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "C:/Users/annav/Desktop/zohoTicketing/clientsecret.json", SCOPES
            )
            creds = flow.run_local_server(port=54543)
            # Save the credentials for the next run
            with open("token.json", "w") as token:
                token.write(creds.to_json())
    return creds

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')

    if not name or not email:
        return jsonify({"error": "Name and email are required"}), 400

    # Get Gmail credentials and token
    try:
        creds = get_gmail_creds()
        token_json = creds.to_json()
    except Exception as e:
        return jsonify({"error": f"Failed to get Gmail credentials: {str(e)}"}), 500

    # Store user information and token in the database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO zoho_users (name, email, json_Token) VALUES (%s, %s, %s)",
            (name, email, token_json)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"message": "User added successfully"}), 201

if __name__ == '__main__':
    app.run(debug=True)
