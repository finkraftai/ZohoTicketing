from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import google.auth
from google.oauth2.credentials import Credentials

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Database configuration/
DB_HOST = "ec2-65-1-12-129.ap-south-1.compute.amazonaws.com"
DB_NAME = "stag_airlines_db"
DB_USER = "airlinedb_user"
DB_PASS = "AVNS_SFBbzpFCBpvhgbI5M1T"

# Function to get database connection
def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    return conn

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    token = data.get('token')

    if not name or not email or not token:
        return jsonify({"error": "Name, email, and token are required"}), 400

    # Store user information and token in the database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO zoho_users (name, email, json_Token) VALUES (%s, %s, %s)",
            (name, email, token)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"message": "User added successfully"}), 201

if __name__ == '__main__':
    app.run(debug=True)
