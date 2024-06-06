# File: gmail_ticket_label_manager.py

import os
import time
import base64
from typing import Any, Dict, List
import psycopg2
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import threading
import re

# Define the scopes and database configuration
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
DATABASE_CONFIG = {
    'user': "airlinedb_user",
    'password': "AVNS_SFBbzpFCBpvhgbI5M1T",
    'host': "ec2-65-1-12-129.ap-south-1.compute.amazonaws.com",
    'port': '5432',
    'database': "stag_airlines_db"
}
LABELS = ["open", "close", "onhold"]

# List of users with their respective credential files
USERS = [
    # {'name': 'Punit', 'credentials': 'token.json', 'email': 'punit@kgrp.in'},
    {'name': 'hari', 'credentials': 'hari.json', 'email': 'harinarayananpari@gmail.com'}

]

# Functions for Gmail API and database operations

def get_gmail_service(creds):
    return build("gmail", "v1", credentials=creds)

def get_credentials(credentials_file):
    creds = None
    if os.path.exists(credentials_file):
        creds = Credentials.from_authorized_user_file(credentials_file, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open(credentials_file, "w") as token:
            token.write(creds.to_json())
    return creds

def parse_email_timestamp(timestamp: str) -> str:
    # Parse the email timestamp to a datetime object
    dt = datetime.strptime(timestamp, '%a, %d %b %Y %H:%M:%S %z')
    # Convert to a format that PostgreSQL can understand
    return dt.strftime('%Y-%m-%d %H:%M:%S%z')

def decode_base64(data):
    if not data:
        return ""
    data = data.replace("-", "+").replace("_", "/")
    return base64.urlsafe_b64decode(data).decode('utf-8')

def get_text(payload, service, msg_id, user_id):
    decoded_parts = set()
    body = ''
    def decode_part(part_body):
        decoded_data = decode_base64(part_body['data'])
        if decoded_data not in decoded_parts:
            decoded_parts.add(decoded_data)
            return decoded_data + "\n"
        return ""
    if payload.get('parts'):
        for part in payload['parts']:
            mimeType = part['mimeType']
            part_body = part['body']
            if mimeType == 'text/plain' and 'data' in part_body:
                body += decode_part(part_body)
            elif 'parts' in part:
                body += get_text(part, service, msg_id, user_id)
    else:
        if payload['body'].get('data'):
            body += decode_part(payload['body'])
    return body.strip()

def extract_message_details(headers: List[Dict[str, str]], user_email: str) -> Dict[str, str]:
    details = {'to': '', 'from': '', 'cc': '', 'bcc': '', 'subject': '', 'date': '', 'other_recipent': '', 'message_id': ''}
    for d in headers:
        name = d["name"].lower()
        if name in details:
            details[name] = d["value"]
        elif name == "message-id":
            details["message_id"] = d["value"]

    # Split the 'to', 'cc', and 'bcc' fields and determine the appropriate 'to' and 'other_recipent'
    to_list = re.split(r',\s*', details['to'])
    cc_list = re.split(r',\s*', details['cc'])
    bcc_list = re.split(r',\s*', details['bcc'])

    all_recipients = to_list + cc_list + bcc_list

    # Clean up email addresses and extract them from names if present
    cleaned_recipients = [re.findall(r'<([^>]+)>', addr)[0] if '<' in addr else addr for addr in all_recipients]

    to_address = [addr for addr in cleaned_recipients if user_email in addr]
    other_recipents = [addr for addr in cleaned_recipients if user_email not in addr]

    # If user's email is not in the list, assign the first email to 'to' and rest to 'other_recipent'
    if not to_address and cleaned_recipients:
        to_address = [cleaned_recipients[0]]
        other_recipents = cleaned_recipients[1:]

    details['to'] = ', '.join(to_address)
    details['other_recipent'] = ', '.join(other_recipents)

    return details


def extract_text_from_html(body, service, msg_id, user_id):
    if 'data' in body:
        decoded_data = decode_base64(body['data'])
    else:
        att_id = body['attachmentId']
        att = service.users().messages().attachments().get(userId=user_id, messageId=msg_id, id=att_id).execute()
        decoded_data = decode_base64(att['data'])
    soup = BeautifulSoup(decoded_data, "lxml")
    return soup.get_text()

def insert_into_table(to_address, from_address, subject, time, body, attachment_count, other_recipent, message_id):
    try:
        connection = psycopg2.connect(**DATABASE_CONFIG)
        cursor = connection.cursor()

        select_query = """
            SELECT COUNT(*) FROM zoho_task_tracker
            WHERE message_id = %s
        """
        if not subject:
            subject = "No subject"

        # Execute the select query
        cursor.execute(select_query, (message_id,))
        count = cursor.fetchone()[0]

        # If count is 0, that means this is not a duplicate entry
        if count == 0:
            insert_query = '''
                INSERT INTO zoho_task_tracker (
                    to_address, from_address, subject, time, body, attachment_count, other_recipent, message_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            '''
            # Extracting the email address from the 'to_address' field if it contains both name and email
            to_address = re.findall(r'<([^>]+)>', to_address)[0] if '<' in to_address else to_address
            # Parse the email timestamp
            time = parse_email_timestamp(time)
            cursor.execute(insert_query, (to_address, from_address, subject, time, body, attachment_count, other_recipent, message_id))
            connection.commit()
        else:
            print(f"Duplicate entry found. Skipping {from_address} - {to_address} - {subject} - {time} - {message_id}")
    except (Exception, psycopg2.Error) as error:
        print("Error while inserting data into PostgreSQL:", error)
    finally:
        if connection:
            cursor.close()
            connection.close()

def process_messages(service: Any, messages: List[Dict[str, Any]], user_email: str) -> None:
    for message in messages:
        msg = service.users().messages().get(userId="me", id=message["id"]).execute()
        # print("resp:", msg)
        payload = msg["payload"]
        headers = payload["headers"]
        details = extract_message_details(headers, user_email)
        body = get_text(payload, service, message["id"], "me")
        attachment_count = sum(1 for part in payload.get("parts", []) if part["filename"]) if 'parts' in payload else 0
        print(f"Storing in database -> To: {details['to']}, From: {details['from']}, Subject: {details['subject']}, Date: {details['date']}, Attachment Count: {attachment_count}, Other Recipient: {details['other_recipent']}, Message-ID: {details['message_id']}")
        insert_into_table(
            details['to'], details['from'], details['subject'], details['date'],
            body, attachment_count, details['other_recipent'], details['message_id']
        )
        print_message(details, body, attachment_count)

def print_message(details, body, attachment_count):
    print(f"--- MESSAGE START ---")
    print("To:", details['to'])
    print("From:", details['from'])
    print("cc & bcc:", details['other_recipent'])
    print("Subject:", details['subject'])
    print("Date:", details['date'])
    print("Attachment Count:", attachment_count)
    print("Body:", body)
    print(f"--- MESSAGE END ---\n\n")

# Update the continuous fetch function to use main_fetch_emails
def continuously_fetch_emails() -> None:
    # Check if timestamp.txt file exists and has content
    if os.path.isfile('timestamp.txt') and os.path.getsize('timestamp.txt') > 0:
        with open("timestamp.txt", "r") as file:
            last_fetch_time = datetime.fromisoformat(file.readline().strip())
    else:
        last_fetch_time = datetime.now() - timedelta(days=1)
    while True:
        print(f"Fetching emails at {last_fetch_time.strftime('%Y-%m-%d %H:%M:%S')}")
        messages_fetched = False
        for user in USERS:
            creds = get_credentials(user['credentials'])
            messages_fetched_user = main_fetch_emails(creds, user['email'], last_fetch_time)
            print(f"--- Fetch email for {user['name']} ---")
            if messages_fetched_user:
                messages_fetched = True
            if messages_fetched:
                main_create_tickets(user['email'])
                print(f"--- Create tickets for {user['name']} ---")
                main_apply_labels(creds, user['email'])
                print(f"--- Apply label for {user['name']} ---")
        if messages_fetched:
            last_fetch_time = datetime.now()
            with open("timestamp.txt", "w") as file:
                file.write(last_fetch_time.isoformat())
        time.sleep(10)

def main_fetch_emails(creds: Credentials, user_email: str, last_fetch_time: datetime) -> bool:
    try:
        from_address_filters = ['@gmail.com',]
        service = get_gmail_service(creds)
        
        # Convert last fetch time to epoch timestamp
        start_epoch = int(last_fetch_time.timestamp())
        
        # Construct the query for filtering emails
        date_filter = f'after:{start_epoch}'
        from_filter = ' OR '.join([f"from:{address}" for address in from_address_filters])
        query = f'{date_filter} ({from_filter})'
        
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], q=query).execute()
        messages = results.get("messages", [])
        print("response from gmail:", messages)
        if not messages:
            print("No new messages.")
            return False
        process_messages(service, messages, user_email)
        return True
    except HttpError as error:
        print(f"An error occurred: {error}")
        return False
    

# Functions for creating tickets
# --------------------------------------------------------------------------------------------------------

def create_contact(access_token, email, region='com'):
    url_create = f"https://desk.zoho.{region}/api/v1/contacts"
    headers = {
        'Authorization': f'Zoho-oauthtoken {access_token}'
    }
    payload = {
        'email': email,
        'lastName': email.split('@')[0]  # Using the email prefix as the last name
    }
    print(payload)
    response_create = requests.post(url_create, json=payload, headers=headers)
    if response_create.status_code == 200 or response_create.status_code == 201:
        new_contact = response_create.json()
        return new_contact['id']
    else:
        raise Exception(f"Failed to create contact: {response_create.json()}")

def create_ticket(access_token, department_id, ticket_subject, ticket_description, contact_email, cc_emails, region='com'):
    url = f"https://desk.zoho.{region}/api/v1/tickets"
    headers = {
        'Authorization': f'Zoho-oauthtoken {access_token}',
        'Content-Type': 'application/json'
    }
    if not ticket_subject.strip():
        ticket_subject = "No Subject"
    # Create contacts for cc emails and get their IDs
    cc_contact_ids = []
    for email in cc_emails:
        if email.strip():  # Check if email is not empty
            contact_id = create_contact(access_token, email, region)
            cc_contact_ids.append(contact_id)

    payload = {
        'departmentId': department_id,
        'secondaryContacts': cc_contact_ids,
        'subject': ticket_subject,
        'description': ticket_description,
        'contact': {
            'email': contact_email,
        },
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200 or response.status_code == 201:
        return response.json()
    else:
        raise Exception(f"Failed to create ticket: {response.json()}")

def get_ticket(current_access_token, ticket_number_id, region='com'):
    url = f"https://desk.zoho.{region}/api/v1/tickets/{ticket_number_id}"
    headers = {
        "Authorization": f"Zoho-oauthtoken {current_access_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None    
    
def update_ticket_info(id, ticket_number, status):
    conn = psycopg2.connect(**DATABASE_CONFIG)
    cur = conn.cursor()
    cur.execute("UPDATE zoho_task_tracker SET ticket_number_id = %s, status = %s WHERE id = %s::uuid", (ticket_number, status, id))
    conn.commit()
    cur.close()
    conn.close()

def read_emails_from_database(user_email):
    conn = psycopg2.connect(**DATABASE_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT id, subject, body, to_address, from_address, time,ticket_number_id,other_recipent FROM zoho_task_tracker WHERE to_address = %s", (user_email,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows    

def main_create_tickets(user_email):
    global current_access_token
    department_id = '227144000098200085'
    processed_combinations = set()
    try:
        emails = read_emails_from_database(user_email)
        for email in emails:
            id, subject, body, to_address, from_address, time, ticket_number_id, other_recipent = email
            # Check if the ticket already exists and is valid
            if ticket_number_id:
                ticket_info = get_ticket(current_access_token, ticket_number_id)
                if ticket_info:
                    print(f"Ticket already created for email ID {id}: {ticket_info}")
                    continue
            if (subject, time, from_address) in processed_combinations:
                print(f"Skipping duplicate entry for subject: {subject}, time: {time}, from_address: {from_address}")
                continue
            try:
                from_address = re.findall(r'<([^>]+)>', from_address)[0] if '<' in from_address else from_address
                cc_emails = other_recipent.split(',') if other_recipent else []
                new_ticket = create_ticket(current_access_token, department_id, subject, body, from_address, cc_emails)
                ticket_number = int(new_ticket['id'])
                status = 'Open'
                update_ticket_info(id, ticket_number, status)
                print(f"Ticket created successfully for email ID {id}: {new_ticket}")
                processed_combinations.add((subject, time, from_address))
            except Exception as e:
                error_message = str(e)
                if "INVALID_DATA" in error_message:
                    print(f"Skipping invalid email for email ID {id}: {to_address}")
                    print(f"Error details: {error_message}")
                else:
                    print(f"Error creating ticket for email ID {id}: {e}")
    except Exception as e:
        print(f"Error: {e}")

# Functions for applying labels based on status
# --------------------------------------------------------------------------------------------------------
def fetch_email_data_from_db(user_email):
    try:
        connection = psycopg2.connect(**DATABASE_CONFIG)
        cursor = connection.cursor()
        query = "SELECT to_address, from_address, subject, status, time FROM zoho_task_tracker WHERE to_address = %s"
        cursor.execute(query, (user_email,))
        rows = cursor.fetchall()
        return rows
    except (Exception, psycopg2.Error) as error:
        print("Error while fetching data from PostgreSQL:", error)
        return []
    finally:
        if connection:
            cursor.close()
            connection.close()

def get_label_id(service, user_id, label_name):
    try:
        labels = service.users().labels().list(userId=user_id).execute().get('labels', [])
        for label in labels:
            if label['name'].lower() == label_name.lower():
                return label['id']
        return None
    except HttpError as error:
        print(f"An error occurred: {error}")
        return None

def apply_label_to_email(service, user_id, message_id, label_id):
    try:
        service.users().messages().modify(
            userId=user_id,
            id=message_id,
            body={'addLabelIds': [label_id]}
        ).execute()
    except HttpError as error:
        print(f"An error occurred: {error}")

def create_label(service, user_id, label_name):
    try:
        label = {'messageListVisibility': 'show', 'name': label_name, 'labelListVisibility': 'labelShow'}
        created_label = service.users().labels().create(userId=user_id, body=label).execute()
        return created_label['id']
    except HttpError as error:
        print(f"An error occurred: {error}")
        return None

def process_email_data(creds, user_email):
    service = get_gmail_service(creds)
    email_data = fetch_email_data_from_db(user_email)
    for to_address, from_address, subject, status, time in email_data:
        if subject == "No subject":
            subject = " "
        print(f'Processing email :, Status: {status}, From: {from_address}, To: {to_address}, Subject: {subject}, Timestamp: {time}')
        label_id = get_label_id(service, "me", status.lower())
        
        if not label_id:
            print(f"Label '{status}' not found in Gmail. Creating...")
            label_id = create_label(service, "me", status.lower())
            if not label_id:
                print(f"Failed to create label '{status}'")
                continue
            print(f"Label '{status}' created successfully")

        # Convert the datetime object to Gmail date format
        gmail_date_format = time.strftime("%Y/%m/%d")
        query = f"to:{to_address} from:{from_address} subject:{subject} after:{gmail_date_format}"

        try:
            results = service.users().messages().list(userId="me", q=query).execute()
            messages = results.get("messages", [])

            if not messages:
                print(f"No messages found for query: {query}")
                continue

            for message in messages:
                apply_label_to_email(service, "me", message["id"], label_id)
                print(f"Labeled message {message['id']} with {status} (to={to_address}, from={from_address}, subject={subject}, time={time})")

        except HttpError as error:
            print(f"An error occurred: {error}")

def main_apply_labels(creds, user_email):
    process_email_data(creds, user_email)  


# Function for monitoring ticket status 
# --------------------------------------------------------------------------------------------------------
def get_ticket_status(current_access_token, ticket_number_id, region='com'):
    url = f"https://desk.zoho.{region}/api/v1/tickets/{ticket_number_id}"
    headers = {
        "Authorization": f"Zoho-oauthtoken {current_access_token}",
        "orgId": '655484237'
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            ticket_info = response.json()
            return ticket_info
        else:
            print(f"Failed to fetch ticket {ticket_number_id}: {response.json(),"due to duplicate entry in db"}")
            return None
    except Exception as e:
        print(f"Error while fetching ticket {ticket_number_id}: {e}")
        return None

def update_ticket_status_in_database(id, status):
    try:
        conn = psycopg2.connect(**DATABASE_CONFIG)
        cur = conn.cursor()
        cur.execute("UPDATE zoho_task_tracker SET status = %s WHERE id = %s::uuid", (status, id))
        conn.commit()
        cur.close()
        conn.close()
        print(f"Status for Database ID {id} updated to {status} in database.")
    except Exception as e:
        print(f"Error while updating database for ticket {id}: {e}")

def monitor_ticket_statuses(current_access_token, region='com', interval=10):
    while True:
        try:
            conn = psycopg2.connect(**DATABASE_CONFIG)
            cur = conn.cursor()
            cur.execute("SELECT id, ticket_number_id, status FROM zoho_task_tracker WHERE ticket_number_id IS NOT NULL")
            rows = cur.fetchall()
            cur.close()
            conn.close()
            for row in rows:
                id, ticket_number_id, current_status = row
                new_status_dict = get_ticket_status(current_access_token, ticket_number_id, region)
                if new_status_dict is None:
                    continue
                new_status = new_status_dict.get('status')
                if new_status and new_status != current_status:
                    print(f"Status changed for ticket ID {ticket_number_id} from {current_status} to {new_status}.")
                    update_ticket_status_in_database(id, new_status)
        except Exception as e:
            print(f"Error while monitoring tickets: {e}")
        time.sleep(interval)

def main_monitor_tickets():   
    monitor_ticket_statuses(current_access_token)

# Functions for monitoring and updating email labels based on status changes
# ---------------------------------------------------------------------------------------------------------
def convert_db_time_to_epoch(db_time):
    return int(db_time.timestamp())

def remove_label_from_email(service, user_id, message_id, label_id):
    try:
        service.users().messages().modify(
            userId=user_id,
            id=message_id,
            body={'removeLabelIds': [label_id]}
        ).execute()
    except HttpError as error:
        print(f"An error occurred: {error}")

def monitor_user_email_labels(user):
    creds = get_credentials(user['credentials'])
    service = get_gmail_service(creds)
    previous_email_data = fetch_email_data_from_db(user['email'])
    while True:
        current_email_data = fetch_email_data_from_db(user['email'])
        for prev_email, curr_email in zip(previous_email_data, current_email_data):
            prev_status = prev_email[3].lower()
            curr_status = curr_email[3].lower()
            if prev_status != curr_status:
                print(f"Status changed from {prev_status} to {curr_status} for email: to={curr_email[0]}, from={curr_email[1]}, subject={curr_email[2]}")
                epoch_time = convert_db_time_to_epoch(curr_email[4])
                query = f"to:{curr_email[0]} from:{curr_email[1]} subject:{curr_email[2]} after:{epoch_time}"
                try:
                    results = service.users().messages().list(userId="me", q=query).execute()
                    messages = results.get("messages", [])
                    if messages:
                        for message in messages:
                            prev_label_id = get_label_id(service, "me", prev_status)
                            curr_label_id = get_label_id(service, "me", curr_status)
                            if not curr_label_id:
                                print(f"Label '{curr_status}' not found in Gmail. Creating...")
                                curr_label_id = create_label(service, "me", curr_status)
                                if not curr_label_id:
                                    print(f"Failed to create label '{curr_status}'")
                                    continue
                                print(f"Label '{curr_status}' created successfully")
                            if prev_label_id:
                                remove_label_from_email(service, "me", message["id"], prev_label_id)
                                print(f"Email {message['id']} removed from label {prev_status}")
                            if curr_label_id:
                                apply_label_to_email(service, "me", message["id"], curr_label_id)
                                print(f"Email {message['id']} added to label {curr_status}")
                except HttpError as error:
                    print(f"An error occurred: {error}")
        previous_email_data = current_email_data
        time.sleep(10)  # Sleep for 10 seconds before checking again

def monitor_and_update_email_labels():
    threads = []
    for user in USERS:
        thread2 = threading.Thread(target=monitor_user_email_labels, args=(user,))
        thread2.start()
        threads.append(thread2)
    
    for thread in threads:
        thread.join()

# Function to refresh the token
# -----------------------------------------------------------------------------------------------------------
def refresh_token(refresh_token, client_id, client_secret):
    token_url = 'https://accounts.zoho.com/oauth/v2/token'
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id,
        'client_secret': client_secret
    }
    response = requests.post(token_url, data=data)
    return response.json()

def token_refresh_loop():
    global current_access_token
    refresh_token_value = '1000.3c3e9ed446949427b141341f12c5a63d.8bc9533c2a902069c9d13cb853551844'
    client_id = '1000.8XZXLIBN7A54Q3HYIZPNWTUBET16ZR'
    client_secret = 'a7f5f504a2783e8a9b090059a1bd7db2ad76ab8849'
    while True:
        new_token_response = refresh_token(refresh_token_value, client_id, client_secret)
        current_access_token = new_token_response['access_token']
        print(f"New access token: {current_access_token}")
        time.sleep(3600)  # Refresh token every hour      



if __name__ == "__main__":
    # Start the token refresh loop in a separate thread
    token_thread = threading.Thread(target=token_refresh_loop, daemon=True)
    token_thread.start()

    time.sleep(5)
    
    fetch_thread = threading.Thread(target=continuously_fetch_emails)
    fetch_thread.start()
    
    ticket_monitor_thread = threading.Thread(target=main_monitor_tickets)
    ticket_monitor_thread.start()
    
    label_monitor_thread = threading.Thread(target=monitor_and_update_email_labels)
    label_monitor_thread.start()
    
    # Joining threads
    fetch_thread.join()
    ticket_monitor_thread.join()
    label_monitor_thread.join()



