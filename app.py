from flask import Flask, request, redirect, render_template, flash, url_for, make_response, jsonify, session, send_file
import pymysql
import bcrypt
import random
import string
import threading
import logging
import time
import traceback
import os
from datetime import datetime, date, timedelta
from decimal import Decimal
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from dateutil.relativedelta import relativedelta
from werkzeug.utils import secure_filename




logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
app.secret_key = 'your_secret_key_here' 

db = pymysql.connect(
    host="localhost",
    user="root",
    password="",
    database="mobilebanking",
    cursorclass=pymysql.cursors.DictCursor
)




#Helper Functions
def get_user_id_from_cookie():
    return request.cookies.get("user_id")

def set_secure_cookie(response, user_id):
    response.set_cookie("user_id", str(user_id), max_age=3600, httponly=True, secure=True, samesite='Strict')
    return response

def get_db_connection():
    return db

def generate_unique_trx_id(cursor):
    while True:
        trx_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        cursor.execute("SELECT trx_id FROM send_money WHERE trx_id = %s", (trx_id,))
        if not cursor.fetchone():
            return trx_id

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def add_months(start_date, months):
    year = start_date.year + ((start_date.month - 1 + months) // 12)
    month = (start_date.month - 1 + months) % 12 + 1
    day = min(start_date.day, [31,
        29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month-1])
    return date(year, month, day)

@app.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("user_id")
    return resp



#Registration and Signin


#user_signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    try:
        firstName = request.form.get("firstName")
        lastName = request.form.get("lastName")
        dob = request.form.get("dob")
        email = request.form.get("email")
        phone = request.form.get("phone")
        nid = request.form.get("nid")
        password = request.form.get("password")
        # Validating phone number 
        if len(phone) != 11 or not phone.startswith("01"):
            return render_template("signup.html", error="Enter a valid 11-digit phone number starting with '01'.")
        try:
            dob_date = datetime.strptime(dob, "%Y-%m-%d").date()
        except ValueError:
            return render_template("signup.html", error="Invalid DOB format. Use YYYY-MM-DD.")
        # Checking if the phone number already exists
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM user_profile WHERE phone_number = %s", (phone,))
            existing_user = cursor.fetchone()
            if existing_user:
                return render_template("signup.html", phone_error="Phone number already in use")
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        with db.cursor() as cursor:
            cursor.execute("""INSERT INTO user_profile (first_name, last_name, dob, email, phone_number, nid, password, balance, points, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 1000, 0, 'active')""", 
                (firstName, lastName, dob_date, email, phone, nid, hashed_password.decode()))
            db.commit()
        return redirect("/login")
    except Exception as e:
        return render_template("signup.html", error=f"Signup error: {str(e)}")

#user_login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    phone = request.form.get("phone")
    password = request.form.get("password")
    if not phone or len(phone) != 11 or not phone.startswith("01"):
        return render_template("login.html", error="Enter a valid 11-digit phone number starting with '01'.")
    
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM user_profile WHERE phone_number = %s", (phone,))
        user = cursor.fetchone()
    
    if user:
        if user["status"] != "active":
            return render_template("account_suspended.html")

        if bcrypt.checkpw(password.encode("utf-8"), user['password'].encode("utf-8")):
            resp = make_response(redirect("/home"))
            resp = set_secure_cookie(resp, user["user_id"])
            return resp

    return render_template("login.html", error="Invalid phone number or password.")



#profile
@app.route('/profile')
def profile():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect("/login")
    cursor = db.cursor(pymysql.cursors.DictCursor)
    try:
        cursor.execute("SELECT * FROM user_profile WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            return "User not found", 404
        profile_data = {
            "username": user["first_name"],
            "name": f"{user['first_name']} {user['last_name']}",
            "phone": user["phone_number"],
            "firstName": user["first_name"],
            "lastName": user["last_name"],
            "dob": user["dob"].strftime("%Y-%m-%d") if user["dob"] else "",
            "email": user["email"],
            "nid": user["nid"],
            "loyaltyPoints": user.get("points", 0),
            "balance": float(user.get("balance", 0.0)),
            "profilePic": user.get("profile_pic", "default.png")  # <--- this line
        }
        return render_template('profile.html', profile=profile_data)
    except Exception as e:
        return f"An error occurred: {str(e)}"
    finally:
        cursor.close()

#edit profile

@app.route('/editprofile', methods=['GET'])
def edit_profile():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect('/login')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM user_profile WHERE user_id = %s", (user_id,))
            user = cursor.fetchone()
        if not user:
            flash('User not found', 'error')
            return redirect('/home')
        profile_data = {
            'name': f"{user['first_name']} {user['last_name']}",
            'phone': user['phone_number'],
            'firstName': user['first_name'],
            'lastName': user['last_name'],
            'dob': user['dob'].strftime('%Y-%m-%d') if user['dob'] else '',
            'email': user['email'],
            'nid': user['nid'],
            'profile_pic': user['profile_pic']
        }
        return render_template('editprofile.html', profile=profile_data)
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect('/home')
    
@app.route('/updateprofile', methods=['POST'])
def update_profile():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect('/login')

    first_name = request.form['firstName']
    last_name = request.form['lastName']
    dob = request.form['dob']
    email = request.form['email']
    nid = request.form['nid']

    profile_pic = None
    update_profile_pic = False

    if 'profilePic' in request.files:
        file = request.files['profilePic']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_folder = 'static/uploads'
            os.makedirs(upload_folder, exist_ok=True)
            profile_pic_path = os.path.join(upload_folder, filename)
            file.save(profile_pic_path)
            profile_pic = f'/{filename}'
            update_profile_pic = True

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            if update_profile_pic:
                update_query = """
                    UPDATE user_profile
                    SET first_name=%s, last_name=%s, dob=%s, email=%s, nid=%s, profile_pic=%s
                    WHERE user_id=%s
                """
                cursor.execute(update_query, (first_name, last_name, dob, email, nid, profile_pic, user_id))
            else:
                update_query = """
                    UPDATE user_profile
                    SET first_name=%s, last_name=%s, dob=%s, email=%s, nid=%s
                    WHERE user_id=%s
                """
                cursor.execute(update_query, (first_name, last_name, dob, email, nid, user_id))

        conn.commit()
        flash('Your Profile Updated Successfully.', 'success')
        return redirect(url_for('edit_profile'))

    except Exception as e:
        print("Update failed:", e)
        flash(f'Error updating profile: {str(e)}', 'error')
        return redirect(url_for('edit_profile'))

    

#send money
#send_now
@app.route("/send_now", methods=["GET", "POST"])
def send_now():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return render_template("login.html")

    if request.method == "GET":
        prefill_name = request.args.get("name")
        prefill_phone = request.args.get("phone")
        success = request.args.get("success", "")
        return render_template("send_now.html", prefill_name=prefill_name, prefill_phone=prefill_phone, success=success)


    recipient_phone = request.form.get("recipient_phone")
    recipient_name = request.form.get("recipient_name")
    amount_str = request.form.get("amount")
    save_info = request.form.get("save_info")

    try:
        amount = float(amount_str)
        if amount <= 0:
            return redirect(url_for('send_now', success='0'))
    except (ValueError, TypeError):
        return redirect(url_for('send_now', success='0'))

    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM user_profile WHERE phone_number = %s", (recipient_phone,))
        recipient = cursor.fetchone()
        if not recipient:
            return redirect(url_for('send_now', success='0'))

        cursor.execute("SELECT balance, transaction_limit FROM user_profile WHERE user_id = %s", (user_id,))
        sender = cursor.fetchone()
        if not sender:
            return render_template("login.html")

        if sender['balance'] < amount:
            return redirect(url_for('send_now', status='insufficient_balance'))

        if sender['transaction_limit'] < amount:
            return redirect(url_for('send_now', status='limit_reached'))

        trx_id = generate_unique_trx_id(cursor)

        cursor.execute("""
            INSERT INTO send_money (user_id, phone_no, name, amount, trx_id)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, recipient_phone, recipient_name, amount, trx_id))

        cursor.execute("UPDATE user_profile SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
        cursor.execute("UPDATE user_profile SET balance = balance + %s WHERE phone_number = %s", (amount, recipient_phone))

        if save_info == "on":
            try:
                cursor.execute("""
                    INSERT IGNORE INTO saved_details (user_id, name, phone)
                    VALUES (%s, %s, %s)
                """, (user_id, recipient_name, recipient_phone))
            except Exception as e:
                print("Error saving recipient details:", e)

        cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)",
                       (user_id, f"Sent {amount} to {recipient_name or recipient_phone}"))
        cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)",
                       (recipient['user_id'], f"Received {amount} from User {user_id}"))

        cursor.execute("""
            INSERT INTO history (user_id, type, trx_id, account, amount)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, "Send Money", trx_id, recipient_phone, -amount))

        db.commit()

    return redirect(url_for('send_now', status='success'))


#Schedule Transactions
@app.route("/schedule_transactions", methods=["GET", "POST"])
def schedule_transactions():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect("/login")

    if request.method == "GET":
        return render_template("schedule_transactions.html")

    phone = request.form.get("account")
    amount = request.form.get("amount")
    scheduled_time_str = request.form.get("datetime")

    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError("Invalid amount")

        scheduled_time = datetime.strptime(scheduled_time_str, "%Y-%m-%dT%H:%M")

        with db.cursor() as cursor:
            cursor.execute("SELECT user_id FROM user_profile WHERE phone_number = %s", (phone,))
            receiver = cursor.fetchone()

            if not receiver:
                return render_template("schedule_transactions.html", error="Recipient not found.")

            receiver_id = receiver["user_id"]
            cursor.execute("""
                INSERT INTO schedule_transactions (sender_id, receiver_id, amount, scheduled_time)
                VALUES (%s, %s, %s, %s)
            """, (user_id, receiver_id, amount, scheduled_time))
            db.commit()

        return render_template("schedule_transactions.html", success="Transaction scheduled successfully!")
    except Exception as e:
        return render_template("schedule_transactions.html", error="Failed to schedule transaction.")
    
def process_scheduled_transactions():
    while True:
        now = datetime.now()
        with db.cursor() as cursor:
            cursor.execute("""
                SELECT * FROM schedule_transactions
                WHERE scheduled_time <= %s AND (status IS NULL OR status = 'pending')
            """, (now,))
            transactions = cursor.fetchall()
            for txn in transactions:
                sender_id = txn["sender_id"]
                receiver_id = txn["receiver_id"]
                amount = txn["amount"]
                schedule_id = txn["schedule_id"]

                cursor.execute("SELECT balance FROM user_profile WHERE user_id = %s", (sender_id,))
                sender = cursor.fetchone()
                cursor.execute("SELECT phone_number FROM user_profile WHERE user_id = %s", (receiver_id,))
                receiver_phone = cursor.fetchone()
                receiver_phone = receiver_phone["phone_number"]
                if not sender or sender["balance"] < amount:
                    cursor.execute("UPDATE schedule_transactions SET status = 'cancelled' WHERE schedule_id = %s", (schedule_id,))
                    alert = f"Schedule transfer to {receiver_phone} of {amount} Taka has been cancelled due to insufficient balance."
                    cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)", (sender_id, alert))
                    continue  

                #Complete transfer
                cursor.execute("UPDATE user_profile SET balance = balance - %s WHERE user_id = %s", (amount, sender_id))
                cursor.execute("UPDATE user_profile SET balance = balance + %s WHERE user_id = %s", (amount, receiver_id))
                alert = f"Schedule transfer to {receiver_phone} of {amount} Taka Successful!"
                cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)", (sender_id, alert))             
                cursor.execute("""
                    INSERT INTO history (user_id, type, trx_id, account, amount)
                    VALUES (%s, 'Scheduled Send Money', 'N/A', %s, %s)
                """, (sender_id, receiver_phone, -amount))
                #update status
                cursor.execute("UPDATE schedule_transactions SET status = 'completed' WHERE schedule_id = %s", (schedule_id,))
            db.commit()
        sleep(5)

@app.route("/api/pending-scheduled-transactions")
def get_scheduled_transactions():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return jsonify([])

    try:
        with db.cursor() as cursor:
            cursor.execute("""
                SELECT sp.scheduled_time, sp.amount, up.phone_number AS receiver_phone
                FROM schedule_transactions sp
                JOIN user_profile up ON sp.receiver_id = up.user_id
                WHERE sp.sender_id = %s AND (sp.status IS NULL OR sp.status = 'pending')
                ORDER BY sp.scheduled_time ASC
            """, (user_id,))
            results = cursor.fetchall()
            for row in results:
                if isinstance(row["scheduled_time"], datetime):
                    row["scheduled_time"] = row["scheduled_time"].isoformat()

        return jsonify(results)
    except Exception as e:
        return jsonify([])



#Payment
#gas bill
@app.route("/gas_bill", methods=["GET", "POST"])
def gas_bill():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect("/login")

    if request.method == "GET":
        return render_template("gas_bill.html")

    name = request.form.get("userName")
    meter_no = request.form.get("meterNo")
    amount = float(request.form.get("amount"))
    month = request.form.get("month")

    installment_option = request.form.get("installmentMonths")
    is_installment = request.form.get("installmentOption") == "on"
   
    with db.cursor() as cursor:
        cursor.execute("SELECT balance, transaction_limit FROM user_profile WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return redirect("/login")

        balance = float(user['balance'])
        trx_limit = int(user['transaction_limit'])

        # INSTALLMENT
        if is_installment and installment_option:
            months = int(installment_option)
            part1 = round(amount / months, 2)

            if balance < part1:
                return render_template("gas_bill.html", popup="insufficient")
            if part1 > trx_limit:
                return render_template("gas_bill.html", popup="limit")

            cursor.execute("UPDATE user_profile SET balance = balance - %s WHERE user_id = %s", (part1, user_id))

            due_1_date = (datetime.now() + timedelta(days=30)).date()
            due_2_date = (datetime.now() + timedelta(days=60)).date() if months == 3 else None

            cursor.execute("""
                INSERT INTO pay_gas
                (user_id, name, meter_no, amount, month, installment, due_1, due_2, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')
            """, (
                user_id, name, meter_no, amount, month, months, due_1_date, due_2_date
            ))

            

            alert = f"Bill payment for Gas ID {meter_no} of {amount} Taka Successful!"
            cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)", (user_id, alert))

            cursor.execute("""
                INSERT INTO history (user_id, type, trx_id, account, amount)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, "Gas Bill Payment in Installment", "N/A", meter_no, -amount))

            db.commit()
            return render_template("gas_bill.html", popup="success")
        
        else:
            if balance < amount:
                return render_template("gas_bill.html", popup="insufficient")
            if amount > trx_limit:
                return render_template("gas_bill.html", popup="limit")

            cursor.execute("UPDATE user_profile SET balance = balance - %s WHERE user_id = %s", (amount, user_id))

            cursor.execute("""
                INSERT INTO pay_gas (user_id, name, meter_no, amount, month)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, name, meter_no, amount, month))

            cursor.execute("UPDATE user_profile SET points = points + %s WHERE user_id = %s", (int(amount // 100), user_id))

            alert = f"Bill payment for Gas ID {meter_no} of {amount} Taka Successful!"
            cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)", (user_id, alert))

            cursor.execute("""
                INSERT INTO history (user_id, type, trx_id, account, amount)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, "Gas Bill Payment", "N/A", meter_no, -amount))
#wifi bill
@app.route("/wifi_bill", methods=["GET", "POST"])
def wifi_bill():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect("/login")

    if request.method == "GET":
        return render_template("wifi_bill.html")

    name = request.form.get("userName")
    wifi_id = request.form.get("meterNo")
    amount = float(request.form.get("amount"))
    month = request.form.get("month")

    installment_option = request.form.get("installmentMonths")
    is_installment = request.form.get("installmentOption") == "on"
    

    with db.cursor() as cursor:
        cursor.execute("SELECT balance, transaction_limit FROM user_profile WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return redirect("/login")

        balance = float(user['balance'])
        trx_limit = int(user['transaction_limit'])

        # INSTALLMENT
        if is_installment and installment_option:
            months = int(installment_option)
            part1 = round(amount / months, 2)

            if balance < part1:
                return render_template("wifi_bill.html", popup="insufficient")
            if part1 > trx_limit:
                return render_template("wifi_bill.html", popup="limit")

            cursor.execute("UPDATE user_profile SET balance = balance - %s WHERE user_id = %s", (part1, user_id))

            due_1_date = (datetime.now() + timedelta(days=30)).date()
            due_2_date = (datetime.now() + timedelta(days=60)).date() if months == 3 else None

            cursor.execute("""
                INSERT INTO pay_wifi
                (user_id, name, wifi_id, amount, month, installment, due_1, due_2, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')
            """, (user_id, name, wifi_id, amount, month, months, due_1_date, due_2_date))

            cursor.execute("UPDATE user_profile SET points = points + %s WHERE user_id = %s", (int(amount // 100), user_id))
            alert = f"Bill payment for WiFi ID {wifi_id} of {amount} Taka Successful!"
            cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)", (user_id, alert))
            cursor.execute("""
                INSERT INTO history (user_id, type, trx_id, account, amount)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, "WiFi Bill Payment in Installment", "N/A", wifi_id, -amount))

            db.commit()
            return render_template("wifi_bill.html", popup="success")
        
        else:
            if balance < amount:
                return render_template("wifi_bill.html", popup="insufficient")
            if amount > trx_limit:
                return render_template("wifi_bill.html", popup="limit")

            cursor.execute("UPDATE user_profile SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cursor.execute("""
                INSERT INTO pay_wifi (user_id, name, wifi_id, amount, month)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, name, wifi_id, amount, month))
            cursor.execute("UPDATE user_profile SET points = points + %s WHERE user_id = %s", (int(amount // 100), user_id))
            alert = f"Bill payment for WiFi ID {wifi_id} of {amount} Taka Successful!"
            cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)", (user_id, alert))
            cursor.execute("""
                INSERT INTO history (user_id, type, trx_id, account, amount)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, "WiFi Bill Payment", "N/A", wifi_id, -amount))
    

#electricity bill
@app.route("/electricity_bill", methods=["GET", "POST"])
def electricity_bill():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect("/login")

    if request.method == "GET":
        return render_template("electricity_bill.html")

    name = request.form.get("userName")
    meter_no = request.form.get("meterNo")
    amount = float(request.form.get("amount"))
    month = request.form.get("month")

    installment_option = request.form.get("installmentMonths")
    is_installment = request.form.get("installmentOption") == "on"

    with db.cursor() as cursor:
        cursor.execute("SELECT balance, transaction_limit FROM user_profile WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return redirect("/login")

        balance = float(user['balance'])
        trx_limit = int(user['transaction_limit'])

        # INSTALLMENT MODE
        if is_installment and installment_option:
            months = int(installment_option)
            part1 = round(amount / months, 2)

            if balance < part1:
                return render_template("electricity_bill.html", popup="insufficient")
            if part1 > trx_limit:
                return render_template("electricity_bill.html", popup="limit")

            cursor.execute("UPDATE user_profile SET balance = balance - %s WHERE user_id = %s", (part1, user_id))

            due_1_date = (datetime.now() + timedelta(days=30)).date()
            due_2_date = (datetime.now() + timedelta(days=60)).date() if months == 3 else None

            cursor.execute("""
                INSERT INTO pay_electricity
                (user_id, name, meter_no, amount, month, installment, due_1, due_2, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')
            """, (
                user_id, name, meter_no, amount, month, months, due_1_date, due_2_date
            ))

            #Notification
            alert = f"Bill payment for Meter ID {meter_no} of {amount} Taka Successful!"
            cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)", (user_id, alert))
            cursor.execute("""
                INSERT INTO history (user_id, type, trx_id, account, amount)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, "Electricity Bill Payment in Installment", "N/A", meter_no, -amount))

            db.commit()
            return render_template("electricity_bill.html", popup="success")
        
        else:
            if balance < amount:
                return render_template("electricity_bill.html", popup="insufficient")
            if amount > trx_limit:
                return render_template("electricity_bill.html", popup="limit")

            cursor.execute("UPDATE user_profile SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cursor.execute("""
                INSERT INTO pay_electricity (user_id, name, meter_no, amount, month)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, name, meter_no, amount, month))
           
            #Notification
            alert = f"Bill payment for Electricity Meter {meter_no} of {amount} Taka Successful!"
            cursor.execute("INSERT INTO notifications (user_id, alerts) VALUES (%s, %s)", (user_id, alert))
            cursor.execute("""
                INSERT INTO history (user_id, type, trx_id, account, amount)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, "Electricity Bill Payment", "N/A", meter_no, -amount))


#Pending Installment
from dateutil.relativedelta import relativedelta
@app.route("/pending_installments")
def pending_installments():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect("/login")

    all_installments = []

    def fetch_due(cursor, table, id_field, label):
        cursor.execute(f"""
            SELECT amount, installment, due_1, due_2 FROM {table}
            WHERE user_id = %s AND status = 'pending'
        """, (user_id,))
        rows = cursor.fetchall()

        for row in rows:
            amt_per = round(row['amount'] / row['installment'], 2)

            if row['due_1']:
                due1 = row['due_1']
                issue1 = due1 - relativedelta(months=1)
                all_installments.append({
                    "service": label,
                    "amount": amt_per,
                    "issue_date": issue1.strftime("%d/%m/%y"),
                    "due_date": due1.strftime("%d/%m/%y")
                })

            if row['due_2']:
                due2 = row['due_2']
                issue2 = due2 - relativedelta(months=2)
                all_installments.append({
                    "service": label,
                    "amount": amt_per,
                    "issue_date": issue2.strftime("%d/%m/%y"),
                    "due_date": due2.strftime("%d/%m/%y")
                })

    with db.cursor() as cursor:
        fetch_due(cursor, "pay_electricity", "meter_no", "Electricity Bill Payment")
        fetch_due(cursor, "pay_gas", "meter_no", "Gas Bill Payment")
        fetch_due(cursor, "pay_wifi", "wifi_id", "WiFi Bill Payment")

    return render_template("pending_installments.html", installments=all_installments)

#Notifications
@app.route('/notifications')
def notifications():
    user_id = request.cookies.get('user_id')
    if not user_id:
        return redirect('/login')
    with db.cursor() as cursor:
        cursor.execute("SELECT alerts, timestamp FROM notifications WHERE user_id = %s ORDER BY timestamp DESC", (user_id,))
        notifications = cursor.fetchall()
    return render_template('notifications.html', notifications=notifications)

@app.route('/clear_notifications', methods=['POST'])
def clear_notifications():
    user_id = request.cookies.get('user_id')
    if not user_id:
        return redirect('/login')
    with db.cursor() as cursor:
        cursor.execute("DELETE FROM notifications WHERE user_id = %s", (user_id,))
    db.commit()
    return redirect('/notifications')


# History
@app.route("/history")
def history():
    user_id = request.cookies.get("user_id")

    if not user_id:
        return "User not logged in or session expired", 401

    try:
        with db.cursor() as cursor:
            cursor.execute("""
                SELECT type, trx_id, account, time, amount
                FROM history
                WHERE user_id = %s
                ORDER BY time DESC
            """, (user_id,))
            history_records = cursor.fetchall()
    except Exception as e:
        history_records = []

    return render_template("history.html", history_records=history_records)



#routes
@app.route("/home")
def home():
    user_id = get_user_id_from_cookie()
    if not user_id:
        return redirect("/login")
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM user_profile WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
    if user:
        return render_template("home.html", user=user)
    else:
        return "User not found", 404
    
@app.route("/")
def homepage():
    return render_template("landing.html")

@app.route("/scheduled_transactions")
def scheduled_transactions():
    return render_template("scheduled_transactions.html")


@app.route("/send_money")
def send_money():
    return render_template("send_money.html")

@app.route("/utility")
def utility():
    return render_template("utility.html")

@app.route("/payment")
def payment():
    return render_template("payment.html")


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Thread(target=process_scheduled_transactions, daemon=True).start()
    app.run(port=8000, debug=True)



