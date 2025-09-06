import os
import re
import io
import zlib
from werkzeug.utils import secure_filename
from flask import Response
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import face_recognition
from PIL import Image
from base64 import b64encode, b64decode
from functools import wraps
import re
import sqlite3  

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///data.db")
@app.route("/")
@login_required
def home():
    message = request.args.get('message')  # Get the message from the query parameters
    return render_template("index.html", message=message)  # Pass the message to the template

@app.route("/home")
@login_required
def index():
    return render_template("index.html")

@app.route("/safe", methods=["GET", "POST"])
def safe():
    if request.method == "GET":
        return render_template("safe.html")
    
    # Get JSON data from request
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data received"})

    # Get user_id and code from JSON data
    user_id = data.get("user_id")
    code = data.get("code")
    if not user_id or not code:
        return jsonify({"success": False, "message": "User ID and code are required"})

    # Get user's safecode from database
    try:
        user = db.execute("SELECT safecode FROM users WHERE username = :user_id", 
                         user_id=user_id)
        
        # Debug: Print the query result
        print(f"Query result: {user}")

        if not user or len(user) == 0:
            return jsonify({"success": False, "message": "User not found"})
            
        registered_safecode = user[0]["safecode"]

        # Compare the codes
        if code == registered_safecode:
            # Reset failed attempts on success
            session.pop("failed_attempts", None)
            return jsonify({"success": True, "redirect": url_for("login")})
        else:
            # Increment failed attempts
            session["failed_attempts"] = session.get("failed_attempts", 0) + 1
            if session["failed_attempts"] >= 3:
                return jsonify({"success": False, "redirect": url_for("safe")})
            return jsonify({"success": False, "message": "Incorrect Safe Code. Try again."})
            
    except Exception as e:
        print(f"Error in safe route: {str(e)}")
        return jsonify({"success": False, "message": "An error occurred"})

@app.route("/face_login", methods=["POST"])
def face_login():
    success = False  # Replace with actual face recognition logic
    
    if not success:
        session["failed_attempts"] = session.get("failed_attempts", 0) + 1
        if session["failed_attempts"] >= 3:
            return redirect(url_for("safe"))  # Redirect to safe page after failed attempts
    
    session.pop("failed_attempts", None)  # Reset failed attempts on success
    return redirect(url_for("home"))  # Redirect to home on success

@app.route("/forgot_pin", methods=["GET", "POST"])
def forgot_pin():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        print(username)
        new_pin = request.form.get("new_pin", "").strip()
        confirm_pin = request.form.get("confirm_pin", "").strip()

        # Ensure all fields are filled
        if not username:
            return jsonify({"success": False, "message": "Username is required."})
        if not new_pin:
            return jsonify({"success": False, "message": "New PIN is required."})
        if not confirm_pin:
            return jsonify({"success": False, "message": "Confirm your new PIN."})

        # Ensure PINs match
        if new_pin != confirm_pin:
            return jsonify({"success": False, "message": "PINs do not match."})

        # Query database for registered username
        user = db.execute("SELECT username FROM users WHERE username = :name", name=username)
        print(user)

        if not user:
            return jsonify({"success": False, "message": "Username not found. Enter the registered username."})

        # Update the safecode (PIN) securely
        db.execute("UPDATE users SET safecode = :new_pin WHERE username = :username",
                   new_pin=new_pin,
                   username=username)

        return jsonify({"success": True, "message": "Safe PIN updated successfully!", "redirect": "/safe"})

    return render_template("forgot_pin.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Assign inputs to variables
        input_username = request.form.get("username")
        input_password = request.form.get("password")

        # Ensure username was submitted
        if not input_username:
            return render_template("login.html",messager = 1)

        # Ensure password was submitted
        elif not input_password:
             return render_template("login.html",messager = 2)

        # Query database for username
        username = db.execute("SELECT * FROM users WHERE username = :username",
                              username=input_username)
        
        print(username)

        # Ensure username exists and password is correct
        if len(username) != 1 or not check_password_hash(username[0]["hash"], input_password):
            return render_template("login.html",messager = 3)

        # Remember which user has logged in
        session["user_id"] = username[0]["id"]

        # Redirect user to home page
    
        return redirect(url_for("home", message="login"))

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Get form inputs
        input_username = request.form.get("username")
        input_password = request.form.get("password")
        input_confirmation = request.form.get("confirmation")
        input_safecode = request.form.get("safecode")

        # Check if any field is empty
        if not input_username:
            return render_template("register.html", messager=1)
        elif not input_password:
            return render_template("register.html", messager=2)
        elif not input_confirmation:
            return render_template("register.html", messager=4)
        elif not input_safecode:
            return render_template("register.html", messager=6)

        # Ensure passwords match
        if input_password != input_confirmation:
            return render_template("register.html", messager=3)

        # Ensure safe code contains only numbers
        if not input_safecode.isdigit():
            flash("Safe code must contain only numbers!", "danger")
            return render_template("register.html", messager=6)

        # Check if username is already taken
        user_check = db.execute("SELECT * FROM users WHERE username = ?", input_username)
        if len(user_check) > 0:
            return render_template("register.html", messager=5)

        # Hash the password
        hashed_password = generate_password_hash(input_password, method="pbkdf2:sha256", salt_length=8)

        # Insert new user into the database
        new_user = db.execute(
            "INSERT INTO users (username, hash, safecode) VALUES (?, ?, ?)",
            input_username,
            hashed_password,
            input_safecode
        )

        if new_user:
            session["user_id"] = new_user  # Log in the user automatically
            flash(f"Successfully registered as {input_username}", "success")
            #return redirect("/")
            return redirect(url_for("home", message="registered"))

    return render_template("register.html")

@app.route("/facereg", methods=["GET", "POST"])
def facereg():
    if "face_login_attempts" not in session:
        session["face_login_attempts"] = 0

    if request.method == "POST":
        try:
            # Get username and validate
            username = request.form.get("name")
            if not username:
                session["face_login_attempts"] += 1
                if session["face_login_attempts"] >= 3:
                    return redirect("/safe")
                return render_template("camera.html", message=1)
            
            # Check if user exists
            user = db.execute("SELECT * FROM users WHERE username = :username", 
                            username=username)
            if len(user) != 1:
                session["face_login_attempts"] += 1
                if session["face_login_attempts"] >= 3:
                    return redirect("/safe")
                return render_template("camera.html", message=1)

            id_ = user[0]['id']
            
            # Get and process image data
            encoded_image = request.form.get("pic")
            if not encoded_image:
                session["face_login_attempts"] += 1
                if session["face_login_attempts"] >= 3:
                    return redirect("/safe")
                return render_template("camera.html", message="No image data received")

            # Add padding and decode
            encoded_image = (encoded_image + "==").encode('utf-8')
            
            # Ensure directory exists
            unknown_directory = './static/face/unknown/'
            os.makedirs(unknown_directory, exist_ok=True)

            # Save the unknown face image
            unknown_path = f'./static/face/unknown/{id_}.jpg'
            try:
                decoded_data = b64decode(encoded_image)
                with open(unknown_path, 'wb') as new_image_handle:
                    new_image_handle.write(decoded_data)
            except Exception as e:
                print(f"Error saving unknown face: {str(e)}")
                session["face_login_attempts"] += 1
                if session["face_login_attempts"] >= 3:
                    return redirect("/safe")
                return render_template("camera.html", message="Error processing image")

            # Check registered face image exists
            registered_face_path = f'./static/face/{id_}.jpg'
            if not os.path.exists(registered_face_path):
                session["face_login_attempts"] += 1
                if session["face_login_attempts"] >= 3:
                    return redirect("/safe")
                return render_template("camera.html", message=5)

            try:
                # Load and process registered face
                image_of_user = face_recognition.load_image_file(registered_face_path)
                user_face_encodings = face_recognition.face_encodings(image_of_user)
                
                if not user_face_encodings:
                    session["face_login_attempts"] += 1
                    if session["face_login_attempts"] >= 3:
                        return redirect("/safe")
                    return render_template("camera.html", message="No face found in registered image")
                
                user_face_encoding = user_face_encodings[0]

                # Load and process unknown face
                unknown_image = face_recognition.load_image_file(unknown_path)
                unknown_face_encodings = face_recognition.face_encodings(unknown_image)
                
                # If no face detected or other processing error
                if not unknown_face_encodings:
                    session["face_login_attempts"] += 1
                    if session["face_login_attempts"] >= 3:
                        return redirect("/safe")
                    return render_template("camera.html", message=2)
                
                unknown_face_encoding = unknown_face_encodings[0]

                # Compare faces
                results = face_recognition.compare_faces([user_face_encoding], 
                                                       unknown_face_encoding,
                                                       tolerance=0.6)

                if results[0]:
                    # Successful match
                    session["face_login_attempts"] = 0
                    session["user_id"] = user[0]["id"]
                    return redirect("/")
                else:
                    # Failed match
                    session["face_login_attempts"] += 1
                    if session["face_login_attempts"] >= 3:
                        return redirect("/safe")
                    return render_template("camera.html", message=3)

            except Exception as e:
                print(f"Error in face recognition: {str(e)}")
                session["face_login_attempts"] += 1
                if session["face_login_attempts"] >= 3:
                    return redirect("/safe")
                return render_template("camera.html", message="Error processing face recognition")

        finally:
            # Cleanup temporary files
            try:
                if os.path.exists(unknown_path):
                    os.remove(unknown_path)
            except:
                pass

    return render_template("camera.html")

@app.route("/facesetup", methods=["GET", "POST"])
def facesetup():
    if request.method == "POST":
        encoded_image = (request.form.get("pic")+"==").encode('utf-8')
        id_=db.execute("SELECT id FROM users WHERE id = :user_id", user_id=session["user_id"])[0]["id"]
        compressed_data = zlib.compress(encoded_image, 9) 
        uncompressed_data = zlib.decompress(compressed_data)
        decoded_data = b64decode(uncompressed_data)
        new_image_handle = open('./static/face/'+str(id_)+'.jpg', 'wb')
        new_image_handle.write(decoded_data)
        new_image_handle.close()
        image_of_bill = face_recognition.load_image_file('./static/face/'+str(id_)+'.jpg')    
        try:
            bill_face_encoding = face_recognition.face_encodings(image_of_bill)[0]
        except:    
            return render_template("face.html",message = 1)
        #return redirect("/home")
        return redirect(url_for("home", message="facesetup"))
    else:
        return render_template("face.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return render_template("error.html",e = e)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == '__main__':
      app.run(debug=True)