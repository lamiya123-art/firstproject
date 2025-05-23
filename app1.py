import os
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from flask_cors import CORS
import bcrypt
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder="templates")
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/GLAMORA')

try:
    client = MongoClient(MONGO_URI)
    client.admin.command('ping')  # Test connection
    print("Successfully connected to MongoDB!")
    
    db = client.get_database()
    cart_collection = db['cart']
    sign_up_collection = db["sign_up"]
    orders_collection = db['completed_orders']
    
except ConnectionFailure as e:
    print("MongoDB connection error:", str(e))
    raise e  # Or handle more gracefully

# Sample product data
products = [
    {"id": 1, "name": "Orange Kurti", "price": 1500, "image": "https://i.pinimg.com/474x/9b/a8/64/9ba8649e5fabfd14dce49d327fc60f3a.jpg"},
    # ... (rest of your product data)
]

# Helper functions
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt)

def verify_password(stored_hash, provided_password):
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash)

# Routes
@app.route("/")
def home():
    return render_template("index.html", products=products)

@app.route("/fullname", methods=["POST"])
def fullname():
    try:
        data = request.get_json()
        if not all(field in data for field in ["Full Name", "Email Address", "Password", "Confirm Password"]):
            return jsonify({"error": "Missing required fields"}), 400

        if data["Password"] != data["Confirm Password"]:
            return jsonify({"error": "Passwords do not match"}), 400

        if sign_up_collection.find_one({"Email Address": data["Email Address"]}):
            return jsonify({"error": "Email already in use"}), 400

        hashed_password = hash_password(data["Password"])
        user_data = {
            "Full Name": data["Full Name"],
            "Email Address": data["Email Address"],
            "Password": hashed_password
        }

        result = sign_up_collection.insert_one(user_data)
        return jsonify({
            "message": "User saved successfully!",
            "user_id": str(result.inserted_id)
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/signup.html', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            if sign_up_collection.find_one({'Email Address': email}):
                flash('Email already exists', 'error')
                return redirect(url_for('signup'))
            
            hashed = hash_password(password)
            sign_up_collection.insert_one({
                'Email Address': email,
                'Password': hashed
            })
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('Registration failed', 'error')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route("/add-to-cart", methods=["POST"])
def add_to_cart():
    try:
        data = request.get_json()
        if not all(key in data for key in ["id", "name", "price", "image"]):
            return jsonify({"error": "Missing product info"}), 400

        cart_item = {
            "id": data["id"],
            "name": data["name"],
            "price": float(data["price"]),
            "image": data["image"],
            "quantity": int(data.get("quantity", 1))
        }

        existing = cart_collection.find_one({"id": cart_item["id"]})
        if existing:
            new_qty = existing["quantity"] + cart_item["quantity"]
            cart_collection.update_one(
                {"id": cart_item["id"]},
                {"$set": {"quantity": new_qty}}
            )
        else:
            cart_collection.insert_one(cart_item)

        return jsonify({
            "message": "Product added to cart",
            "cart": list(cart_collection.find({}, {"_id": 0}))
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ... (rest of your routes with similar error handling)

if __name__ == "__main__":
    app.run(debug=True, port=5001)
