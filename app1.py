from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from flask_cors import CORS
import bcrypt
from bson import SON, ObjectId
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from flask_pymongo import PyMongo

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.secret_key = 'your-secret-key-here'  # Change this to a secure random key
app.config['MONGO_URI'] = 'mongodb://localhost:27017/GLAMORA'
mongo = PyMongo(app)

# MongoDB connection
mongo_uri = "mongodb://localhost:27017/"
client = MongoClient(mongo_uri)

# Verify MongoDB connection
try:
    # Test the connection
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
    
    # Print existing collections
    db_names = client.list_database_names()
    print("Available databases:", db_names)
    
    if "GLAMORA" in db_names:
        print("Collections in GLAMORA:", client.GLAMORA.list_collection_names())
        
except Exception as e:
    print("MongoDB connection error:", str(e))

# Select the database and collections
db = client["GLAMORA"]  # Database name
# Initialize collections
cart_collection = db['cart']
 # Billing collection
sign_up_collection = db["sign_up"]  # Sign-up collection

# Sample product data (for demonstration)
products = [
    {"id": 1, "name": "Orange Kurti", "price": 1500, "image": "https://i.pinimg.com/474x/9b/a8/64/9ba8649e5fabfd14dce49d327fc60f3a.jpg"},
    {"id": 2, "name": "Blue Kurti", "price": 2500, "image": "https://i.pinimg.com/474x/71/e7/a8/71e7a87c4772a54d804433811ae3484a.jpg"},
    {"id": 3, "name": "Grand Kurti", "price": 5000, "image": "https://i.pinimg.com/474x/0b/79/36/0b79364dcbac0b08be1bad781e50e114.jpg"},
    {"id": 4, "name": "Black Bodycon", "price": 3000, "image": "https://i.pinimg.com/474x/f4/79/10/f47910c5360565dab491b2a388497e5e.jpg"},
    {"id": 5, "name": "Red Bodycon", "price": 3500, "image": "https://i.pinimg.com/474x/24/f5/91/24f591931e6d59eb401055875ec41208.jpg"},
    {"id": 6, "name": "Floral Bodycon", "price": 4000, "image": "https://i.pinimg.com/474x/ef/cf/f5/efcff540effba3b95888f5f41194c034.jpg"},
    {"id": 7, "name": "White Skirt", "price": 2500, "image": "https://i.pinimg.com/474x/08/41/da/0841da5558ec9b84ceed41e5937f0569.jpg"},
    {"id": 8, "name": "Black Skirt", "price": 2800, "image": "https://i.pinimg.com/474x/3a/c0/23/3ac02363e5b6204fd11b4596c11be951.jpg"},
    {"id": 9, "name": "Floral Skirt", "price": 1800, "image": "https://i.pinimg.com/474x/07/c6/1d/07c61deb732a3c8a8afdcbaf702b10be.jpg"},
    {"id": 10, "name": "Pink Skirt", "price": 2200, "image": "https://i.pinimg.com/474x/96/e6/3a/96e63ae12189150a5d3a5408c6ef41ab.jpg"}
]

# Hash the password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed_password

# Add this function to verify password
def verify_password(stored_password_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password_hash)

# Root route
@app.route("/")
def home():
    return render_template("index.html", products=products)

# Separate route for handling the API request from the frontend
@app.route("/fullname", methods=["POST"])
def fullname():
    try:
        # Get JSON data from the request
        data = request.get_json()

        # Debug print
        print("Received data:", data)

        # Validate required fields
        if not data or "Full Name" not in data or "Email Address" not in data or "Password" not in data or "Confirm Password" not in data:
            return jsonify({"error": "Missing required fields"}), 400

        # Check if passwords match
        if data["Password"] != data["Confirm Password"]:
            return jsonify({"error": "Passwords do not match"}), 400

        # Check if email already exists in the database
        existing_user = sign_up_collection.find_one({"Email Address": data["Email Address"]})
        if existing_user:
            return jsonify({"error": "Email address already in use"}), 400

        # Hash the password
        hashed_password = hash_password(data["Password"])

        # Prepare user data for insertion
        user_data = {
            "Full Name": data["Full Name"],
            "Email Address": data["Email Address"],
            "Password": hashed_password
        }

        # Debug print
        print("Inserting user data:", user_data)

        # Insert user data into the MongoDB collection
        result = sign_up_collection.insert_one(user_data)

        # Return success response
        return jsonify({
            "message": "User saved successfully!",
            "user_id": str(result.inserted_id)
        }), 201

    except Exception as e:
        print("Error:", str(e))  # Debug print
        return jsonify({"error": str(e)}), 500
    
# Keep the existing sign_up.html route for rendering the page
@app.route('/sign_up.html', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@app.route('/signup.html', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        print(f"\nAttempting to create new user with email: {email}")
        
        # Check if user exists - use sign_up collection
        existing_user = mongo.db.sign_up.find_one({'email': email})
        
        if existing_user is None:
            def hash_password(password):
                salt = bcrypt.gensalt()
                hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
                return hashed_password
            # Hash password using generate_password_hash
        
            
            # Insert new user into sign_up collection
            result = mongo.db.sign_up.insert_one({
                'email': email,
                'password': hashed_password
            })
            
            print(f"User created successfully in sign_up collection")
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        
        flash('Email already exists', 'error')
        return redirect(url_for('signup'))
    
    return render_template('signup.html')

# API to add an item to the cart
@app.route("/add-to-cart", methods=["POST"])
def add_to_cart():
    try:
        # Get JSON data from the request
        data = request.get_json()
        print("Received cart data:", data)  # Debug print

        # Validate required fields
        if not all(key in data for key in ["id", "name", "price", "image"]):
            return jsonify({"error": "Missing required product information"}), 400

        # Format the data for MongoDB
        cart_item = {
            "id": data["id"],
            "name": data["name"],
            "price": float(data["price"]),
            "image": data["image"],
            "quantity": int(data.get("quantity", 1))
        }

        # Check if the product already exists in the cart
        existing_item = cart_collection.find_one({"id": cart_item["id"]})
        
        if existing_item:
            # Update quantity if product exists
            new_quantity = existing_item["quantity"] + cart_item["quantity"]
            cart_collection.update_one(
                {"id": cart_item["id"]},
                {"$set": {"quantity": new_quantity}}
            )
            print(f"Updated quantity for item {cart_item['id']}")  # Debug print
        else:
            # Insert new item
            result = cart_collection.insert_one(cart_item)
            print(f"Inserted new item with ID: {result.inserted_id}")  # Debug print

        # Verify the cart contents
        cart_items = list(cart_collection.find({}, {"_id": 0}))
        print("Current cart contents:", cart_items)  # Debug print

        return jsonify({"message": "Product added to cart successfully", "cart": cart_items}), 200

    except Exception as e:
        print("Error adding to cart:", str(e))  # Debug print
        return jsonify({"error": str(e)}), 500

# API to get cart items
@app.route("/cart-items", methods=["GET"])
def get_cart_items():
    try:
        cart_items = list(cart_collection.find({}, {"_id": 0}))
        print("Retrieved cart items:", cart_items)  # Debug print
        return jsonify(cart_items)
    except Exception as e:
        print("Error getting cart items:", str(e))  # Debug print
        return jsonify({"error": str(e)}), 500

# API to update cart item quantity

def update_cart():
    try:
        data = request.json
        product_id = data.get("product_id")
        action = data.get("action")  # "increase", "decrease", or "remove"

        cart_item = cart_collection.find_one({"id": product_id})
        if not cart_item:
            return jsonify({"error": "Product not found in cart"}), 404

        if action == "increase":
            cart_collection.update_one({"id": product_id}, {"$inc": {"quantity": 1}})
        elif action == "decrease":
            if cart_item["quantity"] > 1:
                cart_collection.update_one({"id": product_id}, {"$inc": {"quantity": -1}})
            else:
                cart_collection.delete_one({"id": product_id})
        elif action == "remove":
            cart_collection.delete_one({"id": product_id})

        return jsonify({"message": "Cart updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API to clear the cart

@app.route("/cart/clear", methods=["DELETE"])
def clear_cart():
    try:
        # Clear the cart collection
        result = cart_collection.delete_many({})
        print(f"Deleted {result.deleted_count} items from cart")  # Debug print
        
        return jsonify({
            "message": "Cart cleared successfully",
            "items_removed": result.deleted_count
        }), 200
    except Exception as e:
        print("Error clearing cart:", str(e))  # Debug print
        return jsonify({"error": "Failed to clear cart: " + str(e)}), 500

# API to save billing details

def save_billing_details():
    try:
        data = request.json  # Get the JSON data from the request
        name = data.get("name")
        email = data.get("email")
        address = data.get("address")
        payment_method = data.get("payment_method")

        # Validate the data (optional)
        if not name or not email or not address or not payment_method:
            return jsonify({"error": "All fields are required"}), 400

        # Save the billing details to MongoDB
        billing_collection.insert_one({
            "name": name,
            "email": email,
            "address": address,
            "payment_method": payment_method,
        })

        return jsonify({"message": "Billing details saved successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Checkout route

@app.route("/api/checkout", methods=["POST"])
def process_checkout():
    try:
        # Get JSON data from the request
        data = request.get_json()
        print("Received checkout data:", data)

        # Get all cart items
        cart_items = list(cart_collection.find({}))
        
        if not cart_items:
            return jsonify({"error": "Cart is empty"}), 400

        # Create a new collection for completed orders
        orders_collection = db['completed_orders']

        # Prepare order with billing details and cart items
        order_data = {
            "order_date": datetime.now(),
            "billing_details": {
                "name": data["billing_details"]["name"],
                "email": data["billing_details"]["email"],
                "address": data["billing_details"]["address"],
                "payment_method": data["billing_details"]["payment_method"]
            },
            "items": cart_items,
            "total_amount": data["total"],
            "status": "ordered"
        }

        # Save the order
        result = orders_collection.insert_one(order_data)
        print(f"Order saved with ID: {result.inserted_id}")

        # Clear the cart after successful order placement
        cart_collection.delete_many({})
        print("Cart cleared successfully")

        return jsonify({
            "message": "Order placed successfully!",
            "order_id": str(result.inserted_id)
        }), 200

    except Exception as e:
        print("Error processing checkout:", str(e))
        return jsonify({"error": str(e)}), 500

# Add a route to get order history
@app.route("/api/orders", methods=["GET"])
def get_orders():
    try:
        orders_collection = db['completed_orders']
        orders = list(orders_collection.find({}, {'_id': str}))
        return jsonify(orders), 200
    except Exception as e:
        print("Error fetching orders:", str(e))
        return jsonify({"error": str(e)}), 500

# HTML page routes
@app.route("/index.html")
def home_page():
    return render_template("index.html", products=products)

@app.route("/cart.html", methods=["GET"])
def cart_page():
    return render_template("cart.html")

@app.route('/login.html', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data - ensure the form field names match
        email = request.form.get('Email Address')  # Ensure this matches the form field name
        password = request.form.get('password')  # Ensure this matches the form field name
        
        print("\n=== LOGIN DEBUG ===")
        print(f"Received email: {email}")
        print(f"Received password: {password}")  # Debug print to check password retrieval
        
        try:
            # Find user with case-insensitive email match
            user = mongo.db.sign_up.find_one({
                "Email Address": {"$regex": f"^{email}$", "$options": "i"}
            })
            
            print(f"Database query result: {user}")
            
            if user:
                print(f"Found user with email: {user.get('Email Address')}")
                # Use bcrypt to verify the password
                stored_password_hash = user.get('Password')
                if isinstance(stored_password_hash, str):
                    stored_password_hash = stored_password_hash.encode('utf-8')
                
                if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash):
                    # Store user info in session
                    session['user_id'] = str(user['_id'])
                    session['email'] = user['Email Address']
                    print("Login successful!")
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
                else:
                    print("Password mismatch")
                    flash('Invalid password', 'error')
            else:
                print(f"No user found with email: {email}")
                all_users = list(mongo.db.sign_up.find({}, {"Email Address": 1, "_id": 0}))
                print("All emails in database:", all_users)
                total_users = mongo.db.sign_up.count_documents({})
                print("Total users in database:", total_users)
                flash('Email not found', 'error')
            
        except Exception as e:
            print(f"Database error: {str(e)}")
            flash('An error occurred', 'error')
        
        print("=== END DEBUG ===\n")
        return redirect(url_for('login'))
    
    return render_template('login.html')
@app.route('/check-session')
def check_session():
    return {
        'logged_in': 'user_id' in session,
        'email': session.get('email', None)
    }

@app.route("/product_page.html")
def product_page():
    return render_template("product_page.html", products=products)

# Add these debug routes to check MongoDB connection and collections
@app.route("/debug/check-db", methods=["GET"])
def check_db():
    try:
        # Test MongoDB connection
        client.admin.command('ping')
        
        # Get collection info
        cart_count = cart_collection.count_documents({})
        billing_count = billing_collection.count_documents({})
        
        return jsonify({
            "status": "connected",
            "database": "GLAMORA",
            "collections": {
                "cart": cart_count,
                "billing": billing_count
            }
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/debug/last-order", methods=["GET"])
def get_last_order():
    try:
        # Get the most recent order
        last_order = billing_collection.find_one({}, sort=[('_id', -1)])
        if last_order:
            last_order['_id'] = str(last_order['_id'])  # Convert ObjectId to string
        return jsonify({"last_order": last_order}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Contact route
@app.route('/contact.html')
def contact():
    return render_template('contact.html')

# Add this route to check if a user exists
@app.route('/check_user_exists/<email>')
def check_user_exists(email):
    user = mongo.db.users.find_one({'email': email})
    if user:
        return f"User exists: {email}"
    return f"User does not exist: {email}"

# Add this route to create a test user
@app.route('/create_test_user')
def create_test_user():
    try:
        test_email = 'test@example.com'
        test_password = 'password123'
        
        # Check if user already exists
        existing_user = mongo.db.users.find_one({'email': test_email})
        if existing_user:
            return 'Test user already exists'
            
        # Create new user
        hashed_password = generate_password_hash(test_password)
        mongo.db.users.insert_one({
            'email': test_email,
            'password': hashed_password,
            'name': 'Test User'
        })
        return f'Test user created successfully. Email: {test_email}, Password: {test_password}'
    except Exception as e:
        return f'Error creating test user: {str(e)}'

# Add this route to list all users
@app.route('/list_users')
def list_users():
    try:
        users = list(mongo.db.users.find({}, {'email': 1, '_id': 0}))
        return f"Users in database: {users}"
    except Exception as e:
        return f"Error: {str(e)}"

# Add this route to check database connection
@app.route('/test_db')
def test_db():
    try:
        # Test database connection and print all users
        users = list(mongo.db.users.find())
        user_emails = [user['email'] for user in users]
        return f'Database connection successful! Users: {user_emails}'
    except Exception as e:
        return f'Database error: {str(e)}'

@app.route('/verify_signup/<email>')
def verify_signup(email):
    try:
        user = mongo.db.users.find_one({"email": email})
        if user:
            return f"User exists with email: {email}"
        return f"No user found with email: {email}"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/check_password/<email>')
def check_password(email):
    try:
        user = mongo.db.users.find_one({"email": email})
        if user:
            # Only show the format/length of the password hash, not the actual hash
            return f"Password hash length: {len(user['password'])}"
        return "User not found"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/list_all_users')
def list_all_users():
    try:
        users = list(mongo.db.users.find({}, {'email': 1, '_id': 0}))
        return {
            'user_count': len(users),
            'users': users
        }
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/check_all_collections')
def check_all_collections():
    try:
        # Check both collections
        sign_up_users = list(mongo.db.sign_up.find({}, {'email': 1, '_id': 0}))
        users = list(mongo.db.users.find({}, {'email': 1, '_id': 0}))
        
        print("\nUsers in sign_up collection:", sign_up_users)
        print("Users in users collection:", users)
        
        return {
            'sign_up_collection': sign_up_users,
            'users_collection': users
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        return {'error': str(e)}

# Debug route to check users
@app.route('/debug/users')
def debug_users():
    try:
        users = list(mongo.db.sign_up.find())
        print("\nAll users in database:")
        for user in users:
            print(f"Email: {user.get('Email Address')}")
            print(f"Fields: {list(user.keys())}")
        return {
            'user_count': len(users),
            'users': [{
                'email': user.get('Email Address'),
                'fields': list(user.keys())
            } for user in users]
        }
    except Exception as e:
        return {'error': str(e)}

if __name__ == "__main__":
    app.run(debug=True, port=5001)  # Changed port to 5001 to match frontend