from flask import Flask, render_template, request, redirect, url_for, session
from pymongo import MongoClient
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from flask import request, redirect, url_for, session
from flask import render_template, redirect, url_for, session, flash
from bson.objectid import ObjectId 
from datetime import datetime 

import re

import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a secure secret key!

# MongoDB Atlas connection
client = MongoClient("mongodb+srv://shelfspace:onlinebookstore@cluster0.msktkcg.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["ShelfSpace"]
users_collection = db["users"]
books_collection = db["books"]
deleted_users_collection = db["deleted_users"]


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = users_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['user_username'] = user.get('username', '')
            session['first_name'] = user.get('first_name', '')
            session['last_name'] = user.get('last_name', '')
            session['role'] = user.get('role', 'customer')
            # Redirect based on role
            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif session['role'] == 'seller':
                return redirect(url_for('seller_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            error = "Invalid username or password."
    return render_template('login.html', error=error)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not re.fullmatch(r'[A-Za-z]+', first_name):
            error = "First name must contain letters only."
        elif not re.fullmatch(r'[A-Za-z]+', last_name):
            error = "Last name must contain letters only."
        elif not re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email):
            error = "Invalid email format."
        elif users_collection.find_one({'email': email}):
            error = "The email address you input is already registered."
        else:
            now = datetime.utcnow()
            hashed_password = generate_password_hash(password)
            user_doc = {
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "username": email,
                "password": hashed_password,
                "role": "customer",
                "created_at": now,
                "updated_at": now
            }
            users_collection.insert_one(user_doc)
            return redirect(url_for('login'))
    return render_template('signup.html', error=error)

@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    filter_role = request.args.get('role')
    search_query = request.args.get('search_query', '').strip()

    # Base query excludes admin users
    query = {"role": {"$ne": "admin"}}

    # Apply role filter if present
    if filter_role and filter_role != "all":
        query['role'] = filter_role

    # Apply search query if present
    if search_query:
        query['$or'] = [
            {'first_name': {'$regex': search_query, '$options': 'i'}},
            {'last_name': {'$regex': search_query, '$options': 'i'}},
            {'email': {'$regex': search_query, '$options': 'i'}}
        ]
    
    users = list(users_collection.find(query))
    return render_template('admin_dashboard.html', users=users, filter_role=filter_role, search_query=search_query)


@app.route('/admin/user/<user_id>')
def admin_view_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user or user.get('role') == 'admin':
        flash("User not found.")
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_view_user.html', user=user)

#SUSPENDED or ACTIVE
@app.route('/admin/user_status/<user_id>', methods=['POST'])
def admin_user_status(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    new_status = request.form.get('new_status')
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"status": new_status}}
    )
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_user/<user_id>', methods=['POST'])
def admin_update_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    role = request.form.get('role', '').strip()
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "first_name": first_name,
            "last_name": last_name,
            "role": role
        }}
    )
    flash("User updated successfully.") 
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_seller_account/<user_id>', methods=['GET', 'POST'])
def create_seller_account(user_id):
    user = users_collection.find_one({'_id': ObjectId(user_id), 'role': 'seller'})
    if not user:
        return "Seller not found.", 404

    if request.method == 'POST':
        # Generate unique seller username
        first_name = user['first_name'].strip()
        last_name = user['last_name'].strip()
        base_username = f"SE_{first_name}{last_name}".replace(" ", "")
        email_domain = "@shelfspace.com"
        username = base_username + email_domain

        # Ensure uniqueness
        counter = 1
        while users_collection.find_one({'username': username}):
            username = f"{base_username}{counter}{email_domain}"
            counter += 1

        # Get birth month and year
        birth_month = user.get('birth_month', '')
        birth_year = str(user.get('birth_year', ''))

        # Generate password: first two letters of month (capitalized) + year
        if birth_month and birth_year:
            password_plain = birth_month[:2].upper() + birth_year
        else:
            password_plain = "Default123"  # fallback

        default_password = generate_password_hash(password_plain)

        # Update user with username, password, status active
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {
                '$set': {
                    'username': username,
                    'password': default_password,
                    'status': 'active'
                }
            }
        )
        return render_template(
            'seller_account_created.html',
            username=username,
            email=user['email'],
            password=password_plain
        )

    return render_template('create_seller_account.html', user=user)


@app.route('/admin/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    # Get the reason from the form
    reason = request.form.get('reason', '').strip()

    # Find the user to be deleted
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Prepare the archived user document
    archived_user = user.copy()
    archived_user['deleted_at'] = datetime.utcnow()
    archived_user['deleted_by'] = session.get('user_email', 'admin')
    archived_user['deletion_reason'] = reason

    # Insert into deleted_users collection
    deleted_users_collection.insert_one(archived_user)

    # Delete from users collection
    users_collection.delete_one({'_id': ObjectId(user_id)})

    flash("User deleted and archived.", "success")
    return redirect(url_for('admin_dashboard'))



@app.route('/admin/approve_seller/<user_id>', methods=['GET', 'POST'])
def admin_approve_seller(user_id):
    # Check admin session
    if session.get('role') != 'admin':
        flash("Please log in as admin to access this page.", "danger")
        return redirect(url_for('login'))

    # Find the seller user
    user = users_collection.find_one({'_id': ObjectId(user_id), 'role': 'seller'})
    if not user:
        flash("Seller not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'approve':
            username = request.form.get('username', '').strip()
            if not username:
                flash("Username is required.", "danger")
                return render_template('admin_approve_seller.html', user=user)

            # Check if username already exists
            if users_collection.find_one({'username': username}):
                flash("Username already exists. Please choose another.", "danger")
                return render_template('admin_approve_seller.html', user=user)

            # Generate default password: first two letters of birth month (uppercase) + year
            birth_month = user.get('birth_month', '')
            birth_year = str(user.get('birth_year', ''))
            if birth_month and birth_year:
                password_plain = birth_month[:2].upper() + birth_year
            else:
                password_plain = "Default123"

            hashed_password = generate_password_hash(password_plain)

            # Update the user document
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {
                    'status': 'active',
                    'username': username,
                    'password': hashed_password,
                    'updated_at': datetime.utcnow()
                }}
            )

            flash(f"APPLICATION has been approved. User will receive email for further instructions.", "success")
            return redirect(url_for('admin_dashboard'))

        elif action == 'disapprove':
            reason = request.form.get('reason', '').strip()
            if not reason:
                flash("Disapproval reason is required.", "danger")
                return render_template('admin_approve_seller.html', user=user)

            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {
                    'status': 'not_approved',
                    'disapproval_reason': reason,
                    'updated_at': datetime.utcnow()
                }}
            )
            flash("Seller disapproved.", "warning")
            return redirect(url_for('admin_dashboard'))

    # GET request: render the approval page
    return render_template('admin_approve_seller.html', user=user)


@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Fixed: redirect to login, not home

    # Initialize cart in session if not present
    if 'cart' not in session:
        session['cart'] = []

    # Handle both GET (for category select, display all) and POST (for legacy support)
    selected_category = request.args.get('category')
    if request.method == 'POST':
        selected_category = request.form.get('category')

    # If "DISPLAY ALL BOOKS" button is clicked, clear category filter
    if request.args.get('display_all'):
        selected_category = None

    # Get all unique categories for the dropdown
    categories = books_collection.distinct("categories")

    # Filter books by category if selected, else show all
    if selected_category:
        books = list(books_collection.find({"categories": selected_category}))
    else:
        books = list(books_collection.find())

    return render_template(
        'home.html',
        categories=categories,
        selected_category=selected_category,
        books=books
    )



@app.route('/view_cart')
def view_cart():
    if 'cart' not in session or not session['cart']:
        cart_books = []
    else:
        cart_books = list(books_collection.find({"BookId": {"$in": session['cart']}}))
    return render_template('cart.html', cart_books=cart_books)

@app.route('/add_to_wishlist/<book_id>', methods=['POST'])
def add_to_wishlist(book_id):
    # Implement your wish list logic here (e.g., store in session or user profile)
    flash("Added to wish list!", "success")
    return redirect(url_for('home'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/contact/seller', methods=['GET', 'POST'])
def contact_seller():
    message = None
    error = None
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        birth_month = request.form.get('birth_month', '')
        birth_year = request.form.get('birth_year', '')
        about = request.form.get('message', '').strip()

        # Basic validation
        if not name or not email or not birth_month or not birth_year or not about:
            error = "Please fill in all required fields."
        elif not re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email):
            error = "Invalid email format."
        else:
            # Split full name into first and last name (simple split)
            parts = name.split(' ', 1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ''

            # Check if seller already exists by email and role
            existing = users_collection.find_one({'email': email, 'role': 'seller'})
            if existing:
                error = "A seller with this email already exists."
            else:
                # Insert seller document with birth_month and birth_year
                users_collection.insert_one({
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'role': 'seller',
                    'status': 'pending',
                    'birth_month': birth_month,
                    'birth_year': birth_year,
                    'about': about,
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                })
                return render_template('contact_seller_thankyou.html', name=first_name)

    return render_template('contact_seller.html', error=error)


@app.route('/seller/dashboard')
def seller_dashboard():
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))
    #seller_id = session['user_id']
    # Fetch books listed by this seller
    #books = list(books_collection.find({'seller_id': seller_id}))
    # (Optional) Fetch recent orders, sales stats, etc.
    return render_template('seller_dashboard.html', role=session.get('role'))


@app.route('/seller/manage')
def seller_manage():
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))
    seller_id = session['user_id']
    # Optionally add search filter here
    books = list(books_collection.find({'seller_id': seller_id}))
    return render_template(
        'seller_manage.html',
        books=books,
        role=session.get('role')
    )


UPLOAD_FOLDER = 'static/books'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/seller/add_book', methods=['GET', 'POST'])
def add_book():
    if request.method == 'POST':
        file = request.files['thumbnail']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Save to static/books
            file_path = os.path.join(app.root_path, 'static', 'books', filename)
            file.save(file_path)
            # Store relative path in DB
            thumbnail_url = url_for('static', filename=f'books/{filename}')
        else:
            thumbnail_url = None

        title = request.form['title']
        author = request.form['author']
        categories = request.form.getlist('categories')  # getlist for multiple values
        price = float(request.form['price'])
        in_stock = int(request.form['in_stock'])

        books_collection.insert_one({
            'seller_id': session['user_id'],
            'thumbnail_url': thumbnail_url,
            'title': title,
            'author': author,
            'categories': categories,  # store as list
            'price': price,
            'in_stock': in_stock
        })
        return redirect(url_for('seller_manage'))
    return render_template('add_book.html')


@app.route('/contact/author')
def contact_author():
    return render_template('contact_author.html')


@app.route('/returns')
def returns():
    return render_template('returns.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/faqs')
def faqs():
    return render_template('faqs.html')


# Example route for adding to cart (not implemented)
@app.route('/add_to_cart/<book_id>', methods=['POST'])
def add_to_cart(book_id):
    # You would implement cart logic here
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
