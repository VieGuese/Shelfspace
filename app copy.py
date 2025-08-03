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
            # Make sure the user has a wishlist field
            if 'wishlist' not in user:
                users_collection.update_one(
                    {'_id': user['_id']},
                    {'$set': {'wishlist': []}}
                )
                # Refresh the user data after update
                user = users_collection.find_one({'_id': user['_id']})

            # Store user info in session
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


from flask import Flask, render_template, request, redirect, url_for, session, flash
from bson.objectid import ObjectId

# Existing imports and setup...

@app.route('/admin/content', methods=['GET'])
def admin_content_management():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    tab = request.args.get('tab', 'books')  # Default tab is 'books'

    # Fetch data according to tab selection
    datagrid_rows = []

    if tab == 'books':
        books = list(books_collection.find({}))
        
        for book in books:
            user = users_collection.find_one({'_id': ObjectId(book['seller_id'])}) if book.get('seller_id') else None
            datagrid_rows.append({
                'type': 'book',
                'id': str(book['_id']),
                'image': book.get('thumbnail_url', ''),
                'title': book.get('title', ''),
                'description': book.get('description', ''),
                'created_by': f"{user['first_name']} {user['last_name']}" if user else '',
                'username': user['username'] if user else '',
                'role': user['role'].capitalize() if user else '',
                'status': book.get('status', 'pending')
            })
    elif tab == 'reviews':
        reviews = list(db['reviews'].find({})) if 'reviews' in db.list_collection_names() else []
        for review in reviews:
            user = users_collection.find_one({'_id': ObjectId(review['user_id'])}) if review.get('user_id') else None
            book = books_collection.find_one({'_id': ObjectId(review['book_id'])}) if review.get('book_id') else None
            datagrid_rows.append({
                'type': 'review',
                'id': str(review['_id']),
                'image': book.get('thumbnail_url', '') if book else '',
                'title': book.get('title', '(Unknown)') if book else '',
                'description': review.get('content', ''),
                'created_by': f"{user['first_name']} {user['last_name']}" if user else '',
                'username': user['username'] if user else '',
                'role': user['role'].capitalize() if user else '',
                'status': review.get('status', 'pending')
            })
    else:
        # Redirect to default tab if invalid
        return redirect(url_for('admin_content_management', tab='books'))

    return render_template(
        'admin_content_management.html',
        datagrid_rows=datagrid_rows,
        tab=tab
    )


@app.route('/admin/content/<content_type>/<item_id>')
def admin_content_view_detail(content_type, item_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if content_type == 'book':
        book = books_collection.find_one({'_id': ObjectId(item_id)})
        if not book:
            flash("Book not found.", "danger")
            return redirect(url_for('admin_content_management', tab='books'))

        user = users_collection.find_one({'_id': ObjectId(book['seller_id'])}) if book.get('seller_id') else None
        item = {
            'type': 'book',
            'id': str(book['_id']),
            'image': book.get('thumbnail_url', ''),
            'title': book.get('title', ''),
            'description': book.get('description', ''),
            'created_by': f"{user['first_name']} {user['last_name']}" if user else '',
            'username': user['username'] if user else '',
            'role': user['role'].capitalize() if user else '',
            'status': book.get('status', 'pending')
        }

        return render_template('admin_content_detail.html', item=item)

    elif content_type == 'review':
        review = db['reviews'].find_one({'_id': ObjectId(item_id)}) if 'reviews' in db.list_collection_names() else None
        if not review:
            flash("Review not found.", "danger")
            return redirect(url_for('admin_content_management', tab='reviews'))

        user = users_collection.find_one({'_id': ObjectId(review['user_id'])}) if review.get('user_id') else None
        book = books_collection.find_one({'_id': ObjectId(review['book_id'])}) if review.get('book_id') else None
        item = {
            'type': 'review',
            'id': str(review['_id']),
            'image': book.get('thumbnail_url', '') if book else '',
            'title': book.get('title', '(Unknown)') if book else '',
            'description': review.get('content', ''),
            'created_by': f"{user['first_name']} {user['last_name']}" if user else '',
            'username': user['username'] if user else '',
            'role': user['role'].capitalize() if user else '',
            'status': review.get('status', 'pending')
        }

        return render_template('admin_content_detail.html', item=item)

    else:
        flash("Invalid content type.", "danger")
        return redirect(url_for('admin_content_management'))


# Keep the action routes from before (approve/reject for books, ok/delete for reviews)
@app.route('/admin/content/book/<item_id>/<action>', methods=['POST'])
def admin_content_book_action(item_id, action):
    if session.get('role') != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('login'))

    book = books_collection.find_one({'_id': ObjectId(item_id)})
    if not book:
        flash("Book not found.", "danger")
        return redirect(url_for('admin_content_management', tab='books'))

    if action == 'approve':
        books_collection.update_one({'_id': ObjectId(item_id)}, {'$set': {'status': 'approved'}})
        flash("Book approved.", "success")
    elif action == 'reject':
        books_collection.update_one({'_id': ObjectId(item_id)}, {'$set': {'status': 'rejected'}})
        flash("Book rejected.", "warning")
    else:
        flash("Invalid action.", "danger")

    return redirect(url_for('admin_content_view_detail', content_type='book', item_id=item_id))


@app.route('/admin/content/review/<item_id>/<action>', methods=['POST'])
def admin_content_review_action(item_id, action):
    if session.get('role') != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('login'))

    if 'reviews' not in db.list_collection_names():
        flash("No reviews collection.", "danger")
        return redirect(url_for('admin_content_management', tab='reviews'))

    review = db['reviews'].find_one({'_id': ObjectId(item_id)})
    if not review:
        flash("Review not found.", "danger")
        return redirect(url_for('admin_content_management', tab='reviews'))

    if action == 'ok':
        db['reviews'].update_one({'_id': ObjectId(item_id)}, {'$set': {'status': 'approved'}})
        flash("Review marked as OK.", "success")
    elif action == 'delete':
        db['reviews'].delete_one({'_id': ObjectId(item_id)})
        flash("Review deleted.", "warning")
        return redirect(url_for('admin_content_management', tab='reviews'))
    else:
        flash("Invalid action.", "danger")

    return redirect(url_for('admin_content_view_detail', content_type='review', item_id=item_id))







from flask import request, session, redirect, url_for, render_template
from bson.objectid import ObjectId

@app.route('/seller/orders')
def seller_manage_orders():
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    seller_id = session['user_id']
    search_term = request.args.get('search', '').strip().lower()

    # Base query: Only orders with relevant statuses
    query = {'status': {'$in': ['pending', 'confirmed', 'shipped', 'delivered']}}

    # Fetch all orders first (you can optimize)
    orders_cursor = db['orders'].find(query).sort('created_at', -1)

    seller_orders = []

    for order in orders_cursor:
        user = None
        if order.get('user_id'):
            try:
                user = users_collection.find_one({'_id': ObjectId(order['user_id'])})
            except Exception:
                user = None

        for item in order.get('books', []):
            if 'seller_id' in item and str(item['seller_id']) == seller_id:
                book = None
                if item.get('book_id'):
                    try:
                        book = books_collection.find_one({'_id': ObjectId(item['book_id'])})
                    except Exception:
                        book = None

                current_stock = book.get('in_stock', 0) if book else 0

                order_id_str = str(order.get('_id', ''))
                book_title = book.get('title', 'Unknown Book') if book else 'Unknown Book'
                user_fullname = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() if user else "Unknown User"

                # If search term is provided, filter by order_id or book_title (case insensitive)
                if search_term:
                    if (search_term not in order_id_str.lower()) and (search_term not in book_title.lower()):
                        continue  # skip this order item as it does not match the search

                seller_orders.append({
                    'order_id': order_id_str,
                    'user_id': str(user.get('_id')) if user else None,
                    'user_fullname': user_fullname,
                    'user_email': user.get('email') if user else None,
                    'book_title': book_title,
                    'in_stock': current_stock,
                    'price': item.get('price', 0),
                    'status': order.get('status', 'pending').capitalize(),
                    'ordered_at': order.get('created_at').strftime('%Y-%m-%d %H:%M:%S') if order.get('created_at') else '',
                })

    return render_template('seller_manage_orders.html', orders=seller_orders)



@app.route('/seller/order/process/<order_id>', methods=['POST'])
def process_order(order_id):
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    # Do your order processing logic here — update DB, change status, etc.
    # Example:
    db.orders.update_one({'_id': ObjectId(order_id)}, {'$set': {'status': 'processed'}})

    flash('Order processed successfully.', 'success')
    return redirect(url_for('seller_manage_orders'))


@app.route('/admin/orders')
def admin_view_orders():
    if session.get('role') != 'admin':
        flash("Please log in as admin to view orders.", "danger")
        return redirect(url_for('login'))

    # Fetch all orders - latest first
    orders = list(db['orders'].find().sort('created_at', -1))

    enriched_orders = []
    for order in orders:
        user = users_collection.find_one({'_id': ObjectId(order.get('user_id'))}) if order.get('user_id') else None

        # Prepare a display string of ordered books and quantities
        books_info = []
        for item in order.get('books', []):
            book = books_collection.find_one({'_id': ObjectId(item['book_id'])}) if item.get('book_id') else None
            title = book.get('title', 'Unknown') if book else "Unknown"
            quantity = item.get('quantity', 1)
            books_info.append(f"{title} (x{quantity})")

        enriched_orders.append({
            'order_id': str(order['_id']),
            'user_fullname': f"{user['first_name']} {user['last_name']}" if user else "Unknown Customer",
            'user_username': user['username'] if user else "",
            'books_ordered': ", ".join(books_info),
            'total_price': order.get('total_price', 0.0),
            'status': order.get('status', 'pending').capitalize(),
            'created_at': order.get('created_at').strftime('%Y-%m-%d %H:%M:%S') if order.get('created_at') else '',
        })

    return render_template('admin_orders.html', orders=enriched_orders)


@app.route('/admin/order/<order_id>')
def admin_order_detail(order_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    order = db['orders'].find_one({'_id': ObjectId(order_id)})
    if not order:
        flash("Order not found.", "danger")
        return redirect(url_for('admin_view_orders'))

    user = users_collection.find_one({'_id': ObjectId(order.get('user_id'))}) if order.get('user_id') else None

    books_info = []
    for item in order.get('books', []):
        book = books_collection.find_one({'_id': ObjectId(item.get('book_id'))}) if item.get('book_id') else None
        seller = None
        if book and book.get('seller_id'):
            seller = users_collection.find_one({'_id': ObjectId(book.get('seller_id'))})

        books_info.append({
            'title': book.get('title', 'Unknown Book') if book else 'Unknown Book',
            'quantity': item.get('quantity', 1),
            'price': item.get('price', 0),
            'thumbnail_url': book.get('thumbnail_url', '') if book else '',  # Add this line
            'seller_fullname': f"{seller['first_name']} {seller['last_name']}" if seller else "Unknown Seller",
            'seller_username': seller['username'] if seller else '',
        })

    return render_template('admin_order_detail.html',
                           order_id=order_id,
                           user=user,
                           status=order.get('status', 'Pending').capitalize(),
                           total_price=order.get('total_price', 0),
                           created_at=order.get('created_at').strftime('%Y-%m-%d %H:%M:%S') if order.get('created_at') else '',
                           books=books_info)





from bson.objectid import ObjectId

@app.context_processor
def inject_unread_count():
    if 'user_id' in session and session.get('role') in {'seller', 'customer'}:
        try:
            user_oid = ObjectId(session['user_id'])
        except Exception:
            return {'unread_count': 0}

        count = db.messages.count_documents({"to_user_id": user_oid, "read": False})
        return {'unread_count': count}
    return {'unread_count': 0}



@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    wishlist = user.get('wishlist', []) if user else []

    selected_category = request.args.get('category')
    if request.method == 'POST':
        selected_category = request.form.get('category')

    if request.args.get('display_all'):
        selected_category = None

    categories = books_collection.distinct("categories")

    filter_query = {"status": "approved"}
    if selected_category:
        filter_query["categories"] = selected_category

    # Fetch all matching books, sorted newest first
    books = list(books_collection.find(filter_query).sort('created_at', -1))

    return render_template(
        'home.html',
        categories=categories,
        selected_category=selected_category,
        books=books,
        wishlist=wishlist
    )



@app.route('/add_to_wishlist/<book_id>', methods=['POST'])
def add_to_wishlist(book_id):
    # Make sure user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = users_collection.find_one({'_id': ObjectId(user_id)})

    if not user:
        return redirect(url_for('login'))  # safety check

    # Convert book_id to string to match stored IDs
    book_id = str(book_id)

    wishlist = user.get('wishlist', [])

    # Avoid duplicate entries
    if book_id not in wishlist:
        wishlist.append(book_id)
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'wishlist': wishlist}}
        )

    # Redirect back to home page
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

    seller_id = session['user_id']

    # Aggregate orders containing books sold by this seller with status pending or new
    pipeline = [
        { '$match': { 'status': 'pending' } },
        { '$unwind': '$books' },
        { '$match': { 'books.seller_id': seller_id } },
        { '$count': 'new_orders_count' }
    ]
    result = list(db['orders'].aggregate(pipeline))
    new_orders_count = result[0]['new_orders_count'] if result else 0

    # Pass count to template
    return render_template('seller_dashboard.html', new_orders_count=new_orders_count)



@app.route('/seller/manage')
def seller_manage():
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    seller_id = session['user_id']  # current logged-in user ID (seller)

    # Fetch only books added by the current seller
    books = list(books_collection.find({'seller_id': seller_id}))

    return render_template('seller_manage.html', books=books, role=session.get('role'))




import os
from datetime import datetime
from flask import request, redirect, url_for, flash, render_template, session
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/books'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/seller/add_book', methods=['GET', 'POST'])
def add_book():
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('thumbnail')
        if not file or file.filename == '':
            flash("Thumbnail image is required.", "danger")
            return render_template('add_book.html')  # Re-display form with message

        if not allowed_file(file.filename):
            flash("Unsupported image format. Allowed: png, jpg, jpeg, gif.", "danger")
            return render_template('add_book.html')

        filename = secure_filename(file.filename)
        timestamp = int(datetime.utcnow().timestamp())
        filename = f"{timestamp}_{filename}"

        save_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
        os.makedirs(save_dir, exist_ok=True)
        filepath = os.path.join(save_dir, filename)
        file.save(filepath)

        thumbnail_url = url_for('static', filename=f'books/{filename}')

        # Retrieve and validate other form fields
        title = request.form.get('title', '').strip()
        author = request.form.get('author', '').strip()
        categories = request.form.getlist('categories')  # list from checkboxes
        price_raw = request.form.get('price', '0').strip()
        in_stock_raw = request.form.get('in_stock', '0').strip()

        try:
            price = float(price_raw)
        except ValueError:
            flash("Invalid price value.", "danger")
            return render_template('add_book.html')

        try:
            in_stock = int(in_stock_raw)
            if in_stock < 0:
                raise ValueError
        except ValueError:
            flash("Invalid stock value.", "danger")
            return render_template('add_book.html')

        # Insert into MongoDB
        books_collection.insert_one({
            'seller_id': session['user_id'],
            'thumbnail_url': thumbnail_url,
            'title': title,
            'author': author,
            'categories': categories,
            'price': price,
            'in_stock': in_stock,
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        })

        flash("Book added successfully.", "success")
        return redirect(url_for('seller_manage'))

    # GET request
    return render_template('add_book.html')







import os
from datetime import datetime
from flask import request, redirect, url_for, flash, render_template, session
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/books'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/seller/book/edit/<book_id>', methods=['GET', 'POST'])
def edit_book(book_id):
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    seller_id = session['user_id']

    try:
        book_oid = ObjectId(book_id)
    except Exception:
        flash("Invalid book ID.", "danger")
        return redirect(url_for('seller_manage'))

    book = books_collection.find_one({"_id": book_oid, "seller_id": seller_id})
    if not book:
        flash("Book not found or access denied.", "danger")
        return redirect(url_for('seller_manage'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        author = request.form.get('author', '').strip()
        categories_raw = request.form.get('categories', '').strip()
        categories = [c.strip() for c in categories_raw.split(',') if c.strip()]
        price_raw = request.form.get('price', '').strip()
        increment_raw = request.form.get('increment_stock', '0').strip()

        try:
            price = float(price_raw)
        except ValueError:
            flash("Invalid price value.", "danger")
            return render_template('seller_edit_book.html', book=book, categories_str=categories_raw)

        try:
            increment = int(increment_raw)
            if increment < 0:
                increment = 0
        except ValueError:
            increment = 0

        new_stock = max(0, book.get('in_stock', 0) + increment)

        file = request.files.get('thumbnail')
        thumbnail_url = book.get('thumbnail_url', '')  # default to old URL

        if file and file.filename != '':
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = int(datetime.utcnow().timestamp())
                filename = f"{book_id}_{timestamp}_{filename}"

                save_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
                os.makedirs(save_dir, exist_ok=True)
                filepath = os.path.join(save_dir, filename)
                file.save(filepath)

                thumbnail_url = url_for('static', filename=f'books/{filename}') + f"?v={timestamp}"
            else:
                flash("Unsupported image format. Allowed: png, jpg, jpeg, gif.", "danger")
                return render_template('seller_edit_book.html', book=book, categories_str=categories_raw)

        # Update in DB
        books_collection.update_one(
            {"_id": book_oid, "seller_id": seller_id},
            {"$set": {
                "title": title,
                "author": author,
                "categories": categories,
                "price": price,
                "in_stock": new_stock,
                "thumbnail_url": thumbnail_url,
                "updated_at": datetime.utcnow()
            }}
        )

        # Refresh book data for template
        book = books_collection.find_one({"_id": book_oid, "seller_id": seller_id})
        categories_str = ', '.join(book.get('categories', []))

        flash("Book updated successfully.", "success")
        return render_template('seller_edit_book.html', book=book, categories_str=categories_str)

    # GET request: render form with existing data
    categories_str = ', '.join(book.get('categories', []))
    return render_template('seller_edit_book.html', book=book, categories_str=categories_str)








@app.route('/contact/author', methods=['GET', 'POST'])
def contact_author():
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
            existing = users_collection.find_one({'email': email, 'role': 'author'})
            if existing:
                error = "An author with this email already exists."
            else:
                # Insert seller document with birth_month and birth_year
                users_collection.insert_one({
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'role': 'author',
                    'status': 'pending',
                    'birth_month': birth_month,
                    'birth_year': birth_year,
                    'about': about,
                    'created_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow()
                })
                return render_template('contact_author_thankyou.html', name=first_name)

    return render_template('contact_author.html', error=error)


@app.route('/admin/approve_author/<user_id>', methods=['GET', 'POST'])
def admin_approve_author(user_id):
    # Check admin session
    if session.get('role') != 'admin':
        flash("Please log in as admin to access this page.", "danger")
        return redirect(url_for('login'))

    # Find the author user
    user = users_collection.find_one({'_id': ObjectId(user_id), 'role': 'author'})
    if not user:
        flash("Author not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'approve':
            username = request.form.get('username', '').strip()
            if not username:
                flash("Username is required.", "danger")
                return render_template('admin_approve_author.html', user=user)

            # Check if username already exists
            if users_collection.find_one({'username': username}):
                flash("Username already exists. Please choose another.", "danger")
                return render_template('admin_approve_author.html', user=user)

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
                return render_template('admin_approve_author.html', user=user)

            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {
                    'status': 'not_approved',
                    'disapproval_reason': reason,
                    'updated_at': datetime.utcnow()
                }}
            )
            flash("Author disapproved.", "warning")
            return redirect(url_for('admin_dashboard'))

    # GET request: render the approval page
    return render_template('admin_approve_author.html', user=user)



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


from flask import request, redirect, url_for, session, flash, render_template
from bson.objectid import ObjectId

@app.route('/add_to_cart/<book_id>', methods=['POST'])
def add_to_cart(book_id):
    if 'user_id' not in session:
        flash("Please log in to add items to your cart.", "danger")
        return redirect(url_for('login'))

    if 'cart' not in session:
        session['cart'] = []

    if book_id not in session['cart']:
        session['cart'].append(book_id)
        session.modified = True

    return redirect(url_for('home'))

@app.route('/view_cart')
def view_cart():
    if 'cart' not in session or not session['cart']:
        cart_books = []
    else:
        try:
            object_ids = [ObjectId(bid) for bid in session['cart']]
        except:
            object_ids = []
        cart_books = list(books_collection.find({"_id": {"$in": object_ids}}))

    return render_template('view_cart.html', cart_books=cart_books)

@app.route('/process_cart_order', methods=['POST'])
def process_cart_order():
    if 'cart' not in session or not session['cart']:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('view_cart'))

    selected_book_ids = request.form.getlist('selected_books')
    action = request.form.get('action')

    if not selected_book_ids:
        flash("Please select at least one book to proceed.", "warning")
        return redirect(url_for('view_cart'))

    # Only keep valid ObjectIds (as strings)
    valid_ids = []
    for bid in selected_book_ids:
        try:
            valid_ids.append(str(ObjectId(bid)))
        except:
            pass

    if not valid_ids:
        flash("Invalid selection.", "danger")
        return redirect(url_for('view_cart'))

    if action == 'order':
        books_to_order = []
        total_price = 0
        for bid in valid_ids:
            quantity_str = request.form.get(f'quantity_{bid}')
            try:
                quantity = int(quantity_str)
                if quantity <= 0:
                    raise ValueError
            except:
                flash(f"Invalid quantity for some books.", "danger")
                return redirect(url_for('view_cart'))

            book = books_collection.find_one({'_id': ObjectId(bid)})
            if not book:
                flash(f"Book with ID {bid} not found.", "danger")
                return redirect(url_for('view_cart'))

            if quantity > book.get('in_stock', 0):
                flash(f"Cannot order {quantity} of '{book['title']}'. Only {book.get('in_stock', 0)} in stock.", "danger")
                return redirect(url_for('view_cart'))

            new_stock = book.get('in_stock', 0) - quantity
            books_collection.update_one({'_id': ObjectId(bid)}, {'$set': {'in_stock': new_stock}})

            # Add to order's books list WITH seller_id
            books_to_order.append({
                'book_id': ObjectId(bid),
                'quantity': quantity,
                'price': book.get('price', 0),
                'seller_id': book.get('seller_id')  # Make sure this matches seller_id stored in your books collection (usually a string or ObjectId)
            })

            # Calculate total price
            total_price += book.get('price', 0) * quantity

            # Remove from session cart after ordering
            if bid in session['cart']:
                session['cart'].remove(bid)
                session.modified = True

        # === Save the order with seller_id per book ===
        if books_to_order:
            db['orders'].insert_one({
                'user_id': ObjectId(session['user_id']),
                'books': books_to_order,
                'total_price': total_price,
                'status': 'pending',
                'created_at': datetime.utcnow()
            })

        flash("Order placed successfully!", 'success')
        return redirect(url_for('view_cart'))

    elif action == 'delete':
        for bid in valid_ids:
            if bid in session['cart']:
                session['cart'].remove(bid)
                session.modified = True
        flash("Selected books removed from cart.", "warning")
        return redirect(url_for('view_cart'))

    else:
        flash("Invalid action.", "danger")
        return redirect(url_for('view_cart'))

from flask import (
    request, render_template, redirect, url_for,
    session, flash
)
from bson.objectid import ObjectId
from datetime import datetime

@app.route('/seller/message/<order_id>/<buyer_id>', methods=['GET', 'POST'])
def seller_message(order_id, buyer_id):
    # Check if logged in and seller role
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    seller_id = session['user_id']

    # Validate ObjectIds
    try:
        buyer_oid = ObjectId(buyer_id)
        order_oid = ObjectId(order_id)
        seller_oid = ObjectId(seller_id)
    except Exception:
        flash("Invalid IDs provided.", "danger")
        return redirect(url_for('seller_manage_orders'))

    # Lookup buyer user
    buyer = users_collection.find_one({'_id': buyer_oid})
    if not buyer:
        flash("Buyer not found.", "danger")
        return redirect(url_for('seller_manage_orders'))

    # Lookup order
    order = db['orders'].find_one({'_id': order_oid})
    if not order:
        flash("Order not found.", "danger")
        return redirect(url_for('seller_manage_orders'))

    # Optional: Get the book title according to this seller's book in the order
    book_title = "the book"
    for item in order.get('books', []):
        if str(item.get('seller_id')) == seller_id:
            book = books_collection.find_one({'_id': ObjectId(item['book_id'])}) if item.get('book_id') else None
            if book:
                book_title = book.get('title', 'the book')
                break

    if request.method == 'POST':
        message_body = request.form.get('message', '').strip()
        if not message_body:
            flash("Message cannot be empty.", "danger")
            return render_template(
                'seller_reply_message.html',
                buyer_email=buyer.get('email', ''),
                buyer_name=f"{buyer.get('first_name', '')} {buyer.get('last_name', '')}",
                book_title=book_title,
                request=request
            )

        # Create message document
        message_doc = {
            "from_user_id": seller_oid,
            "to_user_id": buyer_oid,
            "order_id": order_oid,
            "message": message_body,
            "timestamp": datetime.utcnow(),
            "read": False,
            "attachments": []
        }

        try:
            db.messages.insert_one(message_doc)
        except Exception as e:
            flash(f"An error occurred saving the message: {e}", "danger")
            return render_template(
                'seller_reply_message.html',
                buyer_email=buyer.get('email', ''),
                buyer_name=f"{buyer.get('first_name', '')} {buyer.get('last_name', '')}",
                book_title=book_title,
                request=request
            )

        flash("Your message has been sent to the buyer.", "success")
        return redirect(url_for('seller_manage_orders'))

    # GET request: render the send message form pre-filled with buyer info
    return render_template(
        'seller_reply_message.html',
        buyer_email=buyer.get('email', ''),
        buyer_name=f"{buyer.get('first_name', '')} {buyer.get('last_name', '')}",
        book_title=book_title,
        request=request
    )


from flask import session, redirect, url_for, flash, render_template
from bson.objectid import ObjectId

@app.route('/seller/messages')
def seller_messages():
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    try:
        seller_oid = ObjectId(session['user_id'])
    except Exception:
        flash("Invalid user ID in session.", "danger")
        return redirect(url_for('login'))

    messages = list(db.messages.find({"to_user_id": seller_oid}).sort("timestamp", -1))

    enriched_messages = []
    for msg in messages:
        buyer = users_collection.find_one({'_id': msg.get('from_user_id')})
        buyer_name = f"{buyer.get('first_name', '')} {buyer.get('last_name', '')}" if buyer else "Unknown Buyer"
        buyer_email = buyer.get('email', 'Unknown') if buyer else "Unknown"

        enriched_messages.append({
            '_id': msg.get('_id'),
            'order_id': msg.get('order_id'),
            'message': msg.get('message'),
            'timestamp': msg.get('timestamp'),
            'buyer_name': buyer_name,
            'buyer_email': buyer_email,
            'attachments': msg.get('attachments', []),
            'in_reply_to': msg.get('in_reply_to'),
            'read': msg.get('read', False),
        })

    # Mark unread as read after fetching
    db.messages.update_many({
        "to_user_id": seller_oid,
        "read": False
    }, {"$set": {"read": True}})

    return render_template('seller_messages.html', messages=enriched_messages)





from flask import render_template, redirect, url_for, session, flash
from bson.objectid import ObjectId

@app.route('/seller/messages/<message_id>')
def view_seller_message(message_id):
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    seller_oid = ObjectId(session['user_id'])

    try:
        msg_oid = ObjectId(message_id)
    except Exception:
        flash("Invalid message ID.", "danger")
        return redirect(url_for('seller_messages'))

    msg = db.messages.find_one({"_id": msg_oid, "to_user_id": seller_oid})
    if not msg:
        flash("Message not found or access denied.", "danger")
        return redirect(url_for('seller_messages'))

    buyer = users_collection.find_one({'_id': msg.get('from_user_id')}) if msg.get('from_user_id') else None
    buyer_name = f"{buyer.get('first_name', '')} {buyer.get('last_name', '')}" if buyer else 'Unknown Buyer'
    buyer_email = buyer.get('email', 'Unknown') if buyer else 'Unknown'
    buyer_id = str(buyer['_id']) if buyer else ''

    # Mark as read
    if not msg.get('read', False):
        db.messages.update_one({'_id': msg_oid}, {'$set': {'read': True}})

    return render_template(
        'view_seller_reply_message.html',
        message=msg,
        buyer_name=buyer_name,
        buyer_email=buyer_email,
        buyer_id=buyer_id
    )




@app.route('/seller/messages/delete/<message_id>', methods=['POST'])
def delete_seller_message(message_id):
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    seller_oid = ObjectId(session['user_id'])
    result = db.messages.delete_one({"_id": ObjectId(message_id), "to_user_id": seller_oid})

    if result.deleted_count == 1:
        flash("Message deleted successfully.", "success")
    else:
        flash("Message not found or you cannot delete it.", "danger")

    return redirect(url_for('seller_messages'))


@app.route('/customer/messages')
def customer_messages():
    if 'user_id' not in session or session.get('role') != 'customer':
        return redirect(url_for('login'))

    user_oid = ObjectId(session['user_id'])

    msgs = list(db.messages.find({"to_user_id": user_oid}).sort("timestamp", -1))

    enriched_msgs = []
    for msg in msgs:
        sender = users_collection.find_one({'_id': msg.get('from_user_id')})
        sender_email = sender.get('email', 'Unknown') if sender else 'Unknown'
        msg['_sender_email'] = sender_email
        enriched_msgs.append(msg)

    db.messages.update_many(
        {"to_user_id": user_oid, "read": False},
        {"$set": {"read": True}}
    )

    return render_template('customer_messages.html', messages=enriched_msgs)






from flask import request, redirect, url_for, session, flash, render_template
from bson.objectid import ObjectId
from datetime import datetime

@app.route('/customer/message/reply/<message_id>', methods=['GET', 'POST'])
def customer_reply_message(message_id):
    if 'user_id' not in session or session.get('role') != 'customer':
        return redirect(url_for('login'))

    user_oid = ObjectId(session['user_id'])

    try:
        msg_oid = ObjectId(message_id)
    except Exception:
        flash("Invalid message ID.", "danger")
        return redirect(url_for('customer_messages'))

    orig_msg = db.messages.find_one({"_id": msg_oid})
    if not orig_msg or orig_msg.get('to_user_id') != user_oid:
        flash("Message not found or unauthorized.", "danger")
        return redirect(url_for('customer_messages'))

    # Ensure seller_oid is ObjectId to prevent mismatches
    seller_oid = ObjectId(orig_msg.get('from_user_id'))

    if request.method == 'POST':
        reply_text = request.form.get('message', '').strip()
        if not reply_text:
            flash("Message cannot be empty", "danger")
            return render_template('customer_reply_message.html', original_message=orig_msg)

        reply_doc = {
            "from_user_id": user_oid,
            "to_user_id": seller_oid,
            "order_id": orig_msg.get('order_id'),
            "message": reply_text,
            "timestamp": datetime.utcnow(),
            "read": False,
            "attachments": [],  # adapt if you add file uploads here
            "in_reply_to": orig_msg['_id']
        }
        db.messages.insert_one(reply_doc)
        flash("Your reply has been sent.", "success")
        return redirect(url_for('customer_messages'))

    return render_template('customer_reply_message.html', original_message=orig_msg)





from bson.objectid import ObjectId
from flask import flash

@app.route('/customer/messages/<message_id>')
def view_message(message_id):
    if 'user_id' not in session or session.get('role') != 'customer':
        return redirect(url_for('login'))

    user_oid = ObjectId(session['user_id'])

    # Find message by id and confirm it’s for this user
    msg = db.messages.find_one({"_id": ObjectId(message_id), "to_user_id": user_oid})
    if not msg:
        flash("Message not found or access denied.", "danger")
        return redirect(url_for('customer_messages'))

    # Lookup sender info for display
    sender = users_collection.find_one({'_id': msg['from_user_id']}) if msg.get('from_user_id') else None
    sender_email = sender.get('email', 'Unknown') if sender else 'Unknown'

    # Optionally mark message as read if unread
    if not msg.get('read', False):
        db.messages.update_one({'_id': ObjectId(message_id)}, {'$set': {'read': True}})

    return render_template('view_message.html', message=msg, sender_email=sender_email)




@app.route('/customer/messages/delete/<message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session or session.get('role') != 'customer':
        return redirect(url_for('login'))

    user_oid = ObjectId(session['user_id'])
    result = db.messages.delete_one({"_id": ObjectId(message_id), "to_user_id": user_oid})

    if result.deleted_count == 1:
        flash("Message deleted successfully.", "success")
    else:
        flash("Message not found or you cannot delete it.", "danger")

    return redirect(url_for('customer_messages'))




@app.route('/seller/book/delete/<book_id>', methods=['POST'])
def delete_book(book_id):
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    seller_id = session['user_id']

    try:
        book_oid = ObjectId(book_id)
    except:
        flash("Invalid book ID.", "danger")
        return redirect(url_for('seller_manage'))

    result = books_collection.delete_one({"_id": book_oid, "seller_id": seller_id})

    if result.deleted_count:
        flash("Book deleted successfully.", "success")
    else:
        flash("Book not found or access denied.", "danger")

    return redirect(url_for('seller_manage'))






@app.route('/seller/conversation/<order_id>/<buyer_id>')
def seller_conversation(order_id, buyer_id):
    if 'user_id' not in session or session.get('role') != 'seller':
        return redirect(url_for('login'))

    seller_id = ObjectId(session['user_id'])

    # Get all messages with this order_id between seller and buyer
    messages = list(db.messages.find({
        "order_id": ObjectId(order_id),
        "$or": [
            {"from_user_id": seller_id, "to_user_id": ObjectId(buyer_id)},
            {"from_user_id": ObjectId(buyer_id), "to_user_id": seller_id}
        ]
    }).sort("timestamp", 1))

    # You can enrich messages here as needed

    return render_template('seller_conversation.html', messages=messages, order_id=order_id, buyer_id=buyer_id)



import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'static/books'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/customer/message/reply/<message_id>', methods=['GET', 'POST'])
def reply_message(message_id):
    if 'user_id' not in session or session.get('role') != 'customer':
        return redirect(url_for('login'))

    orig_msg = db.messages.find_one({"_id": ObjectId(message_id)})
    if not orig_msg or orig_msg.get('to_user_id') != ObjectId(session['user_id']):
        flash("Message not found or unauthorized.", "danger")
        return redirect(url_for('customer_messages'))

    if request.method == 'POST':
        reply_text = request.form.get('reply_text', '').strip()
        files = request.files.getlist('attachments')
        attachment_urls = []

        save_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
        os.makedirs(save_dir, exist_ok=True)

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(save_dir, filename))
                url = url_for('static', filename=f'uploads/{filename}')
                attachment_urls.append(url)

        reply_doc = {
            "from_user_id": ObjectId(session['user_id']),
            "to_user_id": orig_msg['from_user_id'],  # seller
            "order_id": orig_msg['order_id'],
            "message": reply_text,
            "timestamp": datetime.utcnow(),
            "attachments": attachment_urls,
            "in_reply_to": ObjectId(message_id)
        }

        db.messages.insert_one(reply_doc)
        flash("Your reply has been sent.", "success")
        return redirect(url_for('customer_messages'))

    return render_template('reply_message.html', original_message=orig_msg)

if __name__ == '__main__':
    app.run(debug=True)