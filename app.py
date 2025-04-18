from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import random

# ML imports for preference matching
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Faker for generating fake users
from faker import Faker

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a strong secret key for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///popconnect.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Regular expression for validating emails
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# ---------- Models ----------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    preferences = db.Column(db.String(1000), nullable=True)  # Increased size for more preferences

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_requests')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_requests')

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# ---------- Helper Functions ----------

def validate_email(email):
    return bool(EMAIL_REGEX.match(email))

def validate_password(password):
    return (
        len(password) >= 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password)
    )

# Enhanced preference options with categories
preference_categories = {
    "Movies & TV": [
        "Marvel", "DC", "Harry Potter", "Stranger Things", "The Witcher",
        "Star Wars", "Star Trek", "Lord of the Rings", "Game of Thrones",
        "The Office", "Friends", "Breaking Bad", "The Mandalorian"
    ],
    "Music": [
        "BTS", "K-pop", "Rock", "Pop", "Classical", "Jazz", "Hip-Hop", "R&B",
        "Country", "EDM", "Metal", "Indie", "Alternative", "Rap", "Reggae"
    ],
    "Books & Authors": [
        "J.K. Rowling", "Stephen King", "George R.R. Martin", "J.R.R. Tolkien",
        "Agatha Christie", "Dan Brown", "John Green", "Margaret Atwood",
        "Haruki Murakami", "Neil Gaiman", "Brandon Sanderson", "Jane Austen"
    ],
    "Genres": [
        "Sci-Fi", "Fantasy", "Mystery", "Thriller", "Documentary", "Comedy",
        "Drama", "Action", "Adventure", "Romance", "Horror", "Historical",
        "Biography", "Self-Help", "Science"
    ],
    "Hobbies": [
        "Gaming", "Reading", "Photography", "Cooking", "Traveling", "Hiking",
        "Painting", "Singing", "Dancing", "Yoga", "Meditation", "Sports",
        "Chess", "Programming", "Gardening"
    ]
}

def get_friend_recommendations(current_user):
    """Use a simple ML approach (CountVectorizer & cosine similarity) 
    to match users based on their preferences."""
    if not current_user.preferences:
        return []
    
    users = User.query.filter(User.preferences != None, User.id != current_user.id).all()
    if not users:
        return []
    
    # Create list of user ids and corresponding preference text
    user_ids = [current_user.id]
    docs = [current_user.preferences]
    
    for user in users:
        user_ids.append(user.id)
        docs.append(user.preferences)
    
    # Vectorize the preferences text
    try:
        vectorizer = CountVectorizer(tokenizer=lambda txt: txt.split(','))
        tf_matrix = vectorizer.fit_transform(docs)
        
        # Compute cosine similarity (compare first user against all others)
        cosine_sim = cosine_similarity(tf_matrix[0:1], tf_matrix).flatten()
        scores = list(zip(user_ids[1:], cosine_sim[1:]))
        
        # Sort by similarity descending and filter out zero matches
        scores = sorted(scores, key=lambda x: x[1], reverse=True)
        scores = [s for s in scores if s[1] > 0]
        
        # Return top 5 recommendations
        recommendations = []
        for user_id, score in scores[:5]:
            user = User.query.get(user_id)
            if user:
                recommendations.append((user, round(score * 100, 2)))  # Convert to percentage
        return recommendations
    except Exception as e:
        print(f"Error in recommendation: {e}")
        return []

def generate_fake_users(n=100):
    """Generate fake users with random preferences if there are fewer than n users."""
    fake = Faker()
    current_count = User.query.count()
    if current_count >= n:
        return
        
    for _ in range(n - current_count):
        username = fake.user_name() + str(random.randint(1, 999))
        email = fake.email()
        password = generate_password_hash("Password123")  # default password for fake users
        
        # Generate random preferences from each category
        prefs = []
        for category, options in preference_categories.items():
            prefs.extend(random.sample(options, random.randint(1, 3)))
        
        user = User(
            username=username,
            email=email,
            password=password,
            preferences=",".join(prefs)
        )
        db.session.add(user)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error generating fake users: {e}")

# ---------- Routes ----------

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        errors = []
        if not username:
            errors.append('Username is required')
        elif len(username) < 3:
            errors.append('Username must be at least 3 characters')
        elif User.query.filter_by(username=username).first():
            errors.append('Username already taken')

        if not email:
            errors.append('Email is required')
        elif not validate_email(email):
            errors.append('Invalid email format')
        elif User.query.filter_by(email=email).first():
            errors.append('Email already registered')

        if not password:
            errors.append('Password is required')
        elif not validate_password(password):
            errors.append('Password must be at least 8 characters with uppercase, lowercase, and a number')
        elif password != confirm_password:
            errors.append('Passwords do not match')

        if errors:
            for error in errors:
                flash(error, 'error')
        else:
            try:
                hashed_password = generate_password_hash(password)
                user = User(username=username, email=email, password=hashed_password)
                db.session.add(user)
                db.session.commit()
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred during registration.', 'error')
                app.logger.error(f"Registration error: {str(e)}")

    return render_template_string(SIGNUP_HTML, base_css=base_css)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            if not user.preferences:
                return redirect(url_for('preferences'))
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')

    return render_template_string(LOGIN_HTML, base_css=base_css)

@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        selected = request.form.getlist('preferences')
        if not selected:
            flash('Please select at least one preference.', 'error')
        else:
            user.preferences = ",".join(selected)
            try:
                db.session.commit()
                flash('Preferences updated successfully! Recommendations will refresh.', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while updating preferences.', 'error')
                app.logger.error(f"Preferences error: {str(e)}")

    # Get current preferences if any
    current_prefs = set(user.preferences.split(',')) if user.preferences else set()
    return render_template_string(
        PREFERENCES_HTML, 
        categories=preference_categories, 
        current_prefs=current_prefs, 
        base_css=base_css
    )

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    if not user.preferences:
        flash('Please set your preferences to get friend recommendations.', 'info')
        return redirect(url_for('preferences'))

    # Generate fake users if needed (only for demo purposes)
    generate_fake_users(100)
    
    recommendations = get_friend_recommendations(user)
    return render_template_string(DASHBOARD_HTML, recommendations=recommendations, base_css=base_css)

@app.route('/friends')
def friends():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    
    try:
        user = User.query.get(session['user_id'])
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
        
        # Get friend requests where the user is the receiver
        incoming = FriendRequest.query.filter_by(
            receiver_id=session['user_id'], 
            status='pending'
        ).all()
        
        # Get accepted friend requests (both directions)
        accepted_sent = FriendRequest.query.filter_by(
            sender_id=session['user_id'], 
            status='accepted'
        ).all()
        accepted_received = FriendRequest.query.filter_by(
            receiver_id=session['user_id'], 
            status='accepted'
        ).all()
        
        friends_list = []
        for req in accepted_sent:
            if req.receiver:  # Check if receiver exists
                friends_list.append(req.receiver)
        for req in accepted_received:
            if req.sender:  # Check if sender exists
                friends_list.append(req.sender)
        
        # Remove duplicates
        friends_list = list({friend.id: friend for friend in friends_list}.values())
        
        return render_template_string(
            FRIENDS_HTML, 
            incoming=incoming, 
            friends_list=friends_list, 
            base_css=base_css
        )
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while loading friends page.', 'error')
        app.logger.error(f"Error in friends route: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/send_friend_request/<int:receiver_id>')
def send_friend_request(receiver_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    
    try:
        sender_id = session['user_id']
        if sender_id == receiver_id:
            flash("You can't send a friend request to yourself!", 'error')
            return redirect(url_for('dashboard'))
        
        # Check if receiver exists
        receiver = User.query.get(receiver_id)
        if not receiver:
            flash('User not found.', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if friend request already exists
        existing = FriendRequest.query.filter_by(
            sender_id=sender_id, 
            receiver_id=receiver_id
        ).first()
        
        if existing:
            flash('Friend request already sent.', 'info')
        else:
            # Check if they're already friends
            already_friends = FriendRequest.query.filter(
                ((FriendRequest.sender_id == sender_id) & (FriendRequest.receiver_id == receiver_id)) |
                ((FriendRequest.sender_id == receiver_id) & (FriendRequest.receiver_id == sender_id)),
                FriendRequest.status == 'accepted'
            ).first()
            
            if already_friends:
                flash('You are already friends with this user.', 'info')
            else:
                new_request = FriendRequest(
                    sender_id=sender_id, 
                    receiver_id=receiver_id, 
                    status='pending'
                )
                db.session.add(new_request)
                db.session.commit()
                flash('Friend request sent!', 'success')
        
        return redirect(request.referrer or url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while sending friend request.', 'error')
        app.logger.error(f"Error in send_friend_request: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/accept_friend_request/<int:request_id>')
def accept_friend_request(request_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    
    try:
        req = FriendRequest.query.get(request_id)
        if req and req.receiver_id == session['user_id']:
            req.status = 'accepted'
            db.session.commit()
            flash('Friend request accepted!', 'success')
        else:
            flash('Invalid friend request.', 'error')
        
        return redirect(url_for('friends'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while accepting friend request.', 'error')
        app.logger.error(f"Error in accept_friend_request: {str(e)}")
        return redirect(url_for('friends'))

@app.route('/chat/<int:friend_id>', methods=['GET', 'POST'])
def chat(friend_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    
    try:
        current_user = User.query.get(session['user_id'])
        if not current_user:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
        
        friend = User.query.get(friend_id)
        if not friend:
            flash('Friend not found.', 'error')
            return redirect(url_for('friends'))
        
        # Check if users are friends
        are_friends = FriendRequest.query.filter(
            ((FriendRequest.sender_id == current_user.id) & (FriendRequest.receiver_id == friend.id)) |
            ((FriendRequest.sender_id == friend.id) & (FriendRequest.receiver_id == current_user.id)),
            FriendRequest.status == 'accepted'
        ).first()
        
        if not are_friends:
            flash('You can only chat with friends.', 'error')
            return redirect(url_for('friends'))

        if request.method == 'POST':
            msg = request.form.get('message', '').strip()
            if msg:
                chat_msg = ChatMessage(
                    sender_id=current_user.id, 
                    receiver_id=friend.id, 
                    message=msg
                )
                db.session.add(chat_msg)
                db.session.commit()
                return redirect(url_for('chat', friend_id=friend_id))
            else:
                flash('Enter a message.', 'error')

        # Retrieve chat history
        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == friend.id)) |
            ((ChatMessage.sender_id == friend.id) & (ChatMessage.receiver_id == current_user.id))
        ).order_by(ChatMessage.timestamp).all()
        
        return render_template_string(
            CHAT_HTML, 
            friend=friend, 
            messages=messages, 
            base_css=base_css
        )
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while loading chat.', 'error')
        app.logger.error(f"Error in chat route: {str(e)}")
        return redirect(url_for('friends'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - Page Not Found</title>
        <style>{{ base_css }}</style>
    </head>
    <body>
        <div class="container">
            <h2>404 - Page Not Found</h2>
            <p>The page you requested could not be found.</p>
            <a href="{{ url_for('index') }}">Return Home</a>
        </div>
    </body>
    </html>
    ''', base_css=base_css), 404

@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>500 - Server Error</title>
        <style>{{ base_css }}</style>
    </head>
    <body>
        <div class="container">
            <h2>500 - Internal Server Error</h2>
            <p>Something went wrong. Please try again later.</p>
            <a href="{{ url_for('index') }}">Return Home</a>
        </div>
    </body>
    </html>
    ''', base_css=base_css), 500

# ---------- HTML Templates ----------

# Base CSS with a blue-purple theme and modern styling
base_css = '''
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: #fff;
    margin: 0;
    padding: 0;
    min-height: 100vh;
}
.container {
    max-width: 800px;
    margin: 20px auto;
    padding: 30px;
    background: rgba(255,255,255,0.1);
    border-radius: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    animation: fadeIn 0.8s ease-in-out;
}
h1, h2, h3 {
    text-align: center;
    margin-bottom: 25px;
    color: #fff;
}
input[type="text"], 
input[type="email"], 
input[type="password"], 
textarea, 
select {
    width: 100%;
    padding: 12px;
    margin: 8px 0 16px;
    border: none;
    border-radius: 10px;
    box-sizing: border-box;
    background: rgba(255,255,255,0.9);
}
button, .btn {
    display: inline-block;
    background-color: #5a67d8;
    color: white;
    padding: 12px 20px;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    font-size: 16px;
    text-align: center;
    text-decoration: none;
    transition: background-color 0.3s;
}
button:hover, .btn:hover {
    background-color: #434190;
}
.switch, .small {
    text-align: center;
    margin-top: 20px;
    font-size: 0.9em;
}
a {
    color: #e0e0e0;
    text-decoration: underline;
}
a:hover {
    color: #fff;
}
.alert {
    padding: 12px;
    margin-bottom: 15px;
    border-radius: 5px;
    text-align: center;
}
.alert.error { background-color: #e53e3e; }
.alert.success { background-color: #48bb78; }
.alert.info { background-color: #4299e1; }
.preference-category {
    margin-bottom: 20px;
    background: rgba(255,255,255,0.1);
    padding: 15px;
    border-radius: 10px;
}
.preference-category h4 {
    margin-top: 0;
    border-bottom: 1px solid rgba(255,255,255,0.2);
    padding-bottom: 8px;
}
.checkboxes {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 10px;
    margin-bottom: 10px;
}
.checkboxes label {
    display: flex;
    align-items: center;
    padding: 8px;
    background: rgba(255,255,255,0.1);
    border-radius: 5px;
    cursor: pointer;
}
.checkboxes label:hover {
    background: rgba(255,255,255,0.2);
}
.checkboxes input[type="checkbox"] {
    margin-right: 8px;
}
.logout, .nav-link {
    display: inline-block;
    padding: 8px 12px;
    margin: 0 5px 10px 0;
    text-decoration: none;
    color: #e0e0e0;
    background: rgba(255,255,255,0.1);
    border-radius: 5px;
}
.logout:hover, .nav-link:hover {
    background: rgba(255,255,255,0.2);
    text-decoration: none;
}
.nav-bar {
    display: flex;
    justify-content: space-between;
    margin-bottom: 20px;
}
.user-list {
    list-style: none;
    padding: 0;
}
.user-list li {
    background: rgba(255,255,255,0.1);
    padding: 15px;
    margin-bottom: 10px;
    border-radius: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.user-list li .actions {
    display: flex;
    gap: 10px;
}
.chat-container {
    max-height: 400px;
    overflow-y: auto;
    background: rgba(255,255,255,0.1);
    padding: 15px;
    border-radius: 10px;
    margin-bottom: 20px;
}
.chat-message {
    margin-bottom: 15px;
    padding: 10px;
    border-radius: 5px;
    background: rgba(255,255,255,0.2);
}
.chat-message.you {
    background: rgba(90, 103, 216, 0.5);
}
.message-info {
    display: flex;
    justify-content: space-between;
    font-size: 0.8em;
    margin-bottom: 5px;
    color: #e0e0e0;
}
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}
'''

SIGNUP_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PopConnect - Sign Up</title>
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <h1>Join PopConnect</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert {{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required value="{{ request.form.username or '' }}">
            <input type="email" name="email" placeholder="Email" required value="{{ request.form.email or '' }}">
            <input type="password" name="password" placeholder="Password" required>
            <input type="password" name="confirm_password" placeholder="Confirm Password" required>
            <button type="submit">Sign Up</button>
        </form>
        <p class="switch">Already have an account? <a href="{{ url_for('login') }}">Login</a></p>
    </div>
</body>
</html>
'''

LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PopConnect - Login</title>
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <h1>Welcome Back!</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert {{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p class="switch">Don't have an account? <a href="{{ url_for('signup') }}">Sign Up</a></p>
    </div>
</body>
</html>
'''

PREFERENCES_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PopConnect - Set Preferences</title>
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <a href="{{ url_for('dashboard') }}" class="logout">Back to Dashboard</a>
        <h1>Set Your Preferences</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert {{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        <form method="post">
            {% for category, options in categories.items() %}
            <div class="preference-category">
                <h4>{{ category }}</h4>
                <div class="checkboxes">
                    {% for option in options %}
                      <label>
                        <input type="checkbox" name="preferences" value="{{ option }}" 
                               {% if option in current_prefs %}checked{% endif %}> 
                        {{ option }}
                      </label>
                    {% endfor %}
                </div>
            </div>
            {% endfor %}
            <button type="submit">Save Preferences</button>
        </form>
    </div>
</body>
</html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PopConnect - Dashboard</title>
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <div class="nav-bar">
            <div>
                <a href="{{ url_for('friends') }}" class="nav-link">My Friends</a>
                <a href="{{ url_for('preferences') }}" class="nav-link">Preferences</a>
            </div>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
        
        <h1>Hello, {{ session.username }}!</h1>
        <h3>Friend Recommendations</h3>
        {% if recommendations %}
            <ul class="user-list">
            {% for user, score in recommendations %}
                <li>
                    <span>{{ user.username }} (Match: {{ score }}%)</span>
                    <div class="actions">
                        <a href="{{ url_for('send_friend_request', receiver_id=user.id) }}" class="btn">Add Friend</a>
                        <a href="{{ url_for('chat', friend_id=user.id) }}" class="btn">Chat</a>
                    </div>
                </li>
            {% endfor %}
            </ul>
        {% else %}
            <p>No recommendations available. Try updating your preferences.</p>
        {% endif %}
    </div>
</body>
</html>
'''

FRIENDS_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PopConnect - Friends</title>
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <div class="nav-bar">
            <div>
                <a href="{{ url_for('dashboard') }}" class="nav-link">Dashboard</a>
                <a href="{{ url_for('preferences') }}" class="nav-link">Preferences</a>
            </div>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
        
        <h1>My Friends</h1>
        
        <h3>Friend Requests</h3>
        {% if incoming %}
            <ul class="user-list">
            {% for req in incoming %}
                <li>
                    <span>Request from {{ req.sender.username }}</span>
                    <div class="actions">
                        <a href="{{ url_for('accept_friend_request', request_id=req.id) }}" class="btn">Accept</a>
                    </div>
                </li>
            {% endfor %}
            </ul>
        {% else %}
            <p>No incoming friend requests.</p>
        {% endif %}
        
        <h3>Friends List</h3>
        {% if friends_list %}
            <ul class="user-list">
            {% for friend in friends_list %}
                <li>
                    <span>{{ friend.username }}</span>
                    <div class="actions">
                        <a href="{{ url_for('chat', friend_id=friend.id) }}" class="btn">Chat</a>
                    </div>
                </li>
            {% endfor %}
            </ul>
        {% else %}
            <p>You have no friends yet. Check your recommendations!</p>
        {% endif %}
    </div>
</body>
</html>
'''

CHAT_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Chat with {{ friend.username }}</title>
    <style>{{ base_css }}</style>
</head>
<body>
    <div class="container">
        <div class="nav-bar">
            <a href="{{ url_for('friends') }}" class="nav-link">Back to Friends</a>
            <a href="{{ url_for('logout') }}" class="logout">Logout</a>
        </div>
        
        <h1>Chat with {{ friend.username }}</h1>
        
        <div class="chat-container">
            {% for msg in messages %}
                <div class="chat-message {% if msg.sender_id == session.user_id %}you{% endif %}">
                    <div class="message-info">
                        <strong>
                            {% if msg.sender_id == session.user_id %}
                                You
                            {% else %}
                                {{ friend.username }}
                            {% endif %}
                        </strong>
                        <span>{{ msg.timestamp.strftime('%Y-%m-%d %H:%M') }}</span>
                    </div>
                    <p>{{ msg.message }}</p>
                </div>
            {% endfor %}
        </div>
        
        <form method="post">
            <textarea name="message" placeholder="Type your message here..." rows="3" required></textarea>
            <button type="submit">Send Message</button>
        </form>
    </div>
</body>
</html>
'''

# ---------- Main ----------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        generate_fake_users(100)  # Generate fake users if needed
    app.run(debug=True)