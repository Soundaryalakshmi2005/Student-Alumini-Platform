from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///alumni_student.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'  # Bootstrap-friendly flash messages

# ---------------------- USER MODEL ----------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    register_number = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Increased length for hashing
    user_type = db.Column(db.String(10), nullable=False)

# ---------------------- CHATBOT SETUP ----------------------
chatbot = ChatBot('AlumniBot')

if not os.path.exists("db.sqlite3"):  # Avoid re-training on every restart
    trainer = ChatterBotCorpusTrainer(chatbot)
    trainer.train("chatterbot.corpus.english")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------- ROUTES ----------------------

# 🏠 Home Page
@app.route('/')
def home():
    return render_template('home.html')

# 🔑 Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Try again!', 'danger')

    return render_template('login.html')

# 📝 Sign-Up Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        register_number = request.form['register_number']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, register_number=register_number, email=email, password=hashed_password, user_type=user_type)

        db.session.add(new_user)
        db.session.commit()

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

# 📊 Dashboard Page
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# 👤 Profile Page (Edit Profile)
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.email = request.form['email']

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('profile.html', user=current_user)

# 💬 Chatbot Route
@app.route('/chat', methods=['POST'])
@login_required
def chat():
    user_input = request.form['user_input']
    response = chatbot.get_response(user_input)
    return str(response)

# 🚪 Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# ---------------------- DATABASE SETUP ----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
