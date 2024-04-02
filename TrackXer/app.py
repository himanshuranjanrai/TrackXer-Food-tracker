from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'your_secret_key'

# Create or connect to the SQLite database
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Drop the users table if it exists
cursor.execute('''DROP TABLE IF EXISTS users''')

# Create the users table with full name, email, and password columns
cursor.execute('''CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fullname TEXT,
                    email TEXT UNIQUE,
                    password TEXT
                )''')
conn.commit()
conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']  # Get full name from form
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)''', (fullname, email, hashed_password))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT id, fullname, email, password FROM users WHERE email = ?''', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['fullname'] = user[1]  # Store full name in session
            session['email'] = user[2]
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', message='Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # Initialize food_items if it's not present in session
        if 'food_items' not in session:
            session['food_items'] = []

        if request.method == 'POST':
            if request.form.get('logout'):
                session.pop('user_id', None)  # Clear session
                session.pop('fullname', None)
                return redirect(url_for('login'))
            else:
                food_name = request.form['food_name']
                calorie_count = request.form['calorie_count']
                session['food_items'].append({'food_name': food_name, 'calorie_count': calorie_count})
                return redirect(url_for('dashboard'))

        return render_template('dashboard.html', fullname=session['fullname'], food_items=session['food_items'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
