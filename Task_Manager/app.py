from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import logging
from logging.handlers import RotatingFileHandler
import os
from flask import session
from flask import Flask, request, redirect, url_for, render_template, flash
from flask import Flask, request, jsonify, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if 'access_token' is in session
        if 'access_token' not in session:
            return redirect(url_for('login', next=request.url))
        try:
            # Manually set the JWT to be the token from the session
            with app.test_request_context():
                # This will raise an exception if the token is invalid
                verify_jwt_in_request()
        except:
            # If token is invalid or not present, redirect to login
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function



app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Generates a random secret key
app.config['JWT_SECRET_KEY'] = os.urandom(24)  # Generates a random JWT secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Logging configuration
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/task_manager.log', maxBytes=10240,
                                   backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
file_handler.setLevel(logging.INFO)  # Adjust this for debugging or production
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)  # Adjust accordingly
app.logger.info('TaskManager startup')



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)

bcrypt = Bcrypt(app)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)

# Define the function for creating tables
def create_tables():
    with app.app_context():
        db.create_all()

@app.route('/')
#@login_required
def index():
    tasks = Task.query.all()
    return render_template('index.html', tasks=tasks)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            access_token = create_access_token(identity=username)
            session['access_token'] = access_token  # Store JWT in session
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('access_token', None)  # Remove JWT from session
    return redirect(url_for('login'))


@app.route('/add', methods=['POST'])
def add_task():
    try:
        task_title = request.form['title']
        task = Task(title=task_title)
        db.session.add(task)
        db.session.commit()
        app.logger.info(f'Task added: {task_title}')
        flash('Task added successfully!')
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f'Failed to add task: {e}', exc_info=True)
        flash('Error adding task.')
        return redirect(url_for('index'))


@app.route('/delete/<int:task_id>', methods=['GET'])
def delete_task(task_id):
    try:
        task = Task.query.get(task_id)
        if task:
            db.session.delete(task)
            db.session.commit()
            app.logger.info(f'Task deleted: {task.id}')
            flash('Task deleted successfully!')
        else:
            app.logger.warning(f'Task with ID {task_id} not found for deletion')
            flash('Task not found.')
    except Exception as e:
        app.logger.error(f'Failed to delete task with ID {task_id}: {e}', exc_info=True)
        flash('Error deleting task.')
    return redirect(url_for('index'))


@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if request.method == 'POST':
        task.title = request.form['title']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit.html', task=task)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))
        else:
            # Create new user
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')



if __name__ == '__main__':
    create_tables()  # Ensure tables are created.
    app.run(debug=True)
