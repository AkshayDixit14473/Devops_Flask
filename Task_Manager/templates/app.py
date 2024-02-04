from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'

db = SQLAlchemy(app)
jwt = JWTManager(app)

#Loging

import logging
from logging.handlers import RotatingFileHandler

# Basic configuration for logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

# Create a file handler object
file_handler = RotatingFileHandler('taskmanager.log', maxBytes=10240, backupCount=10)

# Set the logging level and format for the file handler
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))

# Add the file handler to the app's logger
app.logger.addHandler(file_handler)

#Log
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            access_token = create_access_token(identity=username)
            app.logger.info(f'User {username} logged in successfully')
            return jsonify(access_token=access_token)
        app.logger.warning(f'Failed login attempt for user {username}')
        return jsonify({"msg": "Bad username or password"}), 401
    return render_template('login.html')

# Add similar logging statements in other routes

#Error
#@app.errorhandler(500)
#def internal_error(error):
#    app.logger.error('Server Error: %s', (error))
#    return "500 error"
#
#@app.errorhandler(404)
#def not_found_error(error):
#    app.logger.error('Not Found: %s', (error))
#    return "404 error"




#Integrate Database










# Your code will go here

if __name__ == '__main__':
    app.run(debug=True)

# Database Model
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))

    def __repr__(self):
        return f'<Task {self.title}>'

#User Authentication

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

# Add user_loader and authentication routes here

#Initialize Database
with app.app_context():
    db.create_all()


#Add routes for handling tasks and authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token)
        return jsonify({"msg": "Bad username or password"}), 401
    return render_template('login.html')

@app.route('/tasks', methods=['GET', 'POST'])
@jwt_required()
def tasks():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        new_task = Task(title=title, description=description)
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('tasks'))
    all_tasks = Task.query.all()
    return render_template('tasks.html', tasks=all_tasks)

@app.route('/edit-task/<int:id>', methods=['GET', 'POST'])
@jwt_required()
def edit_task(id):
    task = Task.query.get_or_404(id)
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        db.session.commit()
        return redirect(url_for('tasks'))
    return render_template('edit_task.html', task=task)

@app.route('/delete-task/<int:id>')
@jwt_required()
def delete_task(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('tasks'))
