from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, AnonymousUserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import ValidationError, InputRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import secrets
import json



app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex()
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	password = db.Column(db.String(20), nullable=False)

class Anonymous(AnonymousUserMixin):
	def __init__(self) -> None:
		self.username = 'Guest'

login_manager.anonymous_user = Anonymous

class RegisterForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "username"})
	password = PasswordField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "password"})

	def validate_username(self, username):
		existing_user_username = User.query.filter_by(username=username.data).first()
		if existing_user_username:
			raise ValidationError("That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "username"})
	password = PasswordField(validators=[InputRequired(), Length(
		min=4, max=20)], render_kw={"placeholder": "password"})
	remember = BooleanField(default=False)




class Todo(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(100))
	completed = db.Column(db.Boolean)
	description = db.Column(db.String(150))
	due = db.Column(db.String)
	user_name = db.Column(db.String(20))


@app.route('/')
def index():
	# Show all todos
	try:
		#username = None
		username = current_user.username
		if username == "Guest":
			return redirect(url_for('login'))
			todo_list = session.get('todos')
			if todo_list == None:
				session.put('todos', {})
				todo_list = session['todos'].values()
			todo_list = session['todos'].values()
		else:
			todo_list = Todo.query.filter_by(user_name=username).all()
			
	except Exception as e:
		todo_list = []
		print(e)
	#print(todo_list)
	return render_template("base.html", todo_list = todo_list, username=username)
	

@app.route('/login', methods= ["GET", "POST"])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, form.password.data):
				login_user(user)
				return redirect(url_for('index'))
	return render_template('login.html', form=form)

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


@app.route('/register', methods= ["GET", "POST"])
def register():
	form = RegisterForm()
	if (form.username.data == "Guest"):
		return render_template('register.html', form=form)
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data)
		new_user = User(username=form.username.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for('login'))

	return render_template('register.html', form=form)


@app.route('/logout', methods=["GET", "POST"])
def logout():
	logout_user()
	return redirect(url_for('login'))


@app.route("/add", methods = ["GET", "POST"])
def add():
	# Add new item
	title = request.form.get("title")
	description = request.form.get("description")
	due = request.form.get("due")
	
	if (title == "" and description == "" and due == ""):
		return redirect(url_for("index"))
	if title == "":
		title = "default task name"
	if description=="":
		description = "a task description"
	if due == "":
		due=datetime.date.today().strftime('%m/%d/%y')
	if current_user.username != "Guest":
		new_todo = Todo(title=title, completed = False, description = description, due = due, user_name = current_user.username)
		db.session.add(new_todo)
		db.session.commit()
	else:
		datekey = datetime.datetime.now().ctime()
		session['todos'][datekey] = {"test json": "test val", "title": title, "completed" : False, "description" : description, "due" : due}
	return redirect(url_for("index"))


@app.route("/due/<int:todo_id>", methods = ["POST"])
def due(todo_id):
	todo = Todo.query.filter_by(id=todo_id).first()
	date = request.form.get("due")
	todo.due = date
	db.session.commit()
	return redirect(url_for("index"))

@app.route("/update/<int:todo_id>")
def update(todo_id):
	# Update an item
	if current_user.username != Guest:
		todo = Todo.query.filter_by(id=todo_id).first()
		todo.completed = not todo.completed
		db.session.commit()
	else:
		todo = session.get('todos')
	return redirect(url_for("index"))

@app.route("/delete/<int:todo_id>")
def delete(todo_id):
	# delete an item
	todo = Todo.query.filter_by(id=todo_id).first()
	db.session.delete(todo)
	db.session.commit()
	return redirect(url_for("index"))



if __name__ == "__main__":
	
	with app.app_context():
		
		db.create_all()

		# Example item
		# new_todo = Todo(title="Todo1", completed = False)
		# db.session.add(new_todo)
		# db.session.commit()
	
	
	app.run(debug=True)
