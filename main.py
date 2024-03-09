import flask
import flask_login
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, insert
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class Cafes(db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(256))
    address: Mapped[str] = mapped_column(String(128))
    img_link: Mapped[str] = mapped_column(String)
    coffee_rating: Mapped[int] = mapped_column(Integer)
    wifi_rating: Mapped[int] = mapped_column(Integer)

class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    name: Mapped[str] = mapped_column(String(1000))
    password: Mapped[str] = mapped_column(String(100))

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

@app.route('/')
def home():
    cafes = db.session.execute(db.select(Cafes)).scalars().all()
    user = current_user

    return render_template("index.html", logged_in=current_user.is_authenticated, cafes=cafes, user=user)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        check_if_exist = db.session.execute(db.select(User).where(User.email == request.form['email'])).scalar()
        if check_if_exist == None:
            password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                email=request.form.get('email'),
                name=request.form.get('name'),
                password=password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        else:
            flask.flash("Email already in use")
    return render_template("register.html")

@app.route('/add', methods=['GET', 'POST'])
def add_cafe():
    if current_user.id != 1:
        return redirect(url_for('home'))
    if request.method == 'POST':
        new_cafe = Cafes(
            name = request.form.get('name'),
            description = request.form.get('description'),
            address = request.form.get('address'),
            img_link = request.form.get('img_link'),
            coffee_rating = request.form.get('coffee_rating'),
            wifi_rating = request.form.get('wifi_rating')
        )
        db.session.add(new_cafe)
        db.session.commit()
    return render_template('cafe_add.html', logged_in=current_user.is_authenticated, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = db.session.execute(db.select(User).where(User.email == request.form['email'])).scalar()
        if user != None:
            hashed_password = db.session.execute(db.select(User.password).where(User.email == request.form['email'])).scalar()
            if check_password_hash(hashed_password, request.form['password']):
                login_user(user)
                return redirect(url_for('home'))
        else:
            flask.flash('Account not found')
    return render_template("login.html")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)