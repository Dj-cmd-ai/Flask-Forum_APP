from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import secrets
from PIL import Image
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from authlib.integrations.flask_client import OAuth


app = Flask(__name__)

# --- CONFIGURATION UPDATES ---
# Secret key should be pulled from environment variables for security
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-key-123'

# Neon Postgres Connection logic
# Pull DATABASE_URL from environment (Render/Vercel) or fallback to your string
uri = os.environ.get('DATABASE_URL') or 'postgresql://neondb_owner:npg_i2z4uxotQMjy@ep-icy-dust-ahxdrg11-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'

# SQLAlchemy requires 'postgresql://' prefix; Neon might provide 'postgres://'
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(255), nullable=False, default='https://ui-avatars.com/api/?name=User&background=random')
    # Update this from 128 to 255
    password_hash = db.Column(db.String(255), nullable=False) 
    posts = db.relationship('Post', backref='author', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    category = db.Column(db.String(20), nullable=False, default='General')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)

# --- FORMS ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class TopicForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    category = SelectField('Category', choices=[('General', 'General'), ('Brainwave', 'Brainwave'), ('Help', 'Help')])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post Topic')

class ReplyForm(FlaskForm):
    content = TextAreaField('Reply', validators=[DataRequired()])
    submit = SubmitField('Post Reply')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

# --- HELPERS ---
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    Image.open(form_picture).save(picture_path)
    return picture_fn

# --- ROUTES ---
@app.route("/")
@app.route("/home")
def home():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search')
    category_filter = request.args.get('category')
    
    query = Post.query.filter_by(parent_id=None)
    
    if search_term:
        query = query.filter((Post.title.ilike(f'%{search_term}%')) | (Post.content.ilike(f'%{search_term}%')))
    
    if category_filter:
        query = query.filter_by(category=category_filter)
        
    topics = query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('index.html', topics=topics, search_term=search_term, category_filter=category_filter)

@app.route("/user/<string:username>")
def user_posts(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user, parent_id=None).order_by(Post.date_posted.desc()).all()
    return render_template('user_posts.html', posts=posts, user=user)

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        flash('Login failed', 'danger')
    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            current_user.image_file = save_picture(form.picture.data)
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        return redirect(url_for('account'))
    form.username.data = current_user.username
    form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', image_file=image_file, form=form)

@app.route("/topic/new", methods=['GET', 'POST'])
@login_required
def new_topic():
    form = TopicForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, 
                    content=form.content.data, 
                    author=current_user,
                    category=form.category.data)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('create_topic.html', form=form)

@app.route("/topic/<int:topic_id>", methods=['GET', 'POST'])
def view_topic(topic_id):
    topic = Post.query.get_or_404(topic_id)
    replies = Post.query.filter_by(parent_id=topic_id).all()
    form = ReplyForm()
    if form.validate_on_submit():
        reply = Post(content=form.content.data, parent_id=topic.id, author=current_user)
        db.session.add(reply)
        db.session.commit()
        return redirect(url_for('view_topic', topic_id=topic.id))
    return render_template('topic.html', topic=topic, replies=replies, form=form)

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        return redirect(url_for('home'))
    if post.parent_id is None:
        Post.query.filter_by(parent_id=post.id).delete()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    
    # Check if user exists in Neon database
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        # Create a new user if they don't exist
        user = User(
            username=user_info['name'], 
            email=user_info['email'], 
            password_hash='oauth_managed', # They won't use a password
            image_file=user_info['picture'] # This fixes the broken image issue!
        )
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Initializing database tables on first run
    with app.app_context():
        db.create_all()
    app.run(debug=True)