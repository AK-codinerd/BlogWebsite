# also check the requirements that i have mentioned
import os
import smtplib
from datetime import date
from bs4 import BeautifulSoup
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy

from functools import wraps
# for the password hash
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship

# Import your forms from the forms.py that you created as Flaskform that only done for creating forms and then templates
# wtf forms in the respective templates
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


# the start syntax arranging all
app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
ckeditor = CKEditor(app)
bootstrap = Bootstrap(app)

# using the flask_gravatar for profile images if any doubt just google flask_gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# Create admin-only decorator... so to do this i saw the login_required decorator documentation and copied the same code
# as that and i just updated the condition that only user with id 1 can enter the following route and if someone else
# tries to enter 403 error
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error **** also if someone who's not logged in tries to go to the admin only routes it shows attribute error as no current_user is logged in so to fix that
        if not current_user.is_authenticated or current_user.id != 1:
            # so basically we are checking if the user entering the routes is not authenticated and not admin then abort
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(app)


# CONFIGURE TABLES actually the database tables where we store the blog details and user for the user details and for
# comments
# TODO: Create a User table for all your registered users, for blogposts and comments.
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
# This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    # relation link to one to many: one author many blog_posts
    posts = relationship("BlogPost", back_populates="author")
#     *******Add parent relationship*******
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")

    # this actually represent the object with the email whenever we are searching the object with the query
    def __repr__(self):
        return f"<User: {self.email}>"


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
# Adding a parent class here for the comments for blogpost
    post_comments = relationship("Comment", back_populates="parent_post")



class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    text = db.Column(db.Text, nullable=False)
#  -- --  #*******Add child relationship*******#
    #     #"users.id" The users refers to the tablename of the Users class.
    #     #"comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

# ** adding another child relationship for the blogposts class as each post contains many comments and by taking the
    # above 100 line user add child as example same here just blogpost as parent and comment is a child
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="post_comments")



# creating the databases not necessary to write another file uri for users it will automatically create another one for the user in the same directory as the previous one
with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():  # or you can also do is form.validate_on_submit
        password = request.form.get("password")
        re_enter_password = request.form.get("re_enter_password")
        print(password)
        print(re_enter_password)

        # just finding the user through the entered email to check if the user already exists so if he does we can redirect him to login page
        result = db.session.execute(db.select(User).where(User.email == request.form.get("email")))
        found_email = result.scalar()

        if found_email:
            flash("Email already in use.. Want to Log In")
            return redirect(url_for("login"))
         # after checking the password registering the user and adding in the database
        elif password == re_enter_password:
            new_user = User(email=request.form.get("email"), password=generate_password_hash(password, method="pbkdf2:sha256", salt_length=8), name=request.form.get("name"))
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, current_user=current_user)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # I need to find the user first in the database when the user enters the email
        result = db.session.execute(db.select(User).where(User.email == request.form.get("email")))
        # as email in db is unique so only one result
        found_user = result.scalar()
        # if there is no user found flash the user with incorrect email
        if not found_user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
            # Password incorrect
        elif not check_password_hash(found_user.password, request.form.get("password")):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(found_user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user) # so actually this is the home page and by sending the status of the user through currentuser you are basically sending the status of the user and in the template it will identify the status of the user and it will provide the navs of login and register and logout


# ****Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
# adding the comment form to the route and committing them if to the database if the user commets
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        # checking if the user that is commenting is logged in as we are showing post even to the non login user so to comment he/she needs to login
        if not current_user.is_authenticated:
            flash("You need to Login or Register to comment on this post")
            return redirect(url_for("login"))
        # after validating adding the comment to the databse and see that comment_author is the currant_user and parent post is the requested post the user is seeing right now

        new_comment = Comment(
            comment_author=current_user,
            parent_post=requested_post,
            text=BeautifulSoup(request.form.get("comment"), "lxml").text
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)


# ***Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=request.form.get("title"),
            subtitle=request.form.get("subtitle"),
            body=BeautifulSoup(request.form.get("body"), 'lxml').text,
            author=current_user,
            img_url=request.form.get("img_url"),
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# ****Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


#  Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    # if a form is submitted then taking out the details from the form
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        message = request.form.get("message")
        # Declaring the email and password for sending the email
        user = os.environ.get('MY_EMAIL')
        password = os.environ.get('EMAIL_PASS')

# working with smtplib to mail me the details if someone contact me through the blog website
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=user, password=password)
            connection.sendmail(from_addr=user, to_addrs=os.environ.get("AK_EMAIL"),
                                msg=f"Subject:Contacted Through Blog Website \n\n{name} \n {email} \n {phone} \n"
                                    f" {message}")
        return redirect(url_for("contact", msg_sent=True))
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
