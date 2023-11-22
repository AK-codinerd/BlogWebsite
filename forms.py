from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


#  Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    email = EmailField("Enter your email", validators=[DataRequired()])
    name = StringField("Enter your name", validators=[DataRequired()])
    password = PasswordField("Enter password",validators=[DataRequired()])
    re_enter_password = PasswordField("Re-Enter password", validators=[DataRequired()])
    submit = SubmitField("Register Me")

#  Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = EmailField("enter your email", validators=[DataRequired()])
    password = PasswordField("enter your password", validators=[DataRequired()])
    submit = SubmitField("Log Me In!")


# Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment = CKEditorField("comment", validators=[DataRequired()])
    submit = SubmitField("Add Comment")


