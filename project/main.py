import sqlite3
from flask import send_from_directory
from flask import Flask, redirect, render_template, session, request, url_for
from flask_wtf import FlaskForm
from db import DB
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length
import os
from werkzeug import secure_filename

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'doc', 'docx', 'pptx'])
app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
db = DB()

class NewsModel():
    def __init__(self, connection):
        self.connection = connection
        self.init_table()
        
    def init_table(self):
        cursor = self.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS news 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             title VARCHAR(100),
                             content VARCHAR(1000),
                             user_id INTEGER
                             )''')
        cursor.close()
        self.connection.commit()
        
    def insert(self, title, content, user_id):
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO news 
                          (title, content, user_id) 
                          VALUES (?,?,?)''', (title, content, str(user_id)))
        cursor.close()
        self.connection.commit()
        
    def get(self,news_id ):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM news WHERE id = ?", (str(news_id)))
        row = cursor.fetchone()
        return row
     
    def get_all(self, user_id = None):
        cursor = self.connection.cursor()
        if user_id:
            cursor.execute("SELECT * FROM news WHERE user_id = ?",
                           (str(user_id)))
        else:
            cursor.execute("SELECT * FROM news")
        rows = cursor.fetchall()
        return rows
    
    def delete(self, news_id):
        cursor = self.connection.cursor()
        cursor.execute('''DELETE FROM news WHERE id = ?''', (str(news_id)))
        cursor.close()
        self.connection.commit()        
        
        
class UserModel():
    def __init__(self, connection):
        self.connection = connection
        self.init_table()
        
    def init_table(self):
        cursor = self.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             user_name VARCHAR(50),
                             password_hash VARCHAR(128),
                             name VARCHAR(50),
                             surname VARCHAR(50),
                             info VARCHAR(501)
                             )''')
        cursor.close()
        self.connection.commit()
        
    def insert(self, user_name, password_hash, name, surname, info):
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO users 
                          (user_name, password_hash, name, surname, info) 
                          VALUES (?,?,?,?,?)''', (user_name, password_hash, name, surname, info))
        cursor.close()
        n = self.exists(user_name, password_hash)[1]
        os.mkdir(str(n))
        self.connection.commit()
        
    def get(self, user_id):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (str(user_id)))
        row = cursor.fetchone()
        return row
     
    def get_all(self):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        return rows
    
    def exists(self, user_name, password_hash):
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE user_name = ? AND password_hash = ?",
                       (user_name, password_hash))
        row = cursor.fetchone()
        return (True, row[0]) if row else (False,)
    
    def exist(self, user_name):
        cursor = self.connection.cursor()
        cursor.execute("SELECT user_name FROM users WHERE user_name = ? AND 1 = ?",
                       (str(user_name), 1))
        row = cursor.fetchone()
        return (True, row[0]) if row else (False,)    
    
    def delete(self, news_id):
        cursor = self.connection.cursor()
        cursor.execute('''DELETE FROM news WHERE id = ?''', (str(news_id)))
        cursor.close()
        self.connection.commit()       

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')
    
class RegForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    name = StringField('Имя', validators=[DataRequired()])
    surname = StringField('Фамилия', validators=[DataRequired()])
    password = StringField('Придумайте пароль', validators=[DataRequired()])
    info = TextAreaField('Расскажите о себе', validators=[Length(min=1, max=500)])
    submit = SubmitField('Зарегистрироваться')

 
class AddNewsForm(FlaskForm):
    title = StringField('Заголовок новости', validators=[DataRequired()])
    content = TextAreaField('Текст новости', validators=[DataRequired()])
    submit = SubmitField('Добавить')
    

@app.route('/logout')
def logout():
    session.pop('username', 0)
    session.pop('user_id', 0)
    session.clear()
    return redirect('/login')
    
    
@app.route('/')
@app.route('/index')
def index():
    if 'username' not in session:
        return redirect('/login')
    news = NewsModel(db.get_connection()).get_all(session['user_id'])
    return render_template('index.html', username=session['username'], title = 'Новости',
                           news=news)

@app.route('/login', methods=['GET', 'POST'])
def login():    
    if 'username'  in session:
        return redirect('/index')    
    form = LoginForm()
    if form.validate_on_submit():
        user_name = form.username.data
        password = form.password.data
        user_model = UserModel(db.get_connection())
        exists = user_model.exists(user_name, password)
        if (exists[0]):
            session['username'] = user_name
            session['user_id'] = exists[1]
        return redirect("/index")        
    return render_template('login.html', title='Авторизация', form=form)

@app.route('/add_new', methods=['GET', 'POST'])
def add_news():
    if 'username' not in session:
        return redirect('/login')
    form = AddNewsForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        nm = NewsModel(db.get_connection())
        nm.insert(title,content,session['user_id'])
        return redirect("/index")
    return render_template('add_news.html', title='Добавление новости',
                           form=form, username=session['username'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/add_file', methods=['GET', 'POST'])
def add_file():
    if 'username' not in session:
        return redirect('/login')
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_model = UserModel(db.get_connection())
            file.save(os.path.join(str(session['user_id']), filename))
            return redirect('/add_file')
    return render_template('add_file.html')


@app.route('/delete_news/<int:news_id>', methods=['GET'])
def delete_news(news_id):
    if 'username' not in session:
        return redirect('/login')
    nm = NewsModel(db.get_connection())
    id1 = str(session['user_id'])
    cursor = nm.connection.cursor()
    cursor.execute("SELECT user_id FROM news WHERE id = ? and 1 = ?", (news_id, 1))
    row = cursor.fetchone()  
    if row:
        nm.delete(news_id)
    return redirect("/index")

@app.route('/<int:iid>', methods=['GET'])
def news(iid):
    if 'username' not in session:
        return redirect('/login')
    news = NewsModel(db.get_connection()).get_all(str(iid))
    table = UserModel(db.get_connection()).get(str(iid))
    table = table[3:]
    name = table[0]
    surname = table[1]
    info = table[2]
    return render_template('other_news.html', username=session['username'], title = 'Новости пользователя', news=news, name = name, surname = surname, info = info)

@app.route('/error', methods=['GET', 'POST'])
def error():
    return '<h1> ошибка <h1>'

@app.route('/registration', methods=['GET', 'POST'])
def registration():    
    if 'username'  in session:
        return redirect('/index')    
    form = RegForm()
    if form.validate_on_submit():
        user_name = form.username.data
        name = form.name.data
        surname = form.surname.data
        password = form.password.data
        info = form.info.data        
        user_model = UserModel(db.get_connection()) 
        exists = user_model.exist(user_name)
        if exists[0] != True:
            user_model.insert(user_name, password, name, surname, info)
        return redirect('/login')
    return render_template('registration.html', title='Регистрация', form=form)

@app.route('/files', methods=['GET', 'POST'])
def files():    
    if 'username' not in session:
        return redirect('/login')
    n = list(os.walk(str(session['user_id'])))[0][2]
    news = NewsModel(db.get_connection()).get_all(session['user_id'])
    return render_template('files.html', username=session['username'], title = 'Файлы', news=n)

    

@app.route('/save_file/<string:file_name>', methods=['GET'])
def save_file(file_name):
    if 'username' not in session:
        return redirect('/login')
    return send_from_directory(str(session['user_id']), file_name)    


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
    
     