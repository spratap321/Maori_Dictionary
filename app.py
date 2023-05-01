from flask import Flask, render_template, session, request, redirect
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DATABASE = 'maori_dictionary.db'
app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = "deirejaoejq0i34jqo"


def open_database(db_name):
    # creates connection to database
    try:
        connection = sqlite3.connect(db_name)
        return connection
    except Error as e:
        print(e)
    return None


def is_logged_in():
    if session.get('email') is None:
        print('not logged in')
        return False
    else:
        print('logged in')
        return True


def not_logged_in():
    # checks if logged in, if not page redirects with message
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in')


@app.route('/')
def render_home():  # put application's code
    return render_template('home.html', logged_in=is_logged_in(), user=session.get('firstname'))


@app.route('/vocab')
def render_vocab():
    con = open_database(DATABASE)
    query = "SELECT ID, maori, english, category, definition, level, image FROM vocab_list "
    cur = con.cursor()
    cur.execute(query, )
    vocab_list = cur.fetchall()
    print(vocab_list)
    con.close()
    return render_template("vocab.html", voc=vocab_list,  logged_in=is_logged_in()
                           , user=session.get('name'))


@app.route('/login', methods=['POST', 'GET'])
def render_login():
    not_logged_in()
    print("logging in")
    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        print(email)
        query = """SELECT id, name, password FROM user WHERE email = ?"""
        con = open_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()
        print(user_data)
        try:
            user_id = user_data[0]
            name = user_data[1]
            db_password = user_data[2]
        except IndexError:
            return "/login?error=Email+invalid+or+password+incorrect"

        if not bcrypt.check_password_hash(bcrypt.generate_password_hash(db_password), password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect2122222")

        session['email'] = email
        session['user_id'] = user_id
        session['name'] = name

        print(session)
        return redirect('/')
    return render_template("login.html", logged_in=is_logged_in())


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    if request.method == 'POST':
        print(request.form)
        name = request.form.get('name')
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password2 = request.form.get('password2')
        if password != password2:
            return redirect('/signup?error=Password+do+not+match')

        if len(password) < 8:
            return redirect('/signup?error=Password+must+be+at+least+8+characters')

        con = open_database(DATABASE)
        cur = con.cursor()
        query = 'INSERT INTO user (name, email, password) VALUES (?, ?, ?)'
        try:

            cur.execute(query, (name, email, password))

        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')
        con.commit()
        con.close()

    return render_template('signup.html')


if __name__ == '__main__':
    app.run()
