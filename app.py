
from asyncio.windows_events import NULL

from flask import Flask, session, request, flash, render_template, redirect, send_from_directory
import os
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from flask_session import Session
from flask_login import login_required
from functools import wraps
from datetime import datetime
from flask_socketio import SocketIO, emit

UPLOAD_FOLDER = 'static/Uploads'
app = Flask(__name__)


app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
Session(app)
socketio = SocketIO(app, cors_allowed_origins="*")

users_in_chat = {}

@socketio.on("message", namespace='/chat')
def sendMessage(message):
    print("Recieved message: " + message)
    print(request.sid)
    emit('from_server', message, broadcast=True)


@socketio.on("user_id", namespace='/private')
def recieve_user_id(user_id):
    users_in_chat[user_id] = request.sid
    print(users_in_chat)
    

@socketio.on("private_message", namespace='/private')
def private_message(payload):
    reciever_id = users_in_chat[payload['user_id']]
    message = payload['message']
    chat_id = payload['chat_id']
    emit('new_private_message', {'message': message, 'chat_id': chat_id}, room=reciever_id)
    

@socketio.on("private_file_message", namespace='/private')
def private_file_message(payload):
    reciever_id = users_in_chat[payload['user_id']]
    message = payload['message']
    chat_id = payload['chat_id']
    emit('new_private_file_message', {'message': message, 'chat_id': chat_id}, room=reciever_id)


def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in allowed_extensions

def get_messages(chat_id):
    con = sqlite3.connect("chat.db")
    cur = con.cursor()
    messages = []
    cur.execute("SELECT * FROM messages WHERE chat_id = ?", (chat_id,))
        
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    for row in rows:
        temp = dict(zip(columns, row)) 
        messages.append(temp)
    
    return messages

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
            
        name = request.form.get("username")
        if not name:
            flash("Enter Valid Username !!")
            return render_template("login.html")
        
        cur.execute("SELECT hash FROM users WHERE name = ?" , (name,))
        rows = cur.fetchone()
        if not rows:
            flash("Invalid Username/Password !!")
            return render_template("login.html")
                                
        password = request.form.get("password")
        if not password:
            flash("Enter a Valid Password !!")
            return render_template("login.html")
        
        if check_password_hash(rows[0], password):
            cur.execute("SELECT id FROM users WHERE name = ?" , (name,))
            tmp = cur.fetchone()
            session['user_id'] = tmp[0]
            return redirect("/")
        else:
            flash("Invalid Username/Password !!")
            return render_template("login.html")
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        name = request.form.get("username")
        if not name:
            flash("Enter a valid Username !!")
            return render_template("register.html")
        
        cur.execute("SELECT name FROM users")
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        users = []
        usernames = []
        for row in rows:
            temp = dict(zip(columns, row))
            users.append(temp)
            
        for user in users:
            usernames.append(user['name'])

        if name in usernames:
            flash("Username already in use !!")
            return render_template("register.html")
        
        password = request.form.get("password")
        if not password:
            flash("Enter Valid Password !!")
            return render_template("register.html")
        confirm_password = request.form.get("confirm_password")
        if not confirm_password or confirm_password != password:
            flash("Password Mismatch !!")
            return render_template("register.html")
        
        hash = generate_password_hash(password)
        
        cur.execute("INSERT INTO users(name, hash) VALUES(?, ?)", (name, hash))
        cur.execute("SELECT id FROM users WHERE name = ?", (name,))
        id = cur.fetchone()
        id = id[0]
        cur.execute("INSERT INTO info(person_id) VALUES(?)", (id,))
        con.commit()
        cur.close()
        con.close()
        return redirect("/login")
    else:
        return render_template("register.html")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
       
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    chat_names = []
    profile_img_paths = []
    chats = []
    last_senders = []
    
    con = sqlite3.connect("chat.db")
    cur = con.cursor()
    cur.execute("SELECT profile_img_path FROM users WHERE id =?", (session['user_id'],))
    profile_img_path = cur.fetchone()
    if profile_img_path:
        profile_img_path = profile_img_path[0]
    
    cur.execute("SELECT * FROM chats WHERE adder_id = ? or added_id = ? GROUP BY id ORDER BY last_message_date DESC", (session['user_id'], session['user_id']))
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    for row in rows:
        temp = dict(zip(columns, row))
        chats.append(temp)
    
    for chat in chats:
        if chat['adder_id'] != session['user_id']:
            temp = {'name': chat['adder_name']}
            chat_names.append(temp)
            cur.execute("SELECT profile_img_path FROM users WHERE id = ?", (chat['adder_id'],))
            chat_img_path = cur.fetchone()
            chat_img_path = chat_img_path[0]
            path = {'path': chat_img_path}
            profile_img_paths.append(path)
        else:
            temp = {'name': chat['added_name']}
            chat_names.append(temp)
            cur.execute("SELECT profile_img_path FROM users WHERE id = ?", (chat['added_id'],))
            chat_img_path = cur.fetchone()
            chat_img_path = chat_img_path[0]
            path = {'path': chat_img_path}
            profile_img_paths.append(path)
            
    for chat in chats:
        cur.execute("SELECT id FROM users WHERE id = (SELECT sender_id FROM messages WHERE chat_id = ? and message = ? ORDER BY date DESC LIMIT 1)", (chat['id'], chat['last_message']))
        temp = cur.fetchone()
        if temp:
            temp = temp[0]
        if temp == session['user_id']:
            last_sender_name = {'name': "You"}
            last_senders.append(last_sender_name)
        else:
            cur.execute("SELECT name FROM users WHERE id = ?", (temp,))
            last_sender_name = {'name': cur.fetchone()[0]}
            last_senders.append(last_sender_name)
        
    packed = zip(chats, chat_names, profile_img_paths, last_senders)
    return render_template("index.html", profile_img_path=profile_img_path, packed = packed, chats=chats, user_id=session['user_id'])

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        cur.execute("SELECT friend_id FROM friends WHERE person_id = ?", (session['user_id'],))
        temp = cur.fetchall()
        friends_ids = []
        for i in range(len(temp)):
            friends_ids.append(temp[i][0])
        
        search = request.form.get("search")
        if not search:
            flash("No Users Found")
            return redirect("/")
        
        search = (f"%{search}%")
        cur.execute("SELECT * FROM users WHERE name LIKE ?", (search,))
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        users = []
        for row in rows:
            temp = dict(zip(columns, row))
            users.append(temp)
            
        if not users:
            flash("No Users Found")
            return redirect("/")
        
        cur.execute("SELECT * FROM info WHERE person_id in (SELECT id FROM users WHERE name LIKE ?)", (search,))
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        info = []
        for row in rows:
            temp = dict(zip(columns, row))
            info.append(temp)
            
        packed = zip(users, info)
        return render_template("search.html", packed=packed, user_id=session['user_id'], friends_ids=friends_ids)
    else:
        return redirect("/")
    

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        friend_id = request.form.get("add_friend_id")
        cur.execute("SELECT id from chats WHERE adder_id or added_id = ? and adder_id or added_id = ?", (session['user_id'], friend_id))
        chat_id = cur.fetchone()
        if chat_id:
            cur.execute("INSERT INTO friends(person_id, friend_id) VALUES(?, ?)", (session['user_id'], friend_id))
            con.commit()
            cur.close()
            con.close()
            return redirect("/")   
        
        cur.execute("INSERT INTO friends(person_id, friend_id) VALUES(?, ?)", (session['user_id'], friend_id))
        message = "Added you to contacts"
        date = str(datetime.now())
        date = date.rsplit(":", 1)[0]
        
        cur.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
        adder_name = cur.fetchone()
        adder_name = adder_name[0]
        
        cur.execute("SELECT name FROM users WHERE id = ?", (friend_id,))
        added_name = cur.fetchone()
        added_name = added_name[0]
        
        cur.execute("INSERT INTO chats(adder_id, added_id, last_message, adder_name, added_name, last_message_date) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], friend_id, message, adder_name, added_name, date,))
        cur.execute("SELECT id FROM chats WHERE adder_id = ? and added_id = ?", (session['user_id'], friend_id))
        chat_id = cur.fetchone()
        chat_id = chat_id[0]
        
        cur.execute("INSERT INTO messages(sender_id, reciever_id, message, date, chat_id) VALUES(?, ?, ?, ?, ?)", (session['user_id'], friend_id, message, date, chat_id))
        con.commit()
        cur.close()
        con.close()
        return redirect("/")
    else:
        return redirect("/")
    
    
    
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    con = sqlite3.connect("chat.db")
    cur = con.cursor()
    cur.execute("SELECT name FROM users WHERE id =?", (session['user_id'],))
    
    username = cur.fetchone()
    username = username[0]
    
    friends = []
    cur.execute("SELECT * FROM users WHERE id in (SELECT friend_id FROM friends WHERE person_id = ?)", (session['user_id'],))
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    for row in rows:
        temp = dict(zip(columns, row))
        friends.append(temp)
    
    cur.execute("SELECT profile_img_path FROM users WHERE id =?", (session['user_id'],))
    profile_img_path = cur.fetchone()
    profile_img_path = profile_img_path[0]
    
    cur.execute("SELECT name FROM users")
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    users = []
    usernames = []
    for row in rows:
        temp = dict(zip(columns, row))
        users.append(temp)
    
    cur.execute("SELECT * FROM info WHERE person_id = ?", (session['user_id'],))
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]
    info = []
    for row in rows:
        temp = dict(zip(columns, row))
        info.append(temp)
        
    for user in users:
        usernames.append(user['name'])
    
    if request.method == "POST":
        name = request.form.get("username")
        if not name:
            flash("Enter Valid Username")
            return render_template("settings.html", friends=friends, info=info[0], username=username, profile_img_path = profile_img_path)
        
        if name in usernames and name != username:
            flash("Username Already Used")
            return render_template("settings.html", friends=friends, info=info[0], username=username, profile_img_path = profile_img_path)

        email = request.form.get("email")
        city = request.form.get("city")
        country = request.form.get("country")
        
        while True:
            try:
                day = int(request.form.get("day"))
                if day > 31 or day < 1:
                    flash("Enter Valid Date")
                    return render_template("settings.html", friends=friends, info=info[0], username=username, profile_img_path = profile_img_path)
                break
            except ValueError:
                day = NULL
                break

        while True:
            try:
                month = int(request.form.get("month"))
                if month > 12 or month < 1:
                    flash("Enter Valid Date")
                    return render_template("settings.html", friends=friends, info=info[0], username=username, profile_img_path = profile_img_path)
                break
            except ValueError:
                month = NULL
                break
        
        while True:
            try:
                year = int(request.form.get("year"))
                if year < 1920 or year > 2014:
                    flash("Enter Valid Date")
                    return render_template("settings.html", friends=friends, info=info[0], username=username, profile_img_path = profile_img_path)
                break
            except ValueError:
                year = NULL
                break
        
        cur.execute("UPDATE info SET email= ?, country= ?, city= ?, day= ?, month= ?, year= ? WHERE person_id= ?", (email, country, city, day, month, year, session['user_id']))
        cur.execute("UPDATE users SET name= ? WHERE id = ?", (name, session['user_id']))
        cur.execute("UPDATE chats SET adder_name = ? WHERE adder_id = ?", (name, session['user_id']))
        cur.execute("UPDATE chats SET added_name = ? WHERE added_id = ?", (name, session['user_id']))
        con.commit()
        cur.close()
        con.close()
        return redirect("/settings")
    else:
        return render_template("settings.html", username=username, info=info[0], profile_img_path = profile_img_path, friends=friends)


@app.route("/upload_profile_img", methods=["GET", "POST"])
@login_required
def upload_profile_img():
    con = sqlite3.connect("chat.db")
    cur = con.cursor()
    if request.method == "POST":
        
        allowed_extensions = ["jpg", "png", "jpeg", "bmp"]
        if 'file' not in request.files:
            flash("No Image Selected !!")
            return redirect("/settings")
        
        file = request.files['file']
        if file.filename == '':
            flash("No Image Selected !!")
            return redirect("/settings")
        
        if file and allowed_file(file.filename, allowed_extensions):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_img_path = (f"../static/Uploads/{filename}")
        else:
            flash("Unsupported File Type !!")
            return redirect("/settings")
        
        cur.execute("UPDATE users SET profile_img_path = ? WHERE id = ?", (profile_img_path, session['user_id']))
        con.commit()
        cur.close()
        con.close()
        return redirect("/settings")
    
    else:
        return redirect("/settings")
    

@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        cur.execute("SELECT hash FROM users WHERE id = ?", (session['user_id'],))
        hash = cur.fetchone()
        hash = hash[0]
        
        old_password = request.form.get("old_password")
        if not old_password or not check_password_hash(hash, old_password):
            flash("Password Mismatch")
            return redirect("/settings")
        
        new_password = request.form.get("new_password")
        if not new_password :
            flash("Enter Valid New Password !!")
            return redirect("/settings")
        new_hash = generate_password_hash(new_password)
        
        cur.execute("UPDATE users SET hash = ? WHERE id = ?", (new_hash, session['user_id']))
        con.commit()
        cur.close()
        con.close()
        return redirect("/settings")
    else:
        return redirect("/settings")

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    session.clear()
    return redirect("/login")


@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    if request.method == "POST":
        chat_id = request.form.get("chat_id")
        chat_name = request.form.get("chat_name")
        chat_img = request.form.get("chat_img")
        messages = get_messages(chat_id)
        
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
            
        cur.execute("SELECT id FROM users WHERE name = ?", (chat_name,))
        other_user_id = cur.fetchone()[0]
        
        return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id = other_user_id)
    else:
        return redirect("/")
    
    
@app.route("/send_message", methods=["GET", "POST"])
@login_required
def send_message():    
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        chat_id = request.form.get("chat_id")
        other_user_id = request.form.get("other_user_id")
        chat_name = request.form.get("chat_name")
        chat_img = request.form.get("chat_img")
        message = request.form.get("message")

        if message:
            cur.execute("SELECT id FROM users WHERE name = ?", (chat_name,))
            reciever_id = cur.fetchone()[0]
            date = str(datetime.now())
            date = date.rsplit(":", 1)[0]
            
            if chat_id != "None":
                cur.execute("UPDATE chats SET last_message = ?, last_message_date = ? WHERE id = ?", (message, date, chat_id))
            else:
                cur.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
                adder_name = cur.fetchone()[0]
                cur.execute("INSERT INTO chats(adder_id, added_id, last_message, adder_name, added_name, last_message_date) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message, adder_name, chat_name, date,))
                cur.execute("SELECT id FROM chats WHERE adder_id = ? and added_id = ?", (session['user_id'], other_user_id))
                chat_id = cur.fetchone()[0]
                
        if message:
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, chat_id, date) VALUES(?, ?, ?, ?, ?)", (session['user_id'], reciever_id, message, chat_id, date))
            con.commit()
            cur.close()
            con.close()
            messages = get_messages(chat_id)
        
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id = other_user_id)
        else: 
            flash("Enter Messsage !!")
            messages = get_messages(chat_id)
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id = other_user_id)        
    else:
        return redirect("/")
    
    
@app.route("/upload_img", methods=["GET", "POST"])
@login_required
def upload_img():    
    if request.method == "POST":
        allowed_extensions = ['jpg', 'png', 'bmp', 'jpeg', 'gif']
        chat_id = request.form.get("chat_id")
        other_user_id = request.form.get("other_user_id")
        chat_name = request.form.get("chat_name")
        chat_img = request.form.get("chat_img")
        
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        if 'image' not in request.files:
            flash("No Image Selected !!")
            messages = get_messages(chat_id)
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
        
        file = request.files['image']
        if file.filename == '':
            flash("No Image Selected !!")
            messages = get_messages(chat_id)
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
        
        if file and allowed_file(file.filename, allowed_extensions):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            img_path = (f"../{app.config['UPLOAD_FOLDER']}/{filename}")
            
            reciever_id = other_user_id
            
            date = str(datetime.now())
            date = date.rsplit(":", 1)[0]
            
            message = "Sent an image"
            if chat_id != "None":
                cur.execute("UPDATE chats SET last_message = ?, last_message_date = ? WHERE id = ?", (message, date, chat_id))
            else:
                cur.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
                adder_name = cur.fetchone()[0]
                cur.execute("INSERT INTO chats(adder_id, added_id, last_message, adder_name, added_name, last_message_date) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message, adder_name, chat_name, date,))
                cur.execute("SELECT id FROM chats WHERE adder_id = ? and added_id = ?", (session['user_id'], other_user_id))
                chat_id = cur.fetchone()[0]
                
            cur.execute("INSERT INTO messages(sender_id, reciever_id, img_path, message, chat_id, date) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], reciever_id, img_path, message, chat_id, date))

            con.commit()
            cur.close()
            con.close()
            messages = get_messages(chat_id)
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
        else:
            flash("File Not Supported !!")
            messages = get_messages(chat_id)
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
    else:
        return redirect("/")
    
    
@app.route("/upload_audio", methods=["GET", "POST"])
@login_required
def upload_audio():
    if request.method == "POST":
        allowed_extensions = ['mp3', 'wav', 'aac', 'm4a', 'wma']
        chat_id = request.form.get("chat_id")
        chat_name = request.form.get("chat_name")
        chat_img = request.form.get("chat_img")
        other_user_id = request.form.get("other_user_id")
        messages = get_messages(chat_id)
        
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
              
        if 'audio' not in request.files:
            flash("No Audio File Selected !!")
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
             
        file = request.files['audio']
        if file and allowed_file(file.filename, allowed_extensions):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            audio_path = (f"../{app.config['UPLOAD_FOLDER']}/{filename}")
            
            date = str(datetime.now())
            date = date.rsplit(":", 1)[0]
            message = "Sent an audio file"
            
            if chat_id != "None":
                cur.execute("UPDATE chats SET last_message = ?, last_message_date = ? WHERE id = ?", (message, date, chat_id))
            else:
                cur.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
                adder_name = cur.fetchone()[0]
                cur.execute("INSERT INTO chats(adder_id, added_id, last_message, adder_name, added_name, last_message_date) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message, adder_name, chat_name, date,))
                cur.execute("SELECT id FROM chats WHERE adder_id = ? and added_id = ?", (session['user_id'], other_user_id))
                chat_id = cur.fetchone()[0]
                
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, sound_path, date, chat_id) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message, audio_path, date, chat_id))

            con.commit()
            cur.close()
            con.close()
            messages = get_messages(chat_id)
            
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
        
        else:
            flash("File Not Supported !!")
            messages = get_messages(chat_id)
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
    else:
        return redirect("/")
    
    
@app.route("/upload_vid", methods=["GET", "POST"])
@login_required
def upload_vid():
    if request.method == "POST":
        allowed_extensions = ['mp4', 'mov', 'wmv', 'avi']
        chat_id = request.form.get("chat_id")
        chat_name = request.form.get("chat_name")
        chat_img = request.form.get("chat_img")
        other_user_id = request.form.get("other_user_id")
        messages = get_messages(chat_id)
        
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        if 'video' not in request.files:
            flash("No Video Selected !!")
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
            
        file = request.files['video']
        if file.filename == '':
            flash("No Video Selected !!")
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
        
        if file and allowed_file(file.filename, allowed_extensions):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            vid_path = (f"../{app.config['UPLOAD_FOLDER']}/{filename}")
            
            reciever_id = other_user_id
            date = str(datetime.now())
            date = date.rsplit(":", 1)[0]
            message = "Sent a video"
            
            if chat_id != "None":
                cur.execute("UPDATE chats SET last_message = ?, last_message_date = ? WHERE id = ?", (message, date, chat_id))
            else:
                cur.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
                adder_name = cur.fetchone()[0]
                cur.execute("INSERT INTO chats(adder_id, added_id, last_message, adder_name, added_name, last_message_date) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message, adder_name, chat_name, date,))
                cur.execute("SELECT id FROM chats WHERE adder_id = ? and added_id = ?", (session['user_id'], other_user_id))
                chat_id = cur.fetchone()[0]
                
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, video_path, date, chat_id) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], reciever_id, message, vid_path, date, chat_id))

            con.commit()
            cur.close()
            con.close()
            messages = get_messages(chat_id)
            
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
        else:
            flash("File Not Supported !!")
            messages = get_messages(chat_id)
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
    else:
        return redirect("/")
    
    
@app.route("/upload_file", methods=["GET", "POST"])
@login_required
def upload_file():
    if request.method == "POST":
        chat_id = request.form.get("chat_id")
        chat_name = request.form.get("chat_name")
        chat_img = request.form.get("chat_img")
        other_user_id = request.form.get("other_user_id")
        messages = get_messages(chat_id)
        
        con = sqlite3.connect("chat.db")
        cur = con.cursor()

        if 'file' not in request.files:
            flash("No File Selected !!")
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)

        file = request.files['file']
        if file.filename == '':
            flash("No File Selected !!")
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
        
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_path = (f"../{app.config['UPLOAD_FOLDER']}/{filename}")
            
            date =str(datetime.now())
            date = date.rsplit(":", 1)[0]
            message = filename
            
            if chat_id != "None":
                cur.execute("UPDATE chats SET last_message = ?, last_message_date = ? WHERE id = ?", (message, date, chat_id))
            else:
                cur.execute("SELECT name FROM users WHERE id = ?", (session['user_id'],))
                adder_name = cur.fetchone()[0]
                cur.execute("INSERT INTO chats(adder_id, added_id, last_message, adder_name, added_name, last_message_date) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message, adder_name, chat_name, date,))
                cur.execute("SELECT id FROM chats WHERE adder_id = ? and added_id = ?", (session['user_id'], other_user_id))
                chat_id = cur.fetchone()[0]
                
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, file_path, date, chat_id) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message, file_path, date, chat_id))

            con.commit()
            cur.close()
            con.close()
            messages = get_messages(chat_id)
            
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
        else:
            flash("No File Selected !!")
            return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
    else:
        return redirect("/")
   
   
@app.route("/Uploads/<name>", methods=["GET", "POST"])
@login_required
def download(name):
    if request.method == "POST":
        return send_from_directory(app.config['UPLOAD_FOLDER'], name)
    else:
        return redirect("/")

@app.route("/delete_message", methods=["GET", "POST"])
@login_required
def delete_message():
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        chat_id = request.form.get("chat_id")
        chat_name = request.form.get("chat_name")
        chat_img = request.form.get("chat_img")
        other_user_id = request.form.get("other_user_id")
        message_id = request.form.get("message_id")
        
        cur.execute("SELECT message from messages WHERE id = ? and chat_id = ?", (message_id, chat_id))
        message = cur.fetchone()[0]
        cur.execute("SELECT last_message from chats WHERE id = ?", (chat_id,))
        last_message = cur.fetchone()[0]
        if last_message == message:
            new_last_message_data = []
            cur.execute("SELECT * FROM messages WHERE chat_id = ? and id < ? ORDER BY id DESC LIMIT 1", (chat_id, message_id))
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            for row in rows:
                temp = dict(zip(columns, row))
                new_last_message_data.append(temp)
                
            if new_last_message_data:
                last_message = new_last_message_data[0]['message']
                date = new_last_message_data[0]['date']
                cur.execute("UPDATE chats SET last_message = ?, last_message_date = ? WHERE id = ?", (last_message, date, chat_id))
            else:
                cur.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
                cur.execute("DELETE FROM messages WHERE id = ? and chat_id = ?", (message_id, chat_id))
                con.commit()
                cur.close()
                con.close()            
                return redirect("/")
                
        
        cur.execute("DELETE FROM messages WHERE id = ? and chat_id = ?", (message_id, chat_id))
        con.commit()
        cur.close()
        con.close()
        
        messages = get_messages(chat_id)
        return render_template("chat.html", chat_img=chat_img, chat_name=chat_name, chat_id=chat_id, user_id=session['user_id'], messages=messages, other_user_id=other_user_id)
    else:
        return redirect("/")


@app.route("/redirect_message", methods=["GET", "POST"])
@login_required
def redirect_message():
    if request.method == "POST":
        message_id = request.form.get("message_id")
        chat_names = []
        profile_img_paths = []
        chats = []
            
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        cur.execute("SELECT * FROM chats WHERE adder_id = ? or added_id = ? GROUP BY id ORDER BY last_message_date DESC", (session['user_id'], session['user_id']))
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        for row in rows:
            temp = dict(zip(columns, row))
            chats.append(temp)
        
        for chat in chats:
            if chat['adder_id'] != session['user_id']:
                temp = {'name': chat['adder_name']}
                chat_names.append(temp)
                cur.execute("SELECT profile_img_path FROM users WHERE id = ?", (chat['adder_id'],))
                chat_img_path = cur.fetchone()
                chat_img_path = chat_img_path[0]
                path = {'path': chat_img_path}
                profile_img_paths.append(path)
            else:
                temp = {'name': chat['added_name']}
                chat_names.append(temp)
                cur.execute("SELECT profile_img_path FROM users WHERE id = ?", (chat['added_id'],))
                chat_img_path = cur.fetchone()
                chat_img_path = chat_img_path[0]
                path = {'path': chat_img_path}
                profile_img_paths.append(path)
                
        packed = zip(chats, chat_names, profile_img_paths)
        cur.close()
        con.close()
        
        return render_template("redirect.html", packed=packed, message_id=message_id)
    else:
        return redirect("/")


@app.route("/confirm_redirect_message", methods=["GET", "POST"])
@login_required
def confirm_redirect_message():
    if request.method == "POST":
        chat_id = request.form.get("chat_id")
        chat_img = request.form.get("chat_img")
        chat_name = request.form.get("chat_name")
        message_id = request.form.get("message_id")
        message = []
        
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        cur.execute("SELECT * FROM messages WHERE id = ?", (message_id,))
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        for row in rows:
            temp = dict(zip(columns, row))
            message.append(temp)
        
        cur.execute("SELECT id FROM users WHERE name = ?", (chat_name,))
        other_user_id = cur.fetchone()[0]
        
        date = str(datetime.now())
        date = date.rsplit(":", 1)[0]
        
        if message[0]['img_path']:
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, img_path, date, chat_id) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message[0]['message'], message[0]['img_path'], date, chat_id))
        elif message[0]['video_path']:
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, video_path, date, chat_id) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message[0]['message'], message[0]['video_path'], date, chat_id))
        elif message[0]['file_path']:
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, file_path, date, chat_id) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message[0]['message'], message[0]['file_path'], date, chat_id))
        elif message[0]['sound_path']:
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, sound_path, date, chat_id) VALUES(?, ?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message[0]['message'], message[0]['sound_path'], date, chat_id))
        else:
            cur.execute("INSERT INTO messages(sender_id, reciever_id, message, date, chat_id) VALUES(?, ?, ?, ?, ?)", (session['user_id'], other_user_id, message[0]['message'], date, chat_id))
        
        cur.execute("UPDATE chats SET last_message = ?, last_message_date = ? WHERE id = ?", (message[0]['message'], date, chat_id))
        
        con.commit()
        messages = get_messages(chat_id)
        
        cur.close()
        con.close()
        return render_template("chat.html", messages=messages, other_user_id=other_user_id, chat_id=chat_id, chat_img=chat_img, chat_name=chat_name, user_id=session['user_id'])
    else:
        return redirect("/")


@app.route("/delete_chat", methods=["GET", "POST"])
@login_required
def delete_chat():
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        chat_id = request.form.get("chat_id")
        cur.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
        cur.execute("DELETE FROM messages WHERE chat_id = ?", (chat_id,))
        con.commit()
        cur.close()
        con.close()
        return redirect("/")
    else:
        return redirect("/")
    
    
@app.route("/remove_friend", methods=["GET", "POST"])
@login_required
def remove_friend():
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()

        friend_id = request.form.get("friend_id")
        
        cur.execute("DELETE FROM friends WHERE person_id = ? and friend_id = ?", (session['user_id'], friend_id)) 
        con.commit()
        cur.close()
        con.close()
        
        return redirect("/settings")
    else:
        return redirect("/")

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        con = sqlite3.connect("chat.db")
        cur = con.cursor()
        
        profile_id = request.form.get("profile_id")
        profile_img = request.form.get("profile_img")
        info = []
         
        cur.execute("SELECT name FROM users WHERE id = ?", (profile_id,))
        name = cur.fetchone()[0]
        
        cur.execute("SELECT * FROM info WHERE person_id = ?", (profile_id,))
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        for row in rows:
            temp = dict(zip(columns, row))
            info.append(temp)
            
            
        cur.execute("SELECT id FROM chats WHERE adder_id = ? and added_id = ? or adder_id = ? and added_id = ?", (session['user_id'], profile_id, profile_id, session['user_id']))
        chat_id = cur.fetchone()
        if chat_id:
            chat_id = chat_id[0]
            
        cur.execute("SELECT * FROM friends WHERE person_id = ? and friend_id = ?", (session['user_id'], profile_id))
        friend = cur.fetchone()
        cur.close()
        con.close()
        
        return render_template("profile.html", profile_img=profile_img, profile_id=int(profile_id), info=info, name=name, chat_id=chat_id, friend=friend, user_id=int(session['user_id']))
    else:
        return redirect("/")    
    
if __name__ == '__main__':
    socketio.run(app, host="localhost")