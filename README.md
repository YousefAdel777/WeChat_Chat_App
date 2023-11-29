# WeChat Chat App
#### Video Demo: https://youtu.be/kMw83xy4YHE
#### Description:
WeChat is my CS50 final project. It is a  web chat app that you can use to chat with your family and friends. It is coded in Python using Flask. Sqlite3 is used for database. SocketIO is used for real-time messaging.

## Project Files:

### app.py:
Contains the main back-end source code for the project. 

### chat.db:
Database file contains data about users, messages, chats, info and friends for each user. Sqlite3 is used to create the database.

## Templates:

### layout.html:
Contains the code for the main layout of the web app.
### index.html:
index.html serves as the home page for the web app. It contains chats of the user.

### chat.html:
chat.html contains data (messages and chat info) loaded from chat.db using SQL, Python and Jinja2.
### login.html:
User is redirected to login.html if they are not logged in. It contains input fields for basic login requirements (Password and Username).
### register.html:
register.html enables new users to register. Data from register.html is stored in chat.db if valid.
### settings.html:
Contains multiple input fields, so that user can add personal information to share with other people. Users can also upload their own profile image. Data from settings.html is stored in info table in chat.db. It also enables users to log out from their accounts.
### profile.html:
Loads user info from info table in chat.db using SQL, Python and Jinja2.
### search.html:
Enables users to search for other users by name, view search results and chat with those users.
### redirect.html:
Loads a list of chats, so that user can redirect a particular message to that chat.

## static:
Contains images, CSS files and files uploaded by users.

## CSS:
### all.min.css:
Contains the necessary styling for Font Awesome library icons to function.
### style.css: 
Style.css is the main CSS file in the project. It contains css properties for all elemetns used in html files.
### Noramlize.css:
Normalize.css makes browsers render all elements consistently and in line with modern standards.

## images:
Contains images used in project (logo, default profile image and fav icon).

## Uploads:
Contains images, videos and other files uploaded by users. Paths are stored in chat.db.

## webfonts:
Contains fonts necessary for Font Awesome library icons.