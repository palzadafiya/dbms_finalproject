import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///billbuddy.db")


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
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        vpassword = request.form.get("confirmation")

        if username == "" or password == "":
            return apology("Username and/or Password is missing!")

        if password != vpassword:
            return apology("Password verification failed!")

        entries = db.execute("SELECT * FROM users")
        for entry in entries:
            if entry["username"] == username:
                return apology("Username already exists!")

        hashed_password = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, hash) VALUES (:u, :h)",
            u=username,
            h=hashed_password,
        )
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["user_id"]

    return redirect("/")

@app.route("/about_us")
def about_us():
    return render_template("about_us.html")


@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "GET":
        return render_template("create.html")
    else:
        group_name = request.form.get("group_name")
        password = request.form.get("password")
        if group_name == "" or password == "":
            return apology("Username and/or Password is missing!")
        entries = db.execute("SELECT * FROM groups")
        for entry in entries:
            if entry["group_name"] == group_name:
                return apology("Group Name already exists!")

        hashed_password = generate_password_hash(password)
        db.execute(
            "INSERT INTO groups (group_name, hash) VALUES (:u, :h)",
            u=group_name,
            h=hashed_password,
        )
        flash('Group created successfully!')
    return render_template("create.html")


@app.route("/join", methods=["GET", "POST"])
@login_required
def join():
    if request.method == "GET":
        return render_template("join.html")
    else:
        group_name = request.form.get("group_name")
        password = request.form.get("password")

        if not group_name:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM groups WHERE group_name = ?", group_name
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username and/or password", 403)

        user_id = session["user_id"]
        group_id = rows[0]["group_id"]
        session["group_id"] = group_id

        db.execute("INSERT INTO group_users (group_id, user_id) VALUES (:g, :u)", g=group_id, u = user_id)
        return redirect("/group")



@app.route("/group", methods=["GET", "POST"])
@login_required
def group():
    group_id = session["group_id"]
    row = db.execute("SELECT group_name FROM groups WHERE group_id = ?", group_id)
    gn = row[0]["group_name"]
    if request.method == "GET":
        return render_template("group.html", group_name = gn, expenses_data = get_expenses(group_id))
    else:
        desc = request.form.get("expense_name")
        amount = request.form.get("expense_amount")
        user_id = session["user_id"]
        db.execute("INSERT INTO expenses (description, amount, user_id, group_id) VALUES (?, ?, ?, ?)",(desc),(amount),(user_id),(group_id))

        return render_template("group.html", group_name = gn, expenses_data = get_expenses(group_id))


@app.route("/summary", methods=["GET"])
@login_required
def summary():
    group_id = session["group_id"]
    expenses = get_expenses(group_id)
    n=0
    total=0
    for user in expenses:
        n+=1
        bills = expenses[user]
        sum = 0
        for name in bills:
            sum+=bills[name]
        expenses[user] = sum
        total+=sum
    levana = {}
    devana = {}
    for user in expenses:
        value = (expenses[user]) - ((total)/n)
        if (value > 0):
            levana[user] = value
        else:
            devana[user] = (-1)*value

    levana = dict(sorted(levana.items(), key=lambda item: item[1], reverse=True))
    devana = dict(sorted(devana.items(), key=lambda item: item[1], reverse=True))

    for user in levana:
        levana[user] = round(levana[user], 2)
    for user in devana:
        devana[user] = round(devana[user], 2)

    transactions = []

    while(True):
        _levana = levana.copy()
        _devana = devana.copy()
        if len(levana) == 0:
            break
        while(True):
            c = 0
            for rich_kid in _levana:
                for poor_kid in _devana:
                    try:
                        if levana[rich_kid] == devana[poor_kid]:
                            c=1
                            transactions.append([poor_kid, round(levana[rich_kid],2), rich_kid])
                            del levana[rich_kid]
                            del devana[poor_kid]
                    except:
                        pass

            while(True):
                count = 0
                _levana = levana.copy()
                _devana = devana.copy()
                for rich_kid in _levana:
                    for poor_kid in _devana:
                        try:
                            if levana[rich_kid] - devana[poor_kid] in list(devana.values()):
                                levana[rich_kid] = levana[rich_kid] - devana[poor_kid]
                                transactions.append([poor_kid, round(devana[poor_kid],2), rich_kid])
                                del devana[poor_kid]
                                count = 1
                                c=1
                            if devana[poor_kid] - levana[rich_kid] in list(levana.values()):
                                devana[poor_kid] = devana[poor_kid]- levana[rich_kid]
                                transactions.append([poor_kid, round(levana[rich_kid],2), rich_kid])
                                del levana[rich_kid]
                                count = 1
                                c=1
                        except:
                            pass
                if count == 0:
                    break
            if c == 0:
                break

        levana = dict(sorted(levana.items(), key=lambda item: item[1], reverse=True))
        devana = dict(sorted(devana.items(), key=lambda item: item[1], reverse=True))
        _levana = levana.copy()
        _devana = devana.copy()
        for rich_kid in _levana:
            for poor_kid in _devana:
                try:
                    if levana[rich_kid] - devana[poor_kid] > 0:
                        levana[rich_kid] = levana[rich_kid] - devana[poor_kid]
                        transactions.append([poor_kid, round(devana[poor_kid],2), rich_kid])
                        del devana[poor_kid]
                    else:
                        devana[poor_kid] = devana[poor_kid]- levana[rich_kid]
                        transactions.append([poor_kid, round(levana[rich_kid],2), rich_kid])
                        del levana[rich_kid]
                except:
                    pass
                break
            break


    return render_template("summary.html",mapping=transactions)






"""Helper function"""
def get_expenses(id):
    group_id = id

    rows = db.execute("SELECT user_id FROM group_users WHERE group_id = ?", group_id)
    group_users_id = []
    for row in rows:
        if row["user_id"] not in group_users_id:
            group_users_id.append(row["user_id"])

    # id: name
    group_users_name = {}
    for i in group_users_id:
        data = db.execute("SELECT username FROM users WHERE user_id = ?", i)
        group_users_name[i] = data[0]["username"]

    rows = db.execute("SELECT user_id, description, amount FROM expenses WHERE group_id = ?", group_id)
    expenses = {}

    for row in rows:
        name = group_users_name[row["user_id"]]
        if name not in expenses:
            expenses[name] = {row["description"]:row["amount"]}
        else:
            (expenses[name])[row["description"]] = row["amount"]

    return expenses