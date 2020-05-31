import os
import datetime

from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Set up Database on Heroku
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))


@app.after_request
# Ensure responses aren't cached
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@ app.route("/")
@login_required
def index():
    # Query database for cash
    lines = db.execute("SELECT cash FROM users WHERE id=:user_id",
                       {"user_id": session["user_id"]}).fetchone()
    cash = float(lines["cash"])

    # Query "stocks" table
    rows = db.execute("SELECT symbol, SUM(shares) FROM stocks WHERE user_id=:user_id GROUP BY symbol HAVING SUM(shares) > 0",
                      {"user_id": session["user_id"]}).fetchall()

    if len(rows) == 0:
        return render_template("index.html", cash=usd(cash))

    # Update "stocks" table
    symbols = []
    names = []
    shares = []
    price = []
    total = []

    total_shares = float("{:.2f}".format(0))

    for i in range(len(rows)):
        symbols.append(rows[i]["symbol"])
        names.append(lookup(symbols[i])["name"])
        shares.append(rows[i]["sum"])
        price.append(lookup(symbols[i])["price"])
        total.append(price[i] * float(shares[i]))

        total_shares += total[i]

    for j in range(len(rows)):
        price[j] = usd(price[j])
        total[j] = usd(total[j])

    grand = cash + total_shares

    return render_template("index.html", rows=range(len(rows)), symbols=symbols, shares=shares,
                           names=names, price=price, total=total, cash=usd(cash), grand=usd(grand))


@ app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Check input
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        elif not confirmation:
            return apology("must provide password (again)", 403)
        elif password != confirmation:
            return apology("passwords don't match", 400)

        # Check username
        users = db.execute("SELECT username FROM users WHERE username=:username",
                           {"username": username}).fetchall()
        if len(users) != 0:
            return apology("username is not available", 400)

        # Insert into "users" table
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   {"username": username, "hash": generate_password_hash(password)})
        db.commit()

        # Remember which user has logged in
        users = db.execute("SELECT id FROM users WHERE username=:username",
                           {"username": username}).fetchall()
        session["user_id"] = users[0]["id"]

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Check input
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)

        # Query database for username
        users = db.execute("SELECT * FROM users WHERE username = :username",
                           {"username": username}).fetchall()

        # Ensure username exists and password is correct
        if len(users) != 1 or not check_password_hash(users[0]["hash"], password):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = users[0]["id"]

        return redirect("/")
    else:
        return render_template("login.html")


@ app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@ app.route("/password")
@ login_required
def password():
    return render_template("password.html")


@ app.route("/reset", methods=["POST"])
def reset():
    # Check input
    present_password = request.form.get("present_password")
    new_password = request.form.get("new_password")
    confirmation = request.form.get("confirmation")

    if not present_password:
        return apology("must provide present password", 403)
    elif not new_password:
        return apology("must provide new password", 403)
    elif not confirmation:
        return apology("must provide new password (again)", 403)
    elif new_password != confirmation:
        return apology("passwords don't match", 400)

    # Check previous password
    users = db.execute("SELECT hash FROM users WHERE id=:id",
                       {"id": session["user_id"]}).fetchone()

    if not check_password_hash(users["hash"], present_password):
        return apology("invalid password", 403)
    elif check_password_hash(users["hash"], new_password):
        return apology("same password", 403)

    # Insert into "users" table
    db.execute("UPDATE users SET hash=:hash WHERE id=:id",
               {"hash": generate_password_hash(new_password), "id": session["user_id"]})
    db.commit()

    return redirect("/")


@ app.route("/quote", methods=["GET", "POST"])
@ login_required
def quote():
    if request.method == "POST":
        # Check input
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("missing symbol", 400)

        quote = lookup(symbol)
        if quote == None:
            return apology("invalid symbol", 400)

        # Return quoted.html
        name = quote["name"]
        price = quote["price"]

        return render_template("quoted.html", name=name, symbol=symbol, price=usd(price))
    else:
        return render_template("quote.html")


@ app.route("/buy", methods=["GET", "POST"])
@ login_required
def buy():
    if request.method == "POST":
        # Check input
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        if not symbol:
            return apology("missing symbol", 400)
        elif not shares:
            return apology("missing shares", 400)

        quote = lookup(symbol)
        if quote == None:
            return apology("invalid symbol", 400)

        # Check cash
        price = quote["price"]
        total = price * float(shares)
        rows = db.execute("SELECT cash FROM users WHERE id=:user_id",
                          {"user_id": session["user_id"]}).fetchone()
        cash = float(rows["cash"])

        if cash < total:
            return apology("can't afford", 400)

        # Insert into "stocks" table
        date = datetime.datetime.strptime(datetime.datetime.today().strftime(
            "%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")

        db.execute("INSERT INTO stocks (symbol, shares, price, date, user_id) VALUES (:symbol, :shares, :price, :date, :user_id)",
                   {"symbol": symbol, "shares": int(shares), "price": price, "date": date, "user_id": session["user_id"]})
        db.commit()

        # Update cash
        cash = cash - total

        db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                   {"cash": cash, "id": session["user_id"]})
        db.commit()

        return redirect("/")
    else:
        return render_template("buy.html")


@ app.route("/sell", methods=["GET", "POST"])
@ login_required
def sell():
    # Query "stocks" table
    rows = db.execute("SELECT symbol, SUM(shares) FROM stocks WHERE user_id=:user_id GROUP BY symbol HAVING SUM(shares) > 0",
                      {"user_id": session["user_id"]}).fetchall()

    if request.method == "POST":
        # Check input
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("missing symbol", 400)
        elif not shares:
            return apology("missing shares", 400)

        # Check shares
        for row in rows:
            if symbol == row["symbol"] and int(shares) > row["sum"]:
                return apology("too many shares", 400)

        # Insert into "stocks" table
        quote = lookup(symbol)
        price = quote["price"]
        date = datetime.datetime.strptime(datetime.datetime.today().strftime(
            "%Y-%m-%d %H:%M:%S"), "%Y-%m-%d %H:%M:%S")

        db.execute("INSERT INTO stocks (symbol, shares, price, date, user_id) VALUES (:symbol, :shares, :price, :date, :user_id)",
                   {"symbol": symbol, "shares": -int(shares), "price": price, "date": date, "user_id": session["user_id"]})
        db.commit()

        # Update cash
        rows = db.execute("SELECT cash FROM users WHERE id=:user_id",
                          {"user_id": session["user_id"]}).fetchone()
        cash = float(rows["cash"])
        total = price * float(shares)
        cash = cash + total

        db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                   {"cash": cash, "id": session["user_id"]})
        db.commit()

        return redirect("/")
    else:
        return render_template("sell.html", rows=rows)


@ app.route("/history")
@ login_required
def history():
    # Query "stocks" table
    rows = db.execute("SELECT symbol, shares, price, date FROM stocks WHERE user_id=:user_id",
                      {"user_id": session["user_id"]}).fetchall()
    symbols = []
    shares = []
    price = []
    dates = []

    for i in range(len(rows)):
        symbols.append(rows[i]["symbol"])
        shares.append(rows[i]["shares"])
        price.append(usd(rows[i]["price"]))
        dates.append(rows[i]["date"])

    return render_template("history.html", rows=range(len(rows)), symbols=symbols, shares=shares,
                           price=price, dates=dates)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
