import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    port = db.execute("SELECT ticker, qty FROM portfolio WHERE id = :ident", ident = session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = :ident", ident = session["user_id"])
    nworth = cash[0]["cash"]
    cash[0]["cash"] = usd(cash[0]["cash"])

    for row in port:
        info = lookup(row["ticker"])
        print(row)
        row.update({"price" : usd(info["price"])})
        value = round(info["price"] * row["qty"],2)
        row.update({"value" : usd(value)})
        row.update({"name" : info["name"]})
        nworth = nworth + value

    nworth = usd(nworth)

    return render_template("index.html", port = port, cash = cash, nworth = nworth)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        info = lookup(symbol)

        if info == None:
            return apology("Ticker Symbol Not Found")

        if shares == "":
            return apology("Enter Valid Shares")
        else:
            shares = int(shares)

        if shares < 1:
            return apology("Enter Valid Shares")
        elif symbol == "":
            return apology("Ticker Symbol Not Found")

        cash = db.execute("SELECT cash FROM users WHERE id = :ident", ident = session["user_id"])

        balance = float(cash[0]["cash"])
        price = float(round((shares * info["price"]), 2))

        new_Bal = round(balance - price, 2)
        if new_Bal < 0:
            return apology("Not Enough Cash")
        else:
            ident = session["user_id"]
            db.execute("UPDATE users SET cash = ? WHERE id == ?", new_Bal, ident)
            db.execute("INSERT INTO transactions (id, ticker, price, qty, type) VALUES (:ident, :ticker, :price, :qty, :buy)",
                        ident = ident, ticker = symbol, price = info["price"], qty = shares, buy = "buy")

        # Check if user owns stock and update quantity or create record
        portf = db.execute("SELECT * FROM portfolio WHERE id == ?", ident)
        print(portf)
        for row in portf:
            print(row["ticker"])
            print(symbol)
            if row["ticker"] == symbol:
                quantity = row["qty"]
                nquantity = quantity + shares
                db.execute("UPDATE portfolio SET qty = ? WHERE id == ? and ticker == ?", nquantity, ident, symbol)
                return redirect("/")

        db.execute("INSERT INTO portfolio (id, ticker, qty) VALUES (:ident, :ticker, :qty)", ident = ident, ticker = symbol, qty = shares)
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT ticker, qty, price, time, type FROM transactions WHERE id = :ident", ident=session["user_id"])

    return render_template("history.html", history = history)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        info = lookup(symbol)

        if info == None:
            return apology("Ticker Symbol Not Found")

        else:
            return render_template("quoted.html", symbol = info["symbol"], price = info["price"], name = info["name"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        name = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :name", name = request.form.get("username"))

        if len(rows) != 0 or name == '':
            return apology("invalid username and/or password 1", 403)

        # Check that passwords match
        if password != confirm or password == '':
            return apology("invalid username and/or password 2", 403)

        # Hash user's password
        hashPass = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Enter user into database
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashPass)", username = name, hashPass = hashPass)

        # Get id of new user so you can log in
        login = db.execute("SELECT id FROM users WHERE username = :name", name = request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = login[0]["id"]

        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        stocks = db.execute("SELECT ticker FROM portfolio WHERE id == :ident", ident = session["user_id"])
        return render_template("sell.html", stocks = stocks)
    else:
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")
        info = lookup(symbol)

        # Check that a value is entered for shares
        if shares == "":
            return apology("Enter Valid Share Count")
        else:
            shares = int(shares)

        if shares < 1:
            return apology("Enter Valid Share Count")
        elif symbol == "":
            return apology("Ticker Symbol Not Found")

        cash = db.execute("SELECT cash FROM users WHERE id = :ident", ident = session["user_id"])
        quantity = db.execute("SELECT qty FROM portfolio WHERE id == :ident and ticker == :ticker", ident = session["user_id"], ticker = symbol)

        print(quantity)

        if quantity[0]["qty"] == None:
            return apology("Stock Not Owned")

        if int(quantity[0]["qty"]) < shares:
            return apology("You Don't Have Enough Shares")

        balance = float(cash[0]["cash"])
        value = float(round((shares * info["price"]), 2))

        # Update user's balance
        new_Bal = round(balance + value, 2)
        ident = session["user_id"]

        # Record transaction in History Log
        db.execute("UPDATE users SET cash = ? WHERE id == ?", new_Bal, ident)
        db.execute("INSERT INTO transactions (id, ticker, price, qty, type) VALUES (:ident, :ticker, :price, :qty, :buy)",
                    ident = ident, ticker = symbol, price = info["price"], qty = shares, buy = "sell")

        # Update quantity or delete record
        nquantity = quantity[0]["qty"] - shares
        db.execute("UPDATE portfolio SET qty = ? WHERE ticker == ?", nquantity, symbol)

        # Delete record if new quantity is 0
        if nquantity == 0:
            db.execute("DELETE FROM portfolio WHERE id == ? AND ticker == ?", ident, symbol)
        return redirect("/")

@app.route("/password", methods=["GET", "POST"])
def password():
    """Allow User to Change Password"""
    if request.method=="GET":
        return render_template("password.html")
    else:
        name = request.form.get("username")
        password = request.form.get("password")
        new = request.form.get("new")
        confirm = request.form.get("confirm")

         # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :name", name = name)

        if len(rows) != 1 or name == '':
            return apology("invalid username and/or password", 403)

        # Check that user entered correct current password
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password 1", 403)

        print(new)
        print(confirm)

        # Check that new passwords match
        if new != confirm or new == '':
            return apology("invalid new password 2", 403)

        # Hash user's new password
        hashPass = generate_password_hash(new, method='pbkdf2:sha256', salt_length=8)

        # Enter user into database
        db.execute("UPDATE users SET hash = ? WHERE username = ?", hashPass, name)

        return redirect("/login")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
