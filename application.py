import os
import requests

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from time import gmtime, strftime

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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
    portfolio = db.execute(
        "SELECT item,SUM(nbitem),price,SUM(total) AS bought FROM purchase WHERE id=:id GROUP BY item", id=session["user_id"])
    username = db.execute("SELECT username FROM users WHERE id=:id",id=session["user_id"])
    names = []
    prices = []
    totals = []
    for item in portfolio:
        symbol = str(item["item"])
        quote = lookup(symbol)
        names.append(quote['name'])
        prices.append(usd(item["price"]))
        totals.append(usd(item["SUM(nbitem)"]*quote["price"]))
    return render_template("mail.html", portfolio=portfolio, prices=prices, totals=totals, cash=usd(cash[0]["cash"]), names=names, username=username)


@app.route("/pass", methods=["GET", "POST"])
@login_required
def changpassword():
    """Change password"""
    if request.method == "POST":
        password = request.form.get("password", type=str)
        if not password:
            return apology("please enter your password")
        rows = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid password", 403)

        newpassword = request.form.get("newpassword", type=str)
        confirmation = request.form.get("confirmation", type=str)
        if not newpassword:
            return apology("please enter a new password")
        if not confirmation:
            return apology("confirme your password")
        if newpassword != confirmation:
            return apology("The Password Confirmation must match your Password")
        hashpass = generate_password_hash(newpassword, method='pbkdf2:sha256', salt_length=8)
        rows = db.execute("UPDATE users SET hash=:hashpass WHERE id=:id", hashpass=hashpass, id=session["user_id"])
        return render_template("login.html")
    else:
        return render_template("pass.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("please render a quote symbol")
        data = lookup(symbol)
        if not data:
            return apology("invalid symbol")
        else:
            company = data["name"]
            symb = data["symbol"]
            price = data["price"]
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        nb = request.form.get("shares")
        try:
            shares = int(nb)
        except ValueError:
            return apology("shares must be a posative integer", 400)
        if int(nb) <= 0 or not int(nb):
            return apology("enter a valid number of shares")
        total = float(nb) * data["price"]
        if total > cash[0]["cash"]:
            return apology("you can't affoard this shares")
        else:
            time = strftime("%a, %d %b %Y %H:%M:%S", gmtime())
            rows = db.execute("INSERT INTO purchase (id,item,time,price,nbitem,total) VALUES(:id,:symb,:time,:price,:nb,:total)",
                              id=session["user_id"], symb=symb, time=time, price=price, nb=nb, total=total)
            rows = db.execute("UPDATE users SET cash = cash - :total WHERE id=:id", total=total, id=session["user_id"])
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    if len(username) > 0:
        rows = db.execute("SELECT * FROM users WHERE username = :name", name=username)
        if len(rows) > 0:
            return jsonify(False)
        else:
            return jsonify(True)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    hist = db.execute("SELECT item,nbitem,price,time FROM purchase WHERE id=:id", id=session["user_id"])
    prices = []
    times = []
    i = 0
    for item in hist:
        prices.append(usd(float(hist[i]["price"])))
        times.append(hist[i]["time"])
        i += 1
    return render_template("history.html", hist=hist, prices=prices, times=times)


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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("please render a quote symbol")
        data = lookup(symbol)
        if not data:
            return apology("invalid symbol")
        else:
            company = data["name"]
            symb = data["symbol"]
            price = usd(data["price"])
            return render_template("quoted.html", company=company, symb=symb, price=price)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username", type=str)
        if not username:
            return apology("please provide a username")
        rows = db.execute("SELECT * FROM users WHERE username = :name", name=username)
        if len(rows) > 0:
            return apology("username already existe")

        password = request.form.get("password", type=str)
        confirmation = request.form.get("confirmation", type=str)
        if not password:
            return apology("please enter a password")
        if not confirmation:
            return apology("confirme your password")
        if password != confirmation:
            return apology("The Password Confirmation must match your Password")
        hashpass = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        rows = db.execute("INSERT INTO users (username,hash) VALUES(:name,:passhash)", name=username, passhash=hashpass)
        return render_template("login.html")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    symbols = db.execute("SELECT item FROM purchase WHERE id=:id GROUP BY item", id=session["user_id"])
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("please choose a Shares to sell")
        nb = request.form.get("shares")
        if not nb or not nb.isdigit() or int(nb) <= 0:
            return apology("enter valid shares number")
        nbitem = db.execute("SELECT SUM(nbitem) AS bought FROM purchase WHERE id=:id AND item=:symbol ",
                            id=session["user_id"], symbol=symbol)
        if int(nb) > nbitem[0]["bought"]:
            return apology("too many shares")

        data = lookup(symbol)
        total = float(nb) * data["price"]
        time = strftime("%a, %d %b %Y %H:%M:%S", gmtime())
        rows = db.execute("INSERT INTO purchase (id,item,time,price,nbitem,total) VALUES(:id,:symb,:time,:price,:nb,:total)",
                          id=session["user_id"], symb=symbol, time=time, price=data["price"], nb=-int(nb), total=total)
        rows = db.execute("UPDATE users SET cash = cash + :total WHERE id=:id", total=total, id=session["user_id"])
        return redirect("/")
    else:
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

