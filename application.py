import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd
from passlib.apps import custom_app_context as pwd_context

#Y59B50K5WEHY4FD3

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

"""index page"""
@app.route("/")
@login_required
def index():
     # get symbols of stocks bought by user.
    stock_symbols = db.execute("SELECT symbol FROM stocks WHERE user_id=:user_id GROUP BY symbol;", user_id=session['user_id'])
    grand_total = 0

    if stock_symbols != []:
        stocks = []
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id;", user_id=session['user_id'])

        for symbol in stock_symbols:
            symbol_data = lookup(symbol['symbol'])
            stock_shares = db.execute("SELECT SUM(quantity) FROM stocks WHERE user_id=:user_id AND symbol = :symbol;", \
            user_id=session['user_id'], symbol=symbol_data['symbol'])
            if stock_shares[0]['SUM(quantity)'] <= 0:
                continue
            else:
                stock_info = {}

                #stock_info['name'] = symbol_data['name']
                stock_info['symbol'] = symbol_data['symbol']
                stock_info['price'] = symbol_data['price']
                stock_info['shares'] = stock_shares[0]['SUM(quantity)']
                stock_info['total'] = stock_info['shares'] * stock_info['price']

                stocks.append(stock_info)

        for i in range(len(stocks)):
            grand_total += stocks[i]['total']
        grand_total += cash[0]['cash']

        for i in range(len(stocks)):
            stocks[i]['price'] = usd(stocks[i]['price'])
            stocks[i]['total'] = usd(stocks[i]['total'])

        return render_template("index.html", stocks=stocks, cash=usd(cash[0]['cash']), grand_total=usd(grand_total))

    else:
        cash = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session['user_id'])
        return render_template("index.html", cash=usd(cash[0]['cash']), grand_total = usd(cash[0]['cash']))

"""Buy Stocks"""
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        # check if valid input
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("enter some input")

        # if symbol is empty return apology
        if not symbol:
            return apology("enter a valid symbol")

        # if shares is empty
        if not shares or shares <= 0:
            return apology("enter the number of shares")

        # if can't afford to buy then error
        # get cash from db
        userTotal = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session["user_id"])
        userTotal = int(userTotal[0]['cash'])
        if (shares * symbol['price']) > userTotal:
            return apology("can't afford")
        else:
            db.execute("INSERT INTO stocks (symbol, quantity, price, user_id) VALUES (:symbol, :quantity, :price, :user_id);", \
            symbol=symbol['symbol'], quantity=shares, price=symbol['price'], user_id=session["user_id"])
            # update cash (define old_balance)
            db.execute("UPDATE users SET cash=cash-:total_price WHERE id=:user_id;", total_price=shares*symbol['price'], \
            user_id=session["user_id"])

            return redirect(url_for("index"))

    else:
        return render_template("buy.html")

"""Show history of stocks"""
@app.route("/history")
@login_required
def history():
    stocks = db.execute("SELECT symbol, quantity, price, date_time FROM stocks WHERE user_id=:user_id", user_id=session['user_id'])

    for stock in stocks:
        stock['price'] = usd(stock['price'])

    return render_template("history.html", stocks=stocks)


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
        if len(rows) != 1 or not pwd_context.verify( request.form.get("password"),rows[0]["hash"]):
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


"""Get stock quote."""
@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("stock not found")
        else:
            quote['price'] = usd(quote['price'])
            return render_template("quote.html", quote=quote)
    else:
        return render_template("quote.html")

"""Register user"""
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == 'POST':

        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif not request.form.get("verify"):
            return apology("must provide password", 403)

        if request.form.get("password") != request.form.get("verify"):
            return apology("passwords must match")

        password = request.form.get("password")
        hash = pwd_context.hash(password)

        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", \
        username=request.form.get("username"), hash=hash)
        if not result:
            return apology("Use another username", 403)

        user_id = db.execute("SELECT id FROM users WHERE username IS :username",\
        username=request.form.get("username"))
        session['user_id'] = user_id[0]['id']
        return redirect(url_for("index"))
        #return render_template(login.html)

    else:

        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        # check if valid input
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("enter some input")

        # if symbol is empty return apology
        if not symbol:
            return apology("enter a valid symbol")

        # if shares is empty
        if not shares or shares <= 0:
            return apology("enter the quantity of shares")

        # is the stock in the portfolio?
        stocks_held = db.execute("SELECT SUM(quantity) FROM stocks WHERE user_id=:user_id AND symbol=:symbol;", \
        user_id=session['user_id'], symbol=symbol['symbol'])
        if not stocks_held[0]['SUM(quantity)'] :
            return apology("You don't own this stock")

        # is shares less or = to the stocks held?
        if shares > stocks_held[0]['SUM(quantity)']:
            return apology("You don't have that many stocks")

        # enter a new transaction in stocks
            # ensure a sale is a negative number
        db.execute("INSERT INTO stocks (symbol, quantity, price, user_id) VALUES (:symbol, :quantity, :price, :user_id);", \
        symbol=symbol['symbol'], quantity=-shares, price=symbol['price'], user_id=session["user_id"])

        # update cash
        db.execute("UPDATE users SET cash = cash + :total_price WHERE id = :user_id;", total_price=shares*symbol['price'], \
        user_id=session["user_id"])

        return redirect(url_for("index"))

    else:

        return render_template("sell.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
