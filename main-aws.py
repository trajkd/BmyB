import os

import webapp2
import jinja2

#from google.appengine.api import memcache
# from pymemcache.client.base import Client
# memcache = Client(('bookstobook.dvlw2w.cfg.usw2.cache.amazonaws.com', 11211))
#from google.appengine.ext import db
import boto3

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

import urllib2
import json

#class Book(db.Model):
#    title = db.StringProperty(required=True)
#    authors = db.StringProperty()
#    isbn = db.IntegerProperty(required=True)
#    publishers = db.StringProperty()
#    #date = db.DateTimeProperty()
#    pages = db.StringProperty()
#    language = db.StringProperty()
#    rating = db.RatingProperty()
#    cover = db.StringProperty()
#    description = db.TextProperty()

#class User(db.Model):
#    username = db.StringProperty(required=True)
#    password = db.StringProperty(required=True)
#    email = db.StringProperty()

#class Customer(db.Model):
#    id = db.StringProperty(required=True)
#    email = db.StringProperty(required=True)

def create_book_table(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.client('dynamodb', region_name='us-west-2')
    try:
        table = dynamodb.create_table(
            TableName='Book',
           KeySchema=[
                {
                'AttributeName': 'isbn',
                'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'isbn',
                    'AttributeType': 'N'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        return table
    except dynamodb.exceptions.ResourceInUseException:
        pass
create_book_table()

def create_user_table(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.client('dynamodb', region_name='us-west-2')
    try:
        table = dynamodb.create_table(
            TableName='User',
            KeySchema=[
                {
                    'AttributeName': 'username',
                    'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'username',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        return table
    except dynamodb.exceptions.ResourceInUseException:
        pass
create_user_table()

def create_customer_table(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.client('dynamodb', region_name='us-west-2')
    try:
        table = dynamodb.create_table(
            TableName='Customer',
            KeySchema=[
                {
                    'AttributeName': 'id',
                    'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'id',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        return table
    except dynamodb.exceptions.ResourceInUseException:
        pass
create_customer_table()

ISBN_URL = "http://openlibrary.org/api/books?jscmd=data&format=json&bibkeys=ISBN:"
def get_info(isbn):
        url = ISBN_URL + isbn
        content = json.loads(urllib2.urlopen(url).read())
        if 'ISBN:'+isbn in content:
                entry = content['ISBN:'+isbn]
                title = entry['title']
                authors_array = []
                if 'authors' in entry:
                        for author in entry['authors']:
                                authors_array.append(author['name'])
                authors = ", ".join(authors_array)
                publishers_array = []
                if 'publishers' in entry:
                        for publisher in entry['publishers']:
                                publishers_array.append(publisher['name'])
                publishers = ", ".join(publishers_array)
                pages = "0"
                if 'pagination' in entry:
                        pages = entry['pagination'][:entry['pagination'].find("p.")]
                cover = "Not available"
                if 'cover' in entry:
                        cover = entry['cover']['large']
                return {'title':title, 'authors':authors, 'isbn':(int)(isbn), 'publishers':publishers, 'pages':pages, 'cover':cover}
        else:
                return {}

import re
def valid_username(username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return username and USER_RE.match(username)

def valid_password(password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return password and PASS_RE.match(password)

def valid_email(email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return not email or EMAIL_RE.match(email)

import random
import string
import hashlib

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    if make_pw_hash(name, pw, h.split(",")[1]) == h:
        return True

signupform="""
<h2>Signup</h2>
    <form method="post">
      <table>
        <tbody><tr>
          <td class="label">
            Username
          </td>
          <td>
            <input type="text" name="username" value="%(username)s">
          </td>
          <td class="error">
            %(username_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Password
          </td>
          <td>
            <input type="password" name="password" value="">
          </td>
          <td class="error">
            %(password_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Verify Password
          </td>
          <td>
            <input type="password" name="verify" value="">
          </td>
          <td class="error">
            %(verify_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Email (optional)
          </td>
          <td>
            <input type="text" name="email" value="%(email)s">
          </td>
          <td class="error">
            %(email_error)s
          </td>
        </tr>
      </tbody></table>

      <input type="submit">
    </form>
"""

from boto3.dynamodb.conditions import Key
def scan_books(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

    table = dynamodb.Table('Book')
    scan_kwargs = {
        'ProjectionExpression': "title, authors, isbn, publishers, pages, rating, cover"
    }

    done = False
    start_key = None
    l = []
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        response = table.scan(**scan_kwargs)
        l += response.get('Items', [])
        start_key = response.get('LastEvaluatedKey', None)
        done = start_key is None
    return l

def all_books(update = False):
        #key = 'all'
        #books = memcache.get(key)
        #if books is None or update:
                #books = db.GqlQuery("SELECT * FROM Book ORDER BY title DESC")
                #books = list(books)
        books = scan_books()
                #memcache.set(key, books)
        return books

from botocore.exceptions import ClientError
def get_book_table(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

    table = dynamodb.Table('Book')
    return table

def single_book(book_id, update=False, delete=False):
        #key = str(book_id)
        #if delete:
        #       memcache.delete(key)
        #else:
        #       book = memcache.get(key)
        #       if book is None or update:
        #               #book = Book.get_by_id(long(book_id))
        try:
            response = table.get_item(Key={'isbn': long(book_id)})
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            book = response['Item']
        #memcache.set(key, book)
        return book

class MainPage(webapp2.RequestHandler):
        def get(self):
                books = all_books()
                self.response.out.write(jinja_env.get_template('catalog.html').render(books=books))

def query_users(username, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

    table = dynamodb.Table('User')
    response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    return response['Items']

class NewBookHandler(webapp2.RequestHandler):
        def get(self):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_users(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u['password'].split(",")[0]==password_hash:
                                self.response.out.write(jinja_env.get_template('newbook.html').render(error="",isbn=""))
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')
        def post(self):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_users(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u['password'].split(",")[0]==password_hash:
                                isbn = self.request.get('isbn')
                                books = all_books()
                                for book in books:
                                        if str(book.isbn) in isbn:
                                                self.response.out.write(jinja_env.get_template('newbook.html').render(error="Book already added!", isbn=isbn))
                                                return
                                info = get_info(isbn)
                                if not info:
                                        self.response.out.write(jinja_env.get_template('newbook.html').render(error="Book not found!", isbn=isbn))
                                else:
                                        dynamodb = boto3.resource('dynamodb', endpoint_url="http://localhost:8000")
                                        table = dynamodb.Table('Book')
                                        table.put_item(
                                            Item={
                                                'title': info['title'],
                                                'authors': info['authors'],
                                                'isbn': info['isbn'],
                                                'publishers': info['publishers'],
                                                'pages': info['pages'],
                                                'cover': info['cover']
                                            }
                                        )
                                        all_books(True)
                                        single_book(str(info['isbn']), True)
                                        self.redirect('/')
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')

class NewManualBookHandler(webapp2.RequestHandler):
        def get(self):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_users(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u['password'].split(",")[0]==password_hash:
                                self.response.out.write(jinja_env.get_template('newmanualbook.html').render(error="",title="", authors="", isbn="", publishers="", pages="", cover=""))
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')
        def post(self):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_users(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u['password'].split(",")[0]==password_hash:
                                if not self.request.get('isbn') or not self.request.get('title'):
                                        self.response.out.write(jinja_env.get_template('newmanualbook.html').render(error="ISBN and title required!", title=self.request.get('title'), authors=self.request.get('authors'), isbn=self.request.get('isbn'), publishers=self.request.get('publishers'), pages=self.request.get('pages'), cover=self.request.get('cover')))
                                        return
                                isbn = self.request.get('isbn')
                                books = all_books()
                                for book in books:
                                        if str(book.isbn) in isbn:
                                                self.response.out.write(jinja_env.get_template('newmanualbook.html').render(error="Book already added!", title=self.request.get('title'), authors=self.request.get('authors'), isbn=self.request.get('isbn'), publishers=self.request.get('publishers'), pages=self.request.get('pages'), cover=self.request.get('cover')))
                                                return
                                dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
                                table = dynamodb.Table('Book')
                                table.put_item(
                                    Item={
                                        'title': self.request.get('title'),
                                        'authors': self.request.get('authors'),
                                        'isbn': (int)(self.request.get('isbn')),
                                        'publishers': self.request.get('publishers'),
                                        'pages': self.request.get('pages'),
                                        'cover': self.request.get('cover')
                                    }
                                )
                                #newBook = Book(title=self.request.get('title'), authors=self.request.get('authors'), isbn=(int)(self.request.get('isbn')), publishers=self.request.get('publishers'), pages=self.request.get('pages'), cover=self.request.get('cover'))
                                #newBook.put()
                                all_books(True)
                                #single_book(newBook.key().id(), True)
                                single_book(self.request.get('isbn'), True)
                                self.redirect('/')
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')

class EditBookHandler(webapp2.RequestHandler):
        def get(self, book_id):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_users(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u['password'].split(",")[0]==password_hash:
                                b = Book.get_by_id(long(book_id))
                                self.response.out.write(jinja_env.get_template('editbook.html').render(book=b))
                        else:
                                self.redirect('/'+book_id+'/detail')
                else:
                        self.redirect('/'+book_id+'/detail')
        def post(self, book_id):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_users(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u['password'].split(",")[0]==password_hash:
                                #b = Book.get_by_id(long(book_id))
                                table = get_book_table()
                                if self.request.get('title') != '':
                                        #b.title = self.request.get('title')
                                        response = table.update_item(
                                            Key={
                                                'isbn': isbn
                                            },
                                            UpdateExpression="set title=:t",
                                            ExpressionAttributeValues={
                                                ':t': self.request.get('title')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('authors') != '':
                                        #b.authors = self.request.get('authors')
                                        response = table.update_item(
                                            Key={
                                                'isbn': isbn
                                            },
                                            UpdateExpression="set authors=:a",
                                            ExpressionAttributeValues={
                                                ':a': self.request.get('authors')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('isbn') != '':
                                        #b.isbn = (int)(self.request.get('isbn'))
                                        response = table.update_item(
                                            Key={
                                                'isbn': isbn
                                            },
                                            UpdateExpression="set isbn=:i",
                                            ExpressionAttributeValues={
                                                ':i': (int)(self.request.get('isbn'))
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('publishers') != '':
                                        #b.publishers = self.request.get('publishers')
                                        response = table.update_item(
                                            Key={
                                                'isbn': isbn
                                            },
                                            UpdateExpression="set publishers=:p",
                                            ExpressionAttributeValues={
                                                ':p': self.request.get('publishers')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('pages') != '':
                                        #b.pages = self.request.get('pages')
                                        response = table.update_item(
                                            Key={
                                                'isbn': isbn
                                            },
                                            UpdateExpression="set pages=:g",
                                            ExpressionAttributeValues={
                                                ':g': self.request.get('pages')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('cover') != '':
                                        #b.cover = self.request.get('cover')
                                        response = table.update_item(
                                            Key={
                                                'isbn': isbn
                                            },
                                            UpdateExpression="set cover=:c",
                                            ExpressionAttributeValues={
                                                ':c': self.request.get('cover')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                #b.put()
                                all_books(True)
                                single_book(book_id, True)
                                self.redirect('/')
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')

def delete_book(isbn, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

    table = dynamodb.Table('Book')

    try:
        response = table.delete_item(
            Key={
                'isbn': isbn
            }
        )
    except ClientError as e:
        if e.response['Error']['Code'] == "ConditionalCheckFailedException":
            print(e.response['Error']['Message'])
        else:
            raise
    else:
        return response

class DeleteBookHandler(webapp2.RequestHandler):
        def get(self, book_id):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_users(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u['password'].split(",")[0]==password_hash:
                                b = Book.get_by_id(long(book_id))
                                self.response.out.write(jinja_env.get_template('deletebook.html').render(book=b))
                        else:
                                self.redirect('/'+book_id+'/detail')
                else:
                        self.redirect('/'+book_id+'/detail')
        def post(self, book_id):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_users(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u['password'].split(",")[0]==password_hash:
                                #b = Book.get_by_id(long(book_id))
                                #b.delete()
                                delete_book(book_id)
                                all_books(True)
                                single_book(book_id, False, True)
                                self.redirect('/')
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')

class SignupHandler(webapp2.RequestHandler):
        def write_form(self, username="", email="", username_error="", password_error="", verify_error="", email_error=""):
                self.response.out.write(signupform%{"username": username,
                                                                                                "email": email,
                                                                                                "username_error": username_error,
                                                                                                "password_error": password_error,
                                                                                                "verify_error": verify_error,
                                                                                                "email_error": email_error})
        def get(self):
                self.write_form()
        def post(self, username="", email="", username_error="", password_error="", verify_error="", email_error="", ):
                username = self.request.get("username")
                password = self.request.get("password")
                verify = self.request.get("verify")
                email = self.request.get("email")
                if (valid_username(username) and valid_password(password) and valid_email(email) and password == verify):
                        #if len(db.Query(User).filter("username =", username).fetch(limit=1))==0:
                        if len(query_users(username))==0:
                                password = make_pw_hash(username, password)
                                #u = User(username=username, password=password, email=email)
                                #u.put()
                                dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
                                table = dynamodb.Table('User')
                                table.put_item(
                                    Item={
                                        'username': username,
                                        'password': password,
                                        'email': email
                                    }
                                )
                                #self.response.headers.add_header("Set-Cookie", "userid=%s; Path=/"%(str(u.key().id())+"|"+u.password))
                                self.response.headers.add_header("Set-Cookie", "userid=%s; Path=/"%(username+"|"+password))
                                self.redirect("/")
                        else:
                                self.write_form(username_error="That user already exists.")
                if not valid_username(username):
                        username_error = "That's not a valid username."
                if not valid_password(password):
                        password_error = "That's not a valid password."
                if not password == verify:
                        verify_error = "Your passwords didn't match."
                if not valid_email(email):
                        email_error = "That's not a valid email."
                self.write_form(username, email, username_error, password_error, verify_error, email_error)

def render_str(template, **params):
                t = jinja_env.get_template(template)
                return t.render(params)

class Handler(webapp2.RequestHandler):
        def write(self, *a, **kw):
                self.response.out.write(*a, **kw)
        def render_str(self, template, **params):
                return render_str(template, **params)
        def render(self, template, **kw):
                self.write(self.render_str(template, **kw))

class PermalinkHandler(Handler):
        def get(self, book_id):
                b = single_book(book_id)
                if not b:
                        self.error(404)
                        return
                self.render("permalink.html", book=b)

class LoginHandler(Handler):
        def get(self):
                self.render("login.html", username="", login_error="")
        def post(self):
                username = self.request.get("username")
                password = self.request.get("password")
                #u = db.Query(User).filter("username =", username).fetch(limit=1)
                u = query_users(username)
                if not len(u)==0 and valid_pw(username, password, u[0].password):
                        #self.response.headers.add_header("Set-Cookie", "userid=%s; Path=/"%(str(u[0].key().id())+"|"+str(u[0].password)))
                        self.response.headers.add_header("Set-Cookie", "userid=%s; Path=/"%(str(u[0]['username'])+"|"+str(u[0]['password'])))
                        self.redirect("/new")
                else:
                        self.render("login.html", username=username, login_error="Invalid login")

class LogoutHandler(Handler):
        def get(self):
                self.response.headers.add_header("Set-Cookie", "userid=; Path=/")
                self.redirect("/")

import stripe
stripe.api_key = "sk_test_Zwfb59Bjpkde9suz9L8D3N3Y003fqZuzoD"

def scan_customers(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

    table = dynamodb.Table('Customer')
    scan_kwargs = {
        'ProjectionExpression': "id, email"
    }

    done = False
    start_key = None
    l = []
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        response = table.scan(**scan_kwargs)
        l += response.get('Items', [])
        start_key = response.get('LastEvaluatedKey', None)
        done = start_key is None
    return l

def isNewCustomer(email):
    customers = scan_customers()
    customers = list(customers)
    for c in customers:
        if email == c.email:
            return False
    return True 

class CreateCustomerHandler(Handler):
    def post(self):
        data = json.loads(self.request.body)
        paymentMethod = data['payment_method']
        try:
            if isNewCustomer(data['email']):
                customer = stripe.Customer.create(
                    payment_method=paymentMethod,
                    email=data['email'],
                    invoice_settings={
                        'default_payment_method': paymentMethod
                    }
                )
                dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
                table = dynamodb.Table('Customer')
                table.put_item(
                    Item={
                        'id': customer.id,
                        'email': data['email']
                    }
                )
                #newCustomer = Customer(id=customer.id, email=data['email'])
                #newCustomer.put()
                subscription = stripe.Subscription.create(
                    customer=customer.id,
                    items=[
                    {
                        'plan': 'plan_H4pcEEclVl4I7E',
                    },
                    ],
                    expand=['latest_invoice.payment_intent']
                )
                self.response.headers['Content-Type'] = 'application/json'
                self.response.out.write(str(subscription))
            else:
                self.error(403)
        except Exception as e:
            print(str(e))
            self.error(403)

class SignupFormHandler(Handler):
    def get(self):
        self.render("signupform.html")
    def post(self):
        self.redirect("/create-customer")

import mimetypes
class StaticFileHandler(webapp2.RequestHandler):
    def get(self, path):
        abs_path = os.path.abspath(os.path.join(self.app.config.get('webapp2_static.static_file_path', 'static'), path))
        if os.path.isdir(abs_path) or abs_path.find(os.getcwd()) != 0:
            self.response.set_status(403)
            return
        try:
            f = open(abs_path, 'r')
            self.response.headers.add_header('Content-Type', mimetypes.guess_type(abs_path)[0])
            self.response.headers['Content-Type'] = mimetypes.guess_type(abs_path)[0]
            self.response.out.write(f.read())
            f.close()
        except:
            self.response.set_status(404)

app = webapp2.WSGIApplication([
        ('/', MainPage),
        ('/(\d+)/detail', PermalinkHandler),
        ('/(\d+)/edit', EditBookHandler),
        ('/(\d+)/delete', DeleteBookHandler),
        ('/new', NewBookHandler),
        ('/new/manual', NewManualBookHandler),
        ('/login', LoginHandler),
        ('/logout', LogoutHandler),
        ('/signup', SignupHandler),
        ('/create-customer', CreateCustomerHandler),
        ('/signupform', SignupFormHandler),
        (r'/static/(.+)', StaticFileHandler)
], debug = True)

def main():
    from paste import httpserver
    httpserver.serve(app, host='172.31.10.101', port='80')

if __name__ == '__main__':
    main()
