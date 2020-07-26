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
                self.redirect("https://bookstobook.com/")

class NewBookHandler(webapp2.RequestHandler):
        def get(self):
                self.redirect("https://bookstobook.com/new")

class NewManualBookHandler(webapp2.RequestHandler):
        def get(self):
                self.redirect("https://bookstobook.com/new/manual")

class EditBookHandler(webapp2.RequestHandler):
        def get(self, book_id):
                self.redirect("https://bookstobook.com/"+book_id+"/edit")

class DeleteBookHandler(webapp2.RequestHandler):
        def get(self, book_id):
                self.redirect("https://bookstobook.com/"+book_id+"/delete")

class SignupHandler(webapp2.RequestHandler):
        def get(self):
                self.redirect("https://bookstobook.com/signup")

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
                self.redirect("https://bookstobook.com/"+book_id+"/detail")

class LoginHandler(Handler):
        def get(self):
                self.redirect("https://bookstobook.com/login")

class LogoutHandler(Handler):
        def get(self):
                self.redirect("https://bookstobook.com/logout")

class SignupFormHandler(Handler):
    def get(self):
        self.redirect("https://bookstobook.com/signupform")

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
        ('/signupform', SignupFormHandler),
        (r'/static/(.+)', StaticFileHandler)
], debug = True)

def main():
    from paste import httpserver

    httpserver.serve(app, host='172.31.10.101', port='80')

if __name__ == '__main__':
    main()
