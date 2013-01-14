import webapp2
import jinja2
import os
import re
import hmac
import hashlib
import random
import string

from google.appengine.ext import db
from google.appengine.api import memcache

template_path = os.path.join(os.path.dirname(__file__),'templates')

class Authors(db.Model):
    authorname = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)

class Articles(db.Model):
    title = db.StringProperty(required = True, indexed=True)
    version = db.IntegerProperty(required = True, indexed=True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

def receive_data(title, version = None):
    title = title.replace('/','').lower()
    result = None

    # get latest version if request without version
    if not version:
        key = title
        result = db.GqlQuery("SELECT * FROM Articles WHERE title = :1 ORDER BY version DESC", title)
        
        if result.count() > 0:
                memcache.set(key, result[0])

    # look in the cache if request with version
    elif version:
        key = title + ',' + version
        result = memcache.get(key)
        
        if not result:
            result = db.GqlQuery("SELECT * FROM Articles WHERE title = :1 AND version = :2", title, int(version), limit = 1)

            if result.count() > 0:
                memcache.set(key, result[0])
        
    return memcache.get(key)

# keep it secret
EXTRA = '70jh25g630Bh2gsdB2346bs79dYIOu2g'

def hash_mac(s):
    return hmac.new(EXTRA, s).hexdigest()

def value_hashmac(val):
    return "%s|%s" % (val, hash_mac(val))

def hash_password(name, password, salt = None):
    if not salt:
        salt = ''.join(random.choice(string.letters) for x in range(32))
    return '%s|%s' % (hashlib.sha512(name + password + salt + salt).hexdigest(), salt)

def is_correct(name, password, hashpassword):
    salt = hashpassword.split('|')[1]
    return hashpassword == hash_password(name, password, salt)

environment = jinja2.Environment(loader = jinja2.FileSystemLoader(template_path), autoescape = False)
environment_escaped = jinja2.Environment(loader = jinja2.FileSystemLoader(template_path), autoescape = True)

class Handler(webapp2.RequestHandler):
    
    def post(self):
        title = self.request.get('request').lower()
        SEARCH_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")

        if SEARCH_RE.match(title):
            rqst = Articles.gql("WHERE title = :1", title).get()

            if rqst!=None:
                self.redirect("/wiki/content/%s" % title)

            else:
                self.render_content("search.htm", title=list(title))
        else:
            self.render_content("search.htm")

    def get_signin(self):
        author_id = self.is_signin()
        author = None

        if author_id:
            author = Authors.get_by_id(long(author_id))

        return author
 
    def is_signin(self):
        author_id = None
        author = None
        author_id_str = self.request.cookies.get('author_id')

        if author_id_str:
            author_id = author_id_str.split('|')[0] if author_id_str == value_hashmac(author_id_str.split('|')[0]) else None

        return author_id

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = environment.get_template(template)

        return t.render(params)

    def render_str_escaped(self, template, **params):
        t = environment_escaped.get_template(template)

        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
    def render_content(self, template, **kw):
        content = self.render_str(template, **kw)
        self.render("index.htm", content=content, author=self.get_signin(), **kw)

class Signout(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie', 'author_id=; Path=/')
        self.redirect("/wiki/main")

class Signin(Handler):

    def get(self):
        self.render_content("signin.htm")

    def post(self):
        authorname = self.request.get('authorname')
        password = self.request.get('password')
        authors = db.GqlQuery("SELECT * FROM Authors WHERE authorname = :1", authorname, limit=1)

        if authors.count() == 1 and is_correct(authors[0].authorname, password, authors[0].password):
            self.response.headers.add_header('Set-Cookie', 'author_id=%s; Path=/' % value_hashmac(str(authors[0].key().id())))
            self.redirect("/wiki/main")

        else:
            self.response.headers.add_header('Set-Cookie', 'author_id=; Path=/')
            signin_error="The name or password you entered is incorrect."
            self.render_content("signin.htm", signin_error=signin_error)

AUTHOR_RE = re.compile(r"^[a-zA-Z0-9_-]{1,21}$")
PASSWORD_RE = re.compile(r"^.{1,21}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

class Signup(Handler):

    def get(self):
        self.render_content("signup.htm")

    def post(self):
        authorname = self.request.get('authorname')
        password = self.request.get('password')
        confirm = self.request.get('confirm')
        email = self.request.get('email')

        authorname_error = ""
        password_error = ""
        confirm_error = ""
        email_error = ""

        if not AUTHOR_RE.match(authorname):
            authorname_error = "You have not specified a valid name."

        if (db.GqlQuery("SELECT * FROM Authors WHERE authorname = :1", authorname, limit=1)).count() > 0:
            authorname_error = "Name entered already in use. "

        if not PASSWORD_RE.match(password):
            password_error = "Passwords must be at least 1 character."

        if not password == confirm:
            confirm_error = "Your passwords didn't match."

        if email and not EMAIL_RE.match(email):
            email_error = "Enter a valid e-mail address"

        if not (authorname_error == "" and password_error == "" and confirm_error == "" and not (email and email_error)):
            self.render_content("signup.htm"
                , authorname=authorname
                , authorname_error=authorname_error
                , password_error=password_error
                , confirm_error=confirm_error
                , email=email
                , email_error=email_error)

        else:
            author = Authors(authorname=authorname, password=hash_password(authorname, password), email=email)
            author.put()
            self.response.headers.add_header('Set-Cookie', 'author_id=%s; Path=/' % value_hashmac(str(author.key().id())))
            self.redirect("/wiki/main")

class Edit(Handler):

    def render_edit_page(self, title, content=""):
        if title == None:
            title = '/'

        if title == '/':
            self.redirect("/wiki/main")

        elif self.is_signin():
            article = receive_data(title)
            self.render_content("edit.htm", article=article if article else None)

        else:
            self.redirect("/wiki/signin")

    def get(self, title, args):
        if self.is_signin():
            self.render_edit_page(title = title.lower())

        else:
            self.redirect("/wiki/signin")

    def post(self, title, args):
        if self.is_signin():
            content = self.request.get("content")
            title = title.replace('/','').lower()
            article = receive_data(title)

            if article:
                article = Articles(title=title, version=article.version+1, content=content)

            else:
                article = Articles(title=title, version=1, content=content)

            article.put()
            self.redirect("/wiki/content/_history/%s" % title)

        else:
            self.redirect("/wiki/signin")

class History(Handler):

    def get(self, title, args):
        if title == None:
            title = '/'

        if title == '/':
            self.redirect("/wiki/main")

        title = title.replace('/','').lower()
        versions = db.GqlQuery("SELECT * FROM Articles WHERE title = :1 ORDER BY version DESC", title)
        self.render_content("history.htm", versions=list(versions))
        
class Wiki(Handler):

    def get(self, title, args):
        if title == None:
            title = '/'

        if title == '/':
            self.redirect("/wiki/main")

        title = title.lower()
        version = self.request.get('version')
        article = receive_data(title, version)

        if not article:
            self.redirect("/wiki/content/_edit/%s" % title.replace('/',''))

        else:
            self.render_content("article.htm", article=article)

class Main(Handler):

    def get(self):
        self.redirect("/wiki/main")        

class NotFound(Handler):

    def get(self):
        self.render_content("404.htm")

class Search(Handler):

    def get(self):
        self.render_content("search.htm")        

class MainPage(Handler):
    
    def get(self):
        articles = None
        articles = Articles.gql("ORDER BY created DESC")
        articles.get()
        # last three articles on main page
        last = 3
        self.render_content("main.htm", articles=list(articles[0:last]))

# regexp for wiki content
PAGE_RE = r'((/(?:[a-zA-Z0-9_-]+/?)*))?'

app = webapp2.WSGIApplication([
          ('/', Main)
        , ('/wiki', Main)
        , ('/wiki/', Main)
        , ('/wiki/main', MainPage)
        , ('/wiki/search', Search)        
        , ('/wiki/signin', Signin)
        , ('/wiki/signout', Signout)
        , ('/wiki/content/_history' + PAGE_RE, History)
        , ('/wiki/content/_edit' + PAGE_RE, Edit)
        , ('/wiki/signup', Signup)
        , ('/wiki/content' + PAGE_RE, Wiki)
        , ('/.*', NotFound)
    ], debug=False)