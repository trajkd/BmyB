import urllib
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Book

engine = create_engine('sqlite:///book.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

ISBN_URL = "https://openlibrary.org/api/books?jscmd=data&format=json&bibkeys=ISBN:"
def get_info(isbn):
	url = ISBN_URL + isbn
	content = json.loads(urllib.urlopen(url).read())
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
	pages = 0
	if 'pagination' in entry:
		pages = (int)(entry['pagination'][:entry['pagination'].find("p.")])
	cover = "Not available"
	if 'cover' in entry:
		cover = entry['cover']['large']
	return {'title':title, 'authors':authors, 'isbn':isbn, 'publishers':publishers, 'pages':pages, 'cover':cover}