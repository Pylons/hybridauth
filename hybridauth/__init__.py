import sys
from datetime import datetime

import transaction

from pyramid.config import Configurator
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.httpexceptions import HTTPFound
from pyramid.response import Response
from pyramid.security import Allow
from pyramid.security import Everyone
from pyramid.security import Authenticated
from pyramid.security import DENY_ALL
from pyramid.security import ALL_PERMISSIONS
from pyramid.security import authenticated_userid
from pyramid.security import has_permission
from pyramid.security import remember
from pyramid.security import forget
from pyramid.exceptions import Forbidden
from pyramid.view import view_config

import sqlalchemy as sa
from sqlalchemy import engine_from_config
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import relation
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound

from zope.sqlalchemy import ZopeTransactionExtension

from repoze.monty import marshal

import formencode

import pygments
from pygments import lexers
from pygments import formatters
from pygments import util

# main

def root_factory(request):
    return DBSession.query(Resource).filter(Resource.parent_id==None).one()

def main(global_config, **settings):
    engine = engine_from_config(settings, 'sqlalchemy.')
    initialize_sql(engine)
    if settings.get('password_file') is None:
        raise ValueError('password_file must not be None')
    config = Configurator(
        settings = settings,
        root_factory = root_factory,
        authentication_policy = AuthTktAuthenticationPolicy('seekrit')
        )
    config.add_static_view('static', 'hybridauth:static')
    config.add_route('login', '/login', traverse='/')
    config.add_route('logout', '/logout', traverse='/')
    config.add_route('bin', '/{bin}', traverse='/{bin}')
    config.add_route('manage', '/{bin}/manage', traverse='/{bin}')
    config.add_route('entry', r'/{bin}/{entry:\d+}', traverse='/{bin}/{entry}')
    config.add_route('home', '/public', traverse='/public')
    config.scan('hybridauth')
    return config.make_wsgi_app()

# models

DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()

class Resource(Base):
    __tablename__ = 'resource'

    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String(255), nullable=False)
    parent_id = sa.Column(sa.Integer, sa.ForeignKey('resource.id'))
    _aces = relation('ACE')

    def __init__(self, name, parent_id=None):
        self.name = name
        self.parent_id = parent_id

    def _get_acl(self):
        if self._aces is None:
            raise AttributeError('__acl__')
        q = DBSession.query(ACE).filter(ACE.resource_id==self.id)
        L = []
        for ace in q:
            if ace.permission == '__ALL__':
                permission = ALL_PERMISSIONS
            else:
                permission = ace.permission
            L.append((ace.action, ace.principal, permission))
        return L

    def _set_acl(self, acl):
        aces = []
        for action, principal, permission in acl:
            if permission == ALL_PERMISSIONS:
                permission = '__ALL__'
            aces.append(ACE(self.id, action, principal, permission))
        self._aces = aces

    __acl__ = property(_get_acl, _set_acl)

    @property
    def __parent__(self):
        try:
            return DBSession.query(Resource).filter(
                Resource.id==self.parent_id).one()
        except NoResultFound:
            return None

    def _getOne(self, name):
        return DBSession.query(Resource).filter(
            Resource.parent_id==self.id).filter(Resource.name==name).one()

    def __getitem__(self, name):
        try:
            return self._getOne(name)
        except NoResultFound:
            raise KeyError(name)

    def __delitem__(self, name):
        try:
            resource = self._getOne(name)
        except NoResultFound:
            raise KeyError(name)
        DBSession.delete(resource)

    def __repr__(self):
        return "<Resource(%s, '%s', %s, %s)>" % (self.id,
                                                 self.name,
                                                 self.parent_id,
                                                 self.__acl__)

class ACE(Base):
    __tablename__ = 'ace'

    id = sa.Column(sa.Integer, primary_key=True)
    resource_id = sa.Column(sa.Integer, sa.ForeignKey('resource.id'))
    action = sa.Column(sa.Enum('Allow', 'Deny'))
    principal = sa.Column(sa.String(255), nullable=False)
    permission = sa.Column(sa.String(255), nullable=False)

    def __init__(self, resource_id, action, principal, permission):
        self.resource_id = resource_id
        self.action = action
        self.principal = principal
        self.permission = permission

class Entry(Base):
    __tablename__ = 'entry'

    id = sa.Column(sa.Integer, primary_key=True)
    resource_id = sa.Column(sa.Integer, sa.ForeignKey('resource.id'))
    bin_name = sa.Column(sa.String(255), nullable=False)
    author_name = sa.Column(sa.String(255), nullable=False)
    text = sa.Column(sa.Text(), nullable=False)
    language = sa.Column(sa.String(255), nullable=False)
    date = sa.Column(sa.DateTime(), nullable=False)
    def __init__(self, bin_name, author_name, text, language):
        self.author_name = author_name
        self.text = text
        self.language = language
        self.date = datetime.now()
        self.bin_name = bin_name
        
def initialize_sql(engine):
    DBSession.configure(bind=engine)
    Base.metadata.bind = engine
    Base.metadata.create_all(engine)
    try:
        DBSession.query(Resource).filter(Resource.parent_id==None).one()
    except NoResultFound:
        root = Resource('', None)
        root.__acl__ = [
            (Allow, Everyone, 'view')
            ]
        DBSession.add(root)
        DBSession.flush()
        public = Resource('public', root.id)
        public.__acl__ = [
            (Allow, Authenticated, 'edit'),
            (Allow, 'admin', 'manage')
            ]
        DBSession.add(public)
        private = Resource('private', root.id)
        private.__acl__ = [
            (Allow, Authenticated, 'view'),
            (Allow, 'admin', 'edit'),
            (Allow, 'admin', 'manage'),
            DENY_ALL
            ]
        DBSession.add(private)
        transaction.commit()

# views

app_version = '0.0'

COOKIE_LANGUAGE = 'cluegun.last_lang'
COOKIE_AUTHOR = 'cluegun.last_author'

formatter = formatters.HtmlFormatter(linenos=True, cssclass="source")
style_defs = formatter.get_style_defs()
all_lexers = list(lexers.get_all_lexers())
all_lexers.sort()
lexer_info = []
for name, aliases, filetypes, mimetypes_ in all_lexers:
    lexer_info.append({'alias':aliases[0], 'name':name})

# utility functions

def get_pastes(bin, request, max):
    pastes = []
    entries = DBSession.query(Entry).filter(
        Entry.bin_name==bin).order_by(Entry.date)
    for entry in entries:
        if entry.date is not None:
            pdate = entry.date.strftime('%x at %X')
        else:
            pdate = 'UNKNOWN'
        paste_url = request.route_url('entry', bin=bin, entry=entry.id)
        new = {'author':entry.author_name, 'date':pdate, 'url':paste_url,
               'name':name}
        pastes.append(new)
    return pastes

def preferred_author(request):
    author_name = request.params.get('author_name', u'')
    if not author_name:
        author_name = request.cookies.get(COOKIE_AUTHOR, u'')
    if isinstance(author_name, str):
        author_name = unicode(author_name, 'utf-8')
    return author_name

def check_passwd(passwd_file, login, password):
    if not hasattr(passwd_file, 'read'):
        passwd_file = open(passwd_file, 'r')
    for line in passwd_file:
        try:
            username, hashed = line.rstrip().split(':', 1)
        except ValueError:
            continue
        if username == login:
            if password == hashed:
                return username
    return None

@view_config(route_name='entry', permission='view',
             renderer='hybridauth:templates/entry.pt')
def entry_view(request):
    bin = request.matchdict['bin']
    entry_id = int(request.matchdict['entry'])
    entry = DBSession.query(Entry).filter(
        Entry.bin_name==bin).filter(Entry.id==entry_id).one()
    try:
        if entry.language:
            l = lexers.get_lexer_by_name(entry.language)
        else:
            l = lexers.guess_lexer(entry.text)
        l.aliases[0]
    except util.ClassNotFound:
        # couldn't guess lexer
        l = lexers.TextLexer()

    formatted_paste = pygments.highlight(entry.text, l, formatter)
    pastes = get_pastes(bin, request, 10)
    bin_url = request.route_url('bin', bin=bin)

    return dict(
        author = entry.author_name,
        date = entry.date.strftime('%x at %X'),
        style_defs = style_defs,
        lexer_name = l.name,
        paste = formatted_paste,
        pastes = pastes,
        version = app_version,
        message = None,
        application_url = request.application_url,
        bin_url = bin_url,
        )

class PasteAddSchema(formencode.Schema):
    allow_extra_fields = True
    paste = formencode.validators.NotEmpty()

@view_config(route_name='bin', permission='view',
             renderer='hybridauth:templates/index.pt')
def index_view(request):
    bin = request.matchdict['bin']
    params = request.params
    author_name = preferred_author(request)
    language = u''
    paste = u''
    message = u''
    app_url = request.application_url
    user = authenticated_userid(request)
    can_manage = has_permission('manage', request.context, request)

    if params.has_key('form.submitted'):
        if not has_permission('edit', request.context, request):
            raise Forbidden()

        
        paste = request.params.get('paste', '')
        author_name = request.params.get('author_name', '')
        language = request.params.get('language', '')
        schema = PasteAddSchema()
        message = None
        try:
            schema.to_python(request.params)
        except formencode.validators.Invalid, why:
            message = str(why)
        else:
            response = Response()
            response.set_cookie(COOKIE_AUTHOR, author_name)
            response.set_cookie(COOKIE_LANGUAGE, language)

            if isinstance(author_name, str):
                author_name = unicode(author_name, 'utf-8')
            if isinstance(language, str):
                language = unicode(language, 'utf-8')
            if isinstance(paste, str):
                paste = unicode(paste, 'utf-8')

            entry = Entry(bin, author_name, paste, language)
            DBSession.add(entry)
            DBSession.flush()
            resource = Resource(str(entry.id), request.context.id)
            DBSession.add(resource)
            return HTTPFound(location=request.route_url('entry', bin=bin,
                                                        entry=entry.id))

    pastes = get_pastes(bin, request, 10)

    return dict(
        author_name = author_name,
        paste = paste,
        lexers = lexer_info,
        version = app_version,
        message = message,
        pastes = pastes,
        bin_url = request.route_url('bin', bin=bin),
        application_url = app_url,
        user = user,
        can_manage = can_manage,
        )

@view_config(route_name='manage', permission='manage',
             renderer='hybridauth:templates/manage.pt')
def manage_view(request):
    bin = request.matchdict['bin']
    params = request.params
    app_url = request.application_url

    if params.has_key('form.submitted'):
        form = marshal(request.environ, request.body_file)
        checkboxes = form.get('delete', [])
        for name in checkboxes:
            entry_id = int(name)
            entry = DBSession.query(Entry).filter(id=entry_id).one()
            # remove security node
            del request.context[name]
            # remove entry
            DBSession.delete(entry)
        return HTTPFound(location=app_url)

    pastes = get_pastes(bin, request, sys.maxint)

    return dict(
        version = app_version,
        pastes = pastes,
        application_url = app_url,
        )
        
@view_config(context=Forbidden, renderer='hybridauth:templates/login.pt')
@view_config(route_name='login', renderer='hybridauth:templates/login.pt')
def login(request):
    login_url = request.route_url('login')
    referrer = request.url
    if referrer == login_url:
        referrer = '/' # never use the login form itself as came_from
    came_from = request.params.get('came_from', referrer)
    message = ''
    login = ''
    password = ''
    if not request.exception and 'form.submitted' in request.params:
        login = request.params['login']
        password = request.params['password']
        password_file = request.registry.settings['password_file']
        if check_passwd(password_file, login, password):
            headers = remember(request, login)
            return HTTPFound(location = came_from,
                             headers = headers)
        message = 'Failed login'

    return dict(
        message = message,
        url = request.application_url + '/login',
        came_from = came_from,
        login = login,
        password = password,
        )
    
@view_config(route_name='logout', permission='view')
def logout(request):
    headers = forget(request)
    return HTTPFound(location = request.route_url('home'),
                     headers = headers)
    
# script test

if __name__ == '__main__':
    from sqlalchemy import create_engine
    engine = create_engine('sqlite:///:memory:', echo=True)
    Base.metadata.bind = engine
    Base.metadata.create_all(engine)

    db_session = sessionmaker(bind=engine)()

    parent = Resource('parent')
    db_session.add(parent)
    db_session.commit()

    child = Resource('child', parent.id)
    child.__acl__ = [('Allow', 'fred', 'edit'), ('Allow', 'bob', 'edit')]
    db_session.add(child)
    db_session.commit()

    print parent['child']
    print parent['wontexist']
