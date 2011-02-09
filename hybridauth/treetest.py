from hybridauth import Base
from hybridauth import Resource

from sqlalchemy.orm import sessionmaker

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
