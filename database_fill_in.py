from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, ListItem, User

engine = create_engine('sqlite:///itemcatalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Alan Peke", email="apekelis@gmail.com",
             picture='https://lh3.googleusercontent.com/a-/AAuE7mB1D0ZkxLRJmYQAnDsKfSdtfi_phHCapEjDX74x=s60')
session.add(User1)
session.commit()

# Category "Sports"
category1 = Category(user_id=1, name="Sports")

session.add(category1)
session.commit()

listItem1 = ListItem(user_id=1, name="Soccer", description="A Sport were two opposing teams with 11 players on the field each, try to score goals in the other team's goalie using their bodys, except their hands",
                    category=category1)

session.add(listItem1)
session.commit()


listItem2 = ListItem(user_id=1, name="Hockey", description="A sport in which two teams play against each other by trying to manoeuvre a ball or a puck into the opponent's goal using hockey sticks.",
                    category=category1)

session.add(listItem2)
session.commit()


listItem3 = ListItem(user_id=1, name="Baseball", description="A bat-and-ball game played between two opposing teams who take turns batting and fielding",
                     category=category1)

session.add(listItem3)
session.commit()

listItem4 = ListItem(user_id=1, name="Basketball", description="A team sport in which two teams, most commonly of five players each, opposing one another on a rectangular court, compete with the primary objective of shooting a basketball through the defender's hoop",
                    category=category1)

session.add(listItem4)
session.commit()

listItem5 = ListItem(user_id=1, name="Golf", description="A club-and-ball sport in which players use various clubs to hit balls into a series of holes on a course in as few strokes as possible.",
                    category=category1)

session.add(listItem5)
session.commit()

# Category "Food"
category2 = Category(user_id=1, name="Food")

session.add(category2)
session.commit()

listItem1 = ListItem(user_id=1, name="Rice", description="Rice is the seed of the grass species Oryza sativa (Asian rice) or Oryza glaberrima (African rice).",
                    category=category2)

session.add(listItem1)
session.commit()


listItem2 = ListItem(user_id=1, name="Apple", description="An apple is a sweet, edible fruit produced by an apple tree (Malus domestica).",
                    category=category2)

session.add(listItem2)
session.commit()


listItem3 = ListItem(user_id=1, name="Carrot", description="The carrot (Daucus carota subsp. sativus) is a root vegetable, usually orange in colour, though purple, black, red, white, and yellow cultivars exist.",
                     category=category2)

session.add(listItem3)
session.commit()

