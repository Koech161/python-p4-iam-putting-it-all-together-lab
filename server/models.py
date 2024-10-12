from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.exc import IntegrityError

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    _serializer_exclude = ('recipes',)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String, nullable=False)
    bio = db.Column(db.String, nullable=False)

    recipes = db.relationship('Recipe', back_populates='user', cascade='all, delete-orphan')

    @validates('username')
    def validate_user(self, key, username):
        if not username:
            raise ValueError('No username provided')
        if User.query.filter(User.username == username).first():
            raise ValueError('Username already exist')
        return username
    def __repr__(self):
        return f'<User {self.id}, {self.username}>'
    @hybrid_property
    def password_hash(self):
        return self._password_hash
    @password_hash.setter
    def password_hash(self,password):
        if password:
            password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
            self._password_hash = password_hash.decode('utf-8')
        else:
            raise ValueError('Password cannot be empyty')    
    def authenticate(self,password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8')
        )    

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    _serializer_exclude = ('user',)
    id = db.Column(db.Integer, primary_key=True)
    title =db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = db.relationship('User', back_populates='recipes')

    @validates('instructions')
    def validate_instruction(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError('Instruction must be 50 characters long.')
        return instructions
    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError('No title provided')
        return title
    def __repr__(self):
        return f'<Recipe {self.id} {self.title}>'
