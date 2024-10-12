#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        user = User(username = json['username'])
        user.password_hash = json['password']
        user.image_url = json['image_url']
        user.bio = json['bio']
        db.session.add(user)
        db.session.commit()
        return user.to_dict(), 201
    
        

class CheckSession(Resource):
    def get(self):
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        else:
            return {'error': 'Unauthorized'}, 401
        

class Login(Resource):
    def post(self):
        username = request.get_json()['username']
        user = User.query.filter(User.username == username).first()
        password = request.get_json()['password']
        if user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error': 'Unauthorized'},401

class Logout(Resource):
    def delete(self):
        user_id = session['user_id']
        if user_id:
            session['user_id'] =None
            return {}, 204
        else:
            return {'error': 'Unauthorized'},401
        

class RecipeIndex(Resource):
    def get(self):
        user_id = session['user_id']
        if user_id:
            recipes = Recipe.query.all()
           
            # print(recipes)
            recipes_data =[]
            for recipe in recipes:
                recipe = {
                    "title": recipe.title,
                    "instructions": recipe.instructions,
                    "minutes_to_complete": recipe.minutes_to_complete,
                    "user":{
                        'id': recipe.user.id,
                        'username': recipe.user.username
                    }
                }
                recipes_data.append(recipe)
               
            return recipes_data, 200
        else:
            return {'error': 'Unauthorize'}, 401

    def post(self):
        user_id = session['user_id']  # Use get to avoid KeyError
        if user_id:
            json_data = request.get_json()

            # Validate incoming data
            if not json_data or 'title' not in json_data or 'instructions' not in json_data or 'minutes_to_complete' not in json_data:
                return {'error': 'Invalid data provided.'}, 400  # Bad Request

            try:
                # Create a new Recipe instance
                recipe = Recipe(
                    title=json_data['title'],
                    instructions=json_data['instructions'],
                    minutes_to_complete=json_data['minutes_to_complete'],
                    user_id=user_id  # Use the user_id from the session instead of the JSON
                )

                db.session.add(recipe)
                db.session.commit()
                
                return recipe.to_dict(),201  # HTTP 201 Created
            except Exception as e:
                db.session.rollback()  
                return jsonify({'error': str(e)}), 500  # Internal Server Error
        else:
            return jsonify({'error': 'Unauthorized access. Please log in.'}), 401  # Unauthorized

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)