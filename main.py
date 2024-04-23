from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token,
                                create_refresh_token, get_jwt_identity)
from datetime import timedelta

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:3000",
                                             "http://127.0.0.1:3000", ]}})

with app.app_context():
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=2)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@127.0.0.1:3306/flask_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'gyjguguuhu'
    jwt = JWTManager(app)
    api = Api(app)
    db = SQLAlchemy(app)

    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(255), nullable=False)
        posts = db.relationship('Post', backref='post', lazy=True)

        def set_password(self, password):
            self.password = generate_password_hash(password)
            
        def check_password(self, hashed_password, password):
            return check_password_hash(hashed_password, password)

        def __str__(self):
            return f"{self.id}  , {self.username} , {self.email}"
        
    class Post(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(100), nullable=False)
        body = db.Column(db.Text())
        created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

        def __str__(self):
            return f"{self.title} , {self.body }"
            
    db.create_all()


class UserApiListCreate(Resource):
    @jwt_required()
    def get(self):
        user = User.query.all()
        user_list = [{'id': obj.id, 'username': obj.username, 'email':obj.email } 
                     for obj in user]
        return {"data":user_list}
    
    @jwt_required()
    def post(self):
        username = request.get_json().get('username')
        user_check = User.query.filter_by(username=username)
        if user_check:
            return {'msg': 'username already exists'},500
        
        email = request.get_json().get('email')
        password = request.get_json().get('password')
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return {'message': 'user addded successfully', 'data':{'id':user.id, 'username':
                user.username, 'email': user.email }} , 201

api.add_resource(UserApiListCreate, '/api/user/')


class PostApiListCreate(Resource):
    @jwt_required()
    def get(self):
        post = Post.query.paginate(per_page=2)
        post_list = [{'id': obj.id, 'title': obj.title, 'body':obj.body ,
                      'created_by':obj.created_by } for obj in post]
        return {"data":post_list} , 200
    
    @jwt_required()
    def post(self):
        created_by = request.get_json().get('created_by')
        title = request.get_json().get('title')
        body = request.get_json().get('body')
        
        post = Post(title=title, body=body, created_by=created_by)
        db.session.add(post)
        db.session.commit()

        return {'message': 'post create successfully', 'data':{'id':post.id, 'title':
                post.title, 'body':post.body, 'created_by':post.created_by }} , 201


class PostApiRetriveUpdateDestroy(Resource):
    @jwt_required()
    def get(self, pk):
        obj = Post.query.get_or_404(pk)
        return {'data':{'id':obj.id, 'title':obj.title, 'body':obj.body,
                        'created_by':obj.created_by}}
    
    @jwt_required()
    def put(self,pk):
        obj = Post.query.get_or_404(pk)
        user = User.query.filter_by(username=get_jwt_identity()).first()
        if user.id == obj.created_by:
            title = request.get_json().get('title')
            body = request.get_json().get('body')
            obj.title = title
            obj.body = body
            db.session.commit()
            return {'message': 'post update successfully', 'data':{'id':obj.id, 'title':
                obj.title, 'body':obj.body, 'created_by':obj.created_by }} , 200
        return abort(403, "permission denied")
    
    @jwt_required()
    def delete(self,pk):
        obj = Post.query.get_or_404(pk)
        user = User.query.filter_by(username=get_jwt_identity()).first()
        if user.id == obj.created_by:
            db.session.delete(obj)
            db.session.commit()
            return {'message': 'post delete successfully'} , 204
        return abort(403, "permission denied")

api.add_resource(PostApiListCreate, '/api/post/')
api.add_resource(PostApiRetriveUpdateDestroy, '/api/post/<int:pk>/')   


class Login(Resource):
    def post(self):
        username = request.json.get("username")
        password = request.json.get("password")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(user.password,password):
            access_token = create_access_token(identity=username)
            refresh_token = create_refresh_token(identity=username)
            return {'token':{'access':access_token, 'refresh':refresh_token}}
        return abort(401, "Invalid Credentials")


class Refresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify(access_token=access_token)
 
api.add_resource(Login, '/api/token/')
api.add_resource(Refresh, '/api/refresh/')


if __name__ == "__main__":
    app.run(debug=True)
