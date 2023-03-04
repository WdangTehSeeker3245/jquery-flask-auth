from datetime import timedelta
from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import json

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity,get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

db = SQLAlchemy()
app = Flask(__name__) 
api = Api(app)
bcrypt = Bcrypt(app)
CORS(app)

ACCESS_EXPIRES = timedelta(hours=1)
# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "dummytestapp74" 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_EXPIRES
jwt = JWTManager(app)


# basedir = os.path.dirname(os.path.abspath(__file__))
# database = "sqlite:///" + os.path.join(basedir,"db.sqlite")
# app.config["SQLALCHEMY_DATABASE_URI"] = database
# db.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root@localhost/flasklogin"
db.init_app(app)

class AuthModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(225))

    # method untuk menyimpan data
    def save(self):
        try:
            db.session.add(self)
            db.session.commit()
            return True
        except:
            return False

with app.app_context():
    db.create_all()

class Login(Resource):
    def post(self):
            dataUsername = request.json["username"]
            dataPassword = request.json["password"]
            data = db.session.execute(db.select(AuthModel).filter_by(username=dataUsername)).scalar_one()
            user = data.username
            hashPassword = data.password
            if user:
                authenticated_user = bcrypt.check_password_hash(hashPassword, dataPassword)
                if authenticated_user :
                    access_token = create_access_token(identity=user,expires_delta=ACCESS_EXPIRES)
                    response = {
                        "msg" :"anda berhasil login",
                        "code" : 200,
                        "username" : user,
                        "token" : access_token
                    }
                    return make_response(jsonify(response))   
    

class Register(Resource):
    def post(self):
        dataUsername = request.json["username"]
        dataPassword = request.json["password"]
        hashPasswd = bcrypt.generate_password_hash(dataPassword)
        model = AuthModel(username=dataUsername,password=hashPasswd)
        model.save()

        response = {
            "msg":"data berhasil dimasukan",
            "code": 200
        }
        return response, 200
            

class Admin(Resource):
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        response = {
            "msg" :"Selamat datang Admin "+current_user,
            "code" : 200 ,
        }
        return make_response(jsonify(response), 200)

api.add_resource(Register,'/api/register', methods=["POST"])
api.add_resource(Login,'/api/login', methods=["POST"])
api.add_resource(Admin,'/api/admin', methods=["POST"])


if __name__ == "__main__":
    app.run()