from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
from flask_expects_json import expects_json


app=Flask(__name__)
db=SQLAlchemy(app)
migrate=Migrate(app,db)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config["SQLALCHEMY_DATABASE_URI"]='postgresql://postgres:a@localhost:5432/users_api'
app.config["SECRET_KEY"]="ThisIsMySecretKey"


class UserModel(db.Model):
    __tablename__='users'
    id=db.Column(db.Integer,primary_key=True,unique=True)
    publicid=db.Column(db.String)
    fname=db.Column(db.String)
    lname=db.Column(db.String)
    email=db.Column(db.String,unique=True)
    password=db.Column(db.String)


class TodoModel(db.Model):
    __tablename__='todolist'
    id=db.Column(db.Integer,primary_key=True)
    taskname=db.Column(db.String)
    userid=db.Column(db.Integer,db.ForeignKey('users.id'))


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        refreshtoken=None
        if 'x-refresh-tokens' in request.headers:
            refreshtoken = request.headers['x-refresh-tokens']
        if not refreshtoken:
            return jsonify({'message': 'a valid refresh token is missing'})
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config.get("SECRET_KEY"))
            current_user = UserModel.query.filter_by(id=data['id']).first()
        except jwt.ExpiredSignatureError:
            data = jwt.decode(refreshtoken, app.config.get("SECRET_KEY"))
            current_user = UserModel.query.filter_by(id=data['id']).first()
            accesstoken = jwt.encode({'id': current_user.id,'email':current_user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=1)}, app.config['SECRET_KEY'])
            refreshtoken = jwt.encode({'id': current_user.id,'email':current_user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, app.config['SECRET_KEY'])
            return {"access-token":accesstoken.decode('UTF-8'),"refresh-token":refreshtoken.decode('UTF-8')}
        except jwt.InvalidTokenError:
            return "Token is invalid please login"

        return f(current_user, *args, **kwargs)
    return decorator


    return{"message":"user deleted"}


#routes
@app.route('/users',methods=["GET"])
def get():
    user=UserModel.query.all()
    data=[{
        "id":users.id,
        "fname":users.fname,
        "lname":users.lname,
        "email":users.email,
        "password":users.password
    } for users in user]
    return {"usercount":len(data),"data":data}


schema = {
  "type": "object",
  "properties": {
    "fname": { "type": "string" },
    "lname": { "type": "string" },
    "email": { "type": "string" },
    "password": { "type": "string" }
  },
  "required": ["email","fname","lname","password"]
}
@app.route('/users',methods=["POST"])
@expects_json(schema)
def postusers():
    data=request.get_json()
    hashed_pwd=generate_password_hash(data["password"],method='sha256')
    users=UserModel.query.filter_by(email=data["email"]).first()
    if users:
        return{"error":"Sorry Email id already exists"}
        exit()
    new_user=UserModel(publicid=str(uuid.uuid4()),fname=data["fname"],lname=data["lname"],email=data["email"],password=hashed_pwd)
    db.session.add(new_user)
    db.session.commit()
    return{"message":"newuser created","data":data,'auth_token':""}

@app.route('/todo',methods=["POST"])
@token_required
def posttodo(currentuser):
    data=request.get_json()
    new_todo=TodoModel(taskname=data["taskname"],userid=currentuser.id)
    db.session.add(new_todo)
    db.session.commit()
    return{"message":"todo list created","data":data},200


@app.route('/todo',methods=["GET"])
@token_required
def gettodos(currentuser):
    todos=TodoModel.query.filter_by(userid=currentuser.id).all()
    data=[{
    "taskname":todo.taskname,
    "userid":todo.userid
    }for todo in todos]
    return{"todocount":len(data),"data":data}

@app.route('/todo/<int:todoid>',methods=["GET"])
@token_required
def getspecifictask(currentuser,todoid):
    todos=TodoModel.query.filter_by(userid=currentuser.id,id=todoid).all()
    data=[{
    "taskname":todo.taskname,
    "userid":todo.userid
    }for todo in todos]
    return{"todocount":len(data),"data":data}

@app.route('/todo/<int:todoid>',methods=["PUT"])
@token_required
def updatetodos(currentuser,todoid):
    todos=TodoModel.query.filter_by(id=todoid,userid=currentuser.id).first_or_404()
    data=request.get_json()
    todos.taskname=data["taskname"]
    db.session.commit()
    return{"message":todos.taskname}

@app.route('/todo/<int:todoid>',methods=["DELETE"])
@token_required
def deletetodos(currentuser,todoid):
    todos=TodoModel.query.filter_by(id=todoid,userid=currentuser.id).first()
    if todos:
        db.session.delete(todos)
        db.session.commit()
    else:
        return{"message":"No todo id found"}

    return{"message":"Todo id is deleted"}

@app.route('/users/<usersid>',methods=["GET"])
def getindividualusers(usersid):
    users=UserModel.query.get_or_404(usersid)
    data={
        "id":users.id,
        "fname":users.fname,
        "lname":users.lname,
        "email":users.email,
        "password":users.password
    }
    return{"data":data}

@app.route('/users/<usersid>',methods=["PUT"])
def updateindividualusers(usersid):
    return{"message":"hello"}

@app.route('/users/<usersid>',methods=["DELETE"])
def deleteindividualusers(usersid):
    users=UserModel.query.get_or_404(usersid)
    db.session.delete(users)
    db.session.commit()

@app.route('/login',methods=["POST","GET"])
def loginuser():
    if request.method=="POST":
        post_data=request.get_json()
        user = UserModel.query.filter_by(
        email=post_data.get('email')).first()
        if user and check_password_hash(user.password, post_data.get('password')):
            accesstoken = jwt.encode({'id': user.id,'email':user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, app.config['SECRET_KEY']) 
            refreshtoken = jwt.encode({'id': user.id,'email':user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, app.config['SECRET_KEY'])  
            admintoken = jwt.encode({'isadmin':True, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, app.config['SECRET_KEY'])  
            return{"status":"Login Successful","access-token":accesstoken.decode('UTF-8'),"refresh-token":refreshtoken.decode('UTF-8'),"admintoken":admintoken.decode('UTF-8')}

        else:
            return{"status":"Credentials Error"}
    else:
        return{"message":"Not valid request"}      


@app.route('/users',methods=["GET"])
@token_required
def getusername(currentuser):
    users = UserModel.query.filter_by(id=currentuser.id).first()
    return{"username":users.fname,"email":users.email}


@app.route('/me',methods=["GET"])
@token_required
def token(currentuser):
    data={
        "fname":currentuser.fname,
        "lname":currentuser.lname,
        "email":currentuser.email
    }
    return{"data":data}


@app.route('/url',methods=["GET"])
@token_required
def tokenrequired(currentuser):
    if currentuser:
        return{"success":"Headers contains tokens"}
    else:
        return{"error":"No Token in header"}

if __name__ == "__main__":
    app.run(debug=True)
    