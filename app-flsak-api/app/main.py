from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import re
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///email.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receiver_user_id = db.Column(db.String(50))
    sender_user_id = db.Column(db.String(50))
    subject = db.Column(db.String(50))
    text = db.Column(db.String(50))
    creation_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(address=data['address']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['address'] = user.address
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<address>', methods=['GET'])
@token_required
def get_one_user(current_user, address):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(address=address).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['address'] = user.address
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()

    user = User.query.filter_by(name=data['name']).first()
    if user:
        return jsonify({'message' : 'This name is already used, please try different name.'})
    
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(address=str(data['name'] + "@email.com"), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/user/<address>', methods=['PUT'])
@token_required
def promote_user(current_user ,address):
    if current_user.name != 'admin':
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(address=address).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<address>', methods=['DELETE'])
@token_required
def delete_user(current_user, address):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(address=address).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'address' : user.address, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token' : token, 'address' : user.address})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/get_all_emails', methods=['GET'])
@token_required
def get_all_emails(current_user):
    emails = Email.query.filter_by(receiver_user_id=current_user.address).all()

    output = []
    for email in emails:
        print(email)
        email_data = {}
        email_data['sender_user_id'] = email.sender_user_id
        email_data['receiver_user_id'] = current_user.address
        email_data['subject'] = email.subject
        email_data['text'] = email.text
        email_data['creation_date'] = email.creation_date
        email_data['read'] = email.read
        email_data['id'] = email.id
        output.append(email_data)
    if output:
        return jsonify({'message' : output})
    else:
        return jsonify({'message' : 'No messages'})

@app.route('/get_all_unread_emails', methods=['GET'])
@token_required
def get_all_unread_emails(current_user):
    emails = Email.query.filter_by(receiver_user_id=current_user.address, read=False).all()

    output = []
    for email in emails:
        email_data = {}
        email_data['sender_user_id'] = email.sender_user_id
        email_data['receiver_user_id'] = current_user.address
        email_data['subject'] = email.subject
        email_data['text'] = email.text
        email_data['creation_date'] = email.creation_date
        email_data['read'] = email.read
        email_data['id'] = email.id
        output.append(email_data)
    if output:
        return jsonify({'message' : output})
    else:
        return jsonify({'message' : 'No unread messages'})

@app.route('/create_email', methods=['POST'])
@token_required
def create_email(current_user):
    data = request.get_json()

    new_email = Email(receiver_user_id=data['receiver_user_id'],sender_user_id=current_user.address, subject=data['subject'],text=data['text'], read=False)
    db.session.add(new_email)
    db.session.commit()

    return jsonify({'message' : 'Email sent successfully'})

@app.route('/email/<email_id>', methods=['PUT'])
@token_required
def read_one_email(current_user, email_id):
    email = Email.query.filter_by(id=email_id ,receiver_user_id=current_user.address).first()

    if not email:
        return jsonify({'message' : 'Email was not found!'})

    email_data = {}
    email_data['sender_user_id'] = email.sender_user_id
    email_data['receiver_user_id'] = current_user.address
    email_data['subject'] = email.subject
    email_data['text'] = email.text
    email_data['creation_date'] = email.creation_date
    email_data['read'] = True
    email_data['id'] = email.id
    email.read = True
    db.session.commit()

    return jsonify({'message' : email_data})

@app.route('/email/<email_id>', methods=['DELETE'])
@token_required
def delete_message(current_user, email_id):
    email = Email.query.filter_by(id=email_id ,receiver_user_id=current_user.address).first()

    if not email:
        email = Email.query.filter_by(id=email_id ,sender_user_id=current_user.address).first()

    if not email:
        return jsonify({'message' : 'Email was not found!'})

    db.session.delete(email)
    db.session.commit()

    return jsonify({'message' : 'Email deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)