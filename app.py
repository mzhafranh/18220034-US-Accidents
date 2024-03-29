from flask import Flask, request, render_template, redirect, jsonify, url_for, send_file
from flask_login import UserMixin, login_user, LoginManager,login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pyotp
import datetime
import jwt
import requests
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
import json

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="accidents"
)

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/accidents'
app.config['SECRET_KEY'] = 'supersecretkey@$&*!'
# db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['JSON_SORT_KEYS'] = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "indexLogin"

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

class User(UserMixin):
    def __init__(self, userid, password):
        self.id = userid
        self.password = password

    @staticmethod
    def get(userid):
        cursor = mydb.cursor()
        cursor.execute("SELECT * FROM user WHERE id = %s", [userid])
        result = cursor.fetchall()
        if (len(result) > 0):
            return User(result[0][0], result[0][3])
        else:
            return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({"code" : 400, "status": "fail", "message" : "[ERROR] Token not found"})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({"code" : 400, "status": "fail", "message" : "[ERROR] Token invalid"})
        
        return f(*args, **kwargs)
    
    return decorated

class create_dict(dict): 

    # __init__ function 
    def __init__(self): 
        self = dict() 
        
    # Function to add key:value 
    def add(self, key, value): 
        self[key] = value

    def inc(self, key, value):
        if (self.get(key)):
            self[key] += value
        else:
            self[key] = value

@app.get("/login")
def indexLogin():
    return jsonify({"code" : 400, "status" : "fail", "message" : "[ERROR] Please log in first using /loginapi/ with email and password"}) 

@app.post("/registerapi/")
def addUserAPI():
    email = request.args.get("email")
    username = request.args.get("username")
    password = request.args.get("password")
    role = request.args.get("role")

    cursor = mydb.cursor()
    cursor.execute("SELECT * FROM user WHERE email = %s", [email])
    result = cursor.fetchall()
    if (len(result) > 0):
        return jsonify({"code" : 400, "status" : "fail", "message" : "[ERROR] Email already registered!"}) 
    else:
        hashed_password = bcrypt.generate_password_hash(password)
        cursor.execute("INSERT INTO user (email, username, password, role) VALUES (%s, %s, %s, %s)", [email, username, hashed_password, role])
        mydb.commit() 
        return jsonify({"code" : 200, "status" : "success", "message" : "[SUCCESS] Account succesfully created"})


@app.post("/loginapi/")
def userLoginAPI():
    email = request.args.get("email")
    password = request.args.get("password")

    cursor = mydb.cursor()
    cursor.execute("SELECT * FROM user WHERE email = %s", [email])
    result = cursor.fetchall()
    if (len(result) > 0):
        if(bcrypt.check_password_hash(result[0][3],password)):
            token = jwt.encode({'user_id' : result[0][0], 'email' : result[0][1], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=20)}, app.config['SECRET_KEY'])
            user = User.get(result[0][0])
            login_user(user)
            return jsonify({"code" : 200, "status" : "success", "message":"[SUCCESS] Login Success", "Token" : str(token)})
        else:
            return jsonify({"code" : 400, "status" : "fail", "message":"[ERROR] Invalid username or password"})
    else: 
        return jsonify({"code" : 400, "status" : "fail", "message":"[ERROR] Invalid username or password"})


@app.post("/registerapiotp/")
def addUserAPIOTP():
    email = request.args.get("email")
    username = request.args.get("username")
    password = request.args.get("password")
    role = request.args.get("role")

    cursor = mydb.cursor()
    cursor.execute("SELECT * FROM user WHERE email = %s", [email])
    result = cursor.fetchall()
    if (len(result) > 0):
        return jsonify({"code" : 400, "status" : "fail", "message" : "[ERROR] Email already registered!"}) 
    else:
        hashed_password = bcrypt.generate_password_hash(password)
        cursor.execute("INSERT INTO user (email, username, password, role) VALUES (%s, %s, %s, %s)", [email, username, hashed_password, role])
        mydb.commit()
        otp_key = pyotp.random_base32()

        sender_address = "bukanjeprun@gmail.com"
        sender_pass = "ijvacbyiqhyvpobp"
        receiver_address = request.args.get("email")

        mail_content = f'''[Instructions]
Download google authenticator on your mobile
Create a new account with setup key method.
Provide the required details (name, secret key).
Select time-based authentication.
Submit this generated key in the form.
{otp_key}
'''
        message = MIMEMultipart()
        message['From'] = sender_address
        message['To'] = receiver_address
        message['Subject'] = 'Your 2FA setup to Z-API' 

        message.attach(MIMEText(mail_content, 'plain'))

        session = smtplib.SMTP('smtp.gmail.com',587)
        session.set_debuglevel(1)
        session.starttls()
        session.login(sender_address, sender_pass)
        text = message.as_string()
        session.sendmail(sender_address, receiver_address, text)
        session.quit()

        return jsonify({"code" : 200, "status" : "success", "message" : "[SUCCESS] Account succesfully created, Check your email for 2FA setup"})


@app.post("/loginapiotp/")
def userLoginAPIOTP():
    email = request.args.get("email")
    password = request.args.get("password")
    secret = request.args.get("secret")
    otp = int(request.args.get("otp"))

    cursor = mydb.cursor()
    cursor.execute("SELECT * FROM user WHERE email = %s", [email])
    result = cursor.fetchall()
    if (len(result) > 0):
        if(bcrypt.check_password_hash(result[0][3],password)):
            if pyotp.TOTP(secret).verify(otp):
                token = jwt.encode({'user_id' : result[0][0], 'email' : result[0][1], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=20)}, app.config['SECRET_KEY'])
                user = User.get(result[0][0])
                login_user(user)        
                return jsonify({"code" : 200, "status" : "success", "message":"[SUCCESS] Login success.", "Token" : str(token)})
            else:
                return jsonify({"code" : 400, "status" : "fail", "message":"[ERROR] 2FA Failed"})
        else:
            return jsonify({"code" : 400, "status" : "fail", "message":"[ERROR] Invalid username or password"})
    else: 
        return jsonify({"code" : 400, "status" : "fail", "message":"[ERROR] Invalid username or password"})

@app.get("/email")
@login_required
def email():
    return render_template("email.html")

@app.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('indexLogin'))

@app.get("/report")
# @login_required
@token_required
def searchReport():
    cursor = mydb.cursor()

    if request.args.get("startdate") and request.args.get("enddate"):

        reqstartdate = str(request.args.get("startdate"))
        reqenddate = str(request.args.get("enddate"))

        startdate = datetime.date(int(reqstartdate[:4]), int(reqstartdate[5:7]), int(reqstartdate[8:10]))
        enddate = datetime.date(int(reqenddate[:4]), int(reqenddate[5:7]), int(reqenddate[8:10]))
        enddate = enddate + datetime.timedelta(days=1)
        currdate = startdate

        statdict = create_dict()
        
        while (currdate != enddate):
            statedict = create_dict()
            countydict = create_dict()
            nextdate = currdate + datetime.timedelta(days=1)
            cursor.execute("SELECT * FROM report WHERE start_time BETWEEN %s AND %s", [currdate, nextdate])
            result = cursor.fetchall()
            severity_avg = 0
            for row in result:
                severity_avg += row[1]
                statedict.inc(row[4],1)
                countydict.inc(row[3] + ' - ' + row[4], 1)
            severity_avg = float(severity_avg / len(result))
            statdict.add(str(currdate), ({"date": str(currdate), "total accidents": len(result), "avg severity" : str(round(severity_avg, 2)), "sate": [statedict], "county": [countydict]}))
            currdate = nextdate

        data = jsonify(statdict)
        return (data)

    else:
        data = jsonify({"code":400, "status" : "fail", "message": "Please specify startdate and enddate"})
        return (data)

@app.get("/reportread/")
# @login_required
@token_required
def readReport():
    cursor = mydb.cursor()
    datadict = create_dict()
    cursor.execute("SELECT * FROM report")
    result = cursor.fetchall()
    for row in result:
        datadict.add(row[0], ({"id": row[0], "severity" : row[1], "start_time" : str(row[2]), "county" : row[3], "state" : row[4]}))
    data = jsonify({"code":200, "status" : "success", "data" : [datadict]})
    return (data)

@app.post("/reportadd/")
# @login_required
@token_required
def addReport():
    cursor = mydb.cursor()

    id = request.args.get("id")
    severity = int(request.args.get("severity"))
    start_time = request.args.get("start_time")
    county = request.args.get("county")
    state = request.args.get("state")

    query = ("INSERT INTO report (id, severity, start_time, county, state) VALUES (%s, %s, %s, %s, %s)")
    values = (id, severity, start_time, county, state)
    
    cursor.execute(query, values)

    mydb.commit()

    return jsonify({"code" : 200, "status" : "successs", "message":"[SUCCESS] Record inserted"})

@app.delete("/reportdel/")
# @login_required
@token_required
def deleteReport():
    cursor = mydb.cursor()

    id = str(request.args.get("id"))

    cursor.execute("DELETE FROM report WHERE id LIKE %s", [id])

    mydb.commit()

    return jsonify({"code" : 200, "status" : "successs", "message":"[SUCCESS] Record has been deleted"})

@app.put("/reportedit/")
# @login_required
@token_required
def editReport():
    cursor = mydb.cursor()

    new_id = request.args.get("new_id")
    severity = int(request.args.get("severity"))
    start_time = request.args.get("start_time")
    county = request.args.get("county")
    state = request.args.get("state")
    old_id = request.args.get("old_id")

    query = ("UPDATE report SET id = %s, severity = %s, start_time = %s, county = %s, state = %s WHERE id = %s")
    values = (new_id, severity, start_time, county, state, old_id)
    
    cursor.execute(query, values)

    mydb.commit()

    return jsonify({"code" : 200, "status" : "successs", "message":"[SUCCESS] Record updated"})


@app.get("/visualize/")
# @login_required
@token_required
def visualize():

    # url_zhil = 'http://localhost:5001/'
    # username = 'zhil'
    # password = 'password0815'
    # url_req_token = url_zhil + "?username=" + username + "&password=" + password 
    # rtoken = requests.get(url_req_token)
    # token = rtoken["token"]

    # url_map = ''
    # url_req_map = url_map + "?username=" + username + "&token=" + token

    reqmap = requests.get("http://localhost:5000/exampledata/")

    d_json = reqmap.json()

    x = []
    y = []
    acc_num = []

    for i in range(len(d_json['accidents'])):
        x.append(d_json['accidents'][i]['INTPTLON'])
        y.append(d_json['accidents'][i]['INTPTLAT'])
        acc_num.append(d_json['accidents'][i]['accidents_num'])

    # Make a map of the United States
    plt.figure(figsize=(12, 6))
    map_us = Basemap( 
        llcrnrlat=22, 
        llcrnrlon=-119, 
        urcrnrlat=49, 
        urcrnrlon=-64, 
        projection="lcc",
        lat_1=33,
        lat_2=45,
        lon_0=-95
    )
    map_us.drawmapboundary(fill_color="#A6CAE0", linewidth=0)
    map_us.fillcontinents(color="grey", alpha=0.3)
    map_us.drawcoastlines(linewidth=0.1, color="white")

    # Plot extracted data to the map
    map_us.scatter(x, y, s=acc_num, alpha=0.5, latlon=True)

    # Save image and send to requester
    plt.savefig("map.png")
    return send_file("map.png", mimetype="image/png")

# @app.get("/exampleprint/")
# def getPrint():
#     req = (requests.get("http://localhost:5000/exampledata/").json())
#     for item in req:
#         return str(req[item]["total accidents"])
    

@app.get("/exampledata/")
def getData():
#     return jsonify({
#     "2016-02-09": {
#         "date": "2016-02-09",
#         "total accidents": 24,
#         "avg severity": "2.71",
#         "sate": [
#             {
#                 "OH": 9,
#                 "IN": 10,
#                 "WV": 1,
#                 "MI": 2,
#                 "PA": 2
#             }
#         ],
#         "county": [
#             {
#                 "Franklin - OH": 2,
#                 "Montgomery - OH": 2,
#                 "Hamilton - OH": 1,
#                 "Bartholomew - IN": 1,
#                 "Greene - OH": 1,
#                 "Shelby - IN": 1,
#                 "Decatur - IN": 2,
#                 "Wood - WV": 1,
#                 "Marion - IN": 1,
#                 "Monroe - MI": 2,
#                 "Clark - IN": 1,
#                 "Allegheny - PA": 2,
#                 "Delaware - OH": 1,
#                 "Cuyahoga - OH": 1,
#                 "Summit - OH": 1,
#                 "Jay - IN": 2,
#                 "Wayne - IN": 2
#             }
#         ]
#     },
#     "2016-02-10": {
#         "date": "2016-02-10",
#         "total accidents": 32,
#         "avg severity": "2.5",
#         "sate": [
#             {
#                 "OH": 22,
#                 "IN": 2,
#                 "PA": 3,
#                 "KY": 3,
#                 "WV": 2
#             }
#         ],
#         "county": [
#             {
#                 "Franklin - OH": 5,
#                 "Van Wert - OH": 1,
#                 "Henry - IN": 1,
#                 "Cuyahoga - OH": 6,
#                 "Crawford - PA": 1,
#                 "Montgomery - OH": 4,
#                 "Steuben - IN": 1,
#                 "Jefferson - KY": 3,
#                 "Summit - OH": 2,
#                 "Clark - OH": 1,
#                 "Erie - PA": 1,
#                 "Upshur - WV": 1,
#                 "Lucas - OH": 1,
#                 "Lake - OH": 2,
#                 "Washington - PA": 1,
#                 "Kanawha - WV": 1
#             }
#         ]
#     },
#     "2016-02-11": {
#         "date": "2016-02-11",
#         "total accidents": 58,
#         "avg severity": "2.38",
#         "sate": [
#             {
#                 "IN": 6,
#                 "OH": 40,
#                 "KY": 3,
#                 "WV": 5,
#                 "PA": 4
#             }
#         ],
#         "county": [
#             {
#                 "Steuben - IN": 3,
#                 "Williams - OH": 2,
#                 "Medina - OH": 1,
#                 "Montgomery - OH": 4,
#                 "Cuyahoga - OH": 10,
#                 "Pendleton - KY": 1,
#                 "Kenton - KY": 2,
#                 "Floyd - IN": 1,
#                 "Kanawha - WV": 4,
#                 "Summit - OH": 8,
#                 "Allen - IN": 1,
#                 "Braxton - WV": 1,
#                 "Franklin - OH": 4,
#                 "Hamilton - OH": 11,
#                 "Clark - IN": 1,
#                 "Allegheny - PA": 4
#             }
#         ]
#     }
# })

    return jsonify({ 
    "code" : 200,
    "status" : "success",
    "accidents" : 
        [
            {
                "NAME" : "St. Charles",
                "STUSAB" : "LA", 
                "accidents_num" : 69,
                "INTPTLAT" : 29.9057222,
                "INTPTLON" : -90.3578553
            },
            {
                "NAME" : "San Patricio", 
                "STUSAB" : "TX", 
                "accidents_num" : 42,
                "INTPTLAT" : 28.0117944,
                "INTPTLON" : -97.5171566
            },
            {
                "NAME" : "Sebastian", 
                "STUSAB" : "AR", 
                "accidents_num" : 33,
                "INTPTLAT" : 35.1969808,
                "INTPTLON" : -94.2749889
            }
        ]
})

if __name__ == "__main__":
    app.run()
