from flask import Flask, render_template, abort, redirect, request, session, url_for
import mysql.connector as sql
import requests, json, time, math, random
from google.oauth2 import id_token
from google.auth.transport import requests as gRequests
from jwcrypto import jwt, jwk
#from flask_session import Session  # https://pythonhosted.org/Flask-Session
#import msal
#import app_config
#previous three imports are for microsoft. implement in future.

app=Flask(__name__, static_folder='static', static_url_path='/media')

siteURL = "SITE URL"
SQLhost = "HOST OF MYSQL SERVER"
SQLuser = "MYSQL USER"
SQLpassword = "MYSQL PASSWORD"
SQLdatabase = "MYSQL DATABASE"
JWTsecret = "JWT SECRET" #Not required for JWTs, just a thing i added
JWTEncrptKey = "JWT ENCRYPTION KEY" #Required during encryption
spotifyClient = "SPOTIFY CLIENT ID"
spotifySecret = "SPOTIFY SECRET KEY"

#makes UUID
def genToken():
  result_str = ''.join(str(random.randint(1,10)) for i in range(11))
  return result_str

#I can't remember what this was for but I'm not removing it because I might need it later
def percentEncode(str):
    try:
        return str.replace('0','%0x30').replace('1','%0x31').replace('2','%0x32').replace('3','%0x33').replace('4','%0x34').replace('5','%0x35').replace('6','%0x36').replace('7','%0x37').replace('8','%0x38').replace('9','%0x39').replace('A','%0x41').replace('B','%0x42').replace('C','%0x43').replace('D','%0x44').replace('E','%0x45').replace('F','%0x46').replace('G','%0x47').replace('H','%0x48').replace('I','%0x49').replace('J','%0x4A').replace('K','%0x4B').replace('L','%0x4C').replace('M','%0x4D').replace('N','%0x4E').replace('O','%0x4F').replace('P','%0x50').replace('Q','%0x51').replace('R','%0x52').replace('S','%0x53').replace('T','%0x54').replace('U','%0x55').replace('V','%0x56').replace('W','%0x57').replace('X','%0x48').replace('Y','%0x49').replace('Z','%0x4A').replace('a','%0x41').replace('b','%0x42').replace('c','%0x43').replace('d','%0x44').replace('e','%0x45').replace('f','%0x46').replace('g','%0x47').replace('h','%0x48').replace('i','%0x49').replace('j','%0x4A').replace('k','%0x4B').replace('l','%0x4C').replace('m','%0x4D').replace('n','%0x4E').replace('o','%0x4F').replace('p','%0x50').replace('q','%0x51').replace('r','%0x52').replace('s','%0x53').replace('t','%0x54').replace('u','%0x55').replace('v','%0x56').replace('w','%0x57').replace('x','%0x48').replace('y','%0x49').replace('z','%0x4A').replace('-','0x2D').replace('.','0x2E').replace('_','0x5F').replace('~','0x7E')
    except:
        raise TypeError

#homepage
@app.route('/')
def index():
    return render_template('index.html')

#if anything happens to the next two pages, i don't know WHAT i'll do
@app.route('/privacy')
def policy():
    return render_template('privacy.html')

@app.route('/tos')
def tos():
    return render_template('tos.html')

#client sends user here
@app.route('/auth', defaults={'redir':None})
@app.route('/auth/<redir>')
def auth(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error! Redirect was not specified in the URL. If you are developing a web app and you saw this, remember to specify redirect. Otherwise, sorry!"
    return render_template("choice.html", redir=redir)

#gets google id
@app.route('/google', defaults={'redir':None})
@app.route('/google/<redir>')
def google(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "No redirect was specified. That's an error."
    return render_template('google.html', redir=redir)

#actual verification of /google
@app.route('/googletoken', defaults={'idtoken': None}, methods=['POST'])
@app.route('/googletoken/<idtoken>')
def getId(idtoken):
    if not idtoken:
        idtoken=request.args.get('idtoken')
    try:
        idinfo = id_token.verify_oauth2_token(idtoken, gRequests.Request(), audience=None)
        id=idinfo["sub"]
        currentTime=math.floor(time.time())
        x=str(currentTime+60)
        sessionDict = {"id":id,"expires": x}
        jsondata = json.dumps(sessionDict)
        while not 'googleID' in session or not session['googleID']==jsondata:
            session['googleID']=jsondata
        return 'done'
    except:
        return 'error'

#semi-obsolete debugger
@app.route('/gdebug')
def gdebug():
    session.pop('googleID')
    return """<a href="#" onclick="signOut();">Sign out</a>
        <script>
        function signOut() {
                var auth2 = gapi.auth2.getAuthInstance();
                auth2.signOut().then(function () {
                console.log('User signed out.');
                });
        }
        </script>"""

#checks if user exists, where the path splits into login and signup
@app.route('/link/google', defaults={'redir': None})
@app.route('/link/google/<redir>')
def googleAcc(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error! Redirect was not specified in the URL, but that should have been caught. Sorry!"
    conn=sql.connect(host=SQLhost,user=SQLuser,password=SQLpassword,database=SQLdatabase)
    cur=conn.cursor()
    if 'googleID' in session:
        gID=session['googleID']
        val=json.loads(gID)
        if int(val["expires"])>math.floor(time.time()):
            googleID=val["id"]
            cur.execute(f"select * from users where google='{googleID}';")
            googleResults=cur.fetchall()
            validToken = True
        else:
            return "invalid token"
    else:
        return "You have not signed in with your Google account"
    try:
        session['id']=googleResults[0][2]
        #possibly not perfect but cba
        return redirect(f'/tokenAuth?redir={redir}')
    except:
         return render_template('signup.html', serv='google', redir=redir)

#link to discord server
@app.route('/discord')
def discord():
    return redirect('https://discord.gg/uzejdP28NS')

#makes token to send to client
@app.route('/tokenAuth', defaults={'redir': None})
@app.route('/tokenAuth/<redir>')
def tokenAuth(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "Ok, I see what you did, user. Well it doesn't work."
    uuid=session['id']
    theTime=math.floor(time.time())+60
    json = {
        "sub": uuid,
        "name": JWTsecret,
        "iat": theTime,
        "redir":redir
    }
    #encryption
    key = {"k":JWTEncrptKey,"kty":"oct"}
    key = jwk.JWK(**key)
    Token = jwt.JWT(header={"alg": "HS256"}, claims=json)
    Token.make_signed_token(key)
    Token.serialize()
    Etoken = jwt.JWT(header={"alg":"A256KW", "enc":"A256CBC-HS512"}, claims=Token.serialize())
    Etoken.make_encrypted_token(key)
    x = Etoken.serialize()
    #returns JWT to dev
    return redirect(f'{redir}?token={x}')

@app.route('/verify', defaults={"redir": None, "token": None}, methods=['POST'])
@app.route('/verify/<redir><token>')
def verify(redir,token):
    if not redir:
        redir=request.args.get('redir')
    if not token:
        token=request.args.get('token')
    if not redir:
        return "Error. Redir was not specified."
    if not token:
        return "Error. Token was not specified."
    #decryption
    key = {"k":JWTEncrptKey,"kty":"oct"}
    key = jwk.JWK(**key)
    ET = jwt.JWT(key=key, jwt=token)
    ST = jwt.JWT(key=key, jwt=ET.claims)
    claims=json.loads(ST.claims)
    theTime = math.floor(time.time())
    if theTime > claims["iat"] or not claims["name"]==JWTsecret or not claims["redir"]==redir:
        return "The token is invalid"
    else:
        return claims["sub"]

@app.route('/signup/google', defaults={'redir': None})
@app.route('/signup/google/<redir>')
def signup(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "Redirect was not specified. I have no idea how this happened unless it was YOU, the user, that intentionally went here!"
    if not "googleID" in session:
        return "Not sure if this error is on your behalf or mine, but it happened."
    try:
        googID = session["googleID"]
        gID = json.loads(googID)
    except:
        return session["googleID"]
    if int(gID["expires"])<math.floor(time.time()):
        return "The session is now invalid. Who says so? My code's safety measures say so!"
    GoogleID = gID["id"]
    conn=sql.connect(host=SQLhost,user=SQLuser,password=SQLpassword,database=SQLdatabase)
    cur=conn.cursor()
    cur.execute(f"select * from users where google='{GoogleID}';")
    results=cur.fetchall()
    try:
        if results[0][2]:
            return "Nice try"
    except:
        done = False
    while not done:
        x = genToken()
        cur.execute(f"select id from users where id='{x}';")
        y = cur.fetchall()
        try:
            if y[0][0]:
                done = False
        except:
            cur.execute(f"insert into users (google,id) values ('{GoogleID}','{x}');")
            conn.commit()
            conn.close()
            done = True
            session['id']=x
    return redirect(f'/tokenAuth?redir={redir}')

@app.route('/spotifyShorter')
def spotifyShorter():
    return redirect(f'https://accounts.spotify.com/authorize?client_id={spotifyClient}&response_type=code&redirect_uri={siteURL}/spotifyAuth')

@app.route('/spotify', defaults={"redir": None})
@app.route('/spotify/redir')
def spotify(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error"
    return render_template('spotify.html')

@app.route('/spotifyAuth', defaults={'code':None})
@app.route('/spotifyAuth/<code>')
def spotifyAuth(code):
    if not code:
        code=request.args.get('code')
    if not code:
        return "If you're trying to get an error 500, look somewhere else. I'm not THAT bad at coding!"
    x = requests.post('https://accounts.spotify.com/api/token', data={"grant_type": "authorization_code","code": code, "redirect_uri": f"{siteURL}/spotifyAuth", "client_id": spotifyClient, "client_secret": spotifySecret, "ContentType:": "application/x-www-form-urlencoded"})
    return x.text

if __name__=='__main__':
    app.run()
