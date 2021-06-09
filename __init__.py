from flask import Flask, render_template, abort, redirect, request, session, url_for, flash
import mysql.connector as sql
import requests, json, time, math, random
from google.oauth2 import id_token
from google.auth.transport import requests as gRequests
from jwcrypto import jwt, jwk
from itsdangerous import URLSafeSerializer
from .components import percentEncode, genToken, getCookieWithExpiry
#from flask_session import Session  # https://pythonhosted.org/Flask-Session
#import msal
#import app_config
#previous three imports are for microsoft. implement in future.

app=Flask(__name__, static_folder='static', static_url_path='/media')

x = open('/var/www/assert/assertapp/components/secrets.json','r')
data = json.loads(x.read())
x.close()
site_url = data["site_url"]
SQLhost = data["SQLhost"]
SQLuser = data["SQLuser"]
SQLpassword = data["SQLpassword"]
SQLdatabase = data["SQLdatabase"]
itsdangerous1 = data["itsdangerous1"]
itsdangerous2 = data["itsdangerous2"]
spotifyClient = data["spotifyClient"]
spotifySecret = data["spotifySecret"]
googleClient = data["googleClient"]
identityClient = data["identityClient"]
identitySecret = data["identitySecret"]

def safeEncrypt(data):
    auths = URLSafeSerializer(itsdangerous1,itsdangerous2)
    return auths.dumps(data)

def safeDecrypt(data):
    auths = URLSafeSerializer(itsdangerous1,itsdangerous2)
    return auths.loads(data)

def database():
    return sql.connect(host=SQLhost, user=SQLuser, password=SQLpassword, database=SQLdatabase)

def safeEncode(data):
    return data.replace("\\","\\\\").replace("'","\'")

def safeDecode(data):
    return data.replace("\'","'").replace("\\\\","\\")

@app.before_request
def beforeRequest():
    if request.url_root.startswith("http://"):
        return redirect(request.url_root.replace("http://","https://"))

#homepage
@app.route('/')
def index():
    return render_template('index.html', url=site_url)

#if anything happens to the next two pages, i don't know WHAT i'll do
@app.route('/privacy')
def policy():
    return render_template('privacy.html')

@app.route('/tos')
def tos():
    return render_template('tos.html')

@app.route('/git/')
def git():
    return redirect('https://github.com/AssertApp/Assert')

#client sends user here
@app.route('/auth', defaults={'redir':None})
@app.route('/auth/<redir>')
def auth(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error! Redirect was not specified in the URL. If you are developing a web app and you saw this, remember to specify redirect. Otherwise, sorry!"
    if 'linkID' in session:
        session.pop('linkID')
    return render_template("choice.html", redir=redir)

#gets google id
@app.route('/google', defaults={'link': None, 'redir':None})
@app.route('/google/<link><redir>')
def google(link, redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "No redirect was specified. That's an error."
    if not link:
        link = request.args.get('link')
    if not link:
        link = False
    if link and link=="true":
        link = True
    if 'linkID' in session:
        val = json.loads(session['linkID'])
        if val["service"]=="google":
            session.pop('linkID')
            return "Confusion"
        val["service2"]="google"
        session['linkID']=json.dumps(val)
    if link and link=="false":
        link = False
    return render_template('google.html', redir=redir, link=link, googleClient=googleClient, siteURL=site_url)
    
#actual verification of /google
@app.route('/googletoken', defaults={'idtoken': None}, methods=['POST'])
@app.route('/googletoken/<idtoken>')
def getId(idtoken):
    if not idtoken:
        idtoken=request.args.get('idtoken')
    try:
        idinfo = id_token.verify_oauth2_token(idtoken, gRequests.Request(), audience=None)
        jsondata = getCookieWithExpiry(idinfo["sub"])
        while not 'googleID' in session or not session['googleID']==jsondata:
            session['googleID']=jsondata
        return 'done'
    except:
        return 'error'

#checks if user exists, where the path splits into login and signup
@app.route('/split/google', defaults={'link': None, 'redir': None})
@app.route('/split/google/<link><redir>')
def googleAcc(link, redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error! Redirect was not specified in the URL, but that should have been caught. Sorry!"
    if not link:
        link = request.args.get('link')
    if not link:
        link = False
    if link and link=="true":
        link = True
        return redirect(f'/confirmlink?redir={redir}')
    if link and link=="false":
        link = False
    conn=database()
    cur=conn.cursor()
    if 'googleID' in session:
        gID=session['googleID']
        val=json.loads(gID)
        if val["expires"]>math.floor(time.time()):
            googleID=val["id"]
            cur.execute(f"select * from users where google={safeEncode(googleID)};")
            googleResults=cur.fetchall()
            validToken = True
        else:
            session.pop('googleID')
            return "invalid token"
    else:
        return "You have not signed in with your Google account"
    try:
        session['id']=googleResults[0][2]
        #possibly not perfect but cba
        return redirect(f'/tokenAuth?redir={redir}')
    except:
         return render_template('signup.html', serv='google', redir=redir)

@app.route('/link/google', defaults={'redir': None})
@app.route('/link/google/<redir>')
def googleLink(redir):
    if not redir:
        redir = request.args.get('redir')
    if not redir:
        return "Redirect was not specified in the URL"
    if not 'googleID' in session:
        return "You are either not signed into google or you haven't been signed in for a while."
    gID = session["googleID"]
    val = json.loads(gID)
    if not val["expires"]>math.floor(time.time()):
        return "You have not signed into google in too long"
    googleID = val["id"]
    conn = database()
    cur = conn.cursor()
    cur.execute(f"select * from users where google='{safeEncode(googleID)}';")
    googleResults = cur.fetchall()
    try:
        session['id'] = googleResults[0][2]
        return redirect(f"/tokenAuth?redir={redir}")
    except:
        session['linkID'] = json.dumps({"service": "google", "id": googleID, "expiry": math.floor(time.time()+120)})
        return render_template('choice.html', redir=redir, serv='google', link=True)
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
    conn=database()
    cur=conn.cursor()
    cur.execute(f"select * from users where google='{safeEncode(GoogleID)}';")
    results=cur.fetchall()
    try:
        if results[0][2]:
            return "Nice try"
    except:
        done = False
    while not done:
        x = genToken()
        cur.execute(f"select id from users where id='{safeEncode(x)}';")
        y = cur.fetchall()
        try:
            if y[0][0]:
                done = False
        except:
            cur.execute(f"insert into users (google,id) values ('{safeEncode(GoogleID)}','{safeEncode(x)}');")
            conn.commit()
            conn.close()
            done = True
            session['id']=x
    return redirect(f'/tokenAuth?redir={redir}')

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
        "iat": theTime,
        "redir": redir
    }
    #encryption
    x = safeEncrypt(json)
    return redirect(f'{redir}?token={x}')

@app.route('/verify', defaults={"token": None, "secret": None, "redir": None}, methods=['POST'])
@app.route('/verify/<token><secret><redir>')
def verify(token,secret,redir):
    redir = request.args.get('redir')
    secret = request.args.get('secret')
    token = request.args.get('token')
    if not redir:
        return {"error": "redir not specified"}
    if not token:
        return {"error": "token not specified"}
    if not secret:
        return {"error": "secret not specified"}
    #decryption
    conn = database()
    cur = conn.cursor()
    cur.execute(f"select uuid from developers where secretKey='{safeEncode(secret)}';")
    results = cur.fetchall()
    try:
        assert results[0][0]
        uuid = safeDecode(results[0][0])
    except:
        return {"error": "invalid secret"}
    cur.execute(f"select url from devurls where url='{safeEncode(redir)}' and devid='{safeEncode(uuid)}';")
    results = cur.fetchall()
    try:
        assert results[0][0]==redir
    except:
        return {"error": "url not allowed in dev portal"}
    claims = safeDecrypt(token)
    theTime = math.floor(time.time())
    userID = safeEncrypt(URLSafeSerializer(secret).dumps(claims["sub"]))
    if theTime > claims["iat"] or not claims["redir"]==redir:
        return {"error": "invalid token"}
    else:
        return {"uuid": userID}

@app.route('/spotifyShorter')
def spotifyShorter():
    return redirect(f'https://accounts.spotify.com/authorize?client_id={spotifyClient}&response_type=code&redirect_uri={site_url}/spotifyAuth')

@app.route('/spotify', defaults={'link': None, 'redir': None})
@app.route('/spotify/<link><redir>')
def spotify(link, redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error"
    if not link:
        link = request.args.get('link')
    if not link:
        link = False
    if link and link=="true":
        link = True
        if 'linkID' in session:
            val = json.loads(session['linkID'])
            if val["service"]=="spotify":
                session.pop('linkID')
                return "Confusion"
            val["service2"]="spotify"
            session['linkID']=json.dumps(val)
        else:
            return "I am very, very confused"
    if link and link=="false":
        link = False
    return render_template('spotify.html', redir=redir, link=link)

@app.route('/link/spotify', defaults={'redir': None})
@app.route('/link/spotify/<redir>')
def spotifyLink(redir):
    if not redir:
        redir = request.args.get('redir')
    if not redir:
        return "Redirect was not specified in the URL"
    if not 'googleID' in session:
        return "You are either not signed into spotify or you haven't been signed in for a while."
    sID = session["spotifyID"]
    val = json.loads(sID)
    if not val["expires"]>math.floor(time.time()):
        return "You have not signed into spotify in too long"
    spotifyID = val["id"]
    conn = database()
    cur = conn.cursor()
    cur.execute(f"select * from users where spotify='{safeEncode(spotifyID)}';")
    spotifyResults = cur.fetchall()
    try:
        session['id'] = safeDecode(spotifyResults[0][2])
        return redirect(f"/tokenAuth?redir={redir}")
    except:
        session['linkID'] = json.dumps({"service": "spotify", "id": spotifyID, "expiry": math.floor(time.time()+120)})
        return render_template('choice.html', redir=redir, serv='spotify', link=True)

@app.route('/spotifyAuth', defaults={'code':None})
@app.route('/spotifyAuth/<code>')
def spotifyAuth(code):
    if not code:
        code=request.args.get('code')
    if not code:
        return "If you're trying to get an error 500, look somewhere else. I'm not THAT bad at coding!"
    x = requests.post('https://accounts.spotify.com/api/token', data={"grant_type": "authorization_code","code": code, "redirect_uri": f"{site_url}/spotifyAuth", "client_id": spotifyClient, "client_secret": spotifySecret, "ContentType:": "application/x-www-form-urlencoded"})
    token = json.loads(x.text)["access_token"]
    y = requests.get('https://api.spotify.com/v1/me', headers={"Authorization": f"Bearer {token}"})
    jsondata = getCookieWithExpiry(json.loads(y.text)["id"])
    while not 'spotifyID' in session or not session['spotifyID']==jsondata:
        session['spotifyID']=jsondata
    return """<link rel="stylesheet" href="/media/style.css"><main><h1>You can now close this tab</h1></main>"""

@app.route('/signup/spotify', defaults={'redir': None})
@app.route('/signup/spotify/<redir>')
def spotifySignup(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "Redirect was not specified. I have no idea how this happened unless it was YOU, the user, that intentionally went here!"
    if not "spotifyID" in session:
        return "Not sure if this error is on your behalf or mine, but it happened."
    try:
        spotifID = session["spotifyID"]
        sID = json.loads(spotifID)
    except:
        return session["spotifyID"]
    if sID["expires"]<math.floor(time.time()):
        return "The session is now invalid. Who says so? My code's safety measures say so!"
    spotifyID = sID["id"]
    conn=database()
    cur=conn.cursor()
    cur.execute(f"select * from users where spotify='{safeEncode(spotifyID)}';")
    results=cur.fetchall()
    try:
        if results[0][2]:
            return "Nice try"
    except:
        done = False
    while not done:
        x = genToken()
        cur.execute(f"select id from users where id='{safeEncode(x)}';")
        y = cur.fetchall()
        try:
            if y[0][0]:
                done = False
        except:
            cur.execute(f"insert into users (spotify,id) values ('{safeEncode(spotifyID)}','{safeEncode(x)}');")
            conn.commit()
            conn.close()
            done = True
            session['id']=x
    return redirect(f'/tokenAuth?redir={redir}')

#checks if user exists, where the path splits into login and signup
@app.route('/split/spotify', defaults={'link': None,'redir': None})
@app.route('/split/spotify/<link><redir>')
def spotifyAcc(link, redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error! Redirect was not specified in the URL, but that should have been caught. Sorry!"
    if not link:
        link = request.args.get('link')
    if not link:
        link = False
    if link and link=="true":
        link = True
        return redirect(f'/confirmlink?redir={redir}')
    if link and link=="false":
        link = False
    conn=database()
    cur=conn.cursor()
    if 'spotifyID' in session:
        spID=session['spotifyID']
        val=json.loads(spID)
        if val["expires"]>math.floor(time.time()):
            spotifID=val["id"]
            cur.execute(f"select * from users where spotify='{safeEncode(spotifID)}';")
            spotifyResults=cur.fetchall()
            validToken = True
        else:
            return "invalid token"
    else:
        return "You have not signed in with your Spotify account"
    try:
        session['id']=spotifyResults[0][2]
        #possibly not perfect but cba
        return redirect(f'/tokenAuth?redir={redir}')
    except:
         return render_template('signup.html', serv='spotify', redir=redir)

@app.route('/confirmlink', defaults={'redir': None})
@app.route('/confirmlink/<redir>')
def confirmLink(redir):
    if not redir:
        redir = request.args.get('redir')
    if not redir:
        return "Redir was not specified in the URL"
    if 'linkID' in session:
        val = json.loads(session['linkID'])
        if val["expiry"]>math.floor(time.time()):
            service1 = val["service"]
            service2 = val["service2"]
            if service1==service2:
                return "wha"
            if service1=="google":
                if 'googleID' in session:
                    google = json.loads(session["googleID"])
                    if google["expires"]<math.floor(time.time()):
                        return "This took too long and we cannot verify the authenticity of this request"
                    gID = google["id"]
                    conn = database()
                    cur=conn.cursor()
                    cur.execute(f"select google from users where google='{safeEncode(gID)}';")
                    try:
                        if not safeDecode(cur.fetchall()[0][0])==gID:
                            return "error"
                    except:
                        numberone = {"service": "google","id": gID}
                else:
                    return "invalid"
            elif service1=="spotify":
                if 'spotifyID' in session:
                    spotify = json.loads(session["spotifyID"])
                    if spotify["expires"]<math.floor(time.time()):
                        return "This took too long and we cannot verify the authenticity of this request"
                    sID = spotify["id"]
                    conn = database()
                    cur = conn.cursor()
                    cur.execute(f"select spotify from users where spotify='{safeEncode(sID)}';")
                    try:
                        if not safeDecode(cur.fetchall()[0][0])==sID:
                            return "error"
                    except:
                        numberone = {"service": "spotify","id": sID}
                else:
                    return "invalid"
            elif service1=="identity":
                if 'identityID' in session:
                    identity = json.loads(session["identityID"])
                    if identity["expires"]<math.floor(time.time()):
                        return "This took too long and we cannot verify the authenticity of this request"
                    idID = identity["id"]
                    conn = database()
                    cur = conn.cursor()
                    cur.execute(f"select identity from users where identity='{safeEncode(idID)}';")
                    try:
                        if not safeDecode(cur.fetchall()[0][0])==idID:
                            return "error"
                    except:
                        numberone = {"service": "identity","id": idID}
                else:
                    return "invalid"
            if service2=="google":
                if 'googleID' in session:
                    google = json.loads(session["googleID"])
                    if google["expires"]<math.floor(time.time()):
                        return "This took too long and we cannot verify the authenticity of this request"
                    gID = google["id"]
                    conn = database()
                    cur = conn.cursor()
                    cur.execute(f"select google from users where google='{(gID)}';")
                    if not safeDecode(cur.fetchall()[0][0])==gID:
                        return "error"
                    numbertwo = {"service": "google","id": gID}
                else:
                    return "invalid"
            elif service2=="spotify":
                if 'spotifyID' in session:
                    spotify = json.loads(session["spotifyID"])
                    if spotify["expires"]<math.floor(time.time()):
                        return "This took too long and we cannot verify the authenticity of this request"
                    sID = spotify["id"]
                    conn = database()
                    cur = conn.cursor()
                    cur.execute(f"select spotify from users where spotify='{sID}';")
                    if not safeDecode(cur.fetchall()[0][0])==sID:
                        return "error"
                    numbertwo = {"service": "spotify","id": sID}
                else:
                    return "invalid"
            elif service2=="identity":
                if 'identityID' in session:
                    identity = json.loads(session["identityID"])
                    if identity["expires"]<math.floor(time.time()):
                        return "This took too long and we cannot verify the authenticity of this request"
                    idID = spotify["id"]
                    conn = database()
                    cur = conn.cursor()
                    cur.execute(f"select identity from users where identity='{idID}';")
                    if not safeDecode(cur.fetchall()[0][0])==idID:
                        return "error"
                    numbertwo = {"service": "identity","id": idID}
                else:
                    return "invalid"
            if not service1=="google" and not service1=="spotify" and not service1=="identity" and not service2=="google" and not service2=="spotify" and not service2=="identity":
                return "If this error occurs, email James at james@chaosgb.co.uk. This should not happen, so if you see this, please tell me!"
            session.pop('linkID')
            return render_template("confirmlink.html", code=safeEncrypt({"tolink": numberone, "exists": numbertwo, "expires": math.floor(time.time()+60)}), redir=redir)
        else:
            session.pop('linkID')
            return "This took too long"
    else:
        return "Invalid"

@app.route('/confirmedlink', defaults={'code': None, 'redir': None})
@app.route('/confirmedlink/<code><redir>')
def confirmedlink(code, redir):
    code = request.args.get('code')
    redir = request.args.get('redir')
    if not code or not redir:
        return "error"
    code = safeDecrypt(code)
    if code["expires"]<math.floor(time.time()):
        return "This took too long and we cannot verify the authenticity of this request"
    existing = code["exists"]
    existingService = existing["service"]
    existingID = existing["id"]
    toLink = code["tolink"]
    toLinkService = toLink["service"]
    toLinkID = toLink["id"]
    validServices = ['google', 'spotify', 'identity']
    conn = database()
    cur = conn.cursor()
    if existingService==toLinkService:
        return "Error"
    if not existingService in validServices or not toLinkService in validServices:
        return "Error"
    cur.execute(f"select {toLinkService} from users where {existingService}='{safeEncode(existingID)}';")
    results = cur.fetchall()
    try:
        assert results[0][0]
        return "Error"
    except:
        cur.execute(f"select {existingService} from users where {toLinkService}='{safeEncode(toLinkID)}';")
    results = cur.fetchall()
    try:
        assert results[0][0]
        return "Error"
    except:
        cur.execute(f"select id from users where {existingService}='{safeEncode(existingID)}';")
    ID = safeDecode(cur.fetchall()[0][0])
    cur.execute(f"update users set {toLinkService}='{safeEncode(toLinkID)}' where id={safeEncode(ID)};")
    conn.commit()
    conn.close()
    session['id']=ID
    return redirect(f'/tokenAuth?redir={redir}')

@app.route('/identity/auth')
def identityAuth():
    req = requests.post("https://identity.alles.cx/a/v1/flow", data={"callback":"{siteURL}/identity/callback"}, auth=(identityClient,identitySecret))
    token = json.loads(req.text)["token"]
    return redirect(f"https://identity.alles.cx/login?flow={token}")

@app.route('/identity/callback', defaults={"code": None})
@app.route('/identity/callback/<code>')
def identityCallback(code):
    code = request.args.get('code')
    if not code:
        return "The code was not specified"
    req = requests.get(f"https://identity.alles.cx/a/v1/profile?code={code}", auth=(identityClient,identitySecret))
    jsondata = getCookieWithExpiry(json.loads(req.text)["id"])
    while not 'identityID' in session or not session['identityID']==jsondata:
        session['identityID']=jsondata
    return """<link rel="stylesheet" href="/media/style.css"><main><h1>You can now close this tab</h1></main>"""

@app.route('/identity', defaults={'link': None, 'redir': None})
@app.route('/identity/<link><redir>')
def identity(link, redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error"
    if not link:
        link = request.args.get('link')
    if not link:
        link = False
    if link and link=="true":
        link = True
        if 'linkID' in session:
            val = json.loads(session['linkID'])
            if val["service"]=="identity":
                session.pop('linkID')
                return "Confusion"
            val["service2"]="identity"
            session['linkID']=json.dumps(val)
        else:
            return "I am very, very confused"
    if link and link=="false":
        link = False
    return render_template('identity.html', redir=redir, link=link)

#checks if user exists, where the path splits into login and signup
@app.route('/split/identity', defaults={'link': None,'redir': None})
@app.route('/split/identity/<link><redir>')
def identityAcc(link, redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "That's an error! Redirect was not specified in the URL, but that should have been caught. Sorry!"
    if not link:
        link = request.args.get('link')
    if not link:
        link = False
    if link and link=="true":
        link = True
        return redirect(f'/confirmlink?redir={redir}')
    if link and link=="false":
        link = False
    conn=database()
    cur=conn.cursor()
    if 'identityID' in session:
        idID=session['identityID']
        val=json.loads(idID)
        if val["expires"]>math.floor(time.time()):
            identitID=val["id"]
            cur.execute(f"select * from users where identity='{safeEncode(identitID)}';")
            itentityResults=cur.fetchall()
            validToken = True
        else:
            return "invalid token"
    else:
        return "You have not signed in with your identity account"
    try:
        session['id']=identityResults[0][2]
        #possibly not perfect but cba
        return redirect(f'/tokenAuth?redir={redir}')
    except:
         return render_template('signup.html', serv='identity', redir=redir)

@app.route('/signup/identity', defaults={"redir": None})
@app.route('/signup/identity/<redir>')
def identitySignup(redir):
    if not redir:
        redir=request.args.get('redir')
    if not redir:
        return "Redirect was not specified. I have no idea how this happened unless it was YOU, the user, that intentionally went here!"
    if not "identityID" in session:
        return "Not sure if this error is on your behalf or mine, but it happened."
    try:
        identitID = session["identityID"]
        idID = json.loads(identitID)
    except:
        return session["identityID"]
    if idID["expires"]<math.floor(time.time()):
        return "The session is now invalid. Who says so? My code's safety measures say so!"
    identityID = idID["id"]
    conn=database()
    cur=conn.cursor()
    cur.execute(f"select * from users where identity='{safeEncode(identityID)}';")
    results=cur.fetchall()
    try:
        if results[0][2]:
            return "Nice try"
    except:
        done = False
    while not done:
        x = genToken()
        cur.execute(f"select id from users where id='{safeEncode(x)}';")
        y = cur.fetchall()
        try:
            if y[0][0]:
                done = False
        except:
            cur.execute(f"insert into users (identity,id) values ('{safeEncode(identityID)}','{safeEncode(x)}');")
            conn.commit()
            conn.close()
            done = True
            session['id']=x
    return redirect(f'/tokenAuth?redir={redir}')

@app.route('/link/identity', defaults={'redir': None})
@app.route('/link/identity/<redir>')
def identityLink(redir):
    if not redir:
        redir = request.args.get('redir')
    if not redir:
        return "Redirect was not specified in the URL"
    if not 'identityID' in session:
        return "You are either not signed into spotify or you haven't been signed in for a while."
    idID = session["identityID"]
    val = json.loads(idID)
    if not val["expires"]>math.floor(time.time()):
        return "You have not signed into spotify in too long"
    identityID = val["id"]
    conn = database()
    cur = conn.cursor()
    cur.execute(f"select * from users where identity='{safeEncode(identityID)}';")
    identityResults = cur.fetchall()
    try:
        session['id'] = safeDecode(identityResults[0][2])
        return redirect(f"/tokenAuth?redir={redir}")
    except:
        session['linkID'] = json.dumps({"service": "identity", "id": identityID, "expiry": math.floor(time.time()+120)})
        return render_template('choice.html', redir=redir, serv='identity', link=True)

if __name__=='__main__':
    app.run()
