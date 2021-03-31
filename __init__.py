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

def safeEncrypt(data):
    auths = URLSafeSerializer(itsdangerous1,itsdangerous2)
    return auths.dumps(data)

def safeDecrypt(data):
    auths = URLSafeSerializer(itsdangerous1,itsdangerous2)
    return auths.loads(data)

def database():
    return sql.connect(host=SQLhost, user=SQLuser, password=SQLpassword, database=SQLdatabase)

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
            cur.execute(f"select * from users where google='{googleID}';")
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
    cur.execute(f"select * from users where google='{googleID}';")
    googleResults = cur.fetchall()
    try:
        session['id'] = googleResults[0][2]
        return redirect(f"/tokenAuth?redir={redir}")
    except:
        session['linkID'] = json.dumps({"service": "google", "id": googleID, "expiry": math.floor(time.time()+120)})
        return render_template('choice.html', redir=redir, serv='google', link=True)

@app.route('/link/spotify', defaults={'redir': None})
@app.route('/link/spotify/<redir>')
def spotifyLink(redir):
    if not redir:
        redir = request.args.get('redir')
    if not redir:
        return "Redirect was not specified in the URL"
    if not 'googleID' in session:
        return "You are either not signed into google or you haven't been signed in for a while."
    sID = session["spotifyID"]
    val = json.loads(sID)
    if not val["expires"]>math.floor(time.time()):
        return "You have not signed into google in too long"
    spotifyID = val["id"]
    conn = database()
    cur = conn.cursor()
    cur.execute(f"select * from users where spotify='{spotifyID}';")
    spotifyResults = cur.fetchall()
    try:
        session['id'] = spotifyResults[0][2]
        return redirect(f"/tokenAuth?redir={redir}")
    except:
        session['linkID'] = json.dumps({"service": "spotify", "id": spotifyID, "expiry": math.floor(time.time()+120)})
        return render_template('choice.html', redir=redir, serv='spotify', link=True)

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
    claims = safeDecrypt(token)
    theTime = math.floor(time.time())
    if theTime > claims["iat"] or not claims["redir"]==redir:
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
    conn=database()
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
    cur.execute(f"select * from users where spotify='{spotifyID}';")
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
            cur.execute(f"insert into users (spotify,id) values ('{spotifyID}','{x}');")
            conn.commit()
            conn.close()
            done = True
            session['id']=x
    return redirect(f'/tokenAuth?redir={redir}')

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

@app.route('/git/')
def git():
    return redirect('https://github.com/AssertApp/Assert')

#?checks if user exists, where the path splits into login and signup
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
            cur.execute(f"select * from users where spotify='{spotifID}';")
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
                    cur.execute(f"select google from users where google='{gID}';")
                    try:
                        if not cur.fetchall()[0][0]==gID:
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
                    cur.execute(f"select spotify from users where spotify='{sID}';")
                    try:
                        if not cur.fetchall()[0][0]==sID:
                            return "error"
                    except:
                        numberone = {"service": "spotify","id": sID}
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
                    cur.execute(f"select google from users where google='{gID}';")
                    if not cur.fetchall()[0][0]==gID:
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
                    if not cur.fetchall()[0][0]==sID:
                        return "error"
                    numbertwo = {"service": "spotify","id": sID}
                else:
                    return "invalid"
            if not service1=="google" and not service1=="spotify" and not service2=="google" and not service2=="spotify":
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
    validServices = ['google','spotify']
    conn = database()
    cur = conn.cursor()
    if existingService==toLinkService:
        return "Error"
    if not existingService in validServices or not toLinkService in validServices:
        return "Error"
    cur.execute(f"select {toLinkService} from users where {existingService}='{existingID}';")
    results = cur.fetchall()
    try:
        assert results[0][0]
        return "Error"
    except:
        cur.execute(f"select {existingService} from users where {toLinkService}='{toLinkID}';")
    results = cur.fetchall()
    try:
        assert results[0][0]
        return "Error"
    except:
        cur.execute(f"select id from users where {existingService}='{existingID}';")
    ID = cur.fetchall()[0][0]
    cur.execute(f"update users set {toLinkService}='{toLinkID}' where id={ID};")
    conn.commit()
    conn.close()
    session['id']=ID
    return redirect(f'/tokenAuth?redir={redir}')

if __name__=='__main__':
    app.run()
