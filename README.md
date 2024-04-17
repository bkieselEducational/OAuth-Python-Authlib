[<-- BACK](https://github.com/bkieselEducational/OAuth-SDKs)

# OAuth-Python-Authlib

## Incorporating an OAuth 1.0A flow in your python application:

### Step 1: Register your application with the OAuth Provider and obtain an oauth_consumer_key and oauth_consumer_secret. Unlike OAuth 2.0, no need to register a redirect_uri!

### Step 2: Add the requisite packages to your requirements.txt file

```python
# Here are the additional packages that will allow us to implement an Oauth flow
# You can paste the code below to the bottom of your requirements.txt

authlib==1.3.0
requests==2.31.0
```

### Step 3: You will need to adjust your User model to allow for NULL passwords.

```python
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    if environment == "production":
        __table_args__ = {'schema': SCHEMA}
    ...
    ...
    hashed_password = db.Column(db.String(255), nullable=True, default=None)
    ...
    ...
```

### Step 4: Choose a file to house the 2 necessary endpoints to implement an OAuth flow. 

```python
# Add the necessary imports to the top of your route file!

# OAUTH 1.0A Setup #######################################
import os
from authlib.integrations.requests_client import OAuth1Session
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

EVERNOTE_CONSUMER_KEY = os.getenv('EVERNOTE_CONSUMER_KEY')
EVERNOTE_CONSUMER_SECRET = os.getenv('EVERNOTE_CONSUMER_SECRET')
EVERNOTE_OAUTH_TEMP_URL = os.getenv('EVERNOTE_OAUTH_TEMP_URL')
EVERNOTE_OAUTH_CALLBACK = 'http://localhost:8000/api/auth/oauth/evernote/callback' # Essentially our redirect_uri
EVERNOTE_USER_AUTHORIZATION_ENDPOINT = os.getenv('EVERNOTE_USER_AUTHORIZATION_ENDPOINT')

oauth_client = OAuth1Session(EVERNOTE_CONSUMER_KEY, EVERNOTE_CONSUMER_SECRET)
oauth_client.redirect_uri = EVERNOTE_OAUTH_CALLBACK

# END OAUTH 1.0A Setup ###################################
```


```python
# Our OAuth flow initiating endpoint.

@auth_routes.route('/oauth/evernote/init', methods=['GET'])
def oauth_evernote_set_state():
    # We shall save the value in the Referer Header for use later with the final redirect
    session['referrer'] = request.headers.get('Referer')
    # First, we must request a temporary token that we can
    token_response = oauth_client.fetch_request_token(EVERNOTE_OAUTH_TEMP_URL)

    if token_response['oauth_callback_confirmed'] != 'true':
        return { 'errors': { 'http': { 'code': 400, 'name': 'Bad Request', 'description': 'Evernote cannot verify the callback URI' } } }, 400

    # We must save the token and token_secret in the client so that we can access these values in the callback!
    oauth_client.token = token_response
    oauth_client.token_secret = token_response['oauth_token_secret']

    # Note that the redirect() method ESCAPES our parameters for us!!
    return redirect(EVERNOTE_USER_AUTHORIZATION_ENDPOINT + '?' + 'oauth_token=' + token_response['oauth_token'], 302)
```

```python
# The famous redirect_uri is our 2nd endpoint.

@auth_routes.route('/oauth/evernote/callback', methods=['GET'])
def oauth_evernote_callback():
    '''
    We expect the query parameters below to be returned:
        - oauth_token
        - oauth_verifier
        - sandbox_lnb
    '''
    # The OAuth API returns the oauth_verifier in the request to the redirect_uri to confirm that the user whom authorized the app is the user completing the flow.
    oauth_verifier = request.args.get('oauth_verifier')

    if oauth_verifier == None:
        return { 'errors': { 'http': { 'code': 400, 'name': 'Bad Request', 'description': 'Evernote user authorization failed' } } }, 400

    # Fetch the Access Token (if Needed)
    access_token = oauth_client.fetch_access_token(EVERNOTE_OAUTH_TEMP_URL, oauth_verifier)

    """
    This is where things may get tricky. As OAuth 1.0A does not have OpenID Connect functionality, there is no telling what information you will be able to obtain
    about the user that has just logged in. This will likely be vendor specific. In the case of Evernote, you will NOT get an email!! We will demonstrate using the
    Evernote edam_userID, but your application may handle the user in a very different way.
    """
    en_user_id = access_token['edam_userId']

    user_exists = User.query.filter(User.edam_userId == en_user_id).first()

    if not user_exists:
        user_exists = User(
            username=f'anonymous-{en_user_id}',
            edam_userId=en_user_id
        )

        db.session.add(user_exists)
        db.session.commit()

    login_user(user_exists)

    return redirect(session['referrer']) # This will send the final redirect to our user's browser. As depicted in Line 8 of the flow chart!

```

### Step 5: We will need to install a link in our frontend code to allow our user to initiate the flow.
```javascript
  <a href={`${window.origin}/api/auth/oauth/evernote/init`}><button>OAUTH</button></a>
```
