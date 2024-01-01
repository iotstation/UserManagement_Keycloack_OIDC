from flask import Flask, redirect, url_for, render_template, request , session 
from flask_oidc import OpenIDConnect
import requests
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = '12345678##'  # Update with your own secret key
app.debug = True  # Enable debug mode

app.config['OIDC_CLIENT_SECRETS'] = 'client_secrets.json'
app.config['OIDC_COOKIE_SECURE'] = False
app.config['OIDC_CALLBACK_ROUTE'] = '/oidc/callback'
app.config['OIDC_SCOPES'] = ['openid', 'email', 'profile']

oidc = OpenIDConnect(app)

@app.route('/')
@oidc.require_login
def index():

    # Check if the user is authenticated
    if oidc.user_loggedin:
        return render_template('index.html')
    else:
        return redirect(url_for('oidc.login'))



@app.route('/logout')
def logout():
    session.clear()
    logout_url = oidc.client_secrets['issuer'] + '/protocol/openid-connect/logout'  #####################  http://localhost:8080/realms/smart/protocol/openid-connect/logout
    return redirect(logout_url)


############################################# ADD User ###################################################
@app.route("/add")
def add():
    return render_template("add.html")
#################################################### ADD USER VIA Admin REST API ######################################
@app.route("/savedetails", methods=["POST"])
def saveDetails():
    data = request.form
    print(data['username'])
    print(data['firstName'])
    print(data['lastName'])
    print(data['email'])
    print(data['enabled'])

    # Keycloak token endpoint URL
    token_url = "http://localhost:8080/realms/smart/protocol/openid-connect/token"

    # Keycloak admin credentials
    admin_username = "iot"
    admin_password = "123456"

    # Obtain access token
    token_payload = {
        'client_id': 'fapp',
        'grant_type': 'client_credentials',
        'username': admin_username,
        'password': admin_password,
        'client_secret': 'Your Secret'
    }
    token_response = requests.post(token_url, data=token_payload)
    token_data = token_response.json()
    access_token = token_data.get('access_token')

    if access_token:
        # Keycloak admin API URL
        api_url = "http://localhost:8080/admin/realms/smart/users"

        # User data
        user_data = {
            "username": data['username'],
            "email": data['email'],
            "enabled": True,
            "firstName": data['firstName'],
            "lastName": data['lastName'],
            "emailVerified": False
        }

        # Send POST request to create user
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + access_token
        }
        response = requests.post(api_url, json=user_data, headers=headers)

        if response.status_code == 201:
            return "User created successfully!"

    return "Failed to create user."

if __name__ == '__main__':
    app.run()
