import os
import logging

import oauthlib
from flask import (
    Flask,
    render_template, request, redirect, url_for, session, current_app
)

from flask_dance.contrib.google import make_google_blueprint, google
# oauth
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError, TokenExpiredError
# os.environ
from dotenv import load_dotenv
import boto3
import botocore.exceptions

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
load_dotenv()

K_ENABLED = "ENABLED"
K_DISABLED = "DISABLED"
RULE_NAME = 'P19-021-dev'


def _empty_session():
    """
    Deletes the Google token and clears the session
    """
    if "google" in current_app.blueprints and hasattr(
            current_app.blueprints["google"], "token"
    ):
        del current_app.blueprints["google"].token
    session.clear()


def on_off(client, rule):
    # enable / disable
    xstate = get_state(client, rule)
    if xstate == K_ENABLED:
        # disable the rule
        logging.info(f"rule {rule} is enabled")
        try:
            response = client.disable_rule(Name=rule)

        except botocore.exceptions.ClientError as error:
            logging.info(f"Couldn't disable the event rule {rule}")
            raise

        else:
            logging.info(f"rule {rule} is now disabled")

    elif xstate == K_DISABLED:
        # enable the rule
        logging.info(f"rule {rule} is disabled")
        try:
            response = client.enable_rule(Name=rule)

        except botocore.exceptions.ClientError as error:
            logging.info(f"Couldn't enable the event rule {rule}")
            raise

        else:
            logging.info(f"rule {rule} is now enabled")

    else:
        logging.info("Error getting event rule's state")
        raise


def get_state(client, rule):
    # get state
    # source: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/events.html#EventBridge.Client.list_rules
    try:
        response = client.list_rules(NamePrefix=rule, Limit=1)

    except botocore.exceptions.ClientError as error:
        logging.info(f"Couldn't get event rule {rule} state")
        # raise
        return "NO_STATE"

    else:
        return response['Rules'][0]['State']


def create_client():
    events_client = boto3.client('events',
                                 aws_access_key_id=os.environ["AWS_KEY"],
                                 aws_secret_access_key=os.environ["AWS_SECRET"],
                                 region_name=os.environ["AWS_REGION"])
    return events_client


app = Flask(__name__)
app.config["SECRET_KEY"] = "qwertyasdfgh123#"

back_home = os.environ.get("BACK_HOME")
google_bp = make_google_blueprint(
    client_id=os.getenv("GOO_CLIENT"),
    client_secret=os.getenv("GOO_SHH"),
    scope=[
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
    redirect_to="landing_page",
)
open_gate = os.environ.get("OPEN_GATE")

app.register_blueprint(google_bp, url_prefix="/login")


@app.errorhandler(oauthlib.oauth2.rfc6749.errors.TokenExpiredError)
@app.errorhandler(oauthlib.oauth2.rfc6749.errors.InvalidClientIdError)
def token_expired(_):
    _empty_session()
    return redirect(url_for("landing_page"))


@app.route('/foo', methods=['GET', 'POST'])
def foo():
    if not google.authorized:
        return redirect(url_for("landing_page"))

    value = request.form.get('CloudwatchState')
    events_client = create_client()
    on_off(events_client, RULE_NAME)
    print("Value: " + value)
    # return render_template('index.html')
    return redirect(url_for("landing_page"))


@app.route('/', methods=["GET", "POST"])
def landing_page():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    assert resp.ok, resp.text
    email = resp.json()["email"]

    print(email)  # debug code, can be removed
    print(open_gate)  # debug code, can be removed

    if email in open_gate:
        events_client = create_client()
        state = get_state(events_client, RULE_NAME)
        print(state)  # debug code, can be removed
        return render_template('index.html', state=state, rule_name=RULE_NAME)

    return "<h1>Forbidden: Unauthorized Access</h1>", 403


if __name__ == '__main__':
    app.run()
