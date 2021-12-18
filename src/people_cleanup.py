#!/bin/#!/usr/bin/env python3

import os
import sys
import uuid
import logging
import coloredlogs
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from urllib.parse import urlparse, quote

from webexteamssdk import WebexTeamsAPI, ApiError, AccessToken
webex_api = WebexTeamsAPI(access_token="12345")

import json, requests
from datetime import datetime, timedelta, timezone
import time
from flask import Flask, request, redirect, url_for, make_response

import re
import base64

import concurrent.futures
import signal

flask_app = Flask(__name__)
flask_app.config["DEBUG"] = True
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)7s]  [%(module)s.%(name)s.%(funcName)s]:%(lineno)s %(message)s",
    handlers=[
        logging.FileHandler("/log/debug.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
coloredlogs.install(
    level=os.getenv("LOG_LEVEL", "INFO"),
    fmt="%(asctime)s  [%(levelname)7s]  [%(module)s.%(name)s.%(funcName)s]:%(lineno)s %(message)s",
    logger=logger
)

ADMIN_SCOPE = ["audit:events_read"]

TEAMS_COMPLIANCE_SCOPE = ["spark-compliance:events_read",
    "spark-compliance:memberships_read", "spark-compliance:memberships_write",
    "spark-compliance:messages_read", "spark-compliance:messages_write",
    "spark-compliance:rooms_read", "spark-compliance:rooms_write",
    "spark-compliance:team_memberships_read", "spark-compliance:team_memberships_write",
    "spark-compliance:teams_read",
    "spark:people_read"] # "spark:rooms_read", "spark:kms"
    
TEAMS_COMPLIANCE_READ_SCOPE = ["spark-compliance:events_read",
    "spark-compliance:memberships_read",
    "spark-compliance:messages_read",
    "spark-compliance:rooms_read",
    "spark-compliance:team_memberships_read",
    "spark-compliance:teams_read",
    "spark:people_read"]
    
PEOPLE_ADMIN_SCOPE = [
    "spark-admin:people_read",
    "spark-admin:people_write"
]

MEETINGS_COMPLIANCE_SCOPE = ["spark-compliance:meetings_write"]

DEFAULT_SCOPE = ["spark:kms"]

STATE_CHECK = "webex is great" # integrity test phrase
EVENT_CHECK_INTERVAL = 15 # seconds
EVENT_CHECK_DELAY = 0 # seconds, set the check interval window back in time to allow the event to be stored in Webex
SAFE_TOKEN_DELTA = 3600 # safety seconds before access token expires - renew if smaller

TIMESTAMP_KEY = "LAST_CHECK"

STORAGE_PATH = "/token_storage/data/"
WEBEX_TOKEN_FILE = "webex_tokens_{}.json"
TIMESTAMP_FILE = "timestamp_{}.json"

MAX_PEOPLE_ONCE = 2

def sigterm_handler(_signo, _stack_frame):
    "When sysvinit sends the TERM signal, cleanup before exiting."

    logger.info("Received signal {}, exiting...".format(_signo))
    
    thread_executor._threads.clear()
    concurrent.futures.thread._threads_queues.clear()
    sys.exit(0)

signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)

thread_executor = concurrent.futures.ThreadPoolExecutor()
wxt_username = "PEOPLE_CLEANUP"
wxt_token_key = "PEOPLE_CLEANUP"
token_refreshed = False

options = {
}

# statistics
statistics = {
    "started": datetime.utcnow(),
    "people": 0,
    "max_time": 0,
    "max_time_at": datetime.now()
}

class AccessTokenAbs(AccessToken):
    """
    Store Access Token with a real timestamp.
    
    Access Tokens are generated with 'expires-in' information. In order to store them
    it's better to have a real expiration date and time. Timestamps are saved in UTC.
    Note that Refresh Token expiration is not important. As long as it's being used
    to generate new Access Tokens, its validity is extended even beyond the original expiration date.
    
    Attributes:
        expires_at (float): When the access token expires
        refresh_token_expires_at (float): When the refresh token expires.
    """
    def __init__(self, access_token_json):
        super().__init__(access_token_json)
        if not "expires_at" in self._json_data.keys():
            self._json_data["expires_at"] = str((datetime.now(timezone.utc) + timedelta(seconds = self.expires_in)).timestamp())
        logger.debug("Access Token expires in: {}s, at: {}".format(self.expires_in, self.expires_at))
        if not "refresh_token_expires_at" in self._json_data.keys():
            self._json_data["refresh_token_expires_at"] = str((datetime.now(timezone.utc) + timedelta(seconds = self.refresh_token_expires_in)).timestamp())
        logger.debug("Refresh Token expires in: {}s, at: {}".format(self.refresh_token_expires_in, self.refresh_token_expires_at))
        
    @property
    def expires_at(self):
        return self._json_data["expires_at"]
        
    @property
    def refresh_token_expires_at(self):
        return self._json_data["refresh_token_expires_at"]

def save_tokens(token_key, tokens):
    """
    Save tokens.
    
    Parameters:
        tokens (AccessTokenAbs): Access & Refresh Token object
    """
    global token_refreshed
    
    logger.debug("AT timestamp: {}".format(tokens.expires_at))
    token_record = {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at,
        "refresh_token_expires_at": tokens.refresh_token_expires_at
    }
    file_destination = get_webex_token_file(token_key)
    with open(file_destination, "w") as file:
        logger.debug("Saving Webex tokens to: {}".format(file_destination))
        json.dump(token_record, file)
    
    token_refreshed = True # indicate to the main loop that the Webex token has been refreshed
    
def get_webex_token_file(token_key):
    return STORAGE_PATH + WEBEX_TOKEN_FILE.format(token_key)
    
def get_tokens_for_key(token_key):
    """
    Load tokens.
    
    Parameters:
        token_key (str): A key to the storage of the token
        
    Returns:
        AccessTokenAbs: Access & Refresh Token object or None
    """
    try:
        file_source = get_webex_token_file(token_key)
        with open(file_source, "r") as file:
            logger.debug("Loading Webex tokens from: {}".format(file_source))
            token_data = json.load(file)
            tokens = AccessTokenAbs(token_data)
            return tokens
    except Exception as e:
        logger.info("Webex token load exception: {}".format(e))
        return None

def refresh_tokens_for_key(token_key):
    """
    Run the Webex 'get new token by using refresh token' operation.
    
    Get new Access Token. Note that the expiration of the Refresh Token is automatically
    extended no matter if it's indicated. So if this operation is run regularly within
    the time limits of the Refresh Token (typically 3 months), the Refresh Token never expires.
    
    Parameters:
        token_key (str): A key to the storage of the token
        
    Returns:
        str: message indicating the result of the operation
    """
    tokens = get_tokens_for_key(token_key)
    client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
    client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
    integration_api = WebexTeamsAPI(access_token="12345")
    try:
        new_tokens = AccessTokenAbs(integration_api.access_tokens.refresh(client_id, client_secret, tokens.refresh_token).json_data)
        save_tokens(token_key, new_tokens)
        logger.info("Tokens refreshed for key {}".format(token_key))
    except ApiError as e:
        logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error refreshing an access token. Client Id and Secret loading error: {}".format(e)
        
    return "Tokens refreshed for {}".format(token_key)

def save_timestamp(timestamp_key, timestamp):
    """
    Save a timestamp.
    
    Parameters:
        timestamp_key (str): storage key for the timestamp
        timestamp (float): datetime timestamp
    """
    timestamp_destination = get_timestamp_file(timestamp_key)
    logger.debug("Saving timestamp to {}".format(timestamp_destination))
    with open(timestamp_destination, "w") as file:
        json.dump({"timestamp": timestamp}, file)
    
def load_timestamp(timestamp_key):
    """
    Save a timestamp.
    
    Parameters:
        timestamp_key (str): storage key for the timestamp
        
    Returns:
        float: timestamp for datetime
    """
    timestamp_source = get_timestamp_file(timestamp_key)
    logger.debug("Loading timestamp from {}".format(timestamp_source))
    try:
        with open(timestamp_source, "r") as file:
            ts = json.load(file)
            return float(ts.get("timestamp"))
    except Exception as e:
        logger.info("Timestamp load exception: {}".format(e))
        return None
            
def get_timestamp_file(timestamp_key):
    return STORAGE_PATH + TIMESTAMP_FILE.format(timestamp_key)
    
def load_config(options):
    """
    Load the configuration file.
    
    Returns:
        dict: configuration file JSON
    """
    with open("/config/config.json") as file:
        config = json.load(file)
    
    opt = config.get("options", {})
    for key, value in opt.items():
        options[key] = value
    return config
    
def secure_scheme(scheme):
    return re.sub(r"^http$", "https", scheme)

# Flask part of the code

"""
1. initialize database table if needed
2. start event checking thread
"""
@flask_app.before_first_request
def startup():
    logger.debug("Starting event check...")
    # check_events(EVENT_CHECK_INTERVAL, wxt_compliance, wxt_admin_audit, wxt_resource, wxt_type, wxt_actor_email)
    thread_executor.submit(check_events, EVENT_CHECK_INTERVAL)

@flask_app.route("/")
def hello():
    response = make_response(format_event_stats(), 200)
    response.mimetype = "text/plain"
    return response

"""
OAuth proccess done
"""
@flask_app.route("/authdone", methods=["GET"])
def authdone():
    ## TODO: post the information & help, maybe an event creation form to the 1-1 space with the user
    return "Thank you for providing the authorization. You may close this browser window."

"""
OAuth grant flow start
"""
@flask_app.route("/authorize", methods=["GET"])
def authorize():
    myUrlParts = urlparse(request.url)
    full_redirect_uri = os.getenv("REDIRECT_URI")
    if full_redirect_uri is None:
        full_redirect_uri = myUrlParts.scheme + "://" + myUrlParts.netloc + url_for("manager")
    logger.info("Authorize redirect URL: {}".format(full_redirect_uri))

    client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
    redirect_uri = quote(full_redirect_uri, safe="")
    scope = PEOPLE_ADMIN_SCOPE + DEFAULT_SCOPE
    scope_uri = quote(" ".join(scope), safe="")
    join_url = webex_api.base_url+"authorize?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}".format(client_id, redirect_uri, scope_uri, STATE_CHECK)

    return redirect(join_url)
    
"""
OAuth grant flow redirect url
generate access and refresh tokens using "code" generated in OAuth grant flow
after user successfully authenticated to Webex

See: https://developer.webex.com/blog/real-world-walkthrough-of-building-an-oauth-webex-integration
https://developer.webex.com/docs/integrations
"""   
@flask_app.route("/manager", methods=["GET"])
def manager():
    global wxt_username
    
    if request.args.get("error"):
        return request.args.get("error_description")
        
    input_code = request.args.get("code")
    check_phrase = request.args.get("state")
    logger.debug("Authorization request \"state\": {}, code: {}".format(check_phrase, input_code))

    myUrlParts = urlparse(request.url)
    full_redirect_uri = os.getenv("REDIRECT_URI")
    if full_redirect_uri is None:
        full_redirect_uri = myUrlParts.scheme + "://" + myUrlParts.netloc + url_for("manager")
    logger.debug("Manager redirect URI: {}".format(full_redirect_uri))
    
    try:
        client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
        client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
        tokens = AccessTokenAbs(webex_api.access_tokens.get(client_id, client_secret, input_code, full_redirect_uri).json_data)
        logger.debug("Access info: {}".format(tokens))
    except ApiError as e:
        logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error issuing an access token. Client Id and Secret loading error: {}".format(e)
        
    webex_integration_api = WebexTeamsAPI(access_token=tokens.access_token)
    try:
        user_info = webex_integration_api.people.me()
        logger.debug("Got user info: {}".format(user_info))
        wxt_username = user_info.emails[0]
        save_tokens(wxt_token_key, tokens)
        
        ## TODO: add periodic access token refresh
    except ApiError as e:
        logger.error("Error getting user information: {}".format(e))
        return "Error getting your user information: {}".format(e)
        
    return redirect(url_for("authdone"))
    
# TODO: manual query of events API
@flask_app.route("/queryevents", methods=["GET"])
def query_events():
    results = ""
    
    return results

"""
Check admin API thread. Infinite loop which periodically checks the Admin API.
Doesn't work until "wxt_username" runs through OAuth grant flow above.
Access token is automatically refreshed if needed using Refresh Token.
No additional user authentication is required.
"""
def check_events(check_interval=EVENT_CHECK_INTERVAL):
    global token_refreshed, options, statistics
    
    tokens = None
    wxt_client = None
            
    from_time = datetime.utcnow() - timedelta(seconds = EVENT_CHECK_DELAY)
        
    while True:
        try:
        # logger.debug("Check events tick.")

# check for token until there is one available in the DB        
            if tokens is None or token_refreshed:
                tokens = get_tokens_for_key(wxt_token_key)
                if tokens:
                    wxt_client = WebexTeamsAPI(access_token=tokens.access_token)

                    try:
                        user_info = wxt_client.people.me()
                        logger.debug("Got user info: {}".format(user_info))
                        wx_org_id = user_info.orgId
                    except ApiError as e:
                        logger.error("Me request error: {}".format(e))

                    token_refreshed = False
                else:
                    logger.error("No access tokens for key {}. Authorize the user first.".format(wxt_token_key))
                    
            if tokens:
        # renew access token using refresh token if needed
                # logger.info("tokens: {}".format(tokens))
                token_delta = datetime.fromtimestamp(float(tokens.expires_at)) - datetime.utcnow()
                if token_delta.total_seconds() < SAFE_TOKEN_DELTA:
                    logger.info("Access token is about to expire, renewing...")
                    refresh_tokens_for_key(wxt_token_key)
                    tokens = get_tokens_for_key(wxt_token_key)
                    wxt_client = WebexTeamsAPI(access_token=tokens.access_token)
                    new_client = True

            to_time = datetime.utcnow() - timedelta(seconds = EVENT_CHECK_DELAY)
        # query the Admin API        
            if wxt_client:
                try:
                    from_stamp = from_time.isoformat(timespec="milliseconds")+"Z"
                    to_stamp = to_time.isoformat(timespec="milliseconds")+"Z"
                    logger.debug("check interval {} - {}".format(from_stamp, to_stamp))
                    config = load_config(options)
                    
                    # TODO: get people list, iterate through it
                    people_gen = wxt_client.people.list()
                    email_regex_list = config.get("email_regex")
                    logger.debug(f"email regex: {email_regex_list}")
                    match_people = []
                    for person in people_gen:
                        for match_regex in email_regex_list:
                            if re.match(match_regex, person.emails[0]):
                                match_people.append(person)
                                logger.debug(f"email match for {person.emails[0]}")
                                break
                    
                    if len(match_people) > options.get("max_delete", MAX_PEOPLE_ONCE):
                        send_bot_message("K vymazání je {} účtů. Proveďte to ručně.".format(len(match_people)))
                    elif len(match_people) > 0:
                        people_cleaned = []
                        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as event_executor:
                            for person in match_people:
                                event_executor.submit(handle_event, person, tokens.access_token, options, config, people_cleaned)
                        if len(people_cleaned) > 0:
                            send_report_message(people_cleaned)

                    logger.debug("event handling end at: {}".format(datetime.utcnow().isoformat(timespec="milliseconds")+"Z"))
                                        
                    from_time = to_time
                except ApiError as e:
                    logger.error("Admin audit API request error: {}".format(e))
                    
            # save timestamp
            save_timestamp(TIMESTAMP_KEY, to_time.timestamp())
            now_check = datetime.utcnow() - timedelta(seconds = EVENT_CHECK_DELAY)
            diff = (now_check - to_time).total_seconds()
            logger.info("event processing took {} seconds".format(diff))
            if diff > statistics["max_time"]:
                statistics["max_time"] = diff
                statistics["max_time_at"] = datetime.now()

            check_interval = options.get("check_interval", check_interval)
            if diff < check_interval:
                time.sleep(check_interval - int(diff))
            else:
                logger.error("EVENT PROCESSING IS TAKING TOO LONG ({}), PERFORMANCE IMPROVEMENT NEEDED".format(diff))
        except Exception as e:
            logger.error("check_events() loop exception: {}".format(e))
            time.sleep(check_interval)
        finally:
            pass
            
def handle_event(person, wxt_access_token, options, config, people_cleaned):
    """
    Handle Webex Admin API query result
    """
    try:
        save_event_stats(person)

        person_data = person.json_data
        
        logger.debug(f"About to delete account: {person.emails[0]}")
        try:
            wxt_client = WebexTeamsAPI(access_token = wxt_access_token)
            wxt_client.people.delete(person.id)
            people_cleaned.append(person.emails[0])
        except ApiError as e:
            logger.error("Admin API request error: {}".format(e))

    except Exception as e:
        logger.error("handle_event() exception: {}".format(e))
        
def save_event_stats(event):
    """
    Save statistics
    
    Saves statistics to a "statistics" singleton
    
    Parameters:
        event (Event): Event API response object
    """
    global statistics
    
    statistics["people"] += 1
    
def send_report_message(people_cleaned):
    report_msg = "Vymazané URI účty:  \n{}".format("  \n".join(people_cleaned))
    send_bot_message(report_msg)
        
def send_bot_message(msg):
    try:
        bot_client = WebexTeamsAPI(access_token = os.getenv("BOT_ACCESS_TOKEN"))
        memberships = bot_client.memberships.list()
        for mem in memberships:
            bot_client.messages.create(roomId = mem.roomId, markdown = msg)
    except ApiError as e:
        logger.error("BOT API error: {}".format(e))
    
def format_event_stats():
    """
    Format event statistics for print
    
    Returns:
        str: formatted statistics
    """
    global statistics
    
    start_time = "{:%Y-%m-%d %H:%M:%S GMT}".format(statistics["started"])
    max_timestamp = "{:%Y-%m-%d %H:%M:%S}".format(statistics["max_time_at"])
    now = datetime.utcnow()
    time_diff = now - statistics["started"]
    hours, remainder = divmod(time_diff.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    diff_time = "{}d {:02d}:{:02d}:{:02d}".format(time_diff.days, int(hours), int(minutes), int(seconds))
    result = """Webex People Cleanup

Started: {}
Up: {}

Deleted users: {}
Maximum processing time: {:0.2f}s at {}
""".format(start_time, diff_time, statistics["people"], statistics["max_time"], max_timestamp)
    
    return result

"""
Independent thread startup, see:
https://networklore.com/start-task-with-flask/
"""
def start_runner():
    def start_loop():
        no_proxies = {
          "http": None,
          "https": None,
        }
        not_started = True
        while not_started:
            logger.info('In start loop')
            try:
                r = requests.get('https://127.0.0.1:5050/', proxies=no_proxies, verify=False)
                if r.status_code == 200:
                    logger.info('Server started, quiting start_loop')
                    not_started = False
                else:
                    logger.debug("Status code: {}".format(r.status_code))
            except Exception as e:
                logger.info(f'Server not yet started: {e}')
            time.sleep(2)

    logger.info('Started runner')
    thread_executor.submit(start_loop)


if __name__ == "__main__":
    import argparse
    
    # default_user = os.getenv("COMPLIANCE_USER")
    # if default_user is None:
    #     default_user = os.getenv("COMPLIANCE_USER_DEFAULT")
    #     if default_user is None:
    #         default_user = "COMPLIANCE"
    # 
    # logger.info("Compliance user from env variables: {}".format(default_user))

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='count', help="Set logging level by number of -v's, -v=WARN, -vv=INFO, -vvv=DEBUG")
    
    args = parser.parse_args()
    if args.verbose:
        if args.verbose > 2:
            logging.basicConfig(level=logging.DEBUG)
        elif args.verbose > 1:
            logging.basicConfig(level=logging.INFO)
        if args.verbose > 0:
            logging.basicConfig(level=logging.WARN)
            
    logger.info("Logging level: {}".format(logging.getLogger(__name__).getEffectiveLevel()))
    
    config = load_config(options)

    logger.info("OPTIONS: {}".format(options))
    logger.info("CONFIG: {}".format(config))

    start_runner()
    flask_app.run(host="0.0.0.0", port=5050, ssl_context='adhoc')
