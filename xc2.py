#!/usr/bin/env python3

import argparse
import json
from json import JSONDecodeError
import os
import sys
import time
from dotenv import load_dotenv
import requests


# A more comprehensive description of the requests: https://golfed.xyz/posts/automating-x-without-an-api-access
# TODO: solver for Arkose Labs CAPTCHAs: https://www.arkoselabs.com/arkose-matchkey/

LOGIN_ENDPOINT = "https://api.twitter.com/1.1/onboarding/task.json?flow_name=login"
ACTIVATION_ENDPOINT = "https://api.twitter.com/1.1/guest/activate.json"
SUBTASK_ENDPOINT = "https://api.twitter.com/1.1/onboarding/task.json"
VIEWER_ENDPOINT = "https://twitter.com/i/api/graphql/93NdfGgZRSyQ-6rmHPgdNg/Viewer"
POST_ENDPOINT = "https://twitter.com/i/api/graphql/SoVnbfCycZ7fERGCwpZkYA/CreateTweet"
LIKE_ENDPOINT = "https://twitter.com/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet"
REPOST_ENDPOINT = "https://twitter.com/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet"
DELETE_ENDPOINT = "https://twitter.com/i/api/graphql/VaenaVgh5q5ih7kvyVjgtg/DeleteTweet"
USER_ENDPOINT = "https://twitter.com/i/api/graphql/_pnlqeTOtnpbIL9o-fS_pg/ProfileSpotlightsQuery"
CLAIMS_ENDPOINT = "https://twitter.com/i/api/graphql/lFi3xnx0auUUnyG4YwpCNw/GetUserClaims"
FOLLOW_ENDPOINT = "https://twitter.com/i/api/1.1/friendships/create.json"
UNFOLLOW_ENDPOINT = "https://twitter.com/i/api/1.1/friendships/destroy.json"
UPLOAD_ENDPOINT = "https://upload.twitter.com/1.1/media/upload.json"

AGENT = {
    "authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Gecko/20190101 Chrome/73.0.3683.103 Safari/537.36",
    "referer": "https://twitter.com/sw.js",
    "content-type": "application/json",
    "accept": "application/json",
}

STORE_PATH_PREFIX = "./data/"


def main():
    restored = try_restore()

    if restored is None:
        print("[+] No valid session found, creating new one...")
        session = requests.Session()
        headers = auth(session)
    else:
        print("[+] Restored valid session from the disk")
        session, headers = restored

    if args.post is not None:
        media_id = upload(session, headers, args.media) if args.media is not None else None
        post(session, headers, media_id)

    if args.like is not None:
        like(session, headers, args.like)
    if args.repost is not None:
        repost(session, headers, args.repost)
    if args.delete is not None:
        delete(session, headers, args.delete)
    if args.follow is not None:
        follow(session, headers, args.follow)
    if args.unfollow is not None:
        unfollow(session, headers, args.unfollow)


def parse_args():
    parser = argparse.ArgumentParser(description="X client without consumer keys and secrets")
    parser.add_argument("-p", "--post", default=None, help="create a new post with a text")
    parser.add_argument("-m", "--media", default=None, help="path to the media attached to a post (requires --post)")
    parser.add_argument("-l", "--like", default=None, help="like a post with a post ID")
    parser.add_argument("-r", "--repost", default=None, help="repost a post with a post ID")
    parser.add_argument("-d", "--delete", default=None, help="delete an existing post with a post ID")
    parser.add_argument("-f", "--follow", default=None, help="follow a user with a screen name")
    parser.add_argument("-u", "--unfollow", default=None, help="unfollow a user with a screen name")

    return parser.parse_args()


def auth(session):
    """
    Authenticates a session with Twitter and returns headers for further requests.

    :param requests.Session() session: session to use

    :returns:
        - headers (dict) - headers to use
    """
    print("[+] Authenticating...")

    guest_token = guest(session)
    headers, flow_token = flow(session, guest_token)
    subtask_res = subtasks(session, headers, flow_token)

    print(f"[+] Authenticated as '{subtask_res['subtasks'][0]['open_account']['user']['screen_name']}'")

    ct0(session, headers)
    persist(session, headers)

    return headers


def guest(session):
    """
    Fetches a guest token from `/guest/activate.json` and returns it.

    :param requests.Session() session: session to use

    :returns:
        - guest_token (str) - guest token to use
    """
    res = session.post(ACTIVATION_ENDPOINT, headers=AGENT, timeout=3)
    guest_token = res.json()["guest_token"]

    return guest_token


def flow(session, guest_token):
    """
    Fetches a flow token from `/onboarding/task.json?flow_name=login` and returns it.

    :param requests.Session() session: session to use
    :param str guest_token: guest token to use

    :returns:
        - headers (dict) - headers to use
        - flow_token (str) - flow token to use
    """
    headers = AGENT | {"x-guest-token": guest_token}
    res = session.post(LOGIN_ENDPOINT, headers=headers, timeout=3)
    flow_token = res.json()["flow_token"]

    return headers, flow_token


def subtasks(session, headers, flow_token):
    """
    Performs subtasks in `/onboarding/task.json` and returns the responses.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str flow_token: flow token to use

    :returns:
        - res_json (dict) - response from the last subtask
    """
    credentials = {
        "email": os.getenv("EMAIL"),
        "password": os.getenv("PASSWORD"),
        "alt_identifier": os.getenv("ALTERNATE_ID"),
    }

    if any(v is None for v in credentials.values()):
        print("[-] Missing credentials")
        sys.exit(1)

    subtasks = {
        "LoginJsInstrumentationSubtask": {
            "js_instrumentation": {
                "link": "next_link",
                "response": '{"rf":{"ab8e89b3ae0d58ea1a1513ee59d7740ede65ac3398422167734dd9324a5fc755":-226,"a54c70d9927a36ae9d89b2f9195e028937f80894c19146fd36940f7a7ccbff40":-97,"f0cb2da814518d2fe69debdcabbcb89e23f892e9bc3de3f0e96f38b8b019ce23":-68,"a79d69e899073b51513008cda84efc7dac995fdac92142e8c7e6787f82eee596":-37},"s":"P1OudzcHlw9YXoO43BVSvBXNyOGi38NDrDngXhvg_AHoGyY7P2Hcfa3b8aqODDXvJXkhgyLH7AOVyz90ZD5814DnWIU34j0QqRpufhReTj5shdDxPQQGX60BFjv-84HPalsrkflALpb0TFlZEfPtHRaPEIZVUB19egSlKbIviXdUY02QJzXDK807PK1qCNYdjrBSA-QEIVw38ahxukfO8BsGfNBikhkhI1HtnUhefTrfpVYjBHNBVjCGlpDv-EQXWBQV7L1Muu1tiIljSVfUkOUfFBZr0J1AqZImNDyhZNYSvKDYgbthM1VWTzZYZYfdHso87QGVQEugph93cGgI9QAAAYnv721O"}',
            }
        },
        "LoginEnterUserIdentifierSSO": {
            "settings_list": {
                "link": "next_link",
                "setting_responses": [
                    {"key": "user_identifier", "response_data": {"text_data": {"result": credentials["email"]}}}
                ],
            }
        },
        "LoginEnterAlternateIdentifierSubtask": {
            "enter_text": {"link": "next_link", "text": credentials["alt_identifier"]},
        },
        "LoginEnterPassword": {"enter_password": {"link": "next_link", "password": credentials["password"]}},
        "AccountDuplicationCheck": {"check_logged_in_account": {"link": "AccountDuplicationCheck_false"}},
    }
    next_task = list(subtasks.keys())[0]

    for name, items in subtasks.items():
        if name != next_task:
            # Skip over LoginEnterAlternateIdentifierSubtask
            continue

        print(f"\t[+] Performing subtask '{name}'")

        payload = {"flow_token": flow_token, "subtask_inputs": [{**items, "subtask_id": name}]}
        res = session.post(SUBTASK_ENDPOINT, headers=headers, json=payload, timeout=3)
        res_json = res.json()

        try:
            if "error" in res_json:
                print(f"[-] Error occurred while performing subtask '{name}':\n{res['error']}")
                sys.exit(1)
            else:
                next_task = res_json["subtasks"][0]["subtask_id"]

            if name != "AccountDuplicationCheck":
                flow_token = res_json["flow_token"]

        except KeyError:
            print(f"[-] KeyError parsing response:\n{res_json}")
            sys.exit(1)

    return res_json


def ct0(session, headers):
    """
    Fetches ct0 cookie from `/i/api/graphql/93NdfGgZRSyQ-6rmHPgdNg/Viewer` and updates headers with it.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    """
    _res = session.get(VIEWER_ENDPOINT, headers=headers, timeout=3)
    headers["x-csrf-token"] = session.cookies.get_dict()["ct0"]


def post(session, headers, media_id):
    """
    Creates a new post with a text and an optional media attachment in `/i/api/graphql/SoVnbfCycZ7fERGCwpZkYA/CreateTweet`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str media_id: media ID to attach to a post
    """
    req_body = {
        "features": {
            "freedom_of_speech_not_reach_fetch_enabled": True,
            "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
            "longform_notetweets_consumption_enabled": True,
            "longform_notetweets_inline_media_enabled": True,
            "longform_notetweets_rich_text_read_enabled": True,
            "responsive_web_edit_tweet_api_enabled": True,
            "responsive_web_enhance_cards_enabled": False,
            "responsive_web_graphql_exclude_directive_enabled": True,
            "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
            "responsive_web_graphql_timeline_navigation_enabled": True,
            "responsive_web_media_download_video_enabled": False,
            "responsive_web_twitter_article_tweet_consumption_enabled": False,
            "standardized_nudges_misinfo": True,
            "tweet_awards_web_tipping_enabled": False,
            "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
            "tweetypie_unmention_optimization_enabled": False,
            "verified_phone_label_enabled": False,
            "view_counts_everywhere_api_enabled": True,
            "creator_subscriptions_tweet_preview_api_enabled": False,
        },
        "queryId": "SoVnbfCycZ7fERGCwpZkYA",
        "variables": {
            "dark_request": False,
            "media": {"media_entities": [], "possibly_sensitive": False},
            "semantic_annotation_ids": [],
            "tweet_text": args.post,
        },
    }

    if media_id is not None:
        req_body["variables"]["media"]["media_entities"].append({"media_id": media_id, "tagged_users": []})

    res = session.post(POST_ENDPOINT, headers=headers, json=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while creating post:\n{res.text}")
        sys.exit(1)

    print(f"[+] Created post '{res.json()['data']['create_tweet']['tweet_results']['result']['rest_id']}'")


def upload(session, headers, path):
    """
    Uploads a media file to `/1.1/media/upload.json`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str path: path to the media file

    :returns:
        - media_id (str) - media ID
    """
    print(f"[+] Uploading file '{path}'")

    media_id, total_bytes = initialize_upload(session, headers, path)
    append_upload(session, media_id, path, total_bytes)
    finalize_upload(session, headers, media_id)

    return media_id


def initialize_upload(session, headers, path):
    """
    Initializes upload of a media file to `/1.1/media/upload.json`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str path: path to the media file

    :returns:
        - media_id (str) - media ID
    """
    total_bytes = os.path.getsize(path)
    ext = path.split(".")[-1]
    media_type, category = (
        ("image", "tweet_image") if ext in ["jpg", "jpeg", "png", "webp"] else ("video", "tweet_video")
    )
    req_body = {
        "command": "INIT",
        "media_type": f"{media_type}/{ext}",
        "total_bytes": total_bytes,
        "media_category": category,
    }
    res = session.post(UPLOAD_ENDPOINT, headers=headers, params=req_body, timeout=3)

    media_id = res.json()["media_id_string"]

    if not res.ok:
        print(f"[-] Error occurred while initializing upload:\n{res.text}")
        sys.exit(1)

    return media_id, total_bytes


def append_upload(session, media_id, path, total_bytes):
    """
    Uploads a media file to `/1.1/media/upload.json`.

    :param requests.Session() session: session to use
    :param str media_id: media ID to append to
    :param str path: path to the media file
    :param int total_bytes: total bytes of the media file
    """
    sent = 0
    seg_id = 0

    with open(path, "rb") as f:
        while sent < total_bytes:
            chunk = f.read(4 * 1024 * 1024)
            req_data = {"command": "APPEND", "media_id": media_id, "segment_index": seg_id}
            files = {"media": chunk}
            res = session.post(url=UPLOAD_ENDPOINT, params=req_data, files=files)

            if not res.ok:
                print(f"[-] Error occurred while uploading: {res.text}")
                sys.exit(1)

            sent += chunk.__sizeof__()
            seg_id += 1

            print(f"\t[+] {sent}/{total_bytes} bytes uploaded...")


def finalize_upload(session, headers, media_id):
    """
    Finalizes upload of a media file to `/1.1/media/upload.json`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str media_id: media ID to finalize
    """
    req_body = {"command": "FINALIZE", "media_id": media_id}
    res = session.post(UPLOAD_ENDPOINT, headers=headers, params=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while finalizing upload:\n{res.text}")
        sys.exit(1)

    if "processing_info" in res.json():
        upload_status(session, headers, media_id)
    else:
        print(f"[+] '{media_id}' uploaded successfully and is ready to be used as post attachment")


def upload_status(session, headers, media_id):
    """
    Polls upload status of a media file to `/1.1/media/upload.json` until the file is fully processed.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str media_id: media ID to check status for
    """
    while True:
        print(f"\t[+] Checking uploaded media '{media_id}' status... ", end="")

        req_body = {"command": "STATUS", "media_id": media_id}
        res = session.post(UPLOAD_ENDPOINT, headers=headers, params=req_body, timeout=3)

        status = res.json()["processing_info"]["state"]

        if status == "succeeded":
            print("Done!")
            print(f"[+] '{media_id}' uploaded successfully and is ready to be used as post attachment")

            break

        print("Processing")
        time.sleep(2)


def like(session, headers, post_id):
    """
    Likes an existing post in `/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str post_id: post ID to like
    """
    req_body = {"queryId": "lI07N6Otwv1PhnEgXILM7A", "variables": {"tweet_id": post_id}}
    res = session.post(LIKE_ENDPOINT, headers=headers, json=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while liking post:\n{res.text}")
        sys.exit(1)

    print(f"[+] Liked post '{post_id}'")


def repost(session, headers, post_id):
    """
    Reposts an existing post in `/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str post_id: post ID to repost
    """
    req_body = {"queryId": "ojPdsZsimiJrUGLR1sjUtA", "variables": {"dark_request": False, "tweet_id": post_id}}
    res = session.post(REPOST_ENDPOINT, headers=headers, json=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while reposting post:\n{res.text}")
        sys.exit(1)

    repost_full_text = res.json()["data"]["create_retweet"]["retweet_results"]["result"]["legacy"]["full_text"]
    repost_post_id = res.json()["data"]["create_retweet"]["retweet_results"]["result"]["rest_id"]
    print(f"[+] Created repost with text '{repost_full_text}' and ID '{repost_post_id}'")


def delete(session, headers, post_id):
    """
    Deletes an existing post in `/i/api/graphql/VaenaVgh5q5ih7kvyVjgtg/DeleteTweet`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str post_id: post ID to delete
    """
    req_body = {"queryId": "VaenaVgh5q5ih7kvyVjgtg", "variables": {"dark_request": False, "tweet_id": post_id}}
    res = session.post(DELETE_ENDPOINT, headers=headers, json=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while deleting post:\n{res.text}")
        sys.exit(1)

    print(f"[+] Deleted post '{post_id}'")


def follow(session, headers, screen_name):
    """
    Follows a user in `/i/api/1.1/friendships/create.json`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str screen_name: screen name to follow
    """
    user_id = uid(session, headers, screen_name)
    req_body = {"user_id": user_id}
    res = session.post(FOLLOW_ENDPOINT, headers=headers, params=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while following user:\n{res.text}")
        sys.exit(1)

    print(f"[+] Followed user '{res.json()['screen_name']}'")


def unfollow(session, headers, screen_name):
    """
    Unfollows a user in `/i/api/1.1/friendships/destroy.json`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str screen_name: screen name to unfollow
    """
    user_id = uid(session, headers, screen_name)
    req_body = {"user_id": user_id}
    res = session.post(UNFOLLOW_ENDPOINT, headers=headers, params=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while unfollowing user:\n{res.text}")
        sys.exit(1)

    print(f"[+] Unfollowed user '{res.json()['screen_name']}'")


def uid(session, headers, screen_name):
    """
    Fetches a UID for a given screen name in `/i/api/graphql/_pnlqeTOtnpbIL9o-fS_pg/ProfileSpotlightsQuery`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    :param str screen_name: screen name to fetch UID for

    :returns:
        - str - UID for a given screen name
    """
    req_url = f"{USER_ENDPOINT}?variables=%7B%22screen_name%22%3A%22{screen_name}%22%7D"
    res = session.get(req_url, headers=headers, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while fetching a UID:\n{res.text}")
        sys.exit(1)

    try:
        user_id = res.json()["data"]["user_result_by_screen_name"]["result"]["rest_id"]
    except KeyError:
        print(f"[-] Did not find a matching UID for user '{screen_name}', instead got a response:\n{res.text}")
        sys.exit(1)

    print(f"[+] Found matching UID '{user_id}' for user '{screen_name}'")

    return user_id


def persist(session, headers):
    """
    Stores cookies and headers to `./data/` directory for peristence.

    :param requests.Session() session: session to use
    :param dict headers: headers to use
    """
    with open("./data/cookies.json", "w", encoding="utf-8") as f:
        json.dump(requests.utils.dict_from_cookiejar(session.cookies), f, indent=4)

    with open("./data/headers.json", "w", encoding="utf-8") as f:
        json.dump(headers, f, indent=4)

    print("[+] Stored cookies and headers to './data/'")


def try_restore():
    """
    Tries to restore a session from `./data/` directory.

    :returns:
        - session (requests.Session()) - None if session is not valid anymore
        - headers (dict) - None if session is not valid anymore
    """
    session = requests.Session()

    if os.path.isfile(f"{STORE_PATH_PREFIX}cookies.json") and os.path.isfile(f"{STORE_PATH_PREFIX}headers.json"):
        with open(f"{STORE_PATH_PREFIX}cookies.json", "r", encoding="utf-8") as f:
            cookies = requests.utils.cookiejar_from_dict(json.load(f))
            session.cookies.update(cookies)

        with open(f"{STORE_PATH_PREFIX}headers.json", "r", encoding="utf-8") as f:
            headers = json.load(f)

        if claims(session, headers):
            return session, headers

    return None


def claims(session, headers):
    """
    Checks whether restored session is still valid by fetching claims from `/i/api/graphql/lFi3xnx0auUUnyG4YwpCNw/GetUserClaims`.

    :param requests.Session() session: session to use
    :param dict headers: headers to use

    :returns:
        - bool - True if session is valid, False otherwise
    """
    res = session.get(CLAIMS_ENDPOINT, headers=headers, timeout=3)

    try:
        res.json()["data"]["viewer_v2"]["claims"]
    except JSONDecodeError:
        return False

    return True


if __name__ == "__main__":
    if not os.path.isfile(".env"):
        sys.exit("[-] Missing .env file with credentials")

    load_dotenv()
    args = parse_args()
    main()
