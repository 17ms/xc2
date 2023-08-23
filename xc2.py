#!/usr/bin/env python3

import argparse
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


def main():
    session = requests.Session()
    headers = auth(session)

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
    print("[+] Authenticating...")

    guest_token = guest(session)
    headers, flow_token = flow(session, guest_token)
    subtask_res = subtasks(session, headers, flow_token)

    print(f"[+] Authenticated as '{subtask_res['subtasks'][0]['open_account']['user']['screen_name']}'")

    ct0(session, headers)

    return headers


def guest(session):
    # Fetch guest token (/guest/activate.json)
    res = session.post(ACTIVATION_ENDPOINT, headers=AGENT, timeout=3)
    guest_token = res.json()["guest_token"]

    return guest_token


def flow(session, guest_token):
    # Fetch flow token (/onboarding/task.json?flow_name=login)
    headers = AGENT | {"x-guest-token": guest_token}
    res = session.post(LOGIN_ENDPOINT, headers=headers, timeout=3)
    flow_token = res.json()["flow_token"]

    return headers, flow_token


def subtasks(session, headers, flow_token):
    # Perform subtasks (/onboarding/task.json)
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
    # Fetch ct0 cookie (/i/api/graphql/93NdfGgZRSyQ-6rmHPgdNg/Viewer)
    _res = session.get(VIEWER_ENDPOINT, headers=headers, timeout=3)
    headers["x-csrf-token"] = session.cookies.get_dict()["ct0"]


def post(session, headers, media_id):
    # Create new post (/i/api/graphql/SoVnbfCycZ7fERGCwpZkYA/CreateTweet)
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
    # Upload media (/1.1/media/upload.json)
    print(f"[+] Uploading file '{path}'")

    media_id, total_bytes = initialize_upload(session, headers, path)
    append_upload(session, media_id, path, total_bytes)
    finalize_upload(session, headers, media_id)

    return media_id


def initialize_upload(session, headers, path):
    # Initialize upload and fetch media ID (/i/media/upload.json?command=INIT)
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
    # Upload media chunks (/i/media/upload.json?command=APPEND)
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
    # Finalize upload (/i/media/upload.json?command=FINALIZE)
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
    # Poll upload status (/i/media/upload.json?command=STATUS)
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
    # Like an existing post (/i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet)
    req_body = {"queryId": "lI07N6Otwv1PhnEgXILM7A", "variables": {"tweet_id": post_id}}
    res = session.post(LIKE_ENDPOINT, headers=headers, json=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while liking post:\n{res.text}")
        sys.exit(1)

    print(f"[+] Liked post '{post_id}'")


def repost(session, headers, post_id):
    # Repost a post (/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet)
    req_body = {"queryId": "ojPdsZsimiJrUGLR1sjUtA", "variables": {"dark_request": False, "tweet_id": post_id}}
    res = session.post(REPOST_ENDPOINT, headers=headers, json=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while reposting post:\n{res.text}")
        sys.exit(1)

    repost_full_text = res.json()["data"]["create_retweet"]["retweet_results"]["result"]["legacy"]["full_text"]
    repost_post_id = res.json()["data"]["create_retweet"]["retweet_results"]["result"]["rest_id"]
    print(f"[+] Created repost with text '{repost_full_text}' and ID '{repost_post_id}'")


def delete(session, headers, post_id):
    # Delete post (/i/api/graphql/VaenaVgh5q5ih7kvyVjgtg/DeleteTweet)
    req_body = {"queryId": "VaenaVgh5q5ih7kvyVjgtg", "variables": {"dark_request": False, "tweet_id": post_id}}
    res = session.post(DELETE_ENDPOINT, headers=headers, json=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while deleting post:\n{res.text}")
        sys.exit(1)

    print(f"[+] Deleted post '{post_id}'")


def follow(session, headers, screen_name):
    # Follow user (/i/api/1.1/friendships/create.json)
    user_id = uid(session, headers, screen_name)
    # req_url = f"{FOLLOW_ENDPOINT}?user_id={user_id}"
    # res = session.post(req_url, headers=headers, timeout=3)
    req_body = {"user_id": user_id}
    res = session.post(FOLLOW_ENDPOINT, headers=headers, params=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while following user:\n{res.text}")
        sys.exit(1)

    print(f"[+] Followed user '{res.json()['screen_name']}'")


def unfollow(session, headers, screen_name):
    # Unfollow user (/i/api/1.1/friendships/destroy.json)
    user_id = uid(session, headers, screen_name)
    req_body = {"user_id": user_id}
    res = session.post(UNFOLLOW_ENDPOINT, headers=headers, params=req_body, timeout=3)

    if not res.ok:
        print(f"[-] Error occurred while unfollowing user:\n{res.text}")
        sys.exit(1)

    print(f"[+] Unfollowed user '{res.json()['screen_name']}'")


def uid(session, headers, screen_name):
    # Fetch UID with screen name (/i/api/graphql/_pnlqeTOtnpbIL9o-fS_pg/ProfileSpotlightsQuery)
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


if __name__ == "__main__":
    if not os.path.isfile(".env"):
        sys.exit("[-] Missing .env file with credentials")

    load_dotenv()
    args = parse_args()
    main()
