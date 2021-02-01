import request
import re

HOST = ''
USER = ''

def init_session():
    # Return Session (Cookie)
    r = request.get(HOST)

    # Others stuff if needed
    # cookie = re.search(r'',r.text)
    # cookie = cookie.group(1)
    return r.cookie.get('')



