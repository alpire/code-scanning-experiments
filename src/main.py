from fastapi import FastAPI, Request, Response, HTTPException
import os
import sqlite3
import requests
import urllib
import socket

app = FastAPI()
con = sqlite3.connect(':memory:')

# In dev & testing only, include the stacktrace in the response on internal
# server errors
if os.getenv("FASTAPI_ENV") in ["dev", "test"]:
    @app.exception_handler(Exception)
    async def debug_exception_handler(request: Request, exc: Exception):
        import traceback

        return Response(
            status_code=500,
            content="".join(
                traceback.format_exception(
                    etype=type(exc), value=exc, tb=exc.__traceback__
                )
            )
        )

@app.on_event("startup")
async def startup_event():
    """Creates an in-memory database with a user table, and populate it with
    one account"""
    cur = con.cursor()
    cur.execute('''CREATE TABLE users (email text, password text)''')
    cur.execute('''INSERT INTO users VALUES ('me@me.com', '123456')''')
    con.commit()

@app.get("/")
async def root():
    return {"message": "Hello World"}

#@app.get("/sqli")
#async def sqli(email: str, password: str):
#    cur = con.cursor()
#    cur.execute("SELECT * FROM users WHERE email = '%s' and password = '%s'" % (email, password))
#    return cur.fetchone() is not None
#
# Just sending a private IP works
@app.get("/ssrf/level1")
async def ssrfv1(url: str):
    try:
        requests.get(url,  timeout=0.5)
    except:
        raise HTTPException(status_code=404, detail="bad url")


import ipaddress
def is_external_ip(ip_addr: str) -> bool:
    """Determines if an IP is external.

    :param ip_addr: the IP to check
    :returns: True if the IP is external (non-private), False otherwise
    """
    ip_addr_obj = ipaddress.ip_address(ip_addr)
    return not ip_addr_obj.is_private and ip_addr_obj.is_global


# Private IP are not allowed, but doesn't do DNS resolution
@app.get("/ssrf/level2")
async def ssrfv2(url: str):

    try:
        split = urllib.parse.urlsplit(url)
        hostname = split.hostname
        try:
            if not is_external_ip(hostname):
                raise HTTPException(status_code=404, detail="ATTACK!")
        except ValueError:
            # if not an IP, is_external_ip raises a ValueError
            pass
        requests.get(url,  timeout=0.5)
    except:
        raise HTTPException(status_code=404, detail="exception")

# Private IP are not allowed (after dns resolution)
@app.get("/ssrf/level3")
async def ssrfv3(url: str):
    try:
        split = urllib.parse.urlsplit(url)
        hostname = split.hostname
        if not hostname:
            raise HTTPException(status_code=404, detail="no hostname")
        ip_addr = socket.gethostbyname(hostname)
        if not is_external_ip(ip_addr):
            raise HTTPException(status_code=404, detail="ATTACK!")
        requests.get(url, timeout=0.5)
    except:
        raise HTTPException(status_code=404, detail="exception")

# Private IP are not allowed (after dns resolution), and no redirects
@app.get("/ssrf/level4")
async def ssrfv4(url: str):
    try:
        split = urllib.parse.urlsplit(url)
        hostname = split.hostname
        if not hostname:
            raise HTTPException(status_code=404, detail="no hostname")
        ip_addr = socket.gethostbyname(hostname)
        if not is_external_ip(ip_addr):
            raise HTTPException(status_code=404, detail="ATTACK!")
        requests.get(url, timeout=0.5, allow_redirects=False)
    except:
        raise HTTPException(status_code=404, detail="exception")

# Private IP are not allowed (after dns resolution considering all A records),
# and no redirects
@app.get("/ssrf/level5")
async def ssrfv5(url: str):
    try:
        split = urllib.parse.urlsplit(url)
        hostname = split.hostname
        if not hostname:
            raise HTTPException(status_code=404, detail="no hostname")

        for res in socket.getaddrinfo(hostname, 80):
            af, socktype, proto, canonname, sa = res
            if not is_external_ip(sa[0]):
                raise HTTPException(status_code=404, detail="ATTACK!")
        requests.get(url, timeout=0.5, allow_redirects=False)
    except:
        raise HTTPException(status_code=404, detail="exception")

@app.get("/redirect")
async def redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/redirect")

@app.get("/exception", status_code=500)
async def exception():
    import json
    s = json.loads(open("/tmp/out").read())
    return s
