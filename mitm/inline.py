import os
import json
import uuid
import base64
import urllib
from mitmproxy import ctx
from tinydb import TinyDB
from mitmproxy import controller, proxy
from mitmproxy.proxy.server import ProxyServer

# Command to Beautify JSON Data using Python:
# python -m json.tool input.json > output.json

# mitmdump -s inline.py --port 8090

session = []
kwargs = {
        'ignore_ext': ('.woff','.woff2','.ttf','.jpg', '.js', '.jpeg', '.gif', '.png', '.xml', '.json', '.css', '.swf', 'svg', 'ico', '.cur')
        }
dir1 = os.path.join(os.getcwd())+"/Application_Data/"
if not os.path.exists(dir1):
    os.makedirs(dir1)
dir2 = dir1+"reqs.json"
db = TinyDB(dir2)

def request(flow):
    # ctx.log.info("Logging start of context")
    ignore_ext = kwargs.get('ignore_ext',[])    
    req_url = flow.request.url
    req_url = urllib.parse.unquote(req_url)

    appln = {}
    appln['app_url'] = []
    appln['app_cookie'] = []
    appln['app_url_param'] = []
    appln['app_body_content'] = []
    
    # Extract URLs

    # url_data = req_method + ": "+req_url        
    # print (url_data)
    
    appln['app_url'] = [{flow.request.method: req_url}]


    # Extract Parameters from URLs

    if "?" and "=" in req_url:
        # print ("Parameters in URL:\n")
        req1 = req_url.split('?')[1]
        if "&" in req1:
            req2 = req1.split('&')
            for req3 in req2:
                if "=" in req3:
                    req4 = req3.split('=')[0]
                    # print (req4,"\n")
                    appln['app_url_param'].append(req4)
        else:
            if "=" in req1:
                req4 = req1.split('=')[0]
                # print (req4,"\n")
                appln['app_url_param'] = req4

    # Extract Cookie from Headers

    for header1, value1 in flow.request.headers.items():
        if header1 == 'Cookie':
            if ";" in value1:
                value1 = value1.split("; ")
                for val in value1:
                    if "=" in val:
                        val = val.split("=")
                        appln['app_cookie'].append(val[0])
            else:
                if "=" in value1:
                    val = value1.split("=")[0]
                    appln['app_cookie'] = val

    # Extract Content from Body

    if flow.request.content:
        body1 = flow.request.content
        body1 = urllib.parse.unquote(str(body1), 'utf-8')
        # print (body1)
        appln['app_body_content'] = body1


    # Storing URLs, URL Parameters, Cookies and Body content to the database
    db.insert(appln)
