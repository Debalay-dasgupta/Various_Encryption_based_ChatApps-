import re


def Find(string):
    # findall() has been used
    # with valid conditions for urls in string
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex, string)
    return [x[0] for x in url]

def bol(string):
    if(len(Find((string)))>0):
        return True
    else:
        return False

# www.yeniik.com.tr/wp-admin/js/login.alibaba.com/login.jsp.php
# www.restorevisioncenters.com/html/technology.html