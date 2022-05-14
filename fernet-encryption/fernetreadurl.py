import urllib.request
file1 = open("logs.txt",'w')
link = "https://thingspeak.com/channels/1461170/field/1"
f = urllib.request.urlopen(link)
myfile = f.read()
myfile = myfile.decode()
input=myfile.replace(',','\n')
file1.write(input)

file1.close()