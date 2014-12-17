jCertGrabber
============
Small app for getting SSL certificate of the server. Cert is grabbed before handshake 
so it can be used on servers with client certificate authentication. Jar in dist folder 
is ready-to-use with all libs included.<br/>
<br/>
usage: java -jar jCertGrabber.jar<br/>
 -d,--debug               debug mode<br/>
 -h,--help                print this message<br/>
 -p,--port <port>         target port<br/>
 -t,--target <hostname>   target hostname/ip<br/>
 -w,--timeout <seconds>   connection timeout in seconds (default 5)<br/>
<br/>
It will print certificate details and encoded form. It uses commons cli, commons codec and two 
Bouncy Castle libs (bcpkix and bcprov). Code for cert grabbing is in pure Java and can work 
without any additional libs.