# goldapresetpwd

A simple backend for resetting LDAP passwords written in go.  

This backend accepts JSON data POSTed from axios to `http://ip.addr:8080/request`  

Adjust the CORS origins as necessary and change the binddn (currently users are searched by cn=%s, username, because that's how we store them) to fit your needs.  

Ensure you set the ENV variables `LDAP_SERVER`, `LDAP_PORT`, and `LDAP_USER_DN` or this won't work.
