# OAuth2/JWT portal integration for Apache

## Abstract

Using Apache's mod_rewrite and a FastCGI script to authenticate against an OAuth2/JWT based SSO portal.

Unauthenticated users are redirected to the portal, the JWT token fetched after successful login. The application will get the login in the `REMOTE_USER` variable, similar to HTTP Basic Auth, Kerberos etc.

## Authorization flow

- Useragent requests https://www.example.com/printenv
- Apache sends the cookies to verify.pl instructed by `mod_rewite`:

```
RewriteMap verify "prg:/opt/b4k2sso/bin/verify.pl"
RewriteRule .* - [E=REMOTE_USER:${verify:%{HTTP_COOKIE}}]
```

`verify.pl` is a permanently spawned process, restart of Apache is required to reload (or restart after a crash) verify.pl.

The script uses https://github.com/DCIT/perl-Crypt-JWT to verify the `access_token` using the provided RSA key. In case the token is valid, verify.pl returns the `user_name` from the token, otherwise it will return an empty string. The second RewriteRule packs this output into the environment variable `REMOTE_USER`.

```
RewriteCond %{ENV:REMOTE_USER} =""
RewriteRule .* /b4k2sso?return_uri=%{REQUEST_URI} [R]
```

In case `REMOTE_USER` is empty, `mod_rewrite` redirects the user agent to /b4k2sso. This URI is treated by a FastGCI script - once again, a permanently spawned process, restart of Apache is required to reload (or restart after a crash) `gather.pl`:

```
<Directory "/opt/b4k2sso/bin">
        AllowOverride None
        Options ExecCGI
        Require all granted
        AddHandler fcgid-script .pl
</Directory>

        ScriptAlias /b4k2sso /opt/b4k2sso/bin/gather.pl
```

- `gather.pl` stores the `return_uri` into the cookie *b4k2sso-return_uri*
- It creates a random string and stores it in the cookie *b4k2sso-state*
- It redirects the user agent to the eGov portal

The user is now asked to provide his credentials. In case of a success, the portal redirects the user agent back to /b4k2sso, adding a random code to the URI.

- `gather.pl` compares the state variable with *b4k2sso-state*
- It requests a JWT token from the portal using the provided code, client_id and client_secret
- The access_token is stored in the cookie *b4k2sso-access_token*
- The refresh_token is stored in the cookie *b4k2sso-refresh_token*
- The cookies *b4k2sso-state* and *b4k2sso-return_uri* are deleted
- The user agent is redirected back to the URI from *b4k2sso-return_uri*

The process starts from the beginning. Since the user now presents a valid JWT token, access to the resource is granted.

## Installation

* Place the content of this repo in `/opt/b4k2sso`
* On RHEL/CentOS based systems
  * `yum install git mod_fcgid perl-CGI perl-FCGI perl-JSON-PP perl-JSON-MaybeXS`
  * The missing CryptX and Crypt-JWT modules are prebuilt in this repo, follow the src/README file to rebuild the modules
* Create configuration following `etc/config.pm.sample`
* Adjust vhost configuration following `doc/`
* Give it a try

When everything runs well you will be redirected to the OAuth2/JWT portal. Enter your credentials.

You should come back to the place you wanted to go. The environment variable `REMOTE_USER` should get your login.

## Application integration

`REMOTE_USER` is set by several auth* modules inside Apache, good examples are basic authantication or Kerberos. Application trusting this variable will work straight forward.

A good example is the NextCloud "environment based authentication" found on https://docs.nextcloud.com/server/11/admin_manual/configuration_server/sso_configuration.html

With an additional RewriteRule Apache could be used as a reverse Proxy, passing the `REMOTE_USER` variable as HTTP header to the backend application.

## Demo installation

A good place to see the code working is https://lab.0x1b.ch/printenv.cgi

![Bildschirmfoto 2018-09-22 um 09.42.52](https://raw.githubusercontent.com/adfinis-sygroup/base4kids2-sso/master/doc/Bildschirmfoto%202018-09-22%20um%2009.42.52.png)

![Bildschirmfoto 2018-09-22 um 09.43.17](https://raw.githubusercontent.com/adfinis-sygroup/base4kids2-sso/master/doc/Bildschirmfoto%202018-09-22%20um%2009.43.17.png)

## Performance considerations

`verify.pl` checks the JWT token using RSA public key cryptography. There is a single process running those verifications, limiting the amount of possible requests per time. Ideally only a part of the server's namespace should be protected by `verify.pl` to avoid too many requests.

`gather.pl` requests the tokens from the portal once a user provided his credentials. While we may assume safely the portal is up and running when we get the user agent back into our hands, this request might get stuck. Apache will handle multiple instances of the FastCGI process in parallel to avoid such locks, but a careful configuration of `mod_fcgid` might be required to handle production load.

Perl might not be the fastest way to handle the Authorization flow. The usage of persistent processes to handle authentication and verify tokens minimizes the impact significantly, the cryptographic decoding is realized in a binary module. The current implementation should scale fairly well withtout the need of a rewite in a compiler language.

```
# pstree
systemd─┬─...
        ├─apache2─┬─apache2
        │         ├─apache2───gather.pl
        │         ├─2*[apache2───26*[{apache2}]]
        │         └─verify.pl
...
```

## Security considerations

The JWT tokens must be treated like passwords, they provide access to protected resources.

The cookies are marked HttpOnly to prevent XSS attacks, basically preventing the tokens from being used by client side Java Script.

Since the authorization flow goes back and forward between the portal and the application, the SameSite cookie attribute can't be used to protect from CSRF attacks.

TLS encrypted HTTP is mandatory for all requests.

## Todo

- Switch from exec curl to libcurl
- `access_token` refresh based on `refresh_token`

