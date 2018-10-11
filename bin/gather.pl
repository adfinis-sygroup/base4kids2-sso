#!/usr/bin/perl -w
#
# Adfinis SyGroup AG
# https://github.com/adfinis-sygroup/base4kids2-sso
#
# Get JWT token by using eGov's OAuth2 authorization flow
#
use strict;
use CGI::Fast qw/:standard/;
use MIME::Base64;
use JSON::PP;
use Data::Dumper;

our ($userAuthorizationUri, $accessTokenUri, $client_id, $client_secret,
    $context, $scope, $pubkey);
require "/opt/b4k2sso/etc/config.pm";

my $auth=encode_base64($client_id.":".$client_secret);
chomp $auth;

while (new CGI::Fast) {
  my $myurl=$ENV{'REQUEST_SCHEME'}."://".$ENV{'SERVER_NAME'}."/b4k2sso";

#
# Process redirect for unauthenticated user
  if (defined param('return_uri')) {

    my @chars = ("A".."Z", "a".."z", "0-9");
    my $state;
    $state.=$chars[rand @chars] for 1..8;

    my $return_uri=param('return_uri');

    print "Location: ".
          $userAuthorizationUri."?".
          "client_id=".$client_id."&".
          "response_type=code&".
          "context=".$context."&".
          "redirect_uri=".$myurl."&".
          "scope=".$scope."&".
          "state=".$state."\n";
    print "Set-Cookie: ".
          "b4k2sso-state=".$state."; path=/; HttpOnly;\n";
    print "Set-Cookie: ".
          "b4k2sso-return_uri=".$return_uri."; path=/; HttpOnly;\n";
    print "\n";

#
# Callback from portal
  } elsif (defined param('code')) {
    my $b4k2ssostate=cookie("b4k2sso-state");
    my $b4k2ssoreturn_uri=cookie("b4k2sso-return_uri");
    my $state=param("state");
    my $code=param("code");

    if (! defined $b4k2ssostate or
        ! defined $b4k2ssoreturn_uri or
        ! defined $state or
        ! defined $code or
          $b4k2ssostate ne $state) {
          &error;
          next;
        }

    my $pid=open CMD, "-|";
    my $ret;
    if ($pid == 0) {
      exec "/usr/bin/curl", "-s", "-X", "POST",
        $accessTokenUri,
        "-H", "Authorization: Basic ".$auth,
        "-d", "client_id=".$client_id,
        "-d", "client_secret=".$client_secret,
        "-d", "grant_type=authorization_code",
        "-d", "code=".$code,
        "-d", "redirect_uri=".$myurl;
    } else {
      $ret=<CMD>;
    }
    close CMD;

    if (! defined $ret) {
      &error;
      next;
    }

    my $json=decode_json($ret);
    my $goback=$ENV{'REQUEST_SCHEME'}."://".$ENV{'SERVER_NAME'}.
      $b4k2ssoreturn_uri;

#    print "Content-type: text/plain\n\n";
    print "Location: ".$goback."\n";
    print "Set-Cookie: ".
          "b4k2sso-state=deleted".
          "; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT\n";
    print "Set-Cookie: ".
          "b4k2sso-return_uri=deleted".
          "; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT\n";
    print "Set-Cookie: ".
          "b4k2sso-access_token=".$json->{'access_token'}.
          "; path=/; HttpOnly;\n";
    print "Set-Cookie: ".
          "b4k2sso-refresh_token=".$json->{'refresh_token'}.
          "; path=/; HttpOnly;\n";
    print "\n";
#    print Dumper($json);

#
# Anything else
  } else {
    &error;
    next;
  }
}

#
# Write useless message
sub error {
  print << "EOF";
Content-type: text/html

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Strange Error</title>
</head><body>
<h1>Strange Error</h1>
<p>This should not happen.</p>
<hr>
$ENV{'SERVER_SIGNATURE'}
</body></html>
EOF
}
