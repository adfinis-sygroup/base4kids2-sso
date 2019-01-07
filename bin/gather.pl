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
use POSIX qw(strftime);
use Sys::Hostname;
use Sys::Syslog qw(:standard :macros);
use lib "/opt/b4k2sso/lib64/perl5";
use Crypt::JWT qw(decode_jwt);
use Data::Dumper;

our ($userAuthorizationUri, $accessTokenUri, $client_id, $client_secret,
    $context, $scope, $pubkey);
require "/opt/b4k2sso/etc/config.pm";

my $auth=encode_base64($client_id.":".$client_secret);
chomp $auth;

openlog("b4k2sso", "ndelay,pid", LOG_LOCAL0);

while (new CGI::Fast) {
  my $myurl=$ENV{'REQUEST_SCHEME'}."://".$ENV{'SERVER_NAME'}."/b4k2sso";
  my $remote_addr=$ENV{'REMOTE_ADDR'};

#
# Process redirect for unauthenticated user
  if (defined param('return_uri')) {

    my @chars = ("A".."Z", "a".."z", "0-9");
    my $state;
    $state.=$chars[rand @chars] for 1..8;

    my $return_uri=param('return_uri');

    syslog(LOG_INFO, "$remote_addr [$state]: Redirect to portal");

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

    if (! defined $b4k2ssostate) {
      syslog(LOG_ERR, "$remote_addr [????????]: ERROR missing b4k2sso-state cookie");
      &error($remote_addr, "????????");
      next;
    }

    if (! defined $b4k2ssoreturn_uri) {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR missing b4k2sso-return_uri cookie");
      &error($remote_addr, $b4k2ssostate);
      next;
    }

    if (! defined $state) {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR missing state parameter");
      &error($remote_addr, $b4k2ssostate);
      next;
    }

    if (! defined $code) {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR missing code parameter");
      &error($remote_addr, $b4k2ssostate);
      next;
    }

    if ($b4k2ssostate ne $state) {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR portal state '$state' does not match");
      &error($remote_addr, $b4k2ssostate);
      next;
    }

    syslog(LOG_INFO, "$remote_addr [$b4k2ssostate]: fetching tokens using '$code'");

    my $pid=open CMD, "-|";
    my $ret;
    if ($pid == 0) {
      *STDERR = *STDOUT;
      exec "/usr/bin/curl", "-s", "-S", "-X", "POST",
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
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR missing tokens");
      &error($remote_addr, $b4k2ssostate);
      next;
    }

    my $json;
    eval {
      $json=decode_json($ret);
    } or do {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR invalid tokens '$ret'");
      &error($remote_addr, $b4k2ssostate);
      next;
    };

    my $access_token=$json->{'access_token'};
    my $refresh_token=$json->{'refresh_token'};

    if (! defined $access_token) {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR no access token in '$ret'");
      &error($remote_addr, $b4k2ssostate);
      next;
    }

    my $jwt;
    eval {
      $jwt=decode_jwt(token=>$access_token,key=>\$pubkey);
    } or do {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR invalid access_token in '$ret'");
      &error($remote_addr, $b4k2ssostate);
      next;
    };

    if (! defined $json->{'refresh_token'}) {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR no refresh_token in '$ret'");
      &error($remote_addr, $b4k2ssostate);
      next;
    }

    my $user_name=$jwt->{'user_name'};
    if (! defined $user_name) {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR no user_name in access_token in '$ret'");
      &error($remote_addr, $b4k2ssostate);
      next;
    } 

    eval {
      $jwt=decode_jwt(token=>$refresh_token,key=>\$pubkey);
    } or do {
      syslog(LOG_ERR, "$remote_addr [$b4k2ssostate]: ERROR invalid refresh token in '$ret'");
      &error($remote_addr, $b4k2ssostate);
      next;
    };

    syslog(LOG_INFO, "$remote_addr [$b4k2ssostate]: authenticated as $user_name");

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
    &error($remote_addr, "n/a");
    next;
  }
}

#
# Write useless message
sub error {
  my $date=strftime "%b %e %H:%M:%S %G", localtime;
  my $host=hostname;
  my $pid=$$;
  my $ip=shift;
  my $state=shift;

  print << "EOF";
Content-type: text/html; charset=utf-8

<!DOCTYPE html>

<html lang="de">
  <head>
    <title>SSO Error</title>
    <meta charset="UTF-8">
    <style>
      table, th, td {
        border: 1px solid black;
      }
    </style>
  </head>
  <body>
    <h1>Fehler im Single Sign On</h1>
    <table>
      <tr>
        <td>Date</td>
        <td>$date</td>
      </tr>
      <tr>
        <td>Host</td>
        <td>$host</td>
      </tr>
      <tr>
        <td>PID</td>
        <td>$pid</td>
      </tr>
      <tr>
        <td>Client IP</td>
        <td>$ip</td>
      </tr>
      <tr>
        <td>State</td>
        <td>$state</td>
      </tr>
    </table>
  </body>
</html>
EOF
}
