#!/usr/bin/perl -w
#
# Adfinis SyGroup AG
# https://git.adfinis-sygroup.ch/Beatr/b4k2sso/
#
# Verify JWT token presented in cookies
#
use strict;
use lib "/opt/b4k2sso/lib64/perl5";
use Crypt::JWT qw(decode_jwt);

our ($userAuthorizationUri, $accessTokenUri, $client_id, $client_secret,
    $context, $scope, $pubkey);
require "/opt/b4k2sso/etc/config.pm";

$|=1;

while (<>) {
  chomp;

  my $access_token;
  my $refresh_token;

  if (/b4k2sso-access_token=([^;]+)/) {
    $access_token=$1;
  }

  if (/b4k2sso-refresh_token=([^;]+)/) {
    $refresh_token=$1;
  }

  if (defined $access_token) {
    my $jwt;
    eval {
      $jwt=decode_jwt(token=>$access_token,key=>\$pubkey);
    } or do {
      undef $jwt;
    };

    if (defined $jwt->{'user_name'}) {
      print $jwt->{'user_name'};
    }
  }

  print "\n";
}
