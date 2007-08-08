#!/usr/local/bin/perl

package Authen::NTLM;
use Authen::NTLM::DES;
use Authen::NTLM::MD4;
use MIME::Base64;

use vars qw($VERSION @ISA @EXPORT);
require Exporter;

=head1 NAME

Authen::NTLM - An NTLM authentication module

=head1 SYNOPSIS

    use Mail::IMAPClient;
    use Authen::NTLM;
    my $imap = Mail::IMAPClient->new(Server=>'imaphost');
    ntlm_user($username);
    ntlm_password($password);
    $imap->authenticate("NTLM", Authen::NTLM::ntlm);
    :
    $imap->logout;
    ntlm_reset;
    :

=head1 DESCRIPTION

    This module provides methods to use NTLM authentication.  It can
    be used as an authenticate method with the Mail::IMAPClient module
    to perform the challenge/response mechanism for NTLM connections
    or it can be used on its own for NTLM authentication with other
    protocols (eg. HTTP).

    The implementation is a direct port of the code from F<fetchmail>
    which, itself, has based its NTLM implementation on F<samba>.  As
    such, this code is not especially efficient, however it will still
    take a fraction of a second to negotiate a login on a PII which is
    likely to be good enough for most situations.

=head2 FUNCTIONS

=over 4

=item ntlm_domain()

    Set the domain to use in the NTLM authentication messages.
    Returns the new domain.  Without an argument, this function
    returns the current domain entry.

=item ntlm_user()

    Set the username to use in the NTLM authentication messages.
    Returns the new username.  Without an argument, this function
    returns the current username entry.

=item ntlm_password()

    Set the password to use in the NTLM authentication messages.
    Returns the new password.  Without an argument, this function
    returns the current password entry.

=item ntlm_reset()

    Resets the NTLM challenge/response state machine so that the next
    call to C<ntlm()> will produce an initial connect message.

=item ntlm()

    Generate a reply to a challenge.  The NTLM protocol involves an
    initial empty challenge from the server requiring a message
    response containing the username and domain (which may be empty).
    The first call to C<ntlm()> generates this first message ignoring
    any arguments.

    The second time it is called, it is assumend that the argument is
    the challenge string sent from the server.  This will contain 8
    bytes of data which are used in the DES functions to generate the
    response authentication strings.  The result of the call is the
    final authentication string.

    If C<ntlm_reset()> is called, then the next call to C<ntlm()> will
    start the process again allowing multiple authentications within
    an application.

=back

=head1 AUTHOR

    David (Buzz) Bussenschutt <davidbuzz@gmail.com> - current maintainer
    Mark Bush <Mark.Bush@bushnet.demon.co.uk> - perl port
    Eric S. Raymond - author of fetchmail
    Andrew Tridgell and Jeremy Allison for SMB/Netbios code

=head1 SEE ALSO

L<perl>, L<Mail::IMAPClient>, L<LWP::Authen::Ntlm> 

=head1 HISTORY
    1.03 - fixes long-standing 1 line bug L<http://rt.cpan.org/Public/Bug/Display.html?id=9521> - released by David Bussenschutt 9th Aug 2007 
    1.02 - released by Mark Bush 29th Oct 2001
=cut

$VERSION = "1.03";
@ISA = qw(Exporter);
@EXPORT = qw(ntlm ntlm_domain ntlm_user ntlm_password ntlm_reset);

my $domain = "";
my $user = "";
my $password = "";

my $str_hdr = "vvV";
my $hdr_len = 8;
my $ident = "NTLMSSP";

my $msg1_f = 0x0000b207;
my $msg1 = "Z8VV";
my $msg1_hlen = 16 + ($hdr_len*2);

my $msg2 = "Z8Va${hdr_len}Va8a8a${hdr_len}";
my $msg2_hlen = 12 + $hdr_len + 20 + $hdr_len;

my $msg3 = "Z8V";
my $msg3_tl = "V";
my $msg3_hlen = 12 + ($hdr_len*6) + 4;

my $state = 0;

sub ntlm_domain
{
  if (@_)
  {
    $domain = shift;
  }
  return $domain;
}

sub ntlm_user
{
  if (@_)
  {
    $user = shift;
  }
  return $user;
}

sub ntlm_password
{
  if (@_)
  {
    $password = shift;
  }
  return $password;
}

sub ntlm_reset
{
  $state = 0;
}

sub ntlm
{
  my ($challenge) = @_;

  my ($flags, $user_hdr, $domain_hdr,
      $u_off, $d_off, $c_info, $lmResp, $ntResp, $lm_hdr,
      $nt_hdr, $wks_hdr, $session_hdr, $lm_off, $nt_off,
      $wks_off, $s_off, $u_user);
  my $response;
  if ($state)
  {
    $challenge =~ s/^\s*//;
    $challenge = decode_base64($challenge);
    $c_info = &decode_challenge($challenge);
    $u_user = &unicode($user);
    $domain = substr($challenge, $c_info->{domain}{offset}, $c_info->{domain}{len}); 
    $response = pack($msg3, $ident, 3);
    $lmResp = &lmEncrypt($c_info->{data});
    $ntResp = &ntEncrypt($c_info->{data});
    $lm_off = $msg3_hlen;
    $nt_off = $lm_off + length($lmResp);
    $d_off = $nt_off + length($ntResp);
    $u_off = $d_off + length($domain);
    $wks_off = $u_off + length($u_user);
    $s_off = $wks_off + length($u_user);
    $lm_hdr = &hdr($lmResp, $msg3_hlen, $lm_off);
    $nt_hdr = &hdr($ntResp, $msg3_hlen, $nt_off);
    $domain_hdr = &hdr($domain, $msg3_hlen, $d_off);
    $user_hdr = &hdr($u_user, $msg3_hlen, $u_off);
    $wks_hdr = &hdr($u_user, $msg3_hlen, $wks_off);
    $session_hdr = &hdr("", $msg3_hlen, $s_off);
    $flags = pack($msg3_tl, $c_info->{flags});
    $response .= $lm_hdr . $nt_hdr . $domain_hdr . $user_hdr .
                 $wks_hdr . $session_hdr . $flags .
		 $lmResp . $ntResp . $domain . $u_user . $u_user;
  }
  else # first response;
  {
    $response = pack($msg1, $ident, 1, $msg1_f);
    $u_off = $msg1_hlen;
    $d_off = $u_off + length($user);
    $user_hdr = &hdr($user, $msg1_hlen, $u_off);
    $domain_hdr = &hdr($domain, $msg1_hlen, $d_off);
    $response .= $user_hdr . $domain_hdr . $user . $domain;
    $state = 1;
  }
  return encode_base64($response, "");
}

sub hdr
{
  my ($string, $h_len, $offset) = @_;

  my ($res, $len);
  $len = length($string);
  if ($string)
  {
    $res = pack($str_hdr, $len, $len, $offset);
  }
  else
  {
    $res = pack($str_hdr, 0, 0, $offset - $h_len);
  }
  return $res;
}

sub decode_challenge
{
  my ($challenge) = @_;

  my $res;
  my (@res, @hdr);
  $res->{buffer} = substr($challenge, $msg2_hlen);
  $challenge = substr($challenge, 0, $msg2_hlen);
  @res = unpack($msg2, $challenge);
  $res->{ident} = $res[0];
  $res->{type} = $res[1];
  @hdr = unpack($str_hdr, $res[2]);
  $res->{domain}{len} = $hdr[0];
  $res->{domain}{maxlen} = $hdr[1];
  $res->{domain}{offset} = $hdr[2];
  $res->{flags} = $res[3];
  $res->{data} = $res[4];
  $res->{reserved} = $res[5];
  $res->{empty_hdr} = $res[6];
  return $res;
}

sub unicode
{
  my ($string) = @_;
  my ($reply, $c, $z);

  $z = sprintf "%c", 0;
  foreach $c (split //, $string)
  {
    $reply .= $c . $z;
  }
  return $reply;
}

sub NTunicode
{
  my ($string) = @_;
  my ($reply, $c);

  foreach $c (map {ord($_)} split(//, $string))
  {
    $reply .= pack("v", $c);
  }
  return $reply;
}

sub lmEncrypt
{
  my ($data) = @_;

  my $p14 = substr($password, 0, 14);
  $p14 =~ tr/a-z/A-Z/;
  $p14 .= "\0"x(14-length($p14));
  my $p21 = E_P16($p14);
  $p21 .= "\0"x(21-length($p21));
  my $p24 = E_P24($p21, $data);
  return $p24;
}

sub ntEncrypt
{
  my ($data) = @_;

  my $p21 = &E_md4hash;
  $p21 .= "\0"x(21-length($p21));
  my $p24 = E_P24($p21, $data);
  return $p24;
}

sub E_md4hash
{
  my $wpwd = &NTunicode($password);
  my $p16 = mdfour($wpwd);
  return $p16;
}

1;
