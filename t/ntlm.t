######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {print "1..13\n";}
END {print "not ok 1\n" unless $loaded;}
use Authen::NTLM;
use MIME::Base64;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

#package NTLMTest;

my $user = "test";
my $domain = "test";
my $passwd = "test";
my $msg1 = "TlRMTVNTUAABAAAAB7IAAAQABAAgAAAABAAEACQAAAB0ZXN0dGVzdA==";
my $challenge = "TlRMTVNTUAACAAAABAAEADAAAAAFggEAQUJDREVGR0gAAAAAAAAAAAAAAAAAAAAAdGVzdA==";
my $msg2 = "TlRMTVNTUAADAAAAGAAYAEAAAAAYABgAWAAAAAQABABwAAAACAAIAHQAAAAIAAgAfAAAAAAAAABEAAAABYIBAJ7/TlMo4HLg0gOk6iKq4bv2vk35ozHEKKoqG8nTkQ5S82zyqpJzxPDJHUMynnKsBHRlc3R0AGUAcwB0AHQAZQBzAHQA";

# 2: username

print ((ntlm_user($user) eq $user) ? "ok 2\n" : "not ok 2\n");

# 3: domain

print ((ntlm_domain($domain) eq $domain) ? "ok 3\n" : "not ok 3\n");

# 4: password

print ((ntlm_password($passwd) eq $passwd) ? "ok 4\n" : "not ok 4\n");

# 5: initial message

my $reply1 = ntlm();
print (($reply1 eq $msg1) ? "ok 5\n" : "not ok 5\n");

# 6-12: decode challenge - not normally user accessed

my $c = &Authen::NTLM::decode_challenge(decode_base64($challenge));
print (($c->{ident} eq "NTLMSSP") ? "ok 6\n" : "not ok 6\n");
print (($c->{type} == 2) ? "ok 7\n" : "not ok 7\n");
print (($c->{flags} == 0x00018205) ? "ok 8\n" : "not ok 8\n");
print (($c->{data} eq "ABCDEFGH") ? "ok 9\n" : "not ok 9\n");
print (($c->{domain}{len} == 4) ? "ok 10\n" : "not ok 10\n");
print (($c->{domain}{offset} == 48) ? "ok 11\n" : "not ok 11\n");
print (($c->{buffer} eq "test") ? "ok 12\n" : "not ok 12\n");

# 13: challenge response

my $reply2 = ntlm($challenge);
print (($reply2 eq $msg2) ? "ok 13\n" : "not ok 13\n");
