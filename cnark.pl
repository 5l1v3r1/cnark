#!/usr/bin/env perl

use Modern::Perl;
use Term::ANSIColor qw(:constants);
use Tie::Hash::Indexed;
use IO::Socket::SSL 'debug0';
use Mozilla::CA;

my $osname = $^O;

# Use Win32::Console::ANSI for colorized output on windows
# or Term::ANSIColor for *nixes
if ($osname eq "MSWin32") {
    require Win32::Console::ANSI;
    } else {
        use Term::ANSIColor qw(:constants);
    }

# Core Module for command line options
use Getopt::Long; 

my $version = "v0.5.7";
my $openssl_ver = sprintf("%#.8x", Net::SSLeay::SSLeay());
my $myopenssl_ver;

say "CryptoNark $version running on $osname";

my ( $host, $port, $x509, $pkeybits, $expiry, $sigalg );
my $insecure = '';

my $verifymode = Net::SSLeay::VERIFY_PEER;
my $useragent = "cryptonark-ssl-scantool/" . $version;

sub usage{
    say "Usage: cnark.pl -h|--host <hostname> -p|--port <port number> \n\t\t[-i|--insecure]";
    exit;
  }

usage() if ( ! GetOptions("h|host=s" => \$host, "p|port=s" => \$port, "i|insecure" => \$insecure ) or ( ! defined $host) or ( ! defined $port) );

my $key;
my $value;
my $ssl2client;
my $ssl3client;

my $ssl2_version_string;

# If -i/--insecure option used, do not verify CA certificate
# This is useful if you want to scan an IP address and not a hostname
if ($insecure eq 1 ) {
  $verifymode = 'SSL_VERIFY_NONE';
  }


# Populate arrays with OpenSSL ciphers
# Note:  TLSv1 ciphers and SSLv3 ciphers are 
# identical in OpenSSL

tie my %ssl2_ciphers, 'Tie::Hash::Indexed';
tie my %tls1_ciphers, 'Tie::Hash::Indexed';
tie my %tls12_ciphers, 'Tie::Hash::Indexed';
tie my %openssl_version, 'Tie::Hash::Indexed';

%ssl2_ciphers = (
  'DES-CBC3-MD5' => '168 bits, High Encryption',
  'RC2-CBC-MD5' => '128 bits, Medium Encryption',
  'RC4-MD5' => '128 bits, Medium Encryption',
  'DES-CBC-MD5' => '56 bits, Low Encryption',
  'EXP-RC2-CBC-MD5' => '40 bits, Export-Grade Encryption',
  'EXP-RC4-MD5' => '40 bits, Export-Grade Encryption'
);

# The %tls1_ciphers list is also used for sslv3 tests
%tls1_ciphers = (
  'ECDHE-RSA-AES256-SHA' => '256 bits, High Encryption, Forward Secrecy',
  'ECDHE-ECDSA-AES256-SHA' => '256 bits, High Encryption, Forward Secrecy',
  'AECDH-AES256-SHA' => '256 bits, High Encryption, Anonymous Auth',
  'ECDH-RSA-AES256-SHA' => '256 bits, High Encryption',
  'ECDH-ECDSA-AES256-SHA' => '256 bits, High Encryption',
  'ADH-AES256-SHA' => '256 bits, High Encryption, Anonymous Auth',
  'DHE-RSA-AES256-SHA' => '256 bits, High Encryption, Forward Secrecy',
  'DHE-DSS-AES256-SHA' => '256 bits, High Encryption, Forward Secrecy',
  'AES256-SHA' => '256 bits, High Encryption',
  'ECDHE-RSA-DES-CBC3-SHA' => '168 bits, High Encryption, Forward Secrecy',
  'ECDHE-ECDSA-DES-CBC3-SHA' => '168 bits, High Encryption, Forward Secrecy',
  'AECDH-DES-CBC3-SHA' => '168 bits, High Encryption, Anonymous Auth',
  'ECDH-RSA-DES-CBC3-SHA' => '168 bits, High Encryption',
  'ECDH-ECDSA-DES-CBC3-SHA' => '168 bits, High Encryption',
  'ADH-DES-CBC3-SHA' => '168 bits, High Encryption, Anonymous Auth',
  'EDH-RSA-DES-CBC3-SHA' => '168 bits, High Encryption',
  'EDH-DSS-DES-CBC3-SHA' => '168 bits, High Encryption',
  'DES-CBC3-SHA' => '168 bits, High Encryption',
  'ECDHE-RSA-AES128-SHA' => '128 bits, High Encryption, Forward Secrecy',
  'ECDHE-ECDSA-AES128-SHA' => '128 bits, High Encryption, Forward Secrecy',
  'AECDH-AES128-SHA' => '128 bits, High Encryption, Anonymous Auth',
  'ECDH-RSA-AES128-SHA' => '128 bits, High Encryption',
  'ECDH-ECDSA-AES128-SHA' => '128 bits, High Encryption',
  'ECDHE-RSA-RC4-SHA' => '128 bits, High Encryption, Forward Secrecy',
  'ECDHE-ECDSA-RC4-SHA' => '128 bits, High Encryption, Forward Secrecy',
  'AECDH-RC4-SHA' => '128 bits, High Encryption, Anonymous Auth',
  'ECDH-RSA-RC4-SHA' => '128 bits, High Encryption',
  'ECDH-ECDSA-RC4-SHA' => '128 bits, High Encryption',
  'ADH-AES128-SHA' => '128 bits, High Encryption, Anonymous Auth',
  'DHE-RSA-AES128-SHA' => '128 bits, High Encryption, Forward Secrecy',
  'DHE-DSS-AES128-SHA' => '128 bits, High Encryption, Forward Secrecy',
  'AES128-SHA' => '128 bits, High Encryption',
  'RC4-SHA' => '128 bits, Medium Encryption',
  'RC4-MD5' => '128 bits, Medium Encryption',
  'ADH-RC4-MD5' => '128 bits, Medium Encryption, Anonymous Auth',
  'EDH-RSA-DES-CBC-SHA' => '56 bits, Low Encryption',
  'EDH-DSS-DES-CBC-SHA' => '56 bits, Low Encryption',
  'DES-CBC-SHA' => '56 bits, Low Encryption',
  'ADH-DES-CBC-SHA' => '56 bits, Low Encryption, Anonymous Auth',
  'EXP-ADH-DES-CBC-SHA' => '40 bits, Export-Grade Encryption',
  'EXP-ADH-RC4-MD5' => '40 bits, Export-Grade Encryption',
  'EXP-EDH-RSA-DES-CBC-SHA' => '40 bits, Export-Grade Encryption',
  'EXP-EDH-DSS-DES-CBC-SHA' => '40 bits, Export-Grade Encryption',
  'EXP-DES-CBC-SHA' => '40 bits, Export-Grade Encryption',
  'EXP-RC2-CBC-MD5' => '40 bits, Export-Grade Encryption',
  'EXP-RC4-MD5' => '40 bits, Export-Grade Encryption',
  'NULL-SHA' => 'Null cipher, No Encryption',
  'NULL-MD5' => 'Null cipher, No Encryption'
);

%tls12_ciphers = (
  'ECDHE-RSA-AES256-GCM-SHA384' => '256 bits, High Encryption, Forward Secrecy',
  'ECDHE-ECDSA-AES256-GCM-SHA384' => '256 bits, High Encryption, Forward Secrecy',
  'ECDHE-RSA-AES256-SHA384' => '256 bits, High Encryption, Forward Secrecy',
  'ECDHE-ECDSA-AES256-SHA384' => '256 bits, High Encryption, Forward Secrecy',
  'DHE-DSS-AES256-GCM-SHA384' => '256 bits, High Encryption, Forward Secrecy',
  'DHE-RSA-AES256-GCM-SHA384' => '256 bits, High Encryption, Forward Secrecy',
  'DHE-RSA-AES256-SHA256' => '256 bits, High Encryption, Forward Secrecy',
  'DHE-DSS-AES256-SHA256' => '256 bits, High Encryption, Forward Secrecy',
  'ADH-AES256-GCM-SHA384' => '256 bits, High Encryption, Anonymous Auth',
  'ADH-AES256-SHA256' => '256 bits, High Encryption, Anonymous Auth',
  'ECDH-RSA-AES256-GCM-SHA384' => '256 bits, High Encryption',
  'ECDH-ECDSA-AES256-GCM-SHA384' => '256 bits, High Encryption',
  'ECDH-RSA-AES256-SHA384' => '256 bits, High Encryption',
  'ECDH-ECDSA-AES256-SHA384' => '256 bits, High Encryption',
  'AES256-GCM-SHA384' => '256 bits, High Encryption',
  'AES256-SHA256' => '256 bits, High Encryption',
  'ECDHE-RSA-AES128-GCM-SHA256' => '128 bits, High Encryption, Forward Secrecy',
  'ECDHE-ECDSA-AES128-GCM-SHA256' => '128 bits, High Encryption, Forward Secrecy',
  'ECDHE-RSA-AES128-SHA256' => '128 bits, High Encryption, Forward Secrecy',
  'ECDHE-ECDSA-AES128-SHA256' => '128 bits, High Encryption, Forward Secrecy',
  'DHE-DSS-AES128-GCM-SHA256' => '128 bits, High Encryption, Forward Secrecy',
  'DHE-RSA-AES128-GCM-SHA256' => '128 bits, High Encryption, Forward Secrecy',
  'DHE-RSA-AES128-SHA256' => '128 bits, High Encryption, Forward Secrecy',
  'DHE-DSS-AES128-SHA256' => '128 bits, High Encryption, Forward Secrecy',
  'ADH-AES128-GCM-SHA256' => '128 bits, High Encryption, Anonymous Auth',
  'ADH-AES128-SHA256' => '128 bits, High Encryption, Anonymous Auth',
  'ECDH-RSA-AES128-GCM-SHA256' => '128 bits, High Encryption',
  'ECDH-ECDSA-AES128-GCM-SHA256' => '128 bits, High Encryption',
  'ECDH-RSA-AES128-SHA256' => '128 bits, High Encryption',
  'ECDH-ECDSA-AES128-SHA256' => '128 bits, High Encryption',
  'AES128-GCM-SHA256' => '128 bits, High Encryption',
  'AES128-SHA256' => '128 bits, High Encryption'
  );

%openssl_version = (
    '0x00903100' => 'OpenSSL 0.9.3  - Released May 24 1999',
    '0x00903101' => 'OpenSSL 0.9.3a - Released May 29 1999', 
    '0x00904100' => 'OpenSSL 0.9.4  - Released Aug  9 1999',
    '0x00905100' => 'OpenSSL 0.9.5  - Released Feb 29 2000',
    '0x0090581f' => 'OpenSSL 0.9.5a - Released Apr  3 2000',
    '0x0090600f' => 'OpenSSL 0.9.6  - Released Sep 24 2000',
    '0x0090601f' => 'OpenSSL 0.9.6a - Released Apr  5 2001',
    '0x0090602f' => 'OpenSSL 0.9.6b - Released Jul  9 2001',
    '0x0090603f' => 'OpenSSL 0.9.6c - Released Dec 21 2001',
    '0x0090604f' => 'OpenSSL 0.9.6d - Released May 10 2002',
    '0x0090605f' => 'OpenSSL 0.9.6e - Released Jul 30 2002',
    '0x0090606f' => 'OpenSSL 0.9.6f - Released Aug  8 2002',
    '0x0090607f' => 'OpenSSL 0.9.6g - Released Aug  9 2002',
    '0x0090608f' => 'OpenSSL 0.9.6h - Released Dec  8 2002',
    '0x0090700f' => 'OpenSSL 0.9.7  - Released Dec 31 2002',
    '0x0090609f' => 'OpenSSL 0.9.6i - Released Feb 19 2003',
    '0x0090701f' => 'OpenSSL 0.9.7a - Released Feb 19 2003',
    '0x0090702f' => 'OpenSSL 0.9.7b - Released Apr 10 2003',
    '0x009060af' => 'OpenSSL 0.9.6j - Released Apr 10 2003',
    '0x0090703f' => 'OpenSSL 0.9.7c - Released Sep 30 2003',
    '0x009060bf' => 'OpenSSL 0.9.6k - Released Sep 30 2003',
    '0x009060cf' => 'OpenSSL 0.9.6l - Released Nov  4 2003',
    '0x009060df' => 'OpenSSL 0.9.6m - Released Mar 17 2004',
    '0x0090704f' => 'OpenSSL 0.9.7d - Released Mar 17 2004',
    '0x0090705F' => 'OpenSSL 0.9.7e - Released Oct 25 2004',
    '0x0090706F' => 'OpenSSL 0.9.7f - Released Mar 22 2005',
    '0x0090707f' => 'OpenSSL 0.9.7g - Released Apr 11 2005',
    '0x0090800f' => 'OpenSSL 0.9.8  - Released Jul  5 2005',
    '0x0090708f' => 'OpenSSL 0.9.7h - Released Oct 11 2005',
    '0x0090801f' => 'OpenSSL 0.9.8a - Released Oct 11 2005',
    '0x0090709f' => 'OpenSSL 0.9.7i - Released Oct 15 2005',
    '0x009070af' => 'OpenSSL 0.9.7j - Released May  4 2006',
    '0x0090802f' => 'OpenSSL 0.9.8b - Released May  4 2006',
    '0x009070bf' => 'OpenSSL 0.9.7k - Released Sep  5 2006',
    '0x0090803f' => 'OpenSSL 0.9.8c - Released Sep  5 2006',
    '0x009070cf' => 'OpenSSL 0.9.7l - Released Sep 28 2006',
    '0x0090804f' => 'OpenSSL 0.9.8d - Released Sep 28 2006',
    '0x009070df' => 'OpenSSL 0.9.7m - Released Feb 23 2007',
    '0x0090805f' => 'OpenSSL 0.9.8e - Released Feb 23 2007',
    '0x00908070' => 'OpenSSL 0.9.8f - Released Oct 11 2007',
    '0x0090807f' => 'OpenSSL 0.9.8g - Released Oct 19 2007',
    '0x0090808f' => 'OpenSSL 0.9.8h - Released May 28 2008',
    '0x0090809f' => 'OpenSSL 0.9.8i - Released Sep 15 2008',
    '0x009080af' => 'OpenSSL 0.9.8j - Released Jan  7 2009',
    '0x009080bf' => 'OpenSSL 0.9.8k - Released Mar 25 2009',
    '0x10000001' => 'OpenSSL 1.0.0-beta1 - Released Apr 1 2009',
    '0x10000002' => 'OpenSSL 1.0.0-beta2 - Released Apr 21 2009',
    '0x10000003' => 'OpenSSL 1.0.0-beta3 - Released Jul 15 2009',
    '0x009080cf' => 'OpenSSL 0.9.8l - Released Nov  5 2009',
    '0x10000004' => 'OpenSSL 1.0.0-beta4 - Released Nov 10 2009',
    '0x10000005' => 'OpenSSL 1.0.0-beta5 - Released Jan 20 2010',
    '0x009080d1' => 'OpenSSL 0.9.8m-beta1 - Released Jan 20 2010',
    '0x009080df' => 'OpenSSL 0.9.8m - Released Feb 25 2010',
    '0x009080ef' => 'OpenSSL 0.9.8n - Released Mar 24 2010',
    '0x1000000f' => 'OpenSSL 1.0.0  - Released Mar 29 2010',
    '0x009080ff' => 'OpenSSL 0.9.8o - Released Jun  1 2010',
    '0x1000001f' => 'OpenSSL 1.0.0a - Released Jun  1 2010',
    '0x0090810f' => 'OpenSSL 0.9.8p - Released Nov 16 2010',
    '0x1000002f' => 'OpenSSL 1.0.0b - Released Nov 16 2010',
    '0x0090811f' => 'OpenSSL 0.9.8q - Released Dec  2 2010',
    '0x1000003f' => 'OpenSSL 1.0.0c - Released Dec  2 2010',
    '0x0090812f' => 'OpenSSL 0.9.8r - Released Feb  8 2011',
    '0x1000004f' => 'OpenSSL 1.0.0d - Released Feb  8 2011',
    '0x1000005f' => 'OpenSSL 1.0.0e - Released Sep  6 2011',
    '0x10001001' => 'OpenSSL 1.0.1-beta1 - Released Jan  3 2012',
    '0x1000006f' => 'OpenSSL 1.0.0f - Released Jan  4 2012',
    '0x0090813f' => 'OpenSSL 0.9.8s - Released Jan  4 2012',
    '0x0090814f' => 'OpenSSL 0.9.8t - Released Jan 18 2012',
    '0x1000007f' => 'OpenSSL 1.0.0g - Released Jan 18 2012',
    '0x10001002' => 'OpenSSL 1.0.1-beta2 - Released Jan 19 2012',
    '0x10001003' => 'OpenSSL 1.0.1-beta3 - Released Feb 24 2012',
    '0x1000008f' => 'OpenSSL 1.0.0h - Released Mar 12 2012',
    '0x0090815f' => 'OpenSSL 0.9.8u - Released Mar 12 2012',
    '0x1000100f' => 'OpenSSL 1.0.1  - Released Mar 14 2012',
    '0x1000009f' => 'OpenSSL 1.0.0i - Released Apr 19 2012',
    '0x0090816f' => 'OpenSSL 0.9.8v - Released Apr 19 2012',
    '0x1000101f' => 'OpenSSL 1.0.1a - Released Apr 19 2012',
    '0x0090817f' => 'OpenSSL 0.9.8w - Released Apr 23 2012',
    '0x1000102f' => 'OpenSSL 1.0.1b - Released Apr 26 2012',
    '0x0090818f' => 'OpenSSL 0.9.8x - Released May 10 2012',
    '0x100000af' => 'OpenSSL 1.0.0j - Released May 10 2012',
    '0x1000103f' => 'OpenSSL 1.0.1c - Released May 10 2012',
    '0x0090819f' => 'OpenSSL 0.9.8y - Released Feb  5 2013',
    '0x100000bf' => 'OpenSSL 1.0.0k - Released Feb  5 2013',
    '0x1000104f' => 'OpenSSL 1.0.1d - Released Feb  5 2013',
    '0x1000105f' => 'OpenSSL 1.0.1e - Released Feb 11 2013',
    '0x1000106f' => 'OpenSSL 1.0.1f - Released Jan 6 2014',
    '0x100000cf' => 'OpenSSL 1.0.0l - Released Jan 6 2014',
    '0x10002001' => 'OpenSSL 1.0.2-beta1 - Released Feb 24 2014',
    '0x1000107f' => 'OpenSSL 1.0.1g - Released Apr 7 2014',
    '0x1000108f' => 'OpenSSL 1.0.1h - Released Jun 5 2014',
    '0x100000df' => 'OpenSSL 1.0.0m - Released Jun 5 2014',
    '0x009081af' => 'OpenSSL 0.9.8za - Released Jun 5 2014',
    '0x10002002' => 'OpenSSL 1.0.2-beta2 - Released Jul 22 2014',
    '0x1000109f' => 'OpenSSL 1.0.1i - Released Aug 6 2014',
    '0x100000ef' => 'OpenSSL 1.0.0n - Released Aug 6 2014',
    '0x009081bf' => 'OpenSSL 0.9.8zb - Released Aug 6 2014',
    '0x10002003' => 'OpenSSL 1.0.2-beta3 - Released Sep 25 2014',
    '0x100010af' => 'OpenSSL 1.0.1j - Released Oct 15 2014',
    '0x100000ff' => 'OpenSSL 1.0.0o - Released Oct 15 2014',
    '0x009081cf' => 'OpenSSL 0.9.8zc - Released Oct 15 2014'
);

sub is_insecure{
  print RED, "    " . $key . " -- " . $value . "\n", RESET;
}

sub is_weak{
  if ($key =~ /^EXP-|^NULL|^RC4-MD5|^RC4-SHA|^ADH-|^AECDH|DES-CBC-/) {
    print RED, "    " . $key . " -- " . $value . "\n", RESET;
  }
  else {
    print GREEN, "    " . $key . " -- " . $value . "\n", RESET;
  }
}

# OpenSSL/Net::SSLeay version Check

sub get_openssl_ver{
    while ( ($key, $value) = each %openssl_version ) {
        #if ($key eq $openssl_ver) { say "OpenSSL Version:  $value"; }
        if ($key eq $openssl_ver) { 
            say "Using OpenSSL Version: $value";
            $myopenssl_ver = $key; 
        }
    }
}


# Basic certificate checking
sub cert_info{
say "\nVerifying SSL Certificate...\n";
sleep 2;

my $certclient = IO::Socket::SSL->new(
  PeerHost => "$host:$port",
  SSL_ca_file => Mozilla::CA::SSL_ca_file(),
  SSL_verify_mode => $verifymode,
  SSL_version => 'TLSv1',
  SSL_cipher_list => 'AES256-SHA',
  Proto => 'tcp',
  Timeout => '15',
  ) 
 #   || die("Certificate Peer Verification Failed\n\nCertificate not trusted. This could be due to:\n  + An invalid certificate chain\n  + A self-signed certificate\n  + You are scanning the IP address and not the DNS hostname\n  + Host $host does not appear to be listening on port $port\n  + You misspelled the intended host to be scanned.\n  + The CA signing this cert is not trusted by your version of Mozilla::CA\n  + $!,$SSL_ERROR\n\nRun with the --insecure switch if you wish to test with no certificate verification\n\n"); << Removed reason: A self-signed certificate
    || die("Certificate Peer Verification Failed\n\nCertificate not trusted. This could be due to:\n  + An invalid certificate chain\n  + You are scanning the IP address and not the DNS hostname\n  + Host $host does not appear to be listening on port $port\n  + You misspelled the intended host to be scanned.\n  + The CA signing this cert is not trusted by your version of Mozilla::CA\n  + $!,$SSL_ERROR\n\nRun with the --insecure switch if you wish to test with no certificate verification\n\n");

  $certclient->verify_hostname($host, "http")
    || die("Hostname Verification Failed.\n$host does not match certificate's common name.\n\n");

  $x509 = get_cert($certclient);
  my @x509chain = get_chain($certclient);
  my $chain_length = scalar(@x509chain);
  # Whoops! This next line should not have been here...
  # say "Array x509chain is size: " . @x509chain.length;

  if ($chain_length le 1) {
    say "Certificate appears to be a self-signed certificate";
  } else {
    say "Certificate appears to be valid.";
  }
  
  my $cn = $certclient->peer_certificate("cn");
  if ( $cn eq "" ) {
    say "Certificate Common Name: none";
    }
    else {
      say "Certificate Commmon Name: " . $cn;
      }

  my @san = $certclient->peer_certificate("subjectAltNames");
  my $san_names = join(" ", grep { !( $_ eq 2 ) } @san);

  if ( $san_names eq "" ) {
    say "Subject Alternative Names: none";
    }
    else {
  say "Subject Alternative Names: " . $san_names;
  }

  get_cert_expiration_date();
  get_cert_sig_alg();
  $pkeybits = Net::SSLeay::EVP_PKEY_bits(Net::SSLeay::X509_get_pubkey($x509));
      if ( $pkeybits lt 2048 ) {
        print RED, "Certificate for $host uses a $pkeybits bit key\n", RESET;
    }
    else {
        print GREEN, "Certificate for $host uses a $pkeybits bit key\n", RESET;
    }

    if ( $sigalg eq "sha256WithRSAEncryption") {
        print GREEN, "Certificate Signature Algorithm is: $sigalg\n", RESET;
    }
    else {
      print RED, "Certificate Signature Algorithm is $sigalg\n", RESET;
    }

}

sub get_cert {
    my $certclient = shift()->_get_ssl_object || return;
    return Net::SSLeay::get_peer_certificate($certclient);
}

sub get_chain {
    my $certclient = shift()->_get_ssl_object || return;
    return Net::SSLeay::get_peer_cert_chain($certclient);
}

sub get_cert_expiration_date {
  $expiry = Net::SSLeay::X509_get_notAfter($x509);
  say "Certificate Expires On: " . Net::SSLeay::P_ASN1_TIME_get_isotime($expiry);
}

sub get_cert_sig_alg {
  $sigalg = Net::SSLeay::OBJ_obj2txt(Net::SSLeay::P_X509_get_signature_alg($x509));
}

sub test_ssl2_ciphers{

# OpenSSL >1.0 needs a different version string in order to run sslv2 checks
if ($openssl_ver ge '0x10000000') {
  $ssl2_version_string = 'SSLv23';
} 
else {
  $ssl2_version_string = 'SSLv2';
}

print "\nTesting SSLv2 Ciphers...\n";
sleep 2;
while (($key,$value) = each(%ssl2_ciphers)) {
  my $ssl2client = IO::Socket::SSL->new(
    SSL_verify_mode => 0x00,  
    SSL_version => $ssl2_version_string,
    SSL_cipher_list => $key,
    PeerAddr => $host,
    PeerPort => $port,
    Proto => 'tcp',
    Timeout => '5'
    )
  && is_insecure();
  }
}

sub test_ssl3_ciphers{
print "\nTesting SSLv3 Ciphers...\n";
sleep 2;
while (($key,$value) = each(%tls1_ciphers)) {
  my $ssl3client = IO::Socket::SSL->new(
    SSL_verify_mode => 0x00,
    SSL_version => 'SSLv3',
    SSL_cipher_list => $key,
    PeerAddr => $host,
    PeerPort => $port,
    Proto => 'tcp',
    Timeout => '5'
    )
  && is_insecure();
  }
}


sub test_tls_ciphers{
print "\nTesting TLSv1 Ciphers...\n";
sleep 2;
while (($key,$value) = each(%tls1_ciphers)) {
  my $tls1client = IO::Socket::SSL->new(
    SSL_verify_mode => 0x00,
    SSL_version => 'TLSv1',
    SSL_cipher_list => $key,
    PeerAddr => $host,
    PeerPort => $port,
    Proto => 'tcp',
    Timeout => '5'
    )
  && is_weak(); 
  }
}

sub test_tls12_ciphers{
print "\nTesting TLSv1.2 Ciphers...\n";
sleep 2;
while (($key,$value) = each(%tls12_ciphers)) {
  my $tls12client = IO::Socket::SSL->new(
    SSL_verify_mode => 0x00,
    SSL_version => 'TLSv12',
    SSL_cipher_list => $key,
    PeerAddr => $host,
    PeerPort => $port,
    Proto => 'tcp',
    Timeout => '5'
    )
  && is_weak(); 
  }
}


# Execute all the subroutines!!
  get_openssl_ver();

  if ($openssl_ver le '0x009080cf') {
    say "Your OpenSSL Version is REALLY OLD and doesn't\nsupport TLS Renegotitation. You should upgrade.\n";
  }

  if ($insecure ne 1) {
    cert_info();
    #key_length(); << To be removed in a later version
    }
  #key_length(); << To be removed in a later version
  test_ssl2_ciphers();
  test_ssl3_ciphers();
  test_tls_ciphers();

  if ($openssl_ver ge '0x10000000') {
    test_tls12_ciphers();
  }


__END__

=head1 TITLE

CryptoNark (aka cnark.pl)

=head1 VERSION

Version 0.4.9

=head1 DATE

July 7, 2013

=head1 AUTHOR

Chris Mahns  Contact me at: techstacks [at] gmail [dot] com. Or follow me on twitter: @techstacks

=head1 ATTRIBUTION

CryptoNark was originally based on sslthing.sh by blh [at] blh [dot] se

=head1 DESCRIPTION

CryptoNark (aka 'cnark.pl') is an SSL/TLS vulnerability remediation verification script. It was written to provide the web site administrator with a way to perform before and after testing of SSL/TLS remediation actions. It was not intended to be used as a hack tool.

=head1 USAGE

./cnark.pl -h|--host <hostname> -p|--port <port number> [-i|--insecure]

=head1 DEPENDENCIES

CryptoNark has been tested with perl 5.10, perl 5.12, and perl 5.14.  It makes use of perl functionality that was first introduced in Perl 5.10, so it will not run in perl 5.8 without some modifications. CyrptoNark also relies upon many CPAN modules: Modern::Perl, Term::ANSIColor, Tie::Hash::Indexed, IO::Socket::SSL, Mozilla::CA, and Getopt::Long. 


=head1 VERSION HISTORY

=head2 VERSION 0.1

Almost a direct port of sslthing, this version also tests null and anonymous ssl ciphers and reports accordingly.  A little more information is provided in the output. Works best if used to validate PCI-DSS compliance--to check that null, anonymous and weak ciphers are disabled.  

It probably will not run right "out of the box"--it requires IO::Socket::SSL.  Tie::Hash::Indexed, although not strictly required is nice to have in order to order the hash lists from strongest to weakest. Otherwise, the order could be random making the results a bit harder to read.

=head2 VERSION 0.2

+ Added Color Coded output. Good ciphers are green, bad ones are red.
 
=head2 VERSION 0.2.1

- Removed the SSLv3 Tests.  (Actually, just commented them out for now.)  SSLv3 and TLSv1 utilize the same ciphers so the tests are redundant.

+ Added a message after the display of cipher levels providing links to my site so that you can get information on disabling ciphers

=head2 VERSION 0.2.5

+ Added a HEAD request to display web server type.  Uses some addition modules:  LWP::UserAgent and HTTP::Headers

=head2 VERSION 0.3

+ "Upgraded" cnark to use perl 5.10 features.  Perl 5.10 is now required.

+ Modified script so that it uses command line options using Core Module Getopt::Long.  --host and --port should now be used.

- Removed exception catch on check_server_type() function. I don't think HEAD requests should ever fail but some sites restrict that method too for some reason.

+ cnark now tests for existence of HTTP Methods: TRACE and TRACK.

+ cnark will skip ssl scans if a non ssl port is used.

=head2 VERSION 0.3.1

- Code Clean up
     
+ Modern::Perl is now required

=head2 VERSION 0.3.5

+ Now scans for commonly used "unsafe" URLs. More to come.

=head2 VERSION 0.3.6
     
- Moved some stuff around.

+ Added SSLv3 tests back in.  This functionality was useful to some folks who were looking for output from specific protocols.

+ Added ColdFusion Administrator to unsafe URL check
     
+ Added Tomcat Status URL to unsafe URL Check

+ Tweaked the output for the unsafe URL Check to reduce some redundancy and add a false positive disclaimer. I Should be able to get rid of the disclaimer when better false positive checks are added

+ Added some basic certificate parsing

=head2 VERSION 0.4

+ Added option -xl|--kitchen-sink  By default, cnark.pl now performs ssl-only tests.  The -xl|kitchen-sink will put cryptonark in full betrayal mode.

+ Added Certificate Peer Verification (enabled by default) This causes cryptonark to fail on expired certs, missing root certificates, self-signed certs, and (I hope) invalid certificate chains. Certificate Validation is due to the inclusion of the ca-bundle.crt CA certificate bundle from mod_ssl.

+ Added --insecure option to disable peer verification if you so desire.

- Removed shameless plug

=head2 VERSION 0.4.1

+ There really is a CPAN module for everything!  Added Mozilla::CA, which enables me to utilize Certificate Peer Verification without having to re-distribute and maintain a cacerts file.

+ Added Hostname Validation.  CryptoNark will now fail if you attempt to connect to a site where the hostname does not match the $host argument.  For example, 

+ Doc Cleanup.  embedded pod.  You can now run 'perldoc cnark.pl' for an embedded man page

- Removed code for shameless plug subroutine.

=head2 VERSION 0.4.5

+ Added HTTP PropFind Test, which is executed if the -xl option is specified.

+ Add supporting module:  XML::LibXML

+ Disabled rediretion onthe unsafe URL checks.  This was creating some false positives.

=head2 VERSION 0.4.6

+ Fixed setting of URL to include value from --port variable.  This fixes a problem that had existed for a long time where certain tests would ignore the port argument and default to port 80 or 443.

+ Fixed a regression from an earlier v0.4 release where non-ssl ports were still being scanned for SSL info.

+ Fixed get_server_type function so that it correctly sets the $server_type global variable.

=head2 VERSION 0.4.7

+ Changed/Fixed: First pointed out to me by John Goggan (twitter: @johngoggan), passing the --insecure flag is still somewhat secure in that cryptonark will die if the hostname does not match the certificate common name. This version of cryptonark will not attempt to verify the host or the certificate if the --insecure flag is set.

+ New: CryptoNark will now output subject alternative names in addition to the certificate common name when the ssl certificate is validated.

=head2 VERSION 0.4.8

+ Changed User Agent to 'cryptonark-ssl-scantool' from 'cryptonark-pci-auditer'

+ Removed XML::LibXML, HTTP::Headers, and HTTP::Request Dependencies

+ Removed -xl option. (See next entry)

+ Removed all non-SSL related functions. CryptoNark will be just an ssl tool from now on.

+ Added some OpenSSL/Net::SSLeay version detection. If openssl is greater than or equal to verion 1.0.0, cryptonark will perform TLSv1.2 cipher scans.

+ Added elliptic curve (ECDH/ECDHE) cipher suites to SSLv3/TLSv1 scans. 

+ See http://blog.techstacks.com/cryptonark.html for Notes regarding running cryptonark on Ubuntu.

+ MD5 Ciphers are now flagged as weak.

+ Updated perldoc description, version info, usage, and dependencies.

+ To Do: Add new compliance patterns with corresponding switches like --fips or --rc4.

+ To Do: Add Secure TLS Renegotiation check.

+ To Do: Add way to read server cipher order.

=head2 VERSION 0.4.9

+ CryptoNark will now check the bit length of the public key on the target server and will warn if the length is less than 2048 bits.

+ Removed references to variables and other statements no longer needed when cnark was changed back into an ssl-only script.

=head2 Version 0.5

+ Self-Signed certs will no longer fail certificate validation nor cause a segmentation fault. Although I am still testing this, the assumption cryptonark v0.5 is making is that if there is only one certificate in the certificate chain, it is a self-signed certificate. This change is working around an issue reported to me on Free BSD systems where the certificate bit length on a self signed certificate would be 0 bits and then cryptonark would die with a segmentation fault.

+ Modified the DHE-* Cipher Strings to note that Forward Secrecy is supported on them. Thanks to Michael Rommel (@miro on Twitter) for the heads-up and education.

+ Added more OpenSSL version strings

+ Changed cert_info subroutine to use an AES256-SHA cipher from RC4-SHA.

+ Added subroutine to display certificate expiration

+ Add version check to see if openssl >= 0.9.8m and warn about using an unpatched, non RFC-5746 compliant version

=head2 VERSIOM 0.5.5

+ Added Windows support. (Only tested on Windows 8.1 with Strawberry perl)

+ Removed some debug code that inadvertently got left in the v0.5 release.

+ Added more OpenSSL version strings

+ Modified sslv2 scanning subroutine. On newer versions of openssl, some URLs were causing cryptonark on Windows to crash. Still getting some unexpected results on some hosts though like www.google.com and www.yahoo.com.

+ Modifed Weak Cipher regex to flag all RC4 ciphers as weak (to support industry-wide phase-out of RC4 ciphers). RC4-MD5 and RC4-SHA ciphers have been tagged to let the user know that there is an industry-initiative to phase these out of production use.

+ Modified regex to catch RC4 strings that only matched RC4-MD5 and RC4-SHA

=head2 VERSION 0.5.6

+ Colorization for all SSL3 ciphers has now been changed to red due to the POODLE vulnerability. (Yes, this could have been restricted to CBC-only ciphers under SSL3 and if I get enough feedback, I will be happy to change that)

+ Updated OpenSSL versions to include OpenSSL version released through October 15, 2014.

+ Added Signature Algorithm Check. Will color red on < SHA-2