#!/usr/bin/perl

use lib qw(lib);
use Net::Cisco::ISE;
use Data::Dumper;

my $ise = Net::Cisco::ISE->new(hostname => '10.10.0.1', username => 'hendrikvb', password => 'Secret');
print Dumper $ise->portals;
