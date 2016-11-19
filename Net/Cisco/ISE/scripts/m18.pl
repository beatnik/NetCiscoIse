#!/usr/bin/perl

use lib qw(lib);
use Net::Cisco::ISE;
use Data::Dumper;

my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'hendrikvb', password => 'Secret');
print Dumper $ise->profiles(id=>"0a816bc0-222f-11e6-99ab-005056bf55e0");
