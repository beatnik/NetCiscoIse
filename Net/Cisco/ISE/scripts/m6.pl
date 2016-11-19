#!/usr/bin/perl

use lib qw(lib);
use Net::Cisco::ISE;
use Data::Dumper;


# users call only displayes a very limited set of information. Additional requests need to be made to retrieve explicit information
my $ise = Net::Cisco::ISE->new(hostname => '10.10.0.1', username => 'hendrikvb', password => 'Secret');
print Dumper $ise->networkdevices(id=>"3cc7de43-9b96-11e6-93fb-005056ad1454");
