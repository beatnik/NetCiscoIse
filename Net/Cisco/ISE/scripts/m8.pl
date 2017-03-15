#!/usr/bin/perl

use lib qw(../lib);
use Net::Cisco::ISE;
use Data::Dumper;


# users call only displayes a very limited set of information. Additional requests need to be made to retrieve explicit information
my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'admin', password => 'Secret');
print Dumper $ise->networkdevicegroups(id=>"8dc77530-08c8-11e7-a0a4-005056ad14a4");
