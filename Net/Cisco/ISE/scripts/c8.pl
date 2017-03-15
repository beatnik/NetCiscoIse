#!/usr/bin/perl

use lib qw(../lib);
use Net::Cisco::ISE;
use Net::Cisco::ISE::NetworkDeviceGroup;
use Data::Dumper;

# users call only displayes a very limited set of information. Additional requests need to be made to retrieve explicit information
my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'admin', password => 'Secret');
my $devicegroup = Net::Cisco::ISE::NetworkDeviceGroup->new('name' => 'Location#All Locations#Berlin');
$devicegroup->id("12345-12345-12345-1111");
$devicegroup->type("Location");
$devicegroup->description("Berlin, Germany");
print $ise->create($devicegroup);
print $Net::Cisco::ISE::ERROR;

