#!/usr/bin/perl

use lib qw(../lib);
use Net::Cisco::ISE;
use Net::Cisco::ISE::NetworkDeviceGroup;
use Data::Dumper;

# users call only displayes a very limited set of information. Additional requests need to be made to retrieve explicit information
my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'admin', password => 'Secret');
my $devicegroup = Net::Cisco::ISE::NetworkDeviceGroup->new('name' => 'Location#All Locations#Rome');
$devicegroup->id("12345-12345-12345-2222");
$devicegroup->type("Location");
$devicegroup->description("Roma, Italy");
print $ise->create($devicegroup);
my $id = $Net::Cisco::ISE::ERROR;
print "Press enter to continue";
<STDIN>;
print Dumper $devicegroup;
print "Press enter to continue";
$devicegroup->description("Rome, Italy");
$ise->update($devicegroup);
print $Net::Cisco::ISE::ERROR;

