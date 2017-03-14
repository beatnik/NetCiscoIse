#!/usr/bin/perl

use lib qw(../lib);
use Net::Cisco::ISE;
use Net::Cisco::ISE::NetworkDevice;
use Data::Dumper;

# users call only displayes a very limited set of information. Additional requests need to be made to retrieve explicit information
my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'admin', password => 'Secret');
my $device = Net::Cisco::ISE::NetworkDevice->new('name' => 'Router4');
$device->id("12345-12345-12345-22222");
$device->NetworkDeviceIPList({"NetworkDeviceIP" => [ { "ipaddress" => "10.10.0.4", "mask" => "32" } ] });
$device->NetworkDeviceGroupList( {"NetworkDeviceGroup" => [ "Device Type#All Device Types", "Location#All Locations" ] } );
print $ise->create($device);
print $Net::Cisco::ISE::ERROR;
print "Print enter to continue";
<STDIN>;
$device->description("New Description");
$device->NetworkDeviceIPList({"NetworkDeviceIP" => [ { "ipaddress" => "10.10.0.5", "mask" => "32" } ] });
$ise->update($device);
print $Net::Cisco::ISE::ERROR;
