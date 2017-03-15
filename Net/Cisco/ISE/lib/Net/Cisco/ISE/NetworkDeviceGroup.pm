package Net::Cisco::ISE::NetworkDeviceGroup;
use strict;
use Moose;
use Data::Dumper;

BEGIN {
    use Exporter ();
    use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %actions);
    $VERSION     = '0.01';
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    @EXPORT_OK   = qw();
    %EXPORT_TAGS = ();
};

    %actions = (	"query" => "/ers/config/networkdevicegroup/",
			"create" => "/ers/config/networkdevicegroup/",
               		"update" => "/ers/config/networkdevicegroup/",
                	"getById" => "/ers/config/networkdevicegroup/",
           ); 

# MOOSE!		   
	   
has 'description' => (
      is  => 'rw',
      isa => 'Any',
  );

has 'id' => (
      is  => 'rw',
      isa => 'Str',
  );

has 'name' => (
	is => 'rw',
	isa => 'Str',
	);

has 'type' => (
	is => 'rw',
	isa => 'Str',
	);

# No Moose	

sub toXML
{ my $self = shift;
  my $result = "";
  my $id = $self->id;
  my $description = $self->description || "";
  my $name = $self->name || "";
  my $type = $self->type || "Location";
  if ($id) { $result = "   <id>$id</id>\n"; }
  
  $result = <<XML;
<type>$type</type>
XML

  return $result;
}

sub header
{ my $self = shift;
  my $data = shift;
  my $record = shift;
  my $name = $record->name || "Device Group Name";
  my $id = $record->id || "";
  my $description = $record->description || "Random Description";

  return qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns4:networkdevicegroup description="$description" name="$name" id="$id" xmlns:ers="ers.ise.cisco.com" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns4="network.ers.ise.cisco.com">$data</ns4:networkdevicegroup>};

}


=head1 NAME

Net::Cisco::ISE::NetworkDeviceGroup - Access Cisco ISE functionality through REST API - DeviceGroup fields

=head1 SYNOPSIS

	use Net::Cisco::ISE;
	use Net::Cisco::ISE::NetworkDeviceGroup;
	
	my $acs = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'acsadmin', password => 'testPassword');
	
	my %devicegroups = $acs->networkdevicegroups;
	# Retrieve all device groups from ISE
	# Returns hash with device name / Net::Cisco::ISE::NetworkDeviceGroup pairs

	print $acs->networkdevicegroups->{"All Locations"}->toXML;
	# Dump in XML format (used by ISE for API calls)
	
	my $device = $acs->networkdevicegroups("name","All Locations");
	# Faster call to request specific device group information by name

	my $networkdevicegroup = $acs->networkdevicegroups("id","250");
	# Faster call to request specific device group information by ID (assigned by ISE, present in Net::Cisco::ISE::NetworkDeviceGroup)

	$networkdevicegroup->id(0); # Required for new device group!
	my $id = $acs->create($networkdevicegroup);
	# Create new device group based on Net::Cisco::ISE::NetworkDeviceGroup instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	my $id = $acs->update($networkdevicegroup);
	# Update existing device based on Net::Cisco::ISE::NetworkDeviceGroup instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	$acs->delete($networkdevicegroup);
	# Delete existing device based on Net::Cisco::ISE::NetworkDeviceGroup instance
	
=head1 DESCRIPTION

The Net::Cisco::ISE::NetworkDeviceGroup class holds all the device group relevant information from Cisco ISE 5.x

=head1 USAGE

All calls are typically handled through an instance of the L<Net::Cisco::ISE> class. L<Net::Cisco::ISE::NetworkDeviceGroup> acts as a container for device group related information.

=over 3

=item new

Class constructor. Returns object of Net::Cisco::ISE::NetworkDeviceGroup on succes. The following fields can be set / retrieved:

=over 5

=item description 

=item name 

=item id

=item groupType

Formatting rules may be in place & enforced by Cisco ISE.

=back

=over 3

=item description 

The device group account description, typically used for full device group name.

=item name 

The device group name. This is a required value in the constructor but can be redefined afterwards.

=item groupType

This points to the type of Device Group, typically Location or Device Type but can be customized. See also L<Net::Cisco::ISE::NetworkDevice> C<deviceType>.

=item id

Cisco ISE generates a unique ID for each Device Group record. This field cannot be updated within ISE but is used for reference. Set to 0 when creating a new record or when duplicating an existing device group.

=item toXML

Dump the record in ISE accept XML formatting (without header).

=item header

Generate the correct XML header. Takes output of C<toXML> as argument.

=back

=back

=head1 BUGS

None yet

=head1 SUPPORT

None yet :)

=head1 AUTHOR

    Hendrik Van Belleghem
    CPAN ID: BEATNIK
    hendrik.vanbelleghem@gmail.com

=head1 COPYRIGHT

This program is free software licensed under the...

	The General Public License (GPL)
	Version 2, June 1991

The full text of the license can be found in the
LICENSE file included with this module.


=head1 SEE ALSO

perl(1).

=cut

#################### main pod documentation end ###################
__PACKAGE__->meta->make_immutable();

1;
# The preceding line will help the module return a true value

