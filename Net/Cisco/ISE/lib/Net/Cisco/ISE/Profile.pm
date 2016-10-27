package Net::Cisco::ISE::Profile;
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

    %actions = (	"query" => "/ers/config/profilerprofile/",
			"create" => "/ers/config/profilerprofile/",
               		"update" => "/ers/config/profilerprofile/",
                	"getById" => "/ers/config/profilerprofile/",
           ); 

# MOOSE!		   
	   
has 'id' => (
      is  => 'rw',
      isa => 'Any',
  );

has 'identityStore' => (
      is  => 'rw',
      isa => 'Any',
  );
  
has 'identityStoreId' => (
	is => 'rw',
	isa => 'Any',
);

has 'customAttributes' => (
	is => 'rw',
	isa => 'Any',
);

has 'groupId' => (
	is => 'rw',
	isa => 'Any',
);

has 'portalUser' => (
	is => 'rw',
	isa => 'Any',
);

has 'profileId' => (
	is => 'rw',
	isa => 'Any',
);

has 'staticGroupAssignment' => (
	is => 'rw',
	isa => 'Any',
);

has 'staticProfileAssignment' => (
	is => 'rw',
	isa => 'Any',
);

has 'macAddress' => ( 
      is  => 'rw',
      isa => 'Any',
  );
  
# No Moose	

sub toXML
{ my $self = shift;
  my $result = "";
  my $id = $self->id;
  my $description = $self->description || "";
  my $identitygroupname = $self->identityGroupName || "All Groups";
  my $enabled = $self->enabled || "true";
  my $lastenabled = $self->lastEnabled || "";
  my $lastmodified = $self->lastModified || "";  
  my $macaddress = $self->macAddress || "";    
  if ($id) { $result = "   <id>$id</id>\n"; }
  $result = <<XML;
	<description>$description</description>
	<identityGroupName>$identitygroupname</identityGroupName>
	<enabled>$enabled</enabled>
	<macAddress>$macaddress</macAddress>
XML

  return $result;
}

sub header
{ my $self = shift;
  my $hosts = shift;
  return qq(<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns2:hosts xmlns:ns2="identity.rest.mgmt.ise.nm.cisco.com">$hosts</ns1:hosts>);
}
	
=head1 NAME

Net::Cisco::ISE::Endpoint - Access Cisco ISE functionality through REST API - Endpoint fields

=head1 SYNOPSIS

	use Net::Cisco::ISE;
	use Net::Cisco::ISE::Endpoint;

	my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'iseadmin', password => 'testPassword');
	my $host = Net::Cisco::ISE::Endpoint->new(macAddress=>"00-00-00-00-00-00", "description"=>"R2D2","identityGroupName"=>"All Groups:Droids");
	
	my %hosts = $ise->hosts;
	# Retrieve all hosts from ISE
	# Returns hash with host macAddress / Net::Cisco::ISE::Endpoint pairs

	print $ise->hosts->{"00-00-00-00-00-00"}->toXML;
	# Dump in XML format (used by ISE for API calls)
	
	my $host = $ise->hosts("macAddress","00-00-00-00-00-00");
	# Faster call to request specific host information by MAC Address. No name field exists.

	my $host = $ise->hosts("id","250");
	# Faster call to request specific hosts information by ID (assigned by ISE, present in Net::Cisco::ISE::Endpoint)

	$host->id(0); # Required for new host!
	my $id = $ise->create($host);
	# Create new host based on Net::Cisco::ISE::Endpoint instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	my $id = $ise->update($host);
	# Update existing device based on Net::Cisco::ISE::Endpoint instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	$ise->delete($host);
	# Delete existing host based on Net::Cisco::ISE::Endpoint instance
  
=head1 DESCRIPTION

The Net::Cisco::ISE::Endpoint class holds all the Internal Endpoint relevant information from Cisco ISE 5.x. Endpoints (in this case) are not to be confused with L<Net::Cisco::ISE::Device>. Endpoints are used as an identity item, in case of e.g dot1x configurations.

=head1 USAGE

The Net::Cisco::ISE::Endpoint class holds all the user relevant information from Cisco ISE 5.x

=head1 USAGE

All calls are typically handled through an instance of the L<Net::Cisco::ISE> class. L<Net::Cisco::ISE::Endpoint> acts as a container for host identity related information.

=over 3

=item new

Class constructor. Returns object of L<Net::Cisco::ISE::Endpoint> on succes. The following fields can be set / retrieved:

=over 5

=item description

=item enabled

=item identityGroupName

=item macAddress

=item id

Formatting rules may be in place & enforced by Cisco ISE.

=back

Read-only values:

=over 5

=item created

=item lastModified

=item lastEnabled

=back

=over 3

=item description 

The host description, typically used for host name. This is the only text-field for this record type.

=item enabled

Boolean flag to indicate record status.

=item macAddress

MAC Address for host. Used for actual identification.

=item id

Cisco ISE generates a unique ID for each Endpoint record. This field cannot be updated within ISE but is used for reference. Set to 0 when creating a new record or when duplicating an existing host.

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

