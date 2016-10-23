package Net::Cisco::ISE::IdentityGroup;
use strict;
use Moose;

BEGIN {
    use Exporter ();
    use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %actions);
    $VERSION     = '0.01';
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    @EXPORT_OK   = qw();
    %EXPORT_TAGS = ();
};

    %actions = (	"query" => "/ers/config/identitygroup/",
					"create" => "/ers/config/internaluser/",
               		"update" => "/ers/config/internaluser/",
                	"getById" => "/ers/config/internaluser/",
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

# No Moose	
	
sub toXML
{ my $self = shift;
  my $id = $self->id;
  my $description = $self->description || ""; 
  my $name = $self->name || "";
  my $result = "";
  
  if ($id) { $result = "   <id>$id</id>\n"; }
  $result .= <<XML;
   <description>$description</description>
   <name>$name</name>
XML

return $result;
}

sub header
{ my $self = shift;
  my $users = shift;
  return qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns2:identityGroups xmlns:ns2="identity.rest.mgmt.ise.nm.cisco.com">$users</ns2:identityGroups>};
}

=head1 NAME

Net::Cisco::ISE::IdentityGroup - Access Cisco ISE functionality through REST API - IdentityGroup (usergroup) fields

=head1 SYNOPSIS

	use Net::Cisco::ISE;
	use Net::Cisco::ISE::IdentityGroup;
	
	my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'iseadmin', password => 'testPassword');
	my $identitygroup = Net::Cisco::ISE::IdentityGroup->new("name"=>"All Groups:MilleniumCrew","description"=>"Han, Chewie, Finn and Rey");

	my %identitygroups = $ise->identitygroups;
	# Retrieve all identitygroups from ISE
	# Returns hash with name / Net::Cisco::ISE::IdentityGroup pairs
	
	print $ise->identitygroups->{"All Groups"}->toXML;
	# Dump in XML format (used by ISE for API calls)
	
	my $identitygroup = $ise->identitygroups("name","All Groups");
	# Faster call to request specific identity group information by name

	my $identitygroup = $ise->identitygroups("id","150");
	# Faster call to request specific identity group information by ID (assigned by ISE, present in Net::Cisco::ISE::IdentityGroup)
  
  	$identitygroup->id(0); # Required for new record!
	my $id = $ise->create($identitygroup);
	# Create new identity group based on Net::Cisco::ISE::IdentityGroup instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	my $id = $ise->update($identitygroup);
	# Update existing identitygroup based on Net::Cisco::ISE::IdentityGroup instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	$ise->delete($identitygroup);
	# Delete existing identity group based on Net::Cisco::ISE::IdentityGroup instance
  
=head1 DESCRIPTION

The Net::Cisco::ISE::IdentityGroup class holds all the user group relevant information from Cisco ISE 5.x. See also the C<identitygroup> method in L<Net::Cisco::ISE::User>.

=head1 USAGE

All calls are typically handled through an instance of the L<Net::Cisco::ISE> class. L<Net::Cisco::ISE::User> acts as a container for user related information.

=over 3

=item new

Class constructor. Returns object of Net::Cisco::ISE::IdentityGroup on succes. The following fields can be set / retrieved:

=over 5

=item description

=item name 

=item id

Formatting rules may be in place & enforced by Cisco ISE.

=back

=item description 

The identity group description.

=item name 

The identity group name. This is a required value in the constructor but can be redefined afterwards. This value typically starts with C<All Groups> as a parent group.

=item id

Cisco ISE generates a unique ID for each User record. This field cannot be updated within ISE but is used for reference. Set to 0 when creating a new record or when duplicating an existing identitygroup.

=item toXML

Dump the record in ISE accept XML formatting (without header).

=item header

Generate the correct XML header. Takes output of C<toXML> as argument.

=back

=head1 BUGS

None so far

=head1 SUPPORT

None so far :)

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

