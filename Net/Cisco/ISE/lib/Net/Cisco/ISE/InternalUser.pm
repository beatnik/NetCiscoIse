package Net::Cisco::ISE::InternalUser;
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

    %actions = (	"query" => "/ers/config/internaluser/",
        			"create" => "/ers/config/internaluser/",
               		"update" => "/ers/config/internaluser/",
                	"getById" => "/ers/config/internaluser/",
           ); 

# MOOSE!
		   
has 'email' => (
      is  => 'rw',
      isa => 'Any',
  );

has 'firstName' => (
	is => 'rw',
	isa => 'Str',
);

has 'lastName' => (
	is => 'rw',
	isa => 'Str',
);

has 'id' => (
      is  => 'rw',
      isa => 'Str',
  );

has 'identityGroups' => ( 
	is => 'rw',
	isa => 'Str',
	);

has 'name' => (
	is => 'rw',
	isa => 'Str',
	);

has 'changePassword' => ( 
	is => 'ro',
	isa => 'Str',
	);

#has 'customAttributes' => ( 
#	is => 'ro',
#	isa => 'ArrayRef',
#	auto_deref => '1',
#	);		

has 'expiryDateEnabled' => (
	is => 'rw',
	isa => 'Str',
	);

has 'expiryDate' => (
	is => 'rw',
	isa => 'Str',
);

has 'enablePassword' => (
	is => 'rw',
	isa => 'Str',
	);

has 'enabled' => (
	is => 'rw', 
	isa => 'Str',
	);

has 'password' => (
	is => 'rw',
	isa => 'Str',
	);

has 'passwordIDStore' => (
	is => 'rw',
	isa => 'Str',
	);

# No Moose	
	
sub toXML
{ my $self = shift;
  my $id = $self->id;
  my $identitygroups = $self->identityGroups || "";
  my $name = $self->name || "";
  my $changepassword = $self->changePassword || "false";
  my $enabled = $self->enabled || "true";
  my $password = $self->password || "";
  my $passwordidstore = $self->passwordIDStore || "Internal Users";
  my $enablepassword = $self->enablePassword || "";
  my $expirydate = $self->expirydate || "";
  my $expirydateenabled = $self->expiryDateEnabled || "false";
  my $lastname = $self->lastName || "";
  my $firstname = $self->firstName || "";
  my $email = $self->email || "";
  my $result = "";
  
  if ($id) { $result = "   <id>$id</id>\n"; }
  $result .= <<XML;
  <changePassword>$changepassword</changePassword>
  <customAttributes/>
  <email>$email</email>
  <enabled>$enabled</enabled>
  <firstName>$firstname</firstName>
  <identityGroups>$identitygroups</identityGroups>
  <lastName>$lastname</lastName>
  <password>$password</password> 
  <expiryDateEnabled>$expirydateenabled</expiryDateEnabled>
  <expiryDate>$expirydate</expiryDate>
  <name>$name</name>
  <passwordIDStore>$passwordidstore</passwordIDStore>
XML

return $result;
}

sub header
{ my $self = shift;
  my $internalusers = shift;
  return qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns3:internaluser description="description" name="name" id="id" xmlns:ns2="ers.ise.cisco.com" xmlns:ns3="identity.ers.ise.cisco.com">$internalusers</ns2:internaluser>};

}
	
=head1 NAME

Net::Cisco::ISE::InternalUser - Access Cisco ISE functionality through REST API - User fields

=head1 SYNOPSIS

	use Net::Cisco::ISE;
	use Net::Cisco::ISE::InternalUser;
  
	my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'iseadmin', password => 'testPassword');
	my $user = Net::Cisco::ISE::InternalUser->new("name"=>"soloh","description"=>"Han Solo","identityGroupName"=>"All Groups:MilleniumCrew","password"=>"Leia");

	my %users = $ise->internalusers;
	# Retrieve all users from ISE
	# Returns hash with username / Net::Cisco::ISE::InternalUser pairs
	
	print $ise->internalusers->{"iseadmin"}->toXML;
	# Dump in XML format (used by ISE for API calls)
	
	my $user = $ise->internalusers("name","iseadmin");
	# Faster call to request specific user information by name

	my $user = $ise->internalusers("id","150");
	# Faster call to request specific user information by ID (assigned by ISE, present in Net::Cisco::ISE::InternalUser)

	$user->id(0); # Required for new user!
	my $id = $ise->create($user);
	# Create new user based on Net::Cisco::ISE::InternalUser instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	my $id = $ise->update($user);
	# Update existing user based on Net::Cisco::ISE::InternalUser instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	$ise->delete($user);
	# Delete existing user based on Net::Cisco::ISE::InternalUser instance
	
=head1 DESCRIPTION

The Net::Cisco::ISE::InternalUser class holds all the user relevant information from Cisco ISE 5.x

=head1 USAGE

All calls are typically handled through an instance of the L<Net::Cisco::ISE> class. L<Net::Cisco::ISE::InternalUser> acts as a container for user related information.

=over 3

=item new

Class constructor. Returns object of Net::Cisco::ISE::InternalUser on succes. The following fields can be set / retrieved:

=over 5

=item description 

=item name 

=item identityGroupName

=item enablePassword

=item enabled

=item password

=item passwordNeverExpires

=item passwordType

=item dateExceeds

=item dateExceedsEnabled

=item id

Formatting rules may be in place & enforced by Cisco ISE.

=back

Read-only values:

=over 5

=item changePassword

=item created

=item attributeInfo

=item lastLogin

=item lastModified

=item lastPasswordChange

=item loginFailuresCounter

=back

=over 3

=item description 

The user account description, typically used for full name.

=item name 

The user account name. This is a required value in the constructor but can be redefined afterwards.

=item identityGroupName

The user group name. This is a required value in the constructor but can be redefined afterwards. See L<Net::Cisco::ISE::IdentityGroupName>.

=item enablePassword

The enable password (for Cisco-level access), not needed if you work with command sets in your access policies.

=item enabled

Boolean flag to indicate account status.

=item password

Password. When querying user account information, the password will be masked as *********. This is a required value in the constructor but can be redefined afterwards.

=item passwordNeverExpires

Boolean flag to indicate account expiration status.

=item passwordType

A read-only valie that indicates the password type, either for Internal User or Active Directory (needs confirmation).

=item dateExceeds

Date field to automatically deactivate the account once passed.

=item dateExceedsEnabled

Boolean flag to activate the automatic deactivation feature based on expiration dates.

=item id

Cisco ISE generates a unique ID for each User record. This field cannot be updated within ISE but is used for reference. Set to 0 when creating a new record or when duplicating an existing user.

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

