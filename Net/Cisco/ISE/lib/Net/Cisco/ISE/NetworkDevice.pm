package Net::Cisco::ISE::NetworkDevice;
use strict;
use Moose;
use Data::Dumper;


BEGIN {
    use Exporter ();
    use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS %actions);
    $VERSION     = '0.03';
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    @EXPORT_OK   = qw();
    %EXPORT_TAGS = ();
};

    %actions = (	"query" => "/ers/config/networkdevice/",
					"create" => "/ers/config/networkdevice/",
               		"update" => "/ers/config/networkdevice/",
                	"getById" => "/ers/config/networkdevice/",
           ); 

# MOOSE!		   

has 'id' => (
     is  => 'rw',
     isa => 'Str',
  );

has 'name' => (
	is => 'rw',
	isa => 'Str',
	);
has 'description' => (
	is => 'rw',
	isa => 'Str',
);

has 'authenticationSettings' => (
	is => 'rw',
	isa => 'Any',
);

has 'coaPort' => (
	is => 'rw',
	isa => 'Str',
);

has 'profileName' => (
	is => 'rw',
	isa => 'Str',
);

has 'NetworkDeviceIPList' => (
	is => 'rw',
	isa => 'Any',
);

has 'NetworkDeviceGroupList' => (
	is => 'rw',
	isa => 'Any',
);

has 'modelName' => (
	is => 'rw',
	isa => 'Str',
);

has 'ProfileName' => (
	is => 'rw',
	isa => 'Str',
);

has 'softwareVersion' => (
	is => 'rw',
	isa => 'Str',
); 

has 'snmpsettings' => (
	is => 'rw',
	isa => 'Any',
);

has 'tacacsSettings' => (
	is => 'rw',
	isa => 'Any',
);

has 'trustsecsettings' => (
	is => 'rw',
	isa => 'Any',
);

# No Moose	

sub toXML
{ my $self = shift;
  my $result = "";
  my $id = $self->id;
  my $name = $self->name || "";
  my $description = $self->description || "";
  if ($self->authenticationSettings)
  { my $enablekeywrap = $self->authenticationSettings->{"enablekeywrap"} || "";
    my $keyencryptionkey = $self->authenticationSettings->{"keyencryptionkey"} || "";
    my $keyinputformat = $self->authenticationSettings->{"keyInputFormat"} || "";
    my $messageauthenticatorcodekey = $self->authenticationSettings->{"messageAuthenticatorCodeKey"} || "";
    my $networkprotocol = $self->authenticationSettings->{"networkProtocol"} || "";
    my $radiussharedsecret = $self->authenticationSettings->{"radiusSharedSecret"} || "";
    $result .= <<XML;
<authenticationSettings>
<enableKeyWrap>$enablekeywrap</enableKeyWrap>
<keyEncryptionKey>$keyencryptionkey</keyEncryptionKey>
<keyInputFormat>$keyinputformat</keyInputFormat>
<messageAuthenticatorCodeKey>$messageauthenticatorcodekey</messageAuthenticatorCodeKey>
<networkProtocol>$networkprotocol</networkProtocol>
<radiusSharedSecret>$radiussharedsecret</radiusSharedSecret>
</authenticationSettings>
XML

  } 
  my $coaport = $self->coaPort || "";
  $result .= "<coaPort>$coaport</coaPort>\n";
  if ($self->NetworkDeviceIPList) 
  { $result .= "<NetworkDeviceIPList>\n"; 
    my @networkdeviceiplist = @{ $self->NetworkDeviceIPList->{"NetworkDeviceIP"} };
    for my $networkdeviceiplist (@networkdeviceiplist)
    { my $ipaddress = $networkdeviceiplist->{"ipaddress"} || "";
      my $mask = $networkdeviceiplist->{"mask"} || "";
      $result .= <<XML;
<NetworkDeviceIP>
<ipaddress>$ipaddress</ipaddress>
<mask>$mask</mask>
</NetworkDeviceIP>
XML
    }
  $result .= "</NetworkDeviceIPList>\n"; 
  }
  
  if ($self->NetworkDeviceGroupList) 
  { $result .= "<NetworkDeviceGroupList>\n"; 
    my @networkdevicegrouplist = @{ $self->NetworkDeviceGroupList->{"NetworkDeviceGroup"} };
    for my $networkdevicegroup (@networkdevicegrouplist)
    { my $name = $networkdevicegroup || "";
      $result .= qq(<NetworkDeviceGroup>$name</NetworkDeviceGroup>\n);
    }
    $result .= "</NetworkDeviceGroupList>\n"; 
  }
  my $profilename = $self->profileName || "";
  $result .= "<profileName>$profilename</profileName>";
  if ($self->snmpsettings)
  { $result .= "<snmpsettings>\n";
    my $linktrapquery = $self->snmpsettings->{"linkTrapQuery"} || "";
    my $mactrapquery = $self->snmpsettings->{"macTrapQuery"} || "";
    my $originatingpolicyservicesnode = $self->snmpsettings->{"originatingPolicyServicesNode"} || "";
    my $pollinginterval = $self->snmpsettings->{"pollingInterval"} || "";
    my $rocommunity = $self->snmpsettings->{"roCommunity"} || "";
    my $version = $self->snmpsettings->{"version"} || "";
    my $authpassword = $self->snmpsettings->{"authPassword"} || "";
    my $privacyprotocol = $self->snmpsettings->{"privacyProtocol"} || "";
    my $securitylevel = $self->snmpsettings->{"securityLevel"} || ""; 
    my $authprotocol = $self->snmpsettings->{"authProtocol"} || "";
    my $username = $self->snmpsettings->{"userName"} || "";
    my $privacypassword = $self->snmpsettings->{"privacyPassword"} || "";
      $result .= <<XML;
<snmpsettings>
<linkTrapQuery>$linktrapquery</linkTrapQuery>
<macTrapQuery>$mactrapquery</macTrapQuery>
<originatingPolicyServicesNode>$originatingpolicyservicesnode</originatingPolicyServicesNode>
<pollingInterval>$pollinginterval</pollingInterval>
<roCommunity>$rocommunity</roCommunity>
<version>$version</version>
<authPassword>$authpassword</authPassword>
<privacyProtocl>$privacyprotocol</privacyProtocol>
<securityLevel>$securitylevel</securityLevel>
<authProtocol>$authprotocol</authProtocol>
<userName>$username</userName>
<privacyPassword>$privacypassword</privacyPassword>
</snmpsettings>
XML
  }

 if ($self->tacacsSettings)
 { my $connectmodeoptions = $self->tacacsSettings->{"connectModeOptions"} || "";
   my $sharedsecret = $self->tacacsSettings->{"sharedSecret"} || "";
   $result .= <<XML;
<tacacsSettings>
<connectModeOptions>$connectmodeoptions</connectModeOptions>
<sharedSecret>$sharedsecret</sharedSecret>
</tacacsSettings>
XML

  }

if ($self->trustsecsettings)
{ $result .= qq(<trustsecsettings>);
  if ($self->trustsecsettings->{"deviceAuthenticationSettings"})
  { my $sgadeviceid = $self->trustsecsettings->{"deviceAuthenticationSettings"}{"sgaDeviceId"} || "";
    my $sgadevicepassword = $self->trustsecsettings->{"deviceAuthenticationSettings"}{"sgaDevicePassword"} || "";
   $result .= <<XML;
<deviceAuthenticationSettings>
<sgaDeviceId>$sgadeviceid</sgaDeviceId>
<sgaDevicePassword>$sgadevicepassword</sgaDevicePassword>
</deviceAuthenticationSettings>
XML

  }
  if ($self->trustsecsettings->{"sgaNotificationAndUpdates"})
  { my $sendconfigurationtodeviceusing = $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"sendConfigurationToDeviceUsing"} || "";
    my $downloadpeerauthorizationpolicyeveryxseconds = $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"downlaodPeerAuthorizationPolicyEveryXSeconds"} || "";
    $downloadpeerauthorizationpolicyeveryxseconds ||= $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"downloadPeerAuthorizationPolicyEveryXSeconds"} || ""; 
    my $downloadsgaccllistseveryxseconds = $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"downloadSGACLListsEveryXSeconds"} || "";
    my $downloadenvironmentdataeveryxseconds = $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"downlaodEnvironmentDataEveryXSeconds"} || "";
    $downloadenvironmentdataeveryxseconds ||= $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"downloadEnvironmentDataEveryXSeconds"} || "";
    my $reauthenticationeveryxseconds = $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"reAuthenticationEveryXSeconds"} || "";
    my $sendconfigurationtodevice = $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"sendConfigurationToDevice"} || ""; 
    my $othersgadevicestotrustthisdevice = $self->trustsecsettings->{"sgaNotificationAndUpdates"}{"otherSGADevicesToTrustThisDevice"} || "";
   $result .= <<XML;
<sgaNotificationAndUpdates>
<sendConfigurationToDeviceUsing>$sendconfigurationtodeviceusing</sendConfigurationToDeviceUsing>
<downlaodPeerAuthorizationPolicyEveryXSeconds>$downloadpeerauthorizationpolicyeveryxseconds</downlaodPeerAuthorizationPolicyEveryXSeconds>
<downlaodEnvironmentDataEveryXSeconds>$downloadenvironmentdataeveryxseconds</downlaodEnvironmentDataEveryXSeconds>
<reAuthenticationEveryXSeconds>$reauthenticationeveryxseconds</reAuthenticationEveryXSeconds>
<sendConfigurationToDevice>$sendconfigurationtodevice</sendConfigurationToDevice>
<otherSGADevicesToTrustThisDevice>$othersgadevicestotrustthisdevice</otherSGADevicesToTrustThisDevice>
<downloadSGACLListsEveryXSeconds>$downloadsgaccllistseveryxseconds</downloadSGACLListsEveryXSeconds>
</sgaNotificationAndUpdates>
XML

  }
  if ($self->trustsecsettings->{"deviceConfigurationDeployment"})
  { my $includewhendeployingsgtupdates =  $self->trustsecsettings->{"deviceConfigurationDeployment"}{"includeWhenDeployingSGTUpdates"} || "";
    my $execmodeusername = $self->trustsecsettings->{"deviceConfigurationDeployment"}{"execModeUsername"} || "";
    my $enablemodepassword = $self->trustsecsettings->{"deviceConfigurationDeployment"}{"enableModePassword"} || "";
    my $execmodepassword = $self->trustsecsettings->{"deviceConfigurationDeployment"}{"execModePassword"} || "";
   $result .= <<XML;
<deviceConfigurationDeployment>
<includeWhenDeployingSGTUpdates></includeWhenDeployingSGTUpdates>
<execModeUsername>$execmodeusername</execModeUsername>
<enableModePassword>$enablemodepassword</enableModePassword>
<execModePassword>$execmodepassword</execModePassword>
</deviceConfigurationDeployment>
XML

  }
  $result .= qq(</trustsecsettings>\n);
}
# Not documented by Cisco ISE API:
# SNMP Settings: authPassword
# SNMP Settings: privacyProtocol
# SNMP Settings: securityLevel
# SNMP Settings: authProtocol
# SNMP Settings: userName
# SNMP Settings: privacyPassword
# TACACS Settings: previousSharedSecretExpiry - Probably not implemented for write operations
# TACACS Settings: previousSharedSecret - Probably not implemented for write operations

  return $result;
}

sub header
{ my $self = shift;
  my $data = shift;
  my $record = shift;
  my $name = $record->name || "";
  my $id = $record->id || "";
  my $description = $record->description || "";
  return qq{<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns4:networkdevice description="$description" name="$name" id="$id" xmlns:ers="ers.ise.cisco.com" xmslns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns4="network.ers.ise.cisco.com">$data</ns4:networkdevice>};
}

=pod

=head1 NAME

Net::Cisco::ISE::NetworkDevice - Access Cisco ISE functionality through REST API - NetworkDevice fields

=head1 SYNOPSIS

	use Net::Cisco::ISE;
	use Net::Cisco::ISE::NetworkDevice;
	
	my $ise = Net::Cisco::ISE->new(hostname => '10.0.0.1', username => 'acsadmin', password => 'testPassword');
	
	my %devices = $ise->networkdevices;
	# Retrieve all devices from ISE
	# Returns hash with device name / Net::Cisco::ISE::NetworkDevice pairs

	print $ise->devices->{"MAIN_Router"}->toXML;
	# Dump in XML format (used by ISE for API calls)
	
	my $device = $ise->devices("name","MAIN_Router");
	# Faster call to request specific device information by name

	my $device = $ise->networkdevices("id","b74a0ef2-b29c-afee-0001-4c013751ace9");
	# Faster call to request specific device information by ID (assigned by ISE, present in Net::Cisco::ISE::NetworkDevice)

	$device->id(0); # Required for new device!
	my $id = $ise->create($device);
	# Create new device based on Net::Cisco::ISE::NetworkDevice instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	my $id = $ise->update($device);
	# Update existing device based on Net::Cisco::ISE::NetworkDevice instance
	# Return value is ID generated by ISE
	print "Record ID is $id" if $id;
	print $Net::Cisco::ISE::ERROR unless $id;
	# $Net::Cisco::ISE::ERROR contains details about failure

	$ise->delete($device);
	# Delete existing device based on Net::Cisco::ISE::NetworkDevice instance

=head1 DESCRIPTION

The Net::Cisco::ISE::NetworkDevice class holds all the device relevant information from Cisco ISE 2.x

=head1 USAGE

All calls are typically handled through an instance of the L<Net::Cisco::ISE> class. L<Net::Cisco::ISE::NetworkDevice> acts as a container for device group related information.

=over 3

=item new

Class constructor. Returns object of Net::Cisco::ISE::NetworkDevice on succes. The following fields can be set / retrieved:

=over 5

=item description

=item id

=item name

=item authenticationSettings

=item enableKeyWrap

=item enabled

=item keyEncryptionKey

=item keyInputFormat

=item messageAuthenticatorCodeKey

=item networkProtocol

=item radiusSharedSecret

=item coaPort

=item ipList

=item ipaddress

=item mask

=item ndgList

=item modelName

=item softwareVersion

=item profileName

=item snmpsettings

=item linkTrapQuery

=item macTrapQuery

=item originatingPolicyServicesNode

=item pollingInterval

=item roCommunity

=item version

=item authPassword

=item privacyProtocol

=item securityLevel

=item authProtocol

=item userName

=item privacyPassword

=item tacacsSettings

=item connectModeOptions

=item sharedSecret

=item previousSharedSecretExpiry

=item previousSharedSecret

=item trustsecsettings

=item deviceAuthenticationSettings

=item sgaDeviceId

=item sgaDevicePassword

=item deviceConfigurationDeployment

=item enableModePassword

=item execModePassword

=item execModeUsername

=item includeWhenDeployingSGTUpdates

=item sgaNotificationAndUpdates

=item downlaodEnvironmentDataEveryXSeconds

=item downlaodPeerAuthorizationPolicyEveryXSeconds

=item downloadSGACLListsEveryXSeconds

=item otherSGADevicesToTrustThisDevice

=item reAuthenticationEveryXSeconds

=item sendConfigurationToDevice

=item sendConfigurationToDeviceUsing

=back

Formatting rules may be in place & enforced by Cisco ISE.

=over 3

=item description

The device description.

=item id

The device ID. Cisco ISE generates a unique ID for each Host record. This field cannot be updated within ISE but is used for reference. Set to 0 when creating a new record or when duplicating an existing host.

=item name

The device name, typically something like the sysName or hostname.

=item authenticationSettings

The authentication settings (enableKeyWrap, enabled, keyEncryptionKey, keyInputFormat, messageAuthenticatorCodeKey, networkProtocol, radiusSharedSecret). Values are returned in a hash reference (case-sensitive).

=item enableKeyWrap

=item enabled

=item keyEncryptionKey

=item keyInputFormat

=item messageAuthenticatorCodeKey

=item networkProtocol

=item radiusSharedSecret

=item coaPort

=item ipList

=item ipaddress

=item mask

=item ndgList

=item modelName

=item softwareVersion

=item profileName

=item snmpsettings

=item linkTrapQuery

=item macTrapQuery

=item originatingPolicyServicesNode

=item pollingInterval

=item roCommunity

=item version

=item authPassword *undocumented*

=item privacyProtocol *undocumented*

=item securityLevel *undocumented*

=item authProtocol *undocumented*

=item userName *undocumented*

=item privacyPassword *undocumented*

=item tacacsSettings

=item connectModeOptions

=item sharedSecret

=item previousSharedSecretExpiry *undocumented*

=item previousSharedSecret *undocumented*

=item trustsecsettings

=item deviceAuthenticationSettings

=item sgaDeviceId

=item sgaDevicePassword

=item deviceConfigurationDeployment

=item enableModePassword

=item execModePassword

=item execModeUsername

=item includeWhenDeployingSGTUpdates

=item sgaNotificationAndUpdates

=item downlaodEnvironmentDataEveryXSeconds

=item downlaodPeerAuthorizationPolicyEveryXSeconds

=item downloadSGACLListsEveryXSeconds

=item otherSGADevicesToTrustThisDevice

=item reAuthenticationEveryXSeconds

=item sendConfigurationToDevice

=item sendConfigurationToDeviceUsing

=item  toXML

Dump the record in ISE accept XML formatting (without header).

=item  header

Generate the correct XML header. Takes output of C<toXML> as argument.

=back

=over 3

=back

=back

=head1 BUGS

=head1 SUPPORT

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

