package pf::Switch::Ubiquiti::EdgeSwitch;


=head1 NAME

pf::Switch::Ubiquiti::EdgeSwitch

=head1 SYNOPSIS

pf::Switch::Ubiquiti::EdgeSwitch module manages access to EdgeSwitch

=head1 STATUS

Should work on the EdgeSwitch version started 1.7

=cut

use strict;
use warnings;
use pf::log;

use base ('pf::Switch::Ubiquiti');
use pf::util qw(clean_mac);
use pf::locationlog;
use pf::constants;
use pf::config qw(
    $WIRED_802_1X
    $WIRED_MAC_AUTH
);

sub description { 'EdgeSwitch' }

# importing switch constants
use pf::Switch::constants;

# CAPABILITIES
# access technology supported
use pf::SwitchSupports qw(
    WiredMacAuth
    WiredDot1x
    RadiusVoip
    RadiusDynamicVlanAssignment
    Lldp
);

=head2 isVoIPEnabled

Supports VoIP if enabled.

=cut

sub isVoIPEnabled {
    my ($self) = @_;
    return ( $self->{_VoIPEnabled} == 1 );
}

=head2 wiredeauthTechniques

Return the reference to the deauth technique or the default deauth technique.

=cut

sub wiredeauthTechniques {
    my ($self, $method, $connection_type) = @_;
    my $logger = $self->logger;
    if ($connection_type == $WIRED_802_1X) {
        my $default = $SNMP::SSH;
        my %tech = (
            $SNMP::SSH  => 'deauthenticateMacSSH',
            $SNMP::SNMP => 'dot1xPortReauthenticate',
        );

        if (!defined($method) || !defined($tech{$method})) {
            $method = $default;
        }
        return $method,$tech{$method};
    }
    if ($connection_type == $WIRED_MAC_AUTH) {
        my $default = $SNMP::SSH;
        my %tech = (
            $SNMP::SSH  => 'deauthenticateMacSSH',
            $SNMP::SNMP => 'handleReAssignVlanTrapForWiredMacAuth',
        );

        if (!defined($method) || !defined($tech{$method})) {
            $method = $default;
        }
        return $method,$tech{$method};
    }
}

=head2 dot1xPortReauthenticate


=cut

sub dot1xPortReauthenticate {
    my ($self, $ifIndex, $mac) = @_;

    return $self->_dot1xPortReauthenticate($ifIndex);
}

=head2 returnAuthorizeWrite

Return radius attributes to allow write access (supposed to work)

=cut

sub returnAuthorizeWrite {
    my ($self, $args) = @_;
    my $logger = $self->logger;
    my $radius_reply_ref;
    my $status;
    $radius_reply_ref->{'Cisco-AVPair'} = 'shell:priv-lvl=15';
    $radius_reply_ref->{'Reply-Message'} = "Switch enable access granted by PacketFence";
    $logger->info("User $args->{'user_name'} logged in $args->{'switch'}{'_id'} with write access");
    my $filter = pf::access_filter::radius->new;
    my $rule = $filter->test('returnAuthorizeWrite', $args);
    ($radius_reply_ref, $status) = $filter->handleAnswerInRule($rule,$args,$radius_reply_ref);
    return [$status, %$radius_reply_ref];

}

=head2 returnAuthorizeRead

Return radius attributes to allow read access (supposed to work)

=cut

sub returnAuthorizeRead {
    my ($self, $args) = @_;
    my $logger = $self->logger;
    my $radius_reply_ref;
    my $status;
    $radius_reply_ref->{'Cisco-AVPair'} = 'shell:priv-lvl=3';
    $radius_reply_ref->{'Reply-Message'} = "Switch read access granted by PacketFence";
    $logger->info("User $args->{'user_name'} logged in $args->{'switch'}{'_id'} with read access");
    my $filter = pf::access_filter::radius->new;
    my $rule = $filter->test('returnAuthorizeRead', $args);
    ($radius_reply_ref, $status) = $filter->handleAnswerInRule($rule,$args,$radius_reply_ref);
    return [$status, %$radius_reply_ref];
}


=head2 deauthenticateMacSSH

deauthenticate a MAC address from wireless network using SSH

=cut

sub deauthenticateMacSSH {
    my ( $self, ,$ifindex, $mac ) = @_;
    my $logger = $self->logger;

    if ( !$self->isProductionMode() ) {
        $logger->info("not in production mode ... we won't deauthenticate $mac");
        return 1;
    }

    if ( length($mac) != 17 ) {
        $logger->error("MAC format is incorrect ($mac). Should be xx:xx:xx:xx:xx:xx");
        return 1;
    }

    my $ssh;

    my $send_disconnect_to = $self->{'_ip'};
    # but if controllerIp is set, we send there
    if (defined($self->{'_controllerIp'}) && $self->{'_controllerIp'} ne '') {
        $logger->info("controllerIp is set, we will use controller $self->{_controllerIp} to perform deauth");
        $send_disconnect_to = $self->{'_controllerIp'};
    }

    eval {
        require Net::SSH2;
        $ssh = Net::SSH2->new();
        $ssh->connect($send_disconnect_to);
        $ssh->auth_password($self->{_cliUser},$self->{_cliPwd});
    };

    if ($@) {
        $logger->error("Unable to connect to ".$send_disconnect_to." using ".$self->{_cliTransport}.". Failed with $@");
        return;
    }

    $mac = uc($mac);
    my $locationlog_mac = locationlog_last_entry_mac($mac);
    my $port = $locationlog_mac->{'port'};

    $logger->info("Deauthenticating mac $mac on port $port");
    my $chan;

    # Initiate CLI
    my $cli_cmd = "cli";
    $SIG{ALRM} = sub { die "Timeout\n" };
    eval {
        alarm(15);
        for my $cli_attempt (0..10) {
            $chan = $ssh->channel();
            $chan->shell();

            $logger->warn("Sending CLI command '$cli_cmd' (attempt #$cli_attempt)");
            $chan->write("$cli_cmd\n");
            sleep(1);

            my $buf = "";
            $chan->read($buf, 2048);
            if (index($buf, "(UBNT)") != -1) {
                last;
            }
        }
        alarm(0);
    };
    if ($@) {
        chomp $@;
        if ($@ eq "Timeout") {
            $logger->error("Unable to execute command '$cli_cmd'");
        } else {
            die $@;
        }
    }

    # Deauthenticate the mac address
    my @commands = ("enable", "configure", "interface 0/$port", "shutdown", "no shutdown");
    foreach my $command (@commands) {
        $logger->warn("Sending CLI command '$command'");
        $chan->write("$command\n");
        sleep(0.25);
    }
    $logger->warn("Disconnecting from SSH");
    $ssh->disconnect();

    return 1;
}


=head2 getPhonesLLDPAtIfIndex

Return list of MACs found through LLDP on a given ifIndex.

If this proves to be generic enough, it could be promoted to L<pf::Switch>.
In that case, create a generic ifIndexToLldpLocalPort also.

=cut

sub getPhonesLLDPAtIfIndex {
    my ( $self, $ifIndex ) = @_;
    my $logger = $self->logger;
    my @phones;
    if ( !$self->isVoIPEnabled() ) {
        $logger->debug( "VoIP not enabled on switch "
                . $self->{_ip}
                . ". getPhonesLLDPAtIfIndex will return empty list." );
        return @phones;
    }
    my $oid_lldpRemPortId  = '1.0.8802.1.1.2.1.4.1.1.7';
    my $oid_lldpRemSysCapEnabled = '1.0.8802.1.1.2.1.4.1.1.12';

    if ( !$self->connectRead() ) {
        return @phones;
    }
    $logger->trace(
        "SNMP get_next_request for lldpRemSysCapEnabled: $oid_lldpRemSysCapEnabled");
    my $result = $self->{_sessionRead}
        ->get_table( -baseoid => $oid_lldpRemSysCapEnabled );
    foreach my $oid ( keys %{$result} ) {
        if ( $oid =~ /^$oid_lldpRemSysCapEnabled\.([0-9]+)\.([0-9]+)\.([0-9]+)$/ ) {
            if ( $ifIndex eq $2 ) {
                my $cache_lldpRemTimeMark     = $1;
                my $cache_lldpRemLocalPortNum = $2;
                my $cache_lldpRemIndex        = $3;
                if ( $self->getBitAtPosition($result->{$oid}, $SNMP::LLDP::TELEPHONE) ) {
                    $logger->trace(
                        "SNMP get_request for lldpRemPortId: $oid_lldpRemPortId.$cache_lldpRemTimeMark.$cache_lldpRemLocalPortNum.$cache_lldpRemIndex"
                    );
                    my $MACresult = $self->{_sessionRead}->get_request(
                        -varbindlist => [
                            "$oid_lldpRemPortId.$cache_lldpRemTimeMark.$cache_lldpRemLocalPortNum.$cache_lldpRemIndex"
                        ]
                    );
                    if ($MACresult
                        && ($MACresult->{
                                "$oid_lldpRemPortId.$cache_lldpRemTimeMark.$cache_lldpRemLocalPortNum.$cache_lldpRemIndex"
                            }
                            =~ /^([0-9A-Z]{2})([0-9A-Z]{2})([0-9A-Z]{2})([0-9A-Z]{2})([0-9A-Z]{2})([0-9A-Z]{2})/i
                        )
                        )
                    {
                        push @phones, lc("$1:$2:$3:$4:$5:$6");
                    }
                }
            }
        }
    }
    return @phones;
}

=head2 getBitAtPosition - returns the bit at the position specified

The input must be the untranslated raw result of an snmp get_table

=cut

# TODO move out to a util package


sub getBitAtPosition {
   my ($self, $bitStream, $position) = @_;
   #Expect the hex stream
   if ($bitStream =~ /^0x/) {
       $bitStream =~ s/^0x//i;
       my $bin = join('',map { unpack("B4",pack("H",$_)) } (split //, $bitStream));
       return substr($bin, $position, 1);
   } else {
       my $bin = substr(unpack('B*', $bitStream), -8);
       return substr($bin, $position, 1);
   }
}

=head2 getVoipVSA

Get Voice over IP RADIUS Vendor Specific Attribute (VSA).

=cut

sub getVoipVsa {
    my ($self) = @_;
    return (
    );
}

=item parseRequest

=cut

sub parseRequest {
    my ( $self, $radius_request ) = @_;

    my $client_mac      = ref($radius_request->{'Calling-Station-Id'}) eq 'ARRAY'
                           ? clean_mac($radius_request->{'Calling-Station-Id'}[0])
                           : clean_mac($radius_request->{'Calling-Station-Id'});
    my $user_name       = $self->parseRequestUsername($radius_request);
    my $nas_port_type   = ( defined($radius_request->{'NAS-Port-Type'}) ? $radius_request->{'NAS-Port-Type'} : "virtual" );
    my $port            = $radius_request->{'NAS-Port'};
    my $eap_type        = ( exists($radius_request->{'EAP-Type'}) ? $radius_request->{'EAP-Type'} : 0 );
    my $nas_port_id     = ( defined($radius_request->{'NAS-Port-Id'}) ? $radius_request->{'NAS-Port-Id'} : undef );

    return ($nas_port_type, $eap_type, $client_mac, $port, $user_name, $nas_port_id, undef, $nas_port_id);
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2023 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
