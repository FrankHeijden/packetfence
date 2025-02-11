#!/usr/bin/perl

=head1 NAME

to-11.0-no-slash-32-switches -

=head1 DESCRIPTION

to-11.0-no-slash-32-switches

=cut

use strict;
use warnings;
use lib qw(/usr/local/pf/lib);
use lib qw(/usr/local/pf/lib_perl/lib/perl5);
use pf::IniFiles;
use NetAddr::IP;
use pf::util qw(valid_ip valid_mac run_as_pf);
use pf::file_paths qw(
    $switches_config_file
);
use File::Copy;

run_as_pf();

my $file = $switches_config_file;

if (@ARGV) {
    $file = $ARGV[0];
}

our %types = (
    'Cisco::Catalyst_2950' => 'Cisco::Cisco_IOS_12_x',
    'Cisco::Catalyst_2960' => 'Cisco::Cisco_IOS_15_0',
);

my $cs = pf::IniFiles->new(-file => $file, -allowempty => 1);

my $update = 0;
for my $section ($cs->Sections()) {
    my $type = $cs->val($section, 'type');
    next if !defined $type || !exists $types{$type};
    my $new_type = $types{$type};
    $cs->setval($section, 'type', $new_type);
    $update |= 1;
}

if ($update) {
    $cs->RewriteConfig();
    print "All done\n";
    exit 0;
}


print "Nothing to be done\n";

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

