# See bottom of file for license and copyright information
#
# See Plugin topic for history and plugin information

=begin TML

---+ package Foswiki::Plugins::AntiWikiSpamPlugin

AntiWikiSpam plugin uses the shared Anti-spam regex list to 
check topic text when saving, refusing to save if it finds a match.

=cut

package Foswiki::Plugins::AntiWikiSpamPlugin;

use Error qw(:try);
use strict;

require Foswiki::Func;       # The plugins API
require Foswiki::Plugins;    # For the API version

our $VERSION           = '1.93';
our $RELEASE           = '1.93';
our $SHORTDESCRIPTION  = 'Lightweight wiki spam prevention';
our $NO_PREFS_IN_TOPIC = 1;

#### Plugin handlers

sub initPlugin {
    my ( $topic, $web, $user, $installWeb ) = @_;

    if (   $user eq $Foswiki::cfg{DefaultUserLogin}
        && $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulCount}
        && $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulWebs}
        && $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{IgnoredTopics} )
    {
        if ( $web =~
            /$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulWebs}/
            && $topic !~
            m/$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{IgnoredTopics}/ )
        {
            my $uhist = Foswiki::Func::getSessionValue('userHistory') || '';
            my @hist = split( /:/, $uhist );
            shift @hist
              if (
                scalar @hist >
                $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulCount} +
                5 );
            push( @hist, "$web.$topic" );
            $uhist = join( ':', @hist );
            Foswiki::Func::setSessionValue( 'userHistory', $uhist );
        }
    }

    #forceUpdate
    Foswiki::Func::registerRESTHandler(
        'forceUpdate', \&_RESTforceUpdate,
        validate => 0,

    # SMELL: Foswiki 1.1.x is broken - in CLI environment.
    # It checks for authentication, and sets the script name as the method.
    # Code still requires Admin authority, so it's safe to disable these checks.
        authenticate => 0,
        http_allow   => 'REST,POST',
        description  => 'Run a manual update of the spam regular expressions.',
    );

    Foswiki::Func::registerRESTHandler(
        'removeUser', \&_RESTremoveUser,
        authenticate => 1,
        validate     => $Foswiki::cfg{Validation}{Method} eq 'none' ? 0 : 1,
        http_allow   => 'POST',
        description  => 'Allow administrators to remove registered users.',

    );

    return 1;
}

sub beforeSaveHandler {
    if ( defined $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckTopics} ) {
        return
          unless ( $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckTopics} );
    }
    require Foswiki::Plugins::AntiWikiSpamPlugin::Core;
    return Foswiki::Plugins::AntiWikiSpamPlugin::Core::beforeSaveHandler(@_);
}

sub beforeAttachmentSaveHandler {
    if ( defined $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckAttachments} )
    {
        return
          unless (
            $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckAttachments} );
    }
    require Foswiki::Plugins::AntiWikiSpamPlugin::Core;
    return
      Foswiki::Plugins::AntiWikiSpamPlugin::Core::beforeAttachmentSaveHandler(
        @_);
}

# Handler for $Foswiki::Plugins::VERSION 2.3 and later
sub validateRegistrationHandler {
    if (
        defined $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckRegistrations} )
    {
        return
          unless (
            $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckRegistrations} );
    }
    require Foswiki::Plugins::AntiWikiSpamPlugin::Core;
    return
      Foswiki::Plugins::AntiWikiSpamPlugin::Core::validateRegistrationHandler(
        @_);
}

# Check a registration to see if the email address used is blacklisted
sub registrationHandler {
    return
      if $Foswiki::Plugins::VERSION >=
      2.3;    # 2.3 uses validateRegistrationHandler

    if (
        defined $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckRegistrations} )
    {
        return
          unless (
            $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckRegistrations} );
    }
    require Foswiki::Plugins::AntiWikiSpamPlugin::Core;
    return Foswiki::Plugins::AntiWikiSpamPlugin::Core::registrationHandler(@_);
}

=begin TML

---+ REST handlers
---++ =sub _RESTforceUpdate=


Can be used to force an update of the spam list

Must be called using POST.

=cut

sub _RESTforceUpdate {
    require Foswiki::Plugins::AntiWikiSpamPlugin::Core;
    return Foswiki::Plugins::AntiWikiSpamPlugin::Core::_RESTforceUpdate(@_);
}

=begin TML

---++ =sub _RESTremoveuser=


Remove a user. Expunge them utterly.

Passed with param: user, which can be a wikiname or a login name

Calls the removeUser function to remove the registration
   * Moves the user topic to SuspectSpammer
   * Must be called using POST.

=cut

sub _RESTremoveUser {
    require Foswiki::Plugins::AntiWikiSpamPlugin::Core;
    return Foswiki::Plugins::AntiWikiSpamPlugin::Core::_RESTremoveUser(@_);
}

1;
__END__
Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2005-2009 Sven Dowideit SvenDowideit@wikiring.com
Copyright (C) 2009-2015 George Clark and Foswiki Contributors
Copyright (C) 2012 Crawford Currie http://c-dot.co.uk

AntiWikiSpamPlugin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

For licensing info read LICENSE file in the Foswiki root.
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

As per the GPL, removal of this notice is prohibited.
