# See bottom of file for license and copyright information
package Foswiki::Plugins::AntiWikiSpamPlugin::Core;

use Error qw(:try);
use strict;

require Foswiki::Func;            # The plugins API
require Foswiki::Plugins;         # For the API version
require Foswiki::LoginManager;    # Use static routine to delete sessions

our $pluginName = 'AntiWikiSpamPlugin';
my $bypassFail   = 0;
my $hitThreshold = undef;
my $hits;

# Caches of registration white- and black- lists
our $regoWhite;
our $regoBlack;

use constant MONITOR => 0;

sub beforeSaveHandler {

    # do not uncomment, use $_[0], $_[1]... instead
    ### my ( $text, $topic, $web ) = @_;

    _getPluginPrefs();    # Process preference settings for the plugin

    _writeDebug("beforeSaveHandler( $_[2].$_[1] ) ");
    _downloadRegexUpdate();
    $hits = 0;
    _checkText( $_[2], $_[1], $_[0] );
    return;
}

sub beforeAttachmentSaveHandler {
    ### my ( $attachmentAttr, $topic, $web ) = @_;
    my $attachmentName = $_[0]->{'attachment'};
    my $tmpFilename    = $_[0]->{'tmpFilename'};
    my $text           = Foswiki::Func::readFile($tmpFilename);
    my $wikiName       = Foswiki::Func::getWikiName();

    _getPluginPrefs();

    #SMELL:  This is probably worthtess:
    # - It is extremely costly to regex scan large attachments
    # - It does nothing to address obfuscated scripts
    # - As of version 1.6, disabled by default.

    #from BlackListPlugin
    # check for evil eval() spam in <script>
    if ( $text =~ /<script.*?eval *\(.*?<\/script>/gis )
    {    #TODO: there's got to be a better way to do this.
        Foswiki::Func::writeWarning(
"detected possible javascript exploit by $wikiName at attachment in in $_[2].$_[1]  bypass = $bypassFail"
        );
        if (
            !$bypassFail &&    # User is not in trusted group
            $hitThreshold > 0
          )
        {                      # and Sensitivity not set to simulate

            throw Foswiki::OopsException(
                'attention',
                def   => 'attach_error',
                web   => $_[2],
                topic => $_[1],
                params =>
'The attachment has been rejected as it contains a possible javascript eval exploit.'
            );
        }
    }

    _downloadRegexUpdate();
    $hits = 0;
    _checkText( $_[2], $_[1], $text );
    return;
}

sub validateRegistrationHandler {
    my $data = shift;

    # $data contains at least: WikiName FirstName LastName Email
    # May also contain: Photo Password Confirm AddToGroups
    # Anything else is not used by Registration
    # To spoil the party for a spam registration, check the email address
    # against a blacklist.
    require Socket;

    my ( $user, $domain ) = split( /@/, $data->{Email}, 2 );
    my $packed_ip;
    my $ipad;

    unless ($regoWhite) {
        $regoWhite = _loadRegexList(
            $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{RegistrationWhiteList} );
    }
    my $white = 0;
    foreach my $rego (@$regoWhite) {
        print STDERR "Check domain '$domain' in whitelist /$rego/\n" if MONITOR;
        if ( $domain =~ /$rego/i ) {
            print STDERR "matches $rego\n" if MONITOR;
            $white = 1;
            last;
        }
    }
    if ( !$white && $domain ) {
        $packed_ip = gethostbyname($domain);
        $ipad = $packed_ip ? Socket::inet_ntoa($packed_ip) : undef;
        if ($ipad) {
            foreach my $rego (@$regoWhite) {
                print STDERR "Check IP $ipad in whitelist $rego\n" if MONITOR;
                if ( $ipad =~ /$rego/ ) {
                    print STDERR "matches $rego\n" if MONITOR;
                    $white = 1;
                    last;
                }
            }
        }
    }

    my $black = 0;
    if ($white) {
        unless ($regoBlack) {
            $regoBlack =
              _loadRegexList( $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}
                  {RegistrationBlackList} );
        }
        foreach my $rego (@$regoBlack) {
            print STDERR "Check domain $domain in blacklist $rego\n" if MONITOR;
            if ( $domain =~ /$rego/i ) {
                print STDERR "matches $rego\n" if MONITOR;
                $black = 1;
                last;
            }
        }
        if ( !$black && $domain ) {
            unless ($packed_ip) {
                $packed_ip = gethostbyname($domain);
                $ipad = $packed_ip ? Socket::inet_ntoa($packed_ip) : undef;
            }
            if ($ipad) {
                foreach my $rego (@$regoBlack) {
                    print STDERR "Check IP $ipad in blacklist $rego\n"
                      if MONITOR;
                    if ( $ipad =~ /$rego/ ) {
                        print STDERR "matches $rego\n" if MONITOR;
                        $black = 1;
                        last;
                    }
                }
            }
        }
    }
    print STDERR "white: $white black: $black\n" if MONITOR;
    unless ( $white && !$black ) {
        print STDERR "REJECTED\n" if MONITOR;
        $Foswiki::Plugins::SESSION->logger->log( 'warning',
"Registration of $data->{WikiName} ($data->{Email}) rejected by AntiWikiSpamPlugin: white: $white black: $black"
        );
        throw Error::Simple("'$data->{Email}' triggered the spam filter");
    }
}

# not require >= plugins 2.3
sub registrationHandler {
    my ( $web, $wikiName, $loginName, $data ) = @_;
    my $error;

    try {
        validateRegistrationHandler($data);
    }
    catch Error with {
        $error = shift;
    };

    return unless ($error);

    # Remove the user
    my ( $m, $lm ) = _removeUser( $data->{WikiName} );

    require Foswiki::OopsException;
    $Foswiki::Plugins::SESSION->logger->log( 'warning',
"Registration of $data->{WikiName} ($data->{Email}) rejected by AntiWikiSpamPlugin"
    );
    throw Foswiki::OopsException(
        'attention',
        web    => $data->{webName},
        topic  => $data->{WikiName},
        def    => 'registration_disabled',
        params => ["'$data->{Email}' triggered the spam filter"]
    );
}

sub _RESTforceUpdate {

    unless ( Foswiki::Func::isAnAdmin() ) {
        my $response = $Foswiki::Plugins::SESSION->{response};
        $response->header(
            -status  => 500,
            -type    => 'text/plain',
            -charset => 'UTF-8'
        );
        $response->print('forceUpdate is only available to administrators');
        return;
    }

    _writeDebug('about to forceUpdate');
    _downloadRegexUpdate(1);
    _writeDebug('forceUpdate complete');

    return ${pluginName} . ': SharedSpamList forceUpdate complete ';
}

sub _RESTremoveUser {
    my $session = shift;
    my $query   = Foswiki::Func::getCgiQuery();
    my $user    = $query->param('user');

    my $mess;

    $mess = "user parameter required"
      unless ( $query->param('user') );
    $mess = "removeUser only available to Administrators"
      unless ( Foswiki::Func::isAnAdmin() );

    if ($mess) {
        my $response = $Foswiki::Plugins::SESSION->{response};
        $response->header(
            -status  => 500,
            -type    => 'text/plain',
            -charset => 'UTF-8'
        );
        $response->print($mess);
        return;
    }

    my ( $m, $lm ) = _removeUser($user);

    Foswiki::Func::writeWarning("$user: $lm");

    return ${pluginName} . "<br />" . $m . "<br/> $user processed\n";
}

#### Support functions
sub _writeDebug {
    Foswiki::Func::writeDebug( "- $pluginName - " . $_[0] ) if MONITOR;
    return;
}

sub _saveWorkFile {
    my $fileName = shift;
    my $text     = shift;

    my $workarea = Foswiki::Func::getWorkArea($pluginName);
    Foswiki::Func::saveFile( $workarea . '/' . $fileName, $text );
    return;
}

sub _readWorkFile {
    my $fileName = shift;

    my $workarea = Foswiki::Func::getWorkArea($pluginName);
    return Foswiki::Func::readFile( $workarea . '/' . $fileName );
}

sub _workFileExists {
    my $fileName = shift;

    my $workarea = Foswiki::Func::getWorkArea($pluginName);
    return ( -e $workarea . '/' . $fileName );
}

# downloads a new set of regexes if it is time to do so
sub _downloadRegexUpdate {
    my $forceFlag = shift;

    unless ($forceFlag) {
        return
          unless (
            $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{AutoUpdateSignatures} );
        my $timesUp;
        my $topicExists = _workFileExists( ${pluginName} . '_regexs' );
        if ($topicExists) {
            my $getListTimeOut =
              $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{GETLISTTIMEOUT}
              || 61;

            #has it been more than $getListTimeOut minutes since the last get?
            my $lastTimeWeCheckedForUpdate =
              _readWorkFile( ${pluginName} . '_timeOfLastCheck' );
            _writeDebug(
                "time > ($lastTimeWeCheckedForUpdate + ($getListTimeOut * 60))"
            );
            $timesUp =
              time > ( $lastTimeWeCheckedForUpdate + ( $getListTimeOut * 60 ) );
        }
        return unless ( $timesUp || !$topicExists );
    }

    my $lock =
      _readWorkFile( ${pluginName} . '_lock' )
      ;    # SMELL: that's no good way to do locking
    if ( $lock eq '' ) {
        _writeDebug("beginning download of new spam data");
        _saveWorkFile( ${pluginName} . '_lock', 'lock' );
        my $listUrl =
          $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMREGEXLISTURL};
        my $list = Foswiki::Func::getExternalResource($listUrl)->content();
        if ( defined($list) ) {

            #_writeDebug("$list");
            _saveWorkFile( ${pluginName} . '_regexs',          $list );
            _saveWorkFile( ${pluginName} . '_timeOfLastCheck', time );
        }
        _saveWorkFile( ${pluginName} . '_lock', '' );
    }
    else {
        _writeDebug("download blocked due to lock");
    }
    return;
}

# check a text for spam; throws an oops exception if so
sub _checkText {

    # my ($web, $topic, $text) = @_;
    my $web   = shift;
    my $topic = shift;

    _writeDebug("_checkText($web.$topic, ... )");

    # do localspamlist first
    my $regexs = _loadRegexList(
        $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{LOCALANTISPAMREGEXLISTTOPIC},
        "$web.$topic"
    );
    if (@$regexs) {
        _writeDebug( "LOCAL Regexes: " . scalar @$regexs );
        _checkTextUsingRegex( $web, $topic, $regexs, $_[0] );
    }

    # use the share spam regexs
    $regexs = _makeRegexList( _readWorkFile( ${pluginName} . '_regexs' ) );
    if (@$regexs) {
        _writeDebug( "PUBLIC Regexes: " . scalar @$regexs );
        _checkTextUsingRegex( $web, $topic, $regexs, $_[0] );
    }
    return;
}

# check a text for spam using a given regex; throws an oops exception if it detected spam
sub _checkTextUsingRegex {

    #my ($web, $topic, $regexs, $text) = @_;
    my $web    = shift;
    my $topic  = shift;
    my $regexs = shift;

    _writeDebug("Checking $web.$topic  - HITS start at $hits ");

    foreach my $regex (@$regexs) {

        #_writeDebug ("Checking for $regex ");
        if ( $_[0] =~ /$regex/i ) {
            my $wikiName = Foswiki::Func::getWikiName();
            $hits++;
            Foswiki::Func::writeWarning(
"detected spam from user $wikiName at $web.$topic (regex=$regex) bypass=$bypassFail HIT $hits"
            );
            if (
                !$bypassFail &&           # User is not in trusted group
                $hitThreshold > 0 &&      # and Sensitivity not set to simulate
                $hits >= $hitThreshold    # and sensitivity matches hits.
              )
            {

                # TODO: make this a nicer error, or make its own template
                throw Foswiki::OopsException(
                    'attention',
                    def   => 'save_error',
                    web   => $web,
                    topic => $topic,
                    params =>
"The text of topic $web.$topic has been rejected as it may contain spam."
                );
            }
        }
    }
    return;
}

# Retrieve preference settings
sub _getPluginPrefs {

    $bypassFail = 0;
    my $bypassGroup = '';
    if ( Foswiki::Func::isAnAdmin() ) {
        $bypassFail = 1;
    }
    else {
        $bypassGroup =
             $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{BypassGroup}
          || $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMBYPASSGROUP}
          || '';
        if ($bypassGroup) {
            $bypassFail = Foswiki::Func::isGroupMember("$bypassGroup") || 0;
        }
    }

    if ( defined $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{HitThreshold} ) {
        $hitThreshold =
          $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{HitThreshold};
    }
    else {
        $hitThreshold = 1;
    }

    _writeDebug(
"getPluginPrefs: bypassGroup = $bypassGroup,   bypassFail = $bypassFail HitThreshold = $hitThreshold"
    );
}

# Load a list of regexes from a <verbatim> block in the given topic,
# optionally excluding one topic.
sub _loadRegexList {
    my ( $regexTopic, $exclude ) = @_;

    my $systemWeb = $Foswiki::cfg{SystemWebName};
    ( my $regexWeb, $regexTopic ) =
      Foswiki::Func::normalizeWebTopicName( $systemWeb, $regexTopic );
    return undef if $exclude && "$regexWeb.$regexTopic" eq $exclude;
    return undef unless Foswiki::Func::topicExists( $regexWeb, $regexTopic );

    # Note: Read regex topic without checking access permission.
    # The local anti-spam regular expressions may be protected
    # from general access.
    my ( $meta, $regexs ) = Foswiki::Func::readTopic( $regexWeb, $regexTopic );
    $regexs =~ m#<verbatim>(.*)</verbatim>#ms;
    return _makeRegexList($1);
}

# Given a string of regexes, one per line, split them into an
# array, discarding comments and whitespace
sub _makeRegexList {
    my $regexs = shift;
    return [] unless defined $regexs;
    my @regexes =
      grep { $_ }
      map { $_ =~ /^\s*([^#]*?)\s*(?:$|#)/; $1 }
      split( /\n/, $regexs );
    return \@regexes;
}

# SMELL: some day we'll get our act together and do this in core.
# SMELL: uses unpublished APIs!
sub _removeUser {
    my $user = shift;

    ($user) = $user =~ m/($Foswiki::cfg{LoginNameFilterIn})/;

    # Obtain all the user info before removing things.   If there is no mapping
    # for the user, then assume the entered username will be removed.
    my $cUID     = Foswiki::Func::getCanonicalUserID($user);
    my $wikiname = ($cUID) ? Foswiki::Func::getWikiName($cUID) : $user;
    my $email    = join( ',', Foswiki::Func::wikinameToEmails($wikiname) );

    my ( $message, $logMessage ) =
      ( "Processing $wikiname($email)<br/>", "($email) " );

    if ( $cUID && $cUID =~ m/^BaseUserMapping_/ ) {
        $message    = "Cannot remove $user: $cUID <br />";
        $logMessage = "Cannot remove $user: $cUID";
        return ( $message, $logMessage );
    }

    # Remove the user from the mapping manager
    if ( $cUID && $Foswiki::Plugins::SESSION->{users}->userExists($cUID) ) {
        $Foswiki::Plugins::SESSION->{users}->removeUser($cUID);
        $message    .= ' - user removed from Mapping Manager <br/>';
        $logMessage .= 'Mapping removed, ';
    }
    else {
        $message    .= ' - User not known to the Mapping Manager <br/>';
        $logMessage .= 'unknown to Mapping, ';
    }

    # Kill any user sessions by removing the session files
    my $uid = $cUID || $wikiname;
    my $uSess;
    if ( Foswiki::LoginManager->can('removeUserSessions') ) {
        $uSess = Foswiki::LoginManager::removeUserSessions($uid);
    }
    else {
        $uSess = removeUserSessions($uid);
    }

    if ($uSess) {
        $message    .= " - removed $uSess <br />";
        $logMessage .= "removed: $uSess, ";
    }

    # If a group topic has been entered, don't remove it.
    if ( Foswiki::Func::isGroup($wikiname) ) {
        $message    .= " Cannot remove group $wikiname <br />";
        $logMessage .= "Cannot remove group $wikiname, ";
        return ( $message, $logMessage );
    }

    # Remove the user from any groups.
    my $it = Foswiki::Func::eachGroup();
    $logMessage .= 'Removed from groups: ';
    while ( $it->hasNext() ) {
        my $group = $it->next();

        #$message .= "Checking $group for ($wikiname)<br />";
        if (
            Foswiki::Func::isGroupMember( $group, $wikiname, { expand => 0 } ) )
        {
            $message    .= " - user removed from $group <br />";
            $logMessage .= "$group, ";
            Foswiki::Func::removeUserFromGroup( $wikiname, $group );
        }
    }

    # Remove the users topic, moving it to trash web
    ( my $web, $wikiname ) =
      Foswiki::Func::normalizeWebTopicName( $Foswiki::cfg{UsersWebName},
        $wikiname );

    if ( Foswiki::Func::topicExists( $web, $wikiname ) ) {

        my $newTopic = "SuspectSpammer$wikiname" . time;

        my $from =
          Foswiki::Meta->new( $Foswiki::Plugins::SESSION, $web, $wikiname );
        my $to =
          Foswiki::Meta->new( $Foswiki::Plugins::SESSION,
            $Foswiki::cfg{TrashWebName}, $newTopic );

        $from->move($to);

        $message .=
          " - user topic moved to $Foswiki::cfg{TrashWebName}.$newTopic <br/>";
        $logMessage .=
          "User topic moved to $Foswiki::cfg{TrashWebName}.$newTopic, ";
    }
    else {
        $message    .= ' - user topic not found <br/>';
        $logMessage .= ' User topic not found, ';
    }
    return ( $message, $logMessage );
}

=begin TML

---++ StaticMethod removeUserSessions()

This code has been copied from Foswiki 1.2 lib/Foswiki/LoginManager.pm

Delete session files for a user that is being removed from the system.
Removing the Session prevents any further damage from a spammer when the
account has been removed.

This is a static method, but requires Foswiki::cfg. It is designed to be
run from a session.

=cut

sub removeUserSessions {
    my $user = shift;
    my $msg  = '';

    opendir( my $tmpdir, "$Foswiki::cfg{WorkingDir}/tmp" ) || return '';
    foreach my $fn ( grep( /^cgisess_/, readdir($tmpdir) ) ) {
        my ($file) = $fn =~ m/^(cgisess_.*)$/;

        open my $sessfile, '<', "$Foswiki::cfg{WorkingDir}/tmp/$file"
          or next;
        while (<$sessfile>) {
            if (m/'AUTHUSER' => '$user'/) {
                close $sessfile;
                unlink "$Foswiki::cfg{WorkingDir}/tmp/$file";
                $msg .= $file . ', ';
                last;
            }
        }
        close $sessfile if $sessfile;
    }
    closedir $tmpdir;
    return $msg;
}

1;
__END__
Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2005-2009 Sven Dowideit SvenDowideit@wikiring.com
Copyright (C) 2009-2014 George Clark
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
