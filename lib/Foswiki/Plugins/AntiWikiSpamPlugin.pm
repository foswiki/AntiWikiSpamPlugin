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

our $VERSION           = '$Rev$';
our $RELEASE           = '1.3';
our $SHORTDESCRIPTION  = 'Lightweight wiki spam prevention';
our $NO_PREFS_IN_TOPIC = 1;

our $pluginName = 'AntiWikiSpamPlugin';
my $debug        = 0;
my $bypassFail   = 0;
my $hitThreshold = undef;
my $hits;

# Caches of registration white- and black- lists
our $regoWhite;
our $regoBlack;

=begin TML

---++ initPlugin($topic, $web, $user) -> $boolean
   * =$topic= - the name of the topic in the current CGI query
   * =$web= - the name of the web in the current CGI query
   * =$user= - the login name of the user
   * =$installWeb= - the name of the web the plugin topic is in
     (usually the same as =$Foswiki::cfg{SystemWebName}=)

*REQUIRED*

Called to initialise the plugin. If everything is OK, should return
a non-zero value. On non-fatal failure, should write a message
using =Foswiki::Func::writeWarning= and return 0. In this case
%<nop>FAILEDPLUGINS% will indicate which plugins failed.

In the case of a catastrophic failure that will prevent the whole
installation from working safely, this handler may use 'die', which
will be trapped and reported in the browser.

__Note:__ Please align macro names with the Plugin name, e.g. if
your Plugin is called !FooBarPlugin, name macros FOOBAR and/or
FOOBARSOMETHING. This avoids namespace issues.

=cut

sub initPlugin {
    my ( $topic, $web, $user, $installWeb ) = @_;

    # check for Plugins.pm versions
    if ( $Foswiki::Plugins::VERSION < 2.0 ) {
        Foswiki::Func::writeWarning( 'Version mismatch between ',
            __PACKAGE__, ' and Plugins.pm' );
        return 0;
    }

    #forceUpdate
    Foswiki::Func::registerRESTHandler( 'forceUpdate', \&forceUpdate );

    Foswiki::Func::registerRESTHandler(
        'removeUser', \&removeUser,
        authenticate => 1,
        validate     => 1,
        http_allow   => 'POST'
    );

    $debug = Foswiki::Func::getPreferencesFlag('ANTIWIKISPAMPLUGIN_DEBUG');

    writeDebug(" AntiWikiSpam is initialized ");

    # Plugin correctly initialized
    return 1;
}

sub writeDebug {
    Foswiki::Func::writeDebug( "- $pluginName - " . $_[0] ) if $debug;
    return;
}

=begin TML

---++ beforeSaveHandler($text, $topic, $web, $meta )
   * =$text= - text _with embedded meta-data tags_
   * =$topic= - the name of the topic in the current CGI query
   * =$web= - the name of the web in the current CGI query
   * =$meta= - the metadata of the topic being saved, represented by a Foswiki::Meta object.

This handler is called each time a topic is saved.

*NOTE:* meta-data is embedded in =$text= (using %META: tags). If you modify
the =$meta= object, then it will override any changes to the meta-data
embedded in the text. Modify *either* the META in the text *or* the =$meta=
object, never both. You are recommended to modify the =$meta= object rather
than the text, as this approach is proof against changes in the embedded
text format.

*Since:* Foswiki::Plugins::VERSION = 2.0

=cut

sub beforeSaveHandler {

    # do not uncomment, use $_[0], $_[1]... instead
    ### my ( $text, $topic, $web ) = @_;

    getPluginPrefs();    # Process preference settings for the plugin

    writeDebug("beforeSaveHandler( $_[2].$_[1] ) ");
    downloadRegexUpdate();
    $hits = 0;
    checkText( $_[2], $_[1], $_[0] );
    return;
}

=begin TML

---++ beforeAttachmentSaveHandler(\%attrHash, $topic, $web )
   * =\%attrHash= - reference to hash of attachment attribute values
   * =$topic= - the name of the topic in the current CGI query
   * =$web= - the name of the web in the current CGI query
This handler is called once when an attachment is uploaded. When this
handler is called, the attachment has *not* been recorded in the database.

The attributes hash will include at least the following attributes:
   * =attachment= => the attachment name
   * =comment= - the comment
   * =user= - the user id
   * =tmpFilename= - name of a temporary file containing the attachment data

*Since:* Foswiki::Plugins::VERSION = 2.0

=cut

sub beforeAttachmentSaveHandler {
    ### my ( $attachmentAttr, $topic, $web ) = @_;   # do not uncomment, use $_[0], $_[1]... instead
    my $attachmentName = $_[0]->{"attachment"};
    my $tmpFilename    = $_[0]->{"tmpFilename"};
    my $text           = Foswiki::Func::readFile($tmpFilename);
    my $wikiName       = Foswiki::Func::getWikiName();

    getPluginPrefs();

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

    downloadRegexUpdate();
    $hits = 0;
    checkText( $_[2], $_[1], $text );
    return;
}

=pod

---++ forceUpdate($session) -> $text

can be used to force an update of the spam list

%SCRIPTURL%/rest/AntiWikiSpamPlugin/forceUpdate

=cut

sub forceUpdate {
    writeDebug('about to forceUpdate');
    downloadRegexUpdate(1);
    writeDebug('forceUpdate complete');

    return ${pluginName} . ': SharedSpamList forceUpdate complete ';
}

sub saveWorkFile {
    my $fileName = shift;
    my $text     = shift;

    my $workarea = Foswiki::Func::getWorkArea($pluginName);
    Foswiki::Func::saveFile( $workarea . '/' . $fileName, $text );
    return;
}

sub readWorkFile {
    my $fileName = shift;

    my $workarea = Foswiki::Func::getWorkArea($pluginName);
    return Foswiki::Func::readFile( $workarea . '/' . $fileName );
}

sub fileExists {
    my $fileName = shift;

    my $workarea = Foswiki::Func::getWorkArea($pluginName);
    return ( -e $workarea . '/' . $fileName );
}

=pod 

---++ downloadRegexUpdate ($forceFlag)

downloads a new set of regexes if it is time to do so

=cut

sub downloadRegexUpdate {
    my $forceFlag = shift;

    unless ($forceFlag) {
        my $timesUp;
        my $topicExists = fileExists( ${pluginName} . '_regexs' );
        if ($topicExists) {
            my $getListTimeOut =
              $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{GETLISTTIMEOUT}
              || 61;

            #has it been more than $getListTimeOut minutes since the last get?
            my $lastTimeWeCheckedForUpdate =
              readWorkFile( ${pluginName} . '_timeOfLastCheck' );
            writeDebug(
                "time > ($lastTimeWeCheckedForUpdate + ($getListTimeOut * 60))"
            );
            $timesUp =
              time > ( $lastTimeWeCheckedForUpdate + ( $getListTimeOut * 60 ) );
        }
        return unless ( $timesUp || !$topicExists );
    }

    my $lock =
      readWorkFile( ${pluginName} . '_lock' )
      ;    # SMELL: that's no good way to do locking
    if ( $lock eq '' ) {
        writeDebug("beginning download of new spam data");
        saveWorkFile( ${pluginName} . '_lock', 'lock' );
        my $listUrl =
          $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMREGEXLISTURL};
        my $list = Foswiki::Func::getExternalResource($listUrl)->content();
        if ( defined($list) ) {

            #writeDebug("$list");
            saveWorkFile( ${pluginName} . '_regexs',          $list );
            saveWorkFile( ${pluginName} . '_timeOfLastCheck', time );
        }
        saveWorkFile( ${pluginName} . '_lock', '' );
    }
    else {
        writeDebug("download blocked due to lock");
    }
    return;
}

=begin TML

---++ checkText($web, $topic, $text) 

check a text for spam; throws an oops exception if so

=cut

sub checkText {

    # my ($web, $topic, $text) = @_;
    my $web   = shift;
    my $topic = shift;

    writeDebug("checkText($web.$topic, ... )");

    # do localspamlist first
    my $regexs = _loadRegexList(
        $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{LOCALANTISPAMREGEXLISTTOPIC},
        "$web.$topic"
    );
    if ($regexs) {
        writeDebug("LOCAL Regexes \n($regexs)\n");
        checkTextUsingRegex( $web, $topic, $regexs, $_[0] ) if length($regexs);
    }

    # use the share spam regexs
    $regexs = _makeRegexList( readWorkFile( ${pluginName} . '_regexs' ) );
    checkTextUsingRegex( $web, $topic, $regexs, $_[0] );
    return;
}

=begin TML

---++ checkTextUsingRegex

check a text for spam using a given regex; throws an oops exception if it detected spam

=cut

sub checkTextUsingRegex {

    #my ($web, $topic, $regexs, $text) = @_;
    my $web    = shift;
    my $topic  = shift;
    my $regexs = shift;

    writeDebug("Checking - HITS start at $hits");

    foreach my $regex (@$regexs) {

        #writeDebug ("Checking for $regex ");
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

=pod 

---++ getPluginPrefs() -> 

Retrieve preference settings for the AntiWikiSpam  plugin.

=cut

sub getPluginPrefs {

    $bypassFail = 0;
    my $bypassGroup = '';
    if ( Foswiki::Func::isAnAdmin() ) {
        $bypassFail = 1;
    }
    else {
        $bypassGroup =
          $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMBYPASSGROUP} || '';
        if ($bypassGroup) {
            $bypassFail = Foswiki::Func::isGroupMember("$bypassGroup");
        }
    }

    if ( defined $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{HitThreshold} ) {
        $hitThreshold =
          $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{HitThreshold};
    }
    else {
        $hitThreshold = 1;
    }

    writeDebug(
"getPluginPrefs: bypassGroup = $bypassGroup,   bypassFail = $bypassFail HitThreshold = $hitThreshold"
    );
}

sub _loadRegexList {
    my ( $regexTopic, $exclude ) = @_;

    my $systemWeb = $Foswiki::cfg{SystemWebName};
    ( my $regexWeb, $regexTopic ) =
      Foswiki::Func::normalizeWebTopicName( $systemWeb, $regexTopic );
    return undef if $exclude && "$regexWeb.$regexTopic" eq $exclude;
    return undef unless Foswiki::Func::topicExists( $regexWeb, $regexTopic );

# Note: Read regex topic without checking access permission. The local anti-spam
# regular expressions may be protected from general access.
    my ( $meta, $regexs ) = Foswiki::Func::readTopic( $regexWeb, $regexTopic );
    $regexs =~ m#<verbatim>(.*)</verbatim>#ms;
    return _makeRegexList($1);
}

sub _makeRegexList {
    my $regexs = shift;
    return [] unless defined $regexs;
    my @regexes;
    foreach my $regexLine ( split( /\n/, $regexs ) ) {
        $regexLine =~ /([^#]*)\s*#?/;
        my $regex = $1;
        $regex =~ s/^\s+//;
        $regex =~ s/\s+$//;
        next unless $regex;
        push( @regexes, $regex );
    }
    return \@regexes;
}

# Check a registration to see if the email address used is blacklisted
sub registrationHandler {
    my ( $web, $wikiName, $loginName, $data ) = @_;

 # $data contains at least: WikiName FirstName LastName Email
 # May also contain: Photo Password Confirm AddToGroups
 # Anything else is not used by Registration
 # To spoil the party for a spam registration, check the email address against a
 # blacklist.
    require Socket;

    my ( $user, $domain ) = split( /@/, $data->{Email}, 2 );
    $domain ||= '';
    my $packed_ip = gethostbyname($domain);
    my $ipad = $packed_ip ? Socket::inet_ntoa($packed_ip) : undef;

    unless ($regoWhite) {
        $regoWhite = _loadRegexList(
            $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{RegistrationWhiteList} );
    }
    my $white = scalar(@$regoWhite);    # if there is at least one white expr
    foreach my $rego (@$regoWhite) {
        if ( $domain =~ /$rego/i || $ipad && $ipad =~ /$rego/ ) {
            $white = 1;
            last;
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
            if ( $domain =~ /$rego/i || $ipad && $ipad =~ /$rego/ ) {
                $black = 1;
                last;
            }
        }
    }
    return if $white && !$black;

    # Remove the user
    # SMELL: unpublished APIs! Would not be required if we could hook into
    # the rego process before the user is created
    my $cUID = Foswiki::Func::getCanonicalUserID( $data->{LoginName} );
    $Foswiki::Plugins::SESSION->{users}->removeUser($cUID);
    if (
        Foswiki::Func::topicExists(
            $Foswiki::cfg{UsersWebName},
            $data->{WikiName}
        )
      )
    {

        # Spoof the user so we can delete their topic
        my $safe = $Foswiki::Plugins::SESSION->{user};
        $Foswiki::Plugins::SESSION->{user} = $cUID;
        try {
            Foswiki::Func::moveTopic(
                $Foswiki::cfg{UsersWebName},
                $data->{WikiName},
                $Foswiki::cfg{TrashWebName},
                "SuspectSpammer$data->{WikiName}" . time
            );
        }
        finally {
            $Foswiki::Plugins::SESSION->{user} = $safe;
        };
    }

    require Foswiki::OopsException;
    $Foswiki::Plugins::SESSION->logger->log( 'warning',
"Registration of $data->{WikiName} ($data->{Email}) rejected by AntiWikiSpamPlugin: white: $white black: $black"
    );
    throw Foswiki::OopsException(
        'attention',
        web    => $data->{webName},
        topic  => $data->{WikiName},
        def    => 'problem_adding',
        params => ["'$data->{WikiName}' spam filter was triggered"]
    );
}

=pod

---++ removeUser($session) -> $text

If a SPAM registration makes it through, this REST handler will remove a user.
   * Passed with param: spamuser
   * Calls the removeUser function to remove the registration
   * Moves the user topic to SuspectSpammer

%SCRIPTURL%/rest/AntiWikiSpamPlugin/removeUser?spamuser=UserWikiName

=cut

sub removeUser {
    my $session    = shift;
    my $response   = $session->{response};
    my $query      = Foswiki::Func::getCgiQuery();
    my $message    = '';
    my $logMessage = '';
    my $user       = Foswiki::Func::getWikiUserName();

    return "${pluginName} only available to Administrators"
      unless ( Foswiki::Func::isAnAdmin() );

    return "${pluginName} . ERROR: spamuser parameter required\n"
      unless ( $query->param('spamuser') );

    my ( $web, $spamUser ) =
      Foswiki::Func::normalizeWebTopicName( $Foswiki::cfg{UsersWeb},
        $query->param('spamuser') );

    my $cUID = Foswiki::Func::getCanonicalUserID($spamUser);

    if ( $cUID && $Foswiki::Plugins::SESSION->{users}->userExists($cUID) ) {
        $Foswiki::Plugins::SESSION->{users}->removeUser($cUID);
        $message    .= " - user removed from Mapping Manager <br/>";
        $logMessage .= "Mapping removed, ";
    }
    else {
        $message    .= " - User not known to the Mapping Manager <br/>";
        $logMessage .= "unknown to Mapping, ";
    }

    if ( Foswiki::Func::topicExists( $web, $spamUser ) ) {
        my $newTopic = "SuspectSpammer$spamUser" . time;
        Foswiki::Func::moveTopic( $web, $spamUser, $Foswiki::cfg{TrashWebName},
            $newTopic );
        $message .=
          " - user topic moved to $Foswiki::cfg{TrashWebName}.$newTopic <br/>";
        $logMessage .=
          "User topic moved to $Foswiki::cfg{TrashWebName}.$newTopic, ";
    }
    else {
        $message    .= " - user topic not found <br/>";
        $logMessage .= " User topic not found, ";
    }

    Foswiki::Func::writeWarning("$user: $spamUser $logMessage");

    return ${pluginName} . "<br />" . $message
      . "<br/> $web.$spamUser processed\n";
}

1;
__END__
Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2005-2009 Sven Dowideit SvenDowideit@wikiring.com
Copyright (C) 2009-2012 George Clark
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
