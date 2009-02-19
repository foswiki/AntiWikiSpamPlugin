# Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2005-2008 Sven Dowideit SvenDowideit@wikiring.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details, published at
# http://www.gnu.org/copyleft/gpl.html

=pod

---+ package Foswiki::Plugins::AntiWikiSpamPlugin

AntiWikiSpam plugin uses the shared Anti-spam regex list to 
check topic text when saving, refusing to save if it finds a match.

=cut

package Foswiki::Plugins::AntiWikiSpamPlugin;

use Error qw(:try);
use strict;

require Foswiki::Func;       # The plugins API
require Foswiki::Plugins;    # For the API version

# $VERSION is referred to by Foswiki, and is the only global variable that
# *must* exist in this package.
# This should always be $Rev: 1340 $ so that Foswiki can determine the checked-in
# status of the plugin. It is used by the build automation tools, so
# you should leave it alone.
our $VERSION = '$Rev: 1340 $';

# This is a free-form string you can use to "name" your own plugin version.
# It is *not* used by the build automation tools, but is reported as part
# of the version number in PLUGINDESCRIPTIONS.
our $RELEASE = '$Date: 2008-12-15 04:49:56 +1100 (Mon, 15 Dec 2008) $';

# Short description of this plugin
# One line description, is shown in the %SYSTEMWEB%.TextFormattingRules topic:
our $SHORTDESCRIPTION = 'lightweight wiki spam prevention';

# You must set $NO_PREFS_IN_TOPIC to 0 if you want your plugin to use
# preferences set in the plugin topic. This is required for compatibility
# with older plugins, but imposes a significant performance penalty, and
# is not recommended. Instead, leave $NO_PREFS_IN_TOPIC at 1 and use
# =$Foswiki::cfg= entries set in =LocalSite.cfg=, or if you want the users
# to be able to change settings, then use standard Foswiki preferences that
# can be defined in your %USERSWEB%.SitePreferences and overridden at the web
# and topic level.
our $NO_PREFS_IN_TOPIC = 1;

our $pluginName  = 'AntiWikiSpamPlugin';
our $debug       = 0;
our $bypassFail  = undef;
our $sensitivity = undef;

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

    writeDebug(" AntiWikiSpam is initialized ");

    # Plugin correctly initialized
    return 1;
}

=pod

---++ writeDebug($text)

write debug output if the debug flag is set

=cut

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

    my $action = getCgiAction();
    return unless $action =~ /^save/;

    getPluginPrefs();    # Process preference settings for the plugin

    writeDebug("beforeSaveHandler( $_[2].$_[1] ) ");
    downloadRegexUpdate();
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
            $sensitivity > 0
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

=pod 

---++ checkText($web, $topic, $text) 

check a text for spam; throws an oops exception if so

=cut

sub checkText {

    # my ($web, $topic, $text) = @_;
    my $web   = shift;
    my $topic = shift;

    writeDebug("checkText($web.$topic, ... )");

    # do localspamlist first
    my $regexWeb;
    my $regexTopic =
      $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{LOCALANTISPAMREGEXLISTTOPIC};
    my $systemWeb = $Foswiki::cfg{SystemWebName};
    ( $regexWeb, $regexTopic ) =
      Foswiki::Func::normalizeWebTopicName( $systemWeb, $regexTopic );
    if ( Foswiki::Func::topicExists( $regexWeb, $regexTopic ) ) {
        if ( ( $topic eq $regexTopic ) && ( $web eq $regexWeb ) ) {
            writeDebug("Bypass - anti-spam topic");
            return;    #don't check the anti-spam topic
        }
        my ( $meta, $regexs ) =
          Foswiki::Func::readTopic( $regexWeb, $regexTopic );
        checkTextUsingRegex( $web, $topic, $regexs, $_[0] );
    }

    # use the share spam regexs
    my $regexs = readWorkFile( ${pluginName} . '_regexs' );
    checkTextUsingRegex( $web, $topic, $regexs, $_[0] );
    return;
}

=pod

---++ checkTextUsingRegex

check a text for spam using a given regex; throws an oops exception if it detected spam

=cut

sub checkTextUsingRegex {

    #my ($web, $topic, $regexs, $text) = @_;
    my $web   = shift;
    my $topic = shift;
    my $hits  = 0;

    #load text as a set of regex's, and eval
    foreach my $regexLine ( split( /\n/, $_[0] ) ) {
        $regexLine =~ /([^#]*)\s*#?/;
        my $regex = $1;
        $regex =~ s/^\s+//;
        $regex =~ s/\s+$//;
        if ( $regex ne '' ) {

            #writeDebug ("Checking for $regex ");
            if ( $_[1] =~ /$regex/i ) {
                my $wikiName = Foswiki::Func::getWikiName();
                Foswiki::Func::writeWarning(
"detected spam from user $wikiName at $web.$topic (regex=$regex) bypass=$bypassFail"
                );
                $hits++;
                if (
                    !$bypassFail &&    # User is not in trusted group
                    $sensitivity > 0
                    &&                 # and Sensitivity not set to simulate
                    $hits >= $sensitivity
                  )
                {                      # and sensitivity matches hits.

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
    }
    return;
}

=pod 

---++ getCgiAction() -> $script

our version of getting the script action

=cut

sub getCgiAction {
    my $pathInfo  = $ENV{'PATH_INFO'}   || '';
    my $theAction = $ENV{'REQUEST_URI'} || '';
    if ( $theAction =~ /^.*?\/([^\/]+)$pathInfo.*$/ ) {
        $theAction = $1;
    }
    else {
        $theAction = 'view';
    }

    #writeDebug("PATH_INFO=$ENV{'PATH_INFO'}");
    #writeDebug("REQUEST_URI=$ENV{'REQUEST_URI'}");
    #writeDebug("theAction=$theAction");

    return $theAction;
}

=pod 

---++ getPluginPrefs() -> 

Retrieve preference settings for the AntiWikiSpam  plugin.

=cut

sub getPluginPrefs {
    my $bypassGroup =
      $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMBYPASSGROUP};
    $bypassFail = $bypassGroup && Foswiki::Func::isGroupMember("$bypassGroup");
    if (
        defined $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}
        {ANTISPAMSENSITIVITY} )
    {
        $sensitivity =
          $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMSENSITIVITY};
    }
    else {
        $sensitivity = 1;
    }
    writeDebug(
"beforeSaveHandler: bypassGroup = $bypassGroup,   bypassFail = $bypassFail sensitivity = $sensitivity"
    );
}

1;
__END__
This copyright information applies to the AntiWikiSpamPlugin:

# Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# AntiWikiSpamPlugin is # This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# For licensing info read LICENSE file in the Foswiki root.
