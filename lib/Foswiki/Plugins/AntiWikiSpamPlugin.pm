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
#

=pod

---+ package AntiWikiSpamPlugin

AntiWikiSpam plugin uses the shared Anti-spam regex list to 
check topic text when saving, refusing to save if it finds a matche.

=cut

package Foswiki::Plugins::AntiWikiSpamPlugin;

use Error qw(:try);
use strict;

use vars qw( $VERSION $RELEASE $pluginName $debug );

# This should always be $Rev$ so that Foswiki can determine the checked-in
# status of the plugin. It is used by the build automation tools, so
# you should leave it alone.
$VERSION = '$Rev$';

# This is a free-form string you can use to "name" your own plugin version.
# It is *not* used by the build automation tools, but is reported as part
# of the version number in PLUGINDESCRIPTIONS.
$RELEASE = '1.2';

$pluginName = 'AntiWikiSpamPlugin';    # Name of this Plugin

$debug = 1;                            # toggle me

=pod

---++ initPlugin($topic, $web, $user, $installWeb) -> $boolean
   * =$topic= - the name of the topic in the current CGI query
   * =$web= - the name of the web in the current CGI query
   * =$user= - the login name of the user
   * =$installWeb= - the name of the web the plugin is installed in

not used for plugins specific functionality at present

=cut

sub initPlugin {
    my ( $topic, $web, $user, $installWeb ) = @_;

    # check for Plugins.pm versions
    if ( $Foswiki::Plugins::VERSION < 1.026 ) {
        Foswiki::Func::writeWarning(
            "Version mismatch between $pluginName and Plugins.pm");
        return 0;
    }

    #forceUpdate
    Foswiki::Func::registerRESTHandler( 'forceUpdate', \&forceUpdate );

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

=pod

---++ beforeSaveHandler($text, $topic, $web, $meta )
   * =$text= - text _with embedded meta-data tags_
   * =$topic= - the name of the topic in the current CGI query
   * =$web= - the name of the web in the current CGI query
   * =$meta= - the metadata of the topic being saved, represented by a Foswiki::Meta object 

This handler is called just before the save action, checks 

__NOTE:__ meta-data is embedded in $text (using %META: tags)

=cut

sub beforeSaveHandler {

    # do not uncomment, use $_[0], $_[1]... instead
    ### my ( $text, $topic, $web ) = @_;

    my $action = getCgiAction();
    return unless $action =~ /^save/;

    writeDebug("beforeSaveHandler( $_[2].$_[1] )");
    downloadRegexUpdate();
    checkText( $_[2], $_[1], $_[0] );
    return;
}

=pod

---++ beforeAttachmentSaveHandler($attachmentAttr, $topic, $web)

checks attachments for javascript exploits and spam

=cut

sub beforeAttachmentSaveHandler {
    ### my ( $attachmentAttr, $topic, $web ) = @_;   # do not uncomment, use $_[0], $_[1]... instead
    my $attachmentName = $_[0]->{"attachment"};
    my $tmpFilename    = $_[0]->{"tmpFilename"};
    my $text           = Foswiki::Func::readFile($tmpFilename);

    #from BlackListPlugin
    # check for evil eval() spam in <script>
    if ( $text =~ /<script.*?eval *\(.*?<\/script>/gis )
    {    #TODO: there's got to be a better way to do this.
        Foswiki::Func::writeWarning(
"detected possible javascript exploit at attachment in in $_[2].$_[1]"
        );
        throw Foswiki::OopsException(
            'attention',
            def   => 'attach_error',
            web   => $_[2],
            topic => $_[1],
            params =>
'The attachment has been rejected as it contains a possible javascript eval exploit.'
        );
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
              Foswiki::Func::getPluginPreferencesValue('GETLISTTIMEOUT') || 61;

            #has it been more than $getListTimeOut minutes since the last get?
            my $lastTimeWeCheckedForUpdate =
              readWorkFile( ${pluginName} . '_timeOfLastCheck' );
            writeDebug(
                "time > ($lastTimeWeCheckedForUpdate + ($getListTimeOut * 60))"
            );
            $timesUp =
              time > ( $lastTimeWeCheckedForUpdate + ( $getListTimeOut * 60 ) );
        }
        return unless ($timesUp || !$topicExists);
    }

    writeDebug("downloading new spam data");
    my $lock =
      readWorkFile( ${pluginName} . '_lock' )
      ;    # SMELL: that's no good way to do locking
    if ( $lock eq '' ) {
        writeDebug("downloading new spam data");
        saveWorkFile( ${pluginName} . '_lock', 'lock' );
        my $listUrl =
          Foswiki::Func::getPluginPreferencesValue('ANTISPAMREGEXLISTURL');
        my $list = Foswiki::Func::getExternalResource($listUrl)->content();
        if ( defined($list) ) {

            #writeDebug("$list");
            saveWorkFile( ${pluginName} . '_regexs',          $list );
            saveWorkFile( ${pluginName} . '_timeOfLastCheck', time );
        }
        saveWorkFile( ${pluginName} . '_lock', '' );
    }
    else {
        writeDebug("downloading new spam data");
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
      Foswiki::Func::getPluginPreferencesValue('LOCALANTISPAMREGEXLISTTOPIC');
    my $twikiWeb = Foswiki::Func::getTwikiWebname();
    ( $regexWeb, $regexTopic ) =
      Foswiki::Func::normalizeWebTopicName( $twikiWeb, $regexTopic );
    if ( Foswiki::Func::topicExists( $regexWeb, $regexTopic ) ) {
        if ( ( $topic eq $regexTopic ) && ( $web eq $regexWeb ) ) {
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

    #load text as a set of regex's, and eval
    foreach my $regexLine ( split( /\n/, $_[0] ) ) {
        $regexLine =~ /([^#]*)\s*#?/;
        my $regex = $1;
        $regex =~ s/^\s+//;
        $regex =~ s/\s+$//;
        if ( $regex ne '' ) {
            if ( $_[1] =~ /$regex/i ) {
                Foswiki::Func::writeWarning(
                    "detected spam at $web.$topic (regex=$regex)");

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

1;
