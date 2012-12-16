package AntiWikiSpamPluginTests;

# SMELL: this test suite was retro-fitted to an existing plugin, and
# does *not* test spam removal from topics. It *only* tests the
# registration handlers and removeUser REST handler.

use FoswikiFnTestCase;
our @ISA = qw( FoswikiFnTestCase );

use strict;
use Error (':try');

my $REST_UI_FN;

sub new {
    my $self = shift()->SUPER::new(@_);
    return $self;
}

sub set_up {
    my $this = shift;
    $this->SUPER::set_up();

}

sub loadExtraConfig {
    my $this = shift;
    $this->SUPER::loadExtraConfig();
    $REST_UI_FN ||= $this->getUIFn('rest');
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{Enabled} = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{Module} =
      'Foswiki::Plugins::AntiWikiSpamPlugin';
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckTopics}          = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckAttachments}     = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckRegistrations}   = 1;
    $Foswiki::cfg{Register}{NeedVerification}                        = 0;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMREGEXLISTURL} = '';
}

sub tear_down {
    my $this = shift;
    $this->SUPER::tear_down();
}

#SMELL: Enabling this test breaks the AntiWikiSpamPluginRegTests ???
sub disable_test_spamSaveTopic {
    my $this = shift;

    my ( $meta, $text );
    if ( Foswiki::Func::topicExists( $this->{test_web}, 'SpamTopic' ) ) {
        ( $meta, $text ) =
          Foswiki::Func::readTopic( $this->{test_web}, 'SpamTopic' );
    }
    else {
#if the topic doesn't exist, we can either leave $meta undefined
#or if we need to set more than just the topic text, we create a new Meta object and use it.
        $meta =
          new Foswiki::Meta( $Foswiki::Plugins::SESSION, $this->{test_web},
            'SpamTopic' );
        $text = <<'TEXT';
test
http://buyviagra.com/
spamcheck

TEXT
    }
    try {
        Foswiki::Func::saveTopic( $this->{test_web}, 'SpamTopic', $meta,
            $text );
    }
    catch Foswiki::AccessControlException with {
        my $e = shift;
        die $e;
    }
    catch Error::Simple with {
        my $e = shift;
        die $e;
    }
    otherwise {
        die "otherwise";
    };

    $text = Foswiki::Func::readTopicText( $this->{test_web}, 'SpamTopic' );
    print STDERR "Read $text\n";

}

1;
