package AntiWikiSpamPluginRegTests;

# SMELL: this test suite was retro-fitted to an existing plugin, and
# does *not* test spam removal from topics. It *only* tests the
# registration handlers and removeUser REST handler.

use FoswikiFnTestCase;
our @ISA = qw( FoswikiFnTestCase );

use strict;
use Error (':try');

use Foswiki::Plugins::AntiWikiSpamPlugin;

my $REST_UI_FN;

sub new {
    my $self = shift()->SUPER::new(@_);
    return $self;
}

sub set_up {
    my $this = shift;
    $this->SUPER::set_up();
    $REST_UI_FN ||= $this->getUIFn('rest');

    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{Enabled} = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{Module} =
      'Foswiki::Plugins::AntiWikiSpamPlugin';
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckTopics}          = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckAttachments}     = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckRegistrations}   = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulCount}      = '0';
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulWebs}       = '.*';
    $Foswiki::cfg{Register}{NeedVerification}                        = 0;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMREGEXLISTURL} = '';
    undef $Foswiki::Plugins::AntiWikiSpamPlugin::Core::regoWhite;
    undef $Foswiki::Plugins::AntiWikiSpamPlugin::Core::regoBlack;
}

sub tear_down {
    my $this = shift;
    $this->SUPER::tear_down();
    undef $Foswiki::Plugins::AntiWikiSpamPlugin::Core::regoWhite;
    undef $Foswiki::Plugins::AntiWikiSpamPlugin::Core::regoBlack;
}

# Test removeUser REST handler
sub test_RESTremoveUser {
    my $this = shift;

    $this->assert(
        Foswiki::Func::addUserToGroup(
            $this->{test_user_wikiname},
            $this->{test_user_wikiname} . 'Group',
            1
        )
    );

    my $query =
      Unit::Request->new( { 'user' => $this->{test_user_wikiname}, } );
    $query->method('POST');
    $query->path_info("/AntiWikiSpamPlugin/removeUser");
    $this->createNewFoswikiSession( 'AdminUser', $query );

    my ( $out, $result ) = $this->captureWithKey(
        rest => $REST_UI_FN,
        $this->{session}
    );

    #print STDERR $out;
    $this->assert_matches(
qr/user removed from Mapping Manager.*removed cgisess_.*user removed from $this->{test_user_wikiname}Group.*user topic moved to Trash.*$this->{test_user_wikiname} processed/,
        $out
    );

    # Scumbag should be gone from the passwords DB
    # OK to use filenames; FoswikiFnTestCase forces password manager to
    # HtPasswdUser
    $this->assert_null(
        `grep $this->{test_user_login} $Foswiki::cfg{Htpasswd}{FileName}`);
    $this->assert_null(
        `grep $this->{test_user_wikiname} $Foswiki::cfg{Htpasswd}{FileName}`);
    $this->assert(
        !Foswiki::Func::isGroupMember(
            $this->{test_user_wikiname},
            $this->{test_user_wikiname} . 'Group'
        )
    );

    my ( $crap, $wu ) = Foswiki::Func::readTopic( $Foswiki::cfg{UsersWebName},
        $Foswiki::cfg{UsersTopicName} );
    $this->assert( $wu !~ /$this->{test_user_wikiname}/s );
    $this->assert( $wu !~ /$this->{test_user_login}/s );

    $this->assert(
        !Foswiki::Func::topicExists(
            $Foswiki::cfg{UsersWebName},
            $this->{test_user_wikiname}
        )
    );
}

# Deny a non-admin access to removeUser
sub test_denySelfImmolation {
    my $this = shift;
    my $query =
      Unit::Request->new( { 'user' => $this->{test_user_wikiname}, } );
    $query->method('POST');
    $query->path_info("/AntiWikiSpamPlugin/removeUser");
    $this->createNewFoswikiSession( $this->{test_user_login}, $query );

    my ( $out, $result ) = $this->captureWithKey(
        rest => $REST_UI_FN,
        $this->{session}
    );
    $this->assert_matches( qr/Status: 500/, $out );
    $this->assert_matches( qr/removeUser only available to Administrators/,
        $out );
}

sub test_spamRegistration {
    my $this = shift;
    $Foswiki::cfg{Validation}{Method} = 'none';

    Foswiki::Func::saveTopic( $this->{test_web}, 'WhiteList', undef, <<'TEXT');
<verbatim>
\.info # must have in the email domain
</verbatim>
TEXT
    Foswiki::Func::saveTopic( $this->{test_web}, 'BlackList', undef, <<'TEXT');
<verbatim>
badrobot
^76\.74\.239\.26 # mailinator.com
^72\.51\.33\.80 # another mailinator address
^207\.198\.106\.56 # and another
^23\.239\.11\.30 # and more
</verbatim>
TEXT
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{RegistrationWhiteList} =
      "$this->{test_web}.WhiteList";
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{RegistrationBlackList} =
      "$this->{test_web}.BlackList";
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{Enabled} = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{Module} =
      'Foswiki::Plugins::AntiWikiSpamPlugin';
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckTopics}          = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckAttachments}     = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckRegistrations}   = 1;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulCount}      = '0';
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulWebs}       = '.*';
    $Foswiki::cfg{Register}{NeedVerification}                        = 0;
    $Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMREGEXLISTURL} = '';

    # Does not match whitelist
    my $qd = {
        'TopicName'     => ['UserRegistration'],
        'Fwk1Email'     => ['mustapha@spam.org'],
        'Twk1WikiName'  => ['MustaphaGoody'],
        'Fwk1Name'      => ['Mustapha Goody'],
        'Fwk1LoginName' => ['musta'],
        'Twk1FirstName' => ['Mustapha'],
        'Fwk1LastName'  => ['Goody'],
        'action'        => ['register']
    };
    my $query = Unit::Request->new($qd);
    $query->path_info("/$this->{users_web}/UserRegistration");
    $this->createNewFoswikiSession( $Foswiki::cfg{DefaultUserLogin}, $query );
    $this->{session}->net->setMailHandler( \&FoswikiFnTestCase::sentMail );
    try {
        if ( Foswiki::UI::Register->can('_action_register') ) {
            Foswiki::UI::Register::_action_register( $this->{session} );
        }
        else {
            Foswiki::UI::Register::registerAndNext( $this->{session} );
        }
    }
    catch Foswiki::OopsException with {
        my $e = shift;
        $this->assert_num_equals( 500, $e->{status} );
        $this->assert_matches( qr/triggered the spam filter/,
            $e->{params}->[0] );
    }
    otherwise {
        $this->assert( 0, 'SPAM Registration was permitted' );
    };
    $this->assert(
        !Foswiki::Func::topicExists(
            $Foswiki::cfg{UsersWebName},
            'MustaphaGoody'
        )
    );

    # matches whitelist, matches blacklist
    $qd->{Fwk1Email} = ['mustapha@badrobot.org'];
    $query = Unit::Request->new($qd);
    $this->createNewFoswikiSession( $Foswiki::cfg{DefaultUserLogin}, $query );
    $this->{session}->net->setMailHandler( \&FoswikiFnTestCase::sentMail );
    try {
        if ( Foswiki::UI::Register->can('_action_register') ) {
            Foswiki::UI::Register::_action_register( $this->{session} );
        }
        else {
            Foswiki::UI::Register::registerAndNext( $this->{session} );
        }
    }
    catch Foswiki::OopsException with {
        my $e = shift;
        $this->assert_num_equals( 500, $e->{status} );
        $this->assert_matches( qr/triggered the spam filter/,
            $e->{params}->[0] );
    }
    otherwise {
        $this->assert(0);
    };
    $this->assert(
        !Foswiki::Func::topicExists(
            $Foswiki::cfg{UsersWebName},
            'MustaphaGoody'
        )
    );

    # matches whitelist, matches IP in blacklist
    $qd->{Fwk1Email} = ['mustapha@safetymail.info'];
    $query = Unit::Request->new($qd);
    $this->createNewFoswikiSession( $Foswiki::cfg{DefaultUserLogin}, $query );
    $this->{session}->net->setMailHandler( \&FoswikiFnTestCase::sentMail );
    try {
        if ( Foswiki::UI::Register->can('_action_register') ) {
            Foswiki::UI::Register::_action_register( $this->{session} );
        }
        else {
            Foswiki::UI::Register::registerAndNext( $this->{session} );
        }
    }
    catch Foswiki::OopsException with {
        my $e = shift;
        use Data::Dumper;
        print STDERR Data::Dumper::Dumper( \$e );
        $this->assert_num_equals( 500, $e->{status} );
        $this->assert_matches( qr/triggered the spam filter/,
            $e->{params}->[0] );
    }
    otherwise {
        $this->assert(0);
    };
    $this->assert(
        !Foswiki::Func::topicExists(
            $Foswiki::cfg{UsersWebName},
            'MustaphaGoody'
        )
    );

    # matches whitelist, does not match blacklist => good rego
    $qd->{Fwk1Email} = ['mustapha@mustapha.good.time.info'];
    $query = Unit::Request->new($qd);
    $this->createNewFoswikiSession( $Foswiki::cfg{DefaultUserLogin}, $query );
    $this->{session}->net->setMailHandler( \&FoswikiFnTestCase::sentMail );
    try {
        if ( Foswiki::UI::Register->can('_action_register') ) {
            Foswiki::UI::Register::_action_register( $this->{session} );
        }
        else {
            Foswiki::UI::Register::registerAndNext( $this->{session} );
        }
    }
    catch Foswiki::OopsException with {
        my $e = shift;
        use Data::Dumper;
        print STDERR Data::Dumper::Dumper( \$e );
        $this->assert_num_equals( 200, $e->{status} );
        $this->assert_matches(
qr/A confirmation e-mail has been sent to mustapha\@mustapha.good.time.info/,
            $e->{params}->[0]
        );
    }
    otherwise {
        $this->assert(0);
    };
    $this->assert(
        Foswiki::Func::topicExists(
            $Foswiki::cfg{UsersWebName},
            'MustaphaGoody'
        )
    );
}

1;
