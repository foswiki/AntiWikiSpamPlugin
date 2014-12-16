# ---+ Extensions
# ---++ AntiWikiSpamPlugin
# **BOOLEAN**
# Should topic text be checked against the spam regular expression list?
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckTopics} = $TRUE;

# **BOOLEAN EXPERT**
# Should attachment contents be checked against the spam regular expression list?
# <b>WARNING</b>: Checking attachments could cause a high CPU load on the server.
# It is recommended to us an Antivirus scanner for attachments instead of this
# plugin.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckAttachments} = $FALSE;

# **BOOLEAN**
# Should registrations be checked by the plugin?.  Foswiki versions 1.1.5 and
# newer can also use the Registration EmailFilter for a simpler email address check
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{CheckRegistrations} = $TRUE;

# **STRING 40**
# Regular expression of webs that should have activity before allowing registration
# Often spammer bots jump right into registration. The plugin tracks visited web.topics
# that match this web regex in the user's session for guest users.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulWebs} = '.*';

# **NUMBER**
# Minimum activity count for user in the "Meaningful" webs.   Guests will be blocked
# from registering unless they have visited at least this count of topics.
# Set to zero to disable tracking of guest activity.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{MeaningfulCount} = 10;

# **URL**
# URL where plugin should retrive the list of regular expressions that match spam postings.
# The default site provides the MoinMoin antispam list: http://arch.thinkmo.de/cgi-bin/spam-merge
# <b>Caution</b>: If this site is not reachable, it can seriously degrade updates to the wiki.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMREGEXLISTURL} = 'http://arch.thinkmo.de/cgi-bin/spam-merge';

# **STRING 40**
# Local topic name containing list of regular expressions that match spam postings.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{LOCALANTISPAMREGEXLISTTOPIC} = '$Foswiki::cfg{SystemWebName}.AntiWikiSpamLocalList';

# **BOOLEAN**
# Enable automatic maintenance of spam signatures. Unless this is enabled, you will need to install a cronjob to update
# spam signatures regularly (See the documentation).
# <b>WARNING</b>: As the update process happens as part of a save or upload action downloading and merging
# signatures could cause timeouts and failures of operation. It is recommended to enable this only when maintenance using
# a cronjob isn't possible.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{AutoUpdateSignatures} = $FALSE;

# **NUMBER**
# Age in minutes of the regular expression list.  If this age is exceeded, and <tt>{AutoUpdateSignatures}</tt> is enabled, then 
# a new signature file will be downloaded during the next topic save.   This can slow down your wiki.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{GETLISTTIMEOUT} = 60;

# **STRING 40**
# Group name whose members are allowed to post regardless of spam status.    
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{BypassGroup} = 'AntiWikiSpamBypassGroup';

# **NUMBER**
# Number of potential spam regex matches that will result in blocking save and attach operations.
# Default is 1, blocking on a single match.  Set to -1 to "simulate" operation by logging, but not blocking any actions.
# If un-set, then the default is 1.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{HitThreshold} = 1;

# **STRING 40**
# Name of a topic containing a white-list that limit registrations.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{RegistrationWhiteList} = '$Foswiki::cfg{SystemWebName}.AntiWikiSpamRegistrationWhiteList';

# **STRING 40**
# Name of a topic containing a black-list that limit registrations.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{RegistrationBlackList} = '$Foswiki::cfg{SystemWebName}.AntiWikiSpamRegistrationBlackList';

1;
