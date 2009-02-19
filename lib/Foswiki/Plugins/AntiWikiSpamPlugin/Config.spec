# ---+ Extensions
# ---++ AntiWikiSpamPlugin
# **URL**
# URL where plugin should retrive the list of regular expressions that match spam postings.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMREGEXLISTURL} = 'http://arch.thinkmo.de/cgi-bin/spam-merge';

# **Topic**
# Local topic name containing list of regular expressions that match spam postings.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{LOCALANTISPAMREGEXLISTTOPIC} = '%SYSTEMWEB%.LocalAntiWikiSpamPluginList';

# **Number**
# Age in minutes of the regular expression list, after which a new list will be retrieved.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{GETLISTTIMEOUT} = 60;

# **Topic**
# Group name whose members are allowed to post regardless of spam status.    
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMBYPASSGROUP} = 'AntiWikiSpamBypassGroup';

# **Number**
# Number of potential spam regex matches that will result in blociking save and attach operations.
# Default is 1, blocking on a single match.  Set to 0 to "simulate" operation by logging, but not blocking any actions.
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMSENSITIVITY} = 1;

1;
