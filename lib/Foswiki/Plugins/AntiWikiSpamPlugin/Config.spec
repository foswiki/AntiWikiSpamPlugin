# ---+ Extensions
# ---++ AntiWikiSpamPlugin
# **URL**
# a hash mapping TWiki's TWiki web topics to Foswiki's topics
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{ANTISPAMREGEXLISTURL} = 'http://arch.thinkmo.de/cgi-bin/spam-merge';

# **Topic**
# a hash mapping TWiki's TWiki web topics to Foswiki's topics
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{LOCALANTISPAMREGEXLISTTOPIC} = '%SYSTEMWEB%.LocalAntiWikiSpamPluginList';

# **Number**
# a hash mapping TWiki's TWiki web topics to Foswiki's topics
$Foswiki::cfg{Plugins}{AntiWikiSpamPlugin}{GETLISTTIMEOUT} = 60;

1;
