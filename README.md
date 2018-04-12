# NoNox
Tails a log file for messages such as failed logins - when triggered, runs a command such as setting a firewall rule

NoNox watches log files for events such as "failed password". When such a pattern is seen several 
times within a specified time period (for example, 4 failed login attempts within 10 minutes) 
from the same source, NoNox can execute a command to mitigate the behavior, notify someone, or 
make a record of the event (or all these things). The patterns, time limits, files to monitor, 
and commands that can be triggered are all user-specified, so NoNox can be used to detect many 
kinds of events and to respond in a variety of ways. I use NoNox to monitor for password-scanning 
attacks, and to block attacking hosts at the firewall in real-time.</p>
