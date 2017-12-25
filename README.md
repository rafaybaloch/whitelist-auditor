# Whitelist-Auditor

# Description
To help Captive Portal vendors and Firewall/DPI administrators, we have written a tool which will audit the whitelist for the following:

i)	The tool will check if the domain is part of a CDN network, this will be done by querying the Canonical Name Record (up to two levels) and will match if it points to a CDN network.

ii)	The tool also performs a reverse DNS lookup to check if an IP address is part of a CDN network.

iii)	The tool will check for poorly configured regular expressions that might lead to bypasses.

# Instructions

The tool consists of two different files “Auditor.py” and “sample.txt”. The sample.txt file will contain all the whitelisted domains. The sample.txt must be placed in the same directory as the auditor.py. Once, the analysis is completed the tool will output an excel sheet, which will contain lists of domains that should be reviewed.
