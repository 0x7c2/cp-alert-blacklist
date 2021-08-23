#!/bin/bash
#
# Copyright 2021 by by 0x7c2, Simon Brecht.
# All rights reserved.
# This file is used to automaticly block suspected sources in
# Check Point Gateways within UserDefined Alerting Scripts,
# and is released under the "Apache License 2.0". Please see the LICENSE
# file that should have been included as part of this package.
#
# specify environment settings
#
DBFILE="/tmp/blacklist.sql"
SQLITE="/usr/bin/sqlite3"
CPRIDU="/opt/CPshrd-R80.40/bin/cprid_util"
FW1_BLOCK_DEL="fwaccel dos blacklist -d"
FW1_BLOCK_ADD="fwaccel dos blacklist -a"
BLOCK_TIME="-1 hour"
 
#
# get current log entry from STDIN
#
read LOGENTRY
 
#
# check if database exists, or create it
#
if [ ! -f "$DBFILE" ]; then
   $SQLITE $DBFILE "CREATE TABLE blacklist (ipaddr VARCHAR(30) PRIMARY KEY, fw1 VARCHAR(50), lastupdate DATETIME DEFAULT CURRENT_TIMESTAMP)"
fi
 
#
# process log entry and create field structure
#
while read line; do
   field=$(echo "$line" | cut -d ":" -f 1 | sed 's/ /_/g')
   value=$(echo "$line" | sed 's/: /:/g' | cut -d ":" -f 2-)
   declare "${field}=${value}"
done <<<$(echo $LOGENTRY | sed 's/; /\n/g')
 
 
#
# enforcing new entry
# Origin -> firewall name, must be dns resolvable, try /etc/hosts for gaia
# src    -> ip to fill into blacklist
#
if [ "$ProductName" == "SmartDefense" ]; then
   $SQLITE $DBFILE "INSERT INTO blacklist (ipaddr, fw1) VALUES ('$src', '$Origin')"
   echo "Adding new blocklist entry $src for firewall $Origin"
   $CPRIDU -server $Origin -verbose rexec -rcmd /bin/bash -c "$FW1_BLOCK_ADD $src"
fi
 
 
#
# cleanup old blacklist entries
#
RESULT=$($SQLITE $DBFILE "SELECT ipaddr,fw1 FROM blacklist WHERE lastupdate < DATETIME('now', '$BLOCK_TIME')")
if [ "$RESULT" != "" ]; then
   while read line; do
      BLACK=$(echo $line | cut -d "|" -f 1)
      MODULE=$(echo $line | cut -d "|" -f 2)
      echo "Removing outdated blacklist entry $BLACK from firewall $MODULE"
      $CPRIDU -server $MODULE -verbose rexec -rcmd /bin/bash -c "$FW1_BLOCK_DEL $BLACK"
      $SQLITE $DBFILE "DELETE FROM blacklist WHERE ipaddr='$BLACK' AND fw1='$MODULE'"
   done <<<$RESULT
fi
