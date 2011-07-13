#!/usr/bin/perl
#
# ossec2dshield.pl - Script to submit OSSEC firewall logs to dshield.org
# 
# Note: Dhield format spec available at: http://www.dshield.org/specs.html
#
# History
# -------
# 2011/07/13	Created
#

use strict;
use POSIX;
use Socket;
use Getopt::Long;
use Net::SMTP;

my $version	= "1.0";
my @months	= ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
		   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
my $counter	= 0;
my $body	= "";
my $tz;
my $debug;
my $help;
my $fwlog;
my $userid;
my $statefile;
my $lasttimestamp;
my $newtimestamp;
my $obfuscate;
my $test;
my ($mta, $mtaaddr, $mtaip, $from);

# Command line options
my $result = GetOptions(
		"debug"		=> \$debug,
		"help"		=> \$help,
		"log=s"		=> \$fwlog,
		"userid=s"	=> \$userid,
		"statefile=s"	=> \$statefile,
		"obfuscate"	=> \$obfuscate,
		"test"		=> \$test,
		"from=s"	=> \$from,
		"mta=s"		=> \$mta
);

#
# Display some help
#
if ($help) {
	print <<_HELP_;
Usage: $0 --log=file --userid=dshieldid --statefile=file --from=email --mta=hostname
		[--help] [--debug] [--test] [--obfusctate]
Where:
--help			: This help
--debug			: Display processing details to stdout
--test			: Test only, do not mail the info to dshield.org
--obfuscate		: Obfuscate the destination address (10.x.x.x)
--log=file		: Your OSSEC firewall.log
--userid=dshieldid	: Your dshield.org UserID (see http://www.dshield.org)
--statefile=file	: File to write the state of log processing
--from=email		: Your e-mail address (From:)
--mta=hostname		: Your Mail Transfer Agent (to send mail to dshield.org)
_HELP_
	exit 0
}

$debug && print "Running in debug mode.\n";

#
# Get the system timezone (referenced to GMT)
# Format requested by dshield.org: [+-]HH:MM
#
(($tz = strftime("%z", localtime())) eq "") && die "Cannot get the host timezone";
my $tzh = substr($tz,0, 3);
my $tzm = substr($tz,3, 2);
$tz = sprintf "%s:%s", $tzh, $tzm;
$debug && print "Host timezone: $tz.\n";

#
# We must have a dshield UserID
#
($userid eq "") && die "No Dshield user ID provided";
$debug && print "Using DShield UserID: $userid.\n";

($obfuscate && $debug) && print "Targe IP addresses will be obfuscated.\n";

#
# Check the provided e-mail address
#
($from eq "") && die "No e-mail address provided";
($from =~ /[\w-]+@([\w-]+\.)+[\w-]+/) || die "Incorrect e-mail format";

#
# Check the provided MTA
#
($mta eq "") && die "No MTA provided";
(!($mtaaddr = inet_aton($mta))) && die "Cannot resolve $mta";
$mtaip = inet_ntoa($mtaaddr);
$debug && print "Using MTA: $mtaip.\n";

#
# Read the last processed record timestamp
#
if (-r $statefile && open(STATEFILE, "$statefile")) {
	$lasttimestamp = <STATEFILE>;
	chomp($lasttimestamp);
	close(STATEFILE);
	$debug && print "Last timestamp read: $lasttimestamp.\n";
}
else {
	# Cannot read the file or non-existent
	# Use default timestamp, the "epoch"
	$lasttimestamp = "19700101000000";
	$debug && print "State file not or not readable, using default value.\n";
}

#
# Read the OSSEC firewall log
#
open(FWDATA, "$fwlog") || die "Cannot open/read firewall logs";
while(<FWDATA>) 
{
	my $line = $_;
	chomp($line);

	# We just submit DROP or BLOCK lines
	if ($line =~ /(DROP|BLOCK)/)
	{
		# Example of OSSEC firewall log:
		# 2011 Jul 12 11:55:17 (agent) 12.34.56.78->/var/log/ufw.log DROP TCP 33.44.55.66:2686->12.34.56.78:135
		$line =~ /^(\d+) (\w+) (\d+) (\d+):(\d+):(\d+) .*\-\>.* \w+ (\w+) (\d+\.\d+\.\d+\.\d+):(\d+)-\>(\d+\.\d+\.\d+\.\d+):(\d+)/g;

		# Sanitize data
		my ($month)	= grep $months[$_] eq $2, 0 .. $#months; $month++;
		my $timestamp	= sprintf "%4d-%02d-%02d %02d:%02d:%02d %s",
					$1, $month, $3, $4, $5, $6, $tz;
		my $proto	= $7;
		if ($proto ne "TCP" && $proto ne "UDP") {
			$proto = "???";
		}

		my $srcip	= $8;
		my $srcport	= $9;
		my $dstip	= $10;
		my $dstport	= $11;

		$newtimestamp = sprintf "%04d%02d%02d%02d%02d%02d",
					$1, $month, $3, $4, $5, $6;

		# TODO:
		# Check if we have correct IPv4 addresses
		# To support IPv6?
		if ($srcip =~ /\d+\.\d+\.\d+\.\d+/ && $dstip =~ /\d+\.\d+\.\d+\.\d+/) {

	 		# Do not process line already parsed (based on the timestamp)
			if ($newtimestamp > $lasttimestamp) {

				# Obfuscate destination IP address
				if ($obfuscate) {
					$dstip =~ s/^(\d+)\./10\./;
				}

				# TODO:
				# At the moment, we do not count duplicate entries
				# Count is hardcoded as "1"
				$body = $body . sprintf "%s\t%s\t%d\t%s\t%d\t%s\t%d\t%s\n",
					$timestamp,
					$userid,
					1,
					$srcip, $srcport,
					$dstip, $dstport,
					$proto;
				$counter++;
			}
		}
	}
	
}
close(FWDATA);

$debug && print $body;

#
# Send data to dshield (only of we have valid data)
#
if (!$test && $counter > 0) {
	$debug && print "Sending e-mail.\n";
	my $smtp = Net::SMTP->new($mtaip);
	$smtp->mail("$from");
	# $smtp->to("test\@dshield.org");
	$smtp->to("xavier\@rootshell.be");
	$smtp->data();
	my $buffer = "To: xavier\@rootshell.be\n" .
			"Subject: FORMAT DSHIELD USERID $userid TZ $tz OSSEC2dshield $version\n\n" .
			$body;
	$smtp->datasend($buffer);
	$smtp->dataend();
	$smtp->quit();
}

# Save the last timestamp
if (open(STATE, ">$statefile")) {
	print STATE $newtimestamp . "\n";
	close(STATE);
	$debug && print "Saved timestamp: $newtimestamp.\n";
}
else {
	die "Cannot save the current timestamp";
}

$debug && print "File processed. $counter record(s) processed.\n";

exit 0;