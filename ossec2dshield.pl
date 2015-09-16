#!/usr/bin/perl
#
# ossec2dshield.pl - Script to submit OSSEC firewall logs to dshield.org
# 
# Contact: xavier(at)rootshell(dot)be
# 
# Note: Dhield format spec available at: http://www.dshield.org/specs.html
#
# History
# -------
# 2011/07/13	Created
# 2011/07/14	Added filter for ports
# 2011/07/17	Added logging results to a log file
# 2011/07/27	Added support for duplicate events (counter > 1)
# 2015/06/01	Added command line switch to drop RFC1918 source IP addresses
#

use strict;
use POSIX;
use Socket;
use Getopt::Long;
use Net::SMTP;

my $version	= "1.3";
my @months	= ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
		   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
my %records;
my $key;
my $i;

my $counter	= 0;
my $tz;
my $debug;
my $help;
my $fwlog;
my $logfile;
my $userid;
my $statefile;
my $lasttimestamp;
my $newtimestamp;
my $obfuscate;
my $test;
my ($mta, $mtaaddr, $mtaip, $from);
my $portslist;
my $norfc1918;

# Command line options
my $result = GetOptions(
		"debug"		=> \$debug,
		"help"		=> \$help,
		"file=s"	=> \$fwlog,
		"userid=s"	=> \$userid,
		"statefile=s"	=> \$statefile,
		"log=s"		=> \$logfile,
		"ports=s"	=> \$portslist,
		"obfuscate"	=> \$obfuscate,
		"test"		=> \$test,
		"from=s"	=> \$from,
		"mta=s"		=> \$mta,
		"norfc1918"	=> \$norfc1918
);

#
# Display some help
#
if ($help) {
	print <<_HELP_;
Usage: $0 --file=fwlogs --userid=dshieldid --statefile=file --log=logfile
		--from=email --mta=hostname
		[--help] [--debug] [--test] [--obfusctate] [--norfc1918]
Where:
--help		 	 : This help
--debug			 : Display processing details to stdout
--test		 	 : Test only, do not mail data to dshield.org
--obfuscate		 : Obfuscate the destination address (10.x.x.x)
--norfc1918              : Skip RFC1918 source IP addresses
--ports=port1,!port2,... : Filter destination ports ex: !25,!80,445,53
--file=fwlogs		 : Your OSSEC firewall.log
--userid=dshieldid	 : Your dshield.org UserID (see http://www.dshield.org)
--statefile=file	 : File to write the state of log processing
--log=logfile            : Log script results to logfile
--from=email		 : Your e-mail address (From:)
--mta=hostname		 : Your Mail Transfer Agent (to send mail to dshield.org)
_HELP_
	exit 0
}

$debug && print "Running in debug mode.\n";

#
# Get the system timezone (referenced to GMT)
# Format requested by dshield.org: [+-]HH:MM
#
if (($tz = strftime("%z", localtime())) eq "") {
	WriteLog("Cannot get the host timezone", 1);
	exit 1;
}
my $tzh = substr($tz,0, 3);
my $tzm = substr($tz,3, 2);
$tz = sprintf "%s:%s", $tzh, $tzm;
$debug && print "Host timezone: $tz.\n";

($debug && $portslist ne "") && print "Ports Filter: $portslist.\n";

#
# We must have a dshield UserID
#
if ($userid eq "") {
	WriteLog("No Dshield user ID provided", 1);
	exit 1;
}
$debug && print "Using DShield UserID: $userid.\n";

($obfuscate && $debug) && print "Target IP addresses will be obfuscated.\n";
($norfc1918 && $debug) && print "RFC1918 source IP addresses will be dropped.\n";

#
# Check the provided e-mail address
#
if ($from eq "" ||
    !($from =~ /[\w-]+@([\w-]+\.)+[\w-]+/)) {
	WriteLog("No e-mail or incorrect e-mail address provided\n", 1);
	exit 1;
}

#
# Check the provided MTA
#
if ($mta eq "" ||
    !($mtaaddr = inet_aton($mta))) {
	WriteLog("No MTA or cannot resolve MTA.\n", 1);
	exit 1;
}

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
if (!open(FWDATA, "$fwlog")) {
	WriteLog("Cannot open/read firewall logs.\n", 1);
	exit 1;
}
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
		if ($proto ne "TCP" && $proto ne "tcp" && $proto ne "UDP" && $proto ne "udp") {
			$proto = "???";
		}

		my $srcip	= $8;
		my $srcport	= $9;
		my $dstip	= $10;
		my $dstport	= $11;

		$newtimestamp = sprintf "%04d%02d%02d%02d%02d%02d",
					$1, $month, $3, $4, $5, $6;

		if ($portslist ne "" && ProcessPort($dstport) == 0) {
			next;
		}

		# TODO:
		# Check if we have correct IPv4 addresses
		# To support IPv6?
		if ($srcip =~ /\d+\.\d+\.\d+\.\d+/ && $dstip =~ /\d+\.\d+\.\d+\.\d+/) {

			# Skip RFC1918 source IP addresses
			if ($norfc1918 &&
			    $srcip !~ /(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)/) {

	 			# Do not process line already parsed (based on the timestamp)
				if ($newtimestamp > $lasttimestamp) {

					# Obfuscate destination IP address
					if ($obfuscate) {
						$dstip =~ s/^(\d+)\./10\./;
					}	

					# Process the firewall event
					# Generate a unique key
					$key = $srcip.$srcport.$dstip.$dstport.$proto;
					if (! $records{$key}) {
						# New line: insert a new record
						my @newrecord = ( $timestamp,
								  $userid,
								  1,
								  $srcip, $srcport,
								  $dstip, $dstport,
								  $proto );
						$records{$key} = [ @newrecord ];
						$counter++;
					}
					else {
						# Record already exists, update counter & timestamp
						$records{$key}[0] = $timestamp;
						$records{$key}[2] ++;
					}
				}
			}
		}
	}
	
}
close(FWDATA);

if ($debug) {
	for $key ( keys %records) {
		for $i (0 .. $#{ $records{$key} } ) {
			($i > 0) && print "\t";
			print $records{$key}[$i];
		}
		print "\n";
	}
}

#
# Send data to dshield (only of we have valid data)
#
if (!$test && $counter > 0) {
	$debug && print "Sending e-mail.\n";
	my $body = "";
	my $smtp = Net::SMTP->new($mtaip);

	$smtp->mail("$from");
	$smtp->to("report\@dshield.org");
	$smtp->data();
	# Populate the mail body with our records
	for $key ( keys %records) {
		for $i (0 .. $#{ $records{$key} } ) {
			if ($i > 0) { $body = $body . "\t"; }
			$body = $body . $records{$key}[$i];
		}
		$body = $body . "\n";
	}
	my $buffer = "To: report\@dshield.org\n" .
			"Subject: FORMAT DSHIELD USERID $userid TZ $tz OSSEC2dshield $version\n\n" .
			$body;
	$smtp->datasend($buffer);
	$smtp->dataend();
	$smtp->quit();

	# Save the last timestamp
	if (open(STATE, ">$statefile")) {
		print STATE $newtimestamp . "\n";
		close(STATE);
		$debug && print "Saved timestamp: $newtimestamp.\n";
	}
	else {
		WriteLog("Cannot save the current timestamp\n", 1);
	}
}

$debug && print "File processed. $counter record(s) processed.\n";
WriteLog("File processed. $counter record(s) sent to dshield.org\n",0);

exit 0;

sub ProcessPort() {
	my $dstport = shift;
	my @ports = split(",", $portslist);
	my $found=0;
	my ($port, $port2);
	foreach $port(@ports) {
		if (index($port, "!") == -1) {
			if ($port < 1 || $port > 65535) {
				WriteLog("Invalid port filter: $port\n", 1);
				exit 1;
			}
			if ($dstport eq $port) {
				$found=1;
				last;
			}
		}
		else {
			$port2 = substr($port,1);
			if ($port2 < 1 || $port2 > 65535) {
				WriteLog("Invalid port filter: $port\n", 1);
				exit 1;
			}
			if ($dstport ne $port2) {
				$found=1;
			}
			else {
				$found=0;
				last;
			}
		}
	}
	return($found);
}

sub WriteLog() {
	my $msg = shift;
	my $console = shift;
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);

	if ($console) {
		print $msg;
	}

	if ($logfile && open(LOGFILE, ">>$logfile")) {
		printf LOGFILE "[%04d/%02d/%02d %02d:%02d:%02d] %s", 
			$year+1900, $mon+1, $mday, $hour, $min, $sec, $msg;
		close(LOGFILE);
	}
	else {
		print "ERROR: Cannot write logfile $logfile: $!\n";
		exit 1;
	}
}

# Eof
