#!/usr/bin/perl
#@output=`ifconfig`;
#foreach $line(@output) {
#	if($line =~ m/Link encap/i) {
#		print $line;
#	}
#}

#print "entry: ";
#$_=<STDIN>;

#$nmatch=s:\b0([1-9]):+44 (0) \1:g;

#print "Count: $nmatch\n";
#print;
my $file = open($file_hand,"<","abc.txt");
@lines=<$file_hand>;
#print @lines[0];
#print @lines[1];
#print @lines.length;
@records;
$i = 0;
foreach $line (@lines) {
	while($line =~ m/(\S+)\s+Link\s+(\S+)(!Local)/gi) {
#		if($line =~ m/(\S+)\s+Local\s+(\S+)/gi) {next;}
		@records[$i] = "$1";
		$i++;
#		print "\n$line";
	}
}
print @records;
