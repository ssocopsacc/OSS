<?php
	$selected_host="";
	$virtual_service="";

	if (isset($_POST['selected_host'])) {
        	$selected_host=$_POST['selected_host'];
	}
	if (isset($_POST['virtual_service'])) {
		$virtual_service=$_POST['virtual_service'];
	}

	/* Some magic used to allow the edit command to pull up another web page */
	if ($virtual_service == "EDIT") {
		/* Redirect browser to editing page */
		header("Location: virtual_edit_virt.php?selected_host=$selected_host");
		/* Make sure that code below does not get executed when we redirect. */
		exit;
	}
	
	/* try and make this page non cacheable */
	header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");             // Date in the past
	header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");// always modified
	header("Cache-Control: no-cache, must-revalidate");           // HTTP/1.1
	header("Pragma: no-cache");                                   // HTTP/1.0

	require('parse.php'); /* read in the config! Hurragh! */

?>
<HTML>
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML Strict Level 3//EN">

<HEAD>
<TITLE>Piranha (Virtual Servers)</TITLE>
<STYLE TYPE="text/css">
<!-- 

TD      {
        font-family: helvetica, sans-serif;
        }
        
.logo   {
        color: #FFFFFF;
        }
        
A.logolink      {
        color: #FFFFFF;
        font-size: .8em;
        }
        
.taboff {
        color: #FFFFFF;
        }
        
.tabon  {
        color: #999999;
        }
        
.title  {
        font-size: .8em;
        font-weight: bold;
        color: #660000;
        }
        
.smtext {
        font-size: .8em;
        }
        
.green  {
        color: 
	}
// -->
</STYLE>

</HEAD>

<BODY BGCOLOR="#660000">

<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="5">
	<TR BGCOLOR="#CC0000"> <TD CLASS="logo"> <B>PIRANHA</B> CONFIGURATION TOOL </TD>
	<TD ALIGN=right CLASS="logo">
            <A HREF="introduction.html" CLASS="logolink">
            INTRODUCTION</A> | <A HREF="help.php" CLASS="logolink">
            HELP</A></TD>
	</TR>
</TABLE>

<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="5">
        <TR>
                <TD>&nbsp;<BR><FONT SIZE="+2" COLOR="#CC0000">VIRTUAL SERVERS</FONT><BR>&nbsp;</TD>
        </TR>
</TABLE>

<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="0"><TR><TD BGCOLOR="#FFFFFF">

<?php
	$virtual_service = "";
	if (isset($_POST['virtual_service'])) {
		$virtual_service = $_POST['virtual_service'];
	}

	if ($virtual_service == "ADD") {
		
		add_virtual(); /* append new data */
		
	}
	if ($virtual_service == "DELETE" ) {
		/* if ($debug) { echo "About to delete entry number $selected_host<BR>"; } */
		echo "</TD></TR></TABLE><TABLE WIDTH=\"100%\" BORDER=\"0\" CELLSPACING=\"1\" CELLPADDING=\"5\"><TR><TD BGCOLOR=\"ffffff\"><HR><H2><FONT COLOR=\"#cc0000\" CLASS=\"title\">Click <A HREF=\"virtual_main.php\" NAME=\"Virtual\">HERE</A> for refresh</FONT></H2><HR></TD></TR></TABLE>";
		open_file("w+");
		write_config("1", "", $selected_host);
		exit;
	}

	if ($virtual_service == "(DE)ACTIVATE" ) {
		switch ($virt[$selected_host]['active']) {
			case ""		:	$virt[$selected_host]['active'] = "0";	break;
			case "0"	:	$virt[$selected_host]['active'] = "1";	break;
			case "1"	:	$virt[$selected_host]['active'] = "0";	break;
			default		:	$virt[$selected_host]['active'] = "0";	break;
		}
	}
?>

<TABLE WIDTH="100%" BORDER="0" CELLSPACING="1" CELLPADDING="5">
        <TR BGCOLOR="#666666">
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="control.php" NAME="Control/Monitoring" CLASS="taboff"><B>CONTROL/MONITORING</B></A> </TD>
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="global_settings.php" NAME="Global Settings" CLASS="taboff"><B>GLOBAL SETTINGS</B></A> </TD>
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="redundancy.php" NAME="Redundancy" CLASS="taboff"><B>REDUNDANCY</B></A> </TD>
		<TD WIDTH="25%" ALIGN="CENTER" BGCOLOR="#FFFFFF"> <A HREF="virtual_main.php" NAME="Virtual" CLASS="tabon"><B>VIRTUAL SERVERS</B></A> </TD>
        </TR>
</TABLE>

<FORM METHOD="POST" ENCTYPE="application/x-www-form-urlencoded" ACTION="virtual_main.php">

	<TABLE BORDER="1" CELLSPACING="2" CELLPADDING="6">
		<TR>
			<TD></TD>
			       	<TD CLASS="title">STATUS</TD>
  		              	<TD CLASS="title">NAME</TD>
				<TD CLASS="title">VIP</TD>
				<TD CLASS="title">NETMASK</TD>
   		             	<TD CLASS="title">PORT</TD>
                		<TD CLASS="title">PROTOCOL</TD>
                		<TD CLASS="title">INTERFACE</TD>
		</TR>

<?php
	$loop1 = 1;
	
	while (isset($virt[$loop1]['virtual']) && $virt[$loop1]['virtual'] != "") { /* for all virtual items... */

		/* lhh - this CONFIRM is never made by any form
		if ($virtual_action == "CONFIRM") { $virt[$loop1t]['protocol'] = $index; };
		 */

		echo "<TR>";
		echo "<TD><INPUT TYPE=RADIO	NAME=selected_host	VALUE=$loop1";
			if ($selected_host == "") { $selected_host = 1; }
			if ($loop1 == $selected_host) { echo " CHECKED "; }
			echo "> </TD>";

		echo "<TD><INPUT TYPE=HIDDEN 	NAME=status		SIZE=8	COLS=6	VALUE=";
			switch ($virt[$loop1]['active']) {
				case "0"	:	echo "Down><FONT COLOR=red>down</FONT>"; break;
				case "1"	:	echo "Up><FONT COLOR=blue>up</FONT>"; break;
				case "2"	:	echo "Active><FONT COLOR=green>active</FONT>"; break;
				default		:	echo "Undef><FONT COLOR=cyan>undef</FONT>"; break;
			}
	 		echo "</TD>";

		echo "<TD><INPUT TYPE=HIDDEN 	NAME=name		SIZE=16	COLS=10	VALUE="	. $virt[$loop1]['virtual']	. ">";
		echo $virt[$loop1]['virtual']	. "</TD>";

		$addr = explode(" ", $virt[$loop1]['address']);
		echo "<TD><INPUT TYPE=HIDDEN 	NAME=address		SIZE=16	COLS=10	VALUE="	. $addr[0]	. ">";
		echo $addr[0]	. "</TD>";

		if (isset($virt[$loop1]['vip_nmask'])) {
			$temp = $virt[$loop1]['vip_nmask'];
		} else {
			$temp = "0.0.0.0";
		}
		echo "<TD><INPUT TYPE=HIDDEN 	NAME=vip_nmask		SIZE=16	COLS=10	VALUE="	. $temp . ">";

		if ($temp == "0.0.0.0") {
			echo "Unused</TD>";
		} else {
			echo $virt[$loop1]['vip_nmask']	. "</TD>";
		}


		echo "<TD><INPUT TYPE=HIDDEN 	NAME=port		SIZE=6	COLS=10	VALUE="	. $virt[$loop1]['port']		. ">";
		if ($virt[$loop1]['port']) {
			echo  $virt[$loop1]['port']	. "</TD>";
		} else {
			echo "n/a</TD>";
		}

		echo "<TD>";

//		if ($protocol == "" ) { 
//			$protocol = $virt[$loop1]['protocol'];
//		} else {
//			$virt[$loop1]['protocol'] = $protocol;
//		};
	
		switch ($virt[$loop1]['protocol']) {
			case	""	:	$virt[$loop1]['protocol'] = "tcp"; break;
			case	"tcp"	:	$virt[$loop1]['protocol'] = "tcp"; break;
			case	"udp"	:	$virt[$loop1]['protocol'] = "udp"; break;
			default		:	$virt[$loop1]['protocol'] = "tcp"; break;
		}

		echo $virt[$loop1]['protocol'];
		echo "</TD>";
			
		if (!isset($addr[1])) {
			$addr[1] = "";
		}
		
		echo "<TD><INPUT TYPE=HIDDEN 	NAME=interface	SIZE=16	COLS=10	VALUE="	. $addr[1]	. ">";
		echo $addr[1]	. "</TD>";
		echo "</TR>";
		$loop1++;
	}
?>
	<!-- end of dynamic generation -->

	</TABLE>
	<BR>

	<P>
	<!-- should align beside the above table -->

	<TABLE>
		<TR>
			<TD><INPUT TYPE="SUBMIT" NAME="virtual_service" VALUE="ADD"></TD>
			<TD><INPUT TYPE="SUBMIT" NAME="virtual_service" VALUE="DELETE"></TD>
			<TD><INPUT TYPE="SUBMIT" NAME="virtual_service" VALUE="EDIT"></TD>
			<TD><INPUT TYPE="SUBMIT" NAME="virtual_service" VALUE="(DE)ACTIVATE"></TD>
		</TR>
	</TABLE>
	<P>
	Note: Use the radio button on the side to select which virtual service you wish to edit before selecting 'EDIT' or 'DELETE'
<?php // echo "<INPUT TYPE=HIDDEN NAME=selected_host VALUE=$selected_host>" ?>

<?php
	if ($virtual_service != "DELETE") {
		open_file("w+");
		write_config("");
	}
?>

</FORM>
</TD></TR></TABLE>
</BODY>
</HTML>
