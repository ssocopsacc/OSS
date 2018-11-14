<?php
        $edit_action = $_GET['edit_action'];
        $selected_host = $_GET['selected_host'];
        $selected = $_GET['selected'];

	/* try and make this page non cacheable */
	header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");             // Date in the past
	header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT"); // always modified
	header("Cache-Control: no-cache, must-revalidate");           // HTTP/1.1
	header("Pragma: no-cache");                                   // HTTP/1.0

	require('parse.php');
	$s = 0;
	if ($selected == "") {
		$s = 1;
		$selected_host = 1;$selected=1;
		while($serv[$selected_host][$selected]['server'] != "") {
			if($serv[$selected_host][$selected]['server'] == "[unnamed]" && $serv[$selected_host][$selected]['address'] == "0.0.0.0") {
				break;
			}
			$selected++;
		}
	}

	if($selected != "" && $serv[$selected_host][$selected]['server'] == "[unnamed]") {
		$s = 1;
	}

	$loop1 = 1; $loop2 = 1;
	while($serv[$loop1][$loop2]['server'] != "") {
		$loop2++;
	}
//	$loop2--;

	if ($edit_action == "CANCEL") {
		if($serv[$selected_host][$selected]['server'] == "[unnamed]" && $serv[$selected_host][$selected]['address'] == "0.0.0.0") {
		$serv[$selected_host][$selected]['active']		=	2;
		$serv[$selected_host+1][$selected]['active']		=	2;
		open_file ("w+");
		write_config("");
	}
		header("Location: global_settings.php");		
		exit;
	}
	
	if (isset($_GET['edit_action']) && (($edit_action == "SAVE") || $edit_action == "MODIFY")) {
                $name = $_GET['name'];
//                $nmask = $_GET['nmask'];
                $address = $_GET['address'];
                $weight = $_GET['weight'];
//		$port = $_GET['port'];
//		echo "virtual address=".$virt[1]['address'];
		$count = 1;
		$flag1 = 0;
		$flag2 = 0;
		while( $count < $loop2) {
			if($count == $selected) { $count++; continue; }
			if((isset($serv[$selected_host][$count]['server']))) {
				if($name == $serv[$selected_host][$count]['server']) {
					$flag1 = 1;
//					break;
				}
				if($address == $serv[$selected_host][$count]['address']) {
					$flag2 = 1;
//					break;
				}
			}
			$count++;
		}
		$temp = explode(" ", $virt[1]['address']);
		if($flag1 == 1) {
			echo "<script language=\"javascript\">alert(\"server name is already in use for other server\")</script>";
		}
		else {
			if($flag2 == 1) {
				echo "<script language=\"javascript\">alert(\"IP Address is already in use for other server\")</script>";
			}
			else {
				if($temp[0] == $address) {
					echo "<script language=\"javascript\">alert(\"Server IP Address specified is already used as Virtual IP address\")</script>";
				}
				else {
				if ($name == "") {
					$name1 = $serv[$selected_host][$selected]['server'];
					$name2 = $serv[$selected_host][$selected]['server'];
				}
				else {
					$serv[$selected_host][$selected]['server']	=	str_replace(" ", "_", $name);
					$serv[$selected_host+1][$selected]['server']	=	str_replace(" ", "_", $name);
				}

				$serv[$selected_host][$selected]['address']		=	$address;
				$serv[$selected_host+1][$selected]['address']		=	$address;

				$serv[$selected_host][$selected]['active']		=	1;
				$serv[$selected_host+1][$selected]['active']		=	1;

				if ($nmask != "Unused" ) {
					$serv[$selected_host][$selected]['nmask']	=	$nmask;
					$serv[$selected_host+1][$selected]['nmask']	=	$nmask;
				}
				else {
					$serv[$selected_host][$selected]['nmask']	=	"";
					$serv[$selected_host+1][$selected]['nmask']	=	"";
				}
		
//		$serv[$selected_host][$selected]['heartbeat']		=	$heartbeat_lvs;
//		$serv[$selected_host][$selected]['port']		=	$port;
				$serv[$selected_host][$selected]['weight']		=	$weight;
//		$serv[$selected_host+1][$selected]['port']		=	$port;
				$serv[$selected_host+1][$selected]['weight']		=	$weight;
				header("Location: global_settings.php");
				}
			}
		}
	}

?>
<HTML>
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML Strict Level 3//EN">

<HEAD>
<TITLE>Propalms (Virtual servers - Editing virtual server - Editing real server)</TITLE>
<link href = "appearance.css" rel = "stylesheet" type = "text/css"/>
<script type="text/javascript" language="javascript" src="functions.js"></script>

<!--<STYLE TYPE="text/css">
 

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


</STYLE>
-->
</HEAD>

<BODY>
<!--
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
                <TD>&nbsp;<BR><FONT SIZE="+2" COLOR="#CC0000">EDIT REAL SERVER</FONT><BR>&nbsp;</TD>
        </TR>
</TABLE>


<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="0"><TR><TD BGCOLOR="#FFFFFF">


<TABLE WIDTH="100%" BORDER="0" CELLSPACING="1" CELLPADDING="5">
        <TR BGCOLOR="#666666">
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="control.php" NAME="Control/Monitoring" CLASS="taboff"><B>CONTROL/MONITORING</B></A> </TD>
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="global_settings.php" NAME="Global Settings" CLASS="taboff"><B>GLOBAL SETTINGS</B></A> </TD>
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="redundancy.php" NAME="Redundancy" CLASS="taboff"><B>REDUNDANCY</B></A> </TD>
		<TD WIDTH="25%" ALIGN="CENTER" BGCOLOR="#FFFFFF"> <A HREF="virtual_main.php" NAME="Virtual" CLASS="tabon"><B>VIRTUAL SERVERS</B></A> </TD>
        </TR>
</TABLE>
<?php
	// echo "Query = $QUERY_STRING";

?>


<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="5">
        <TR BGCOLOR="#EEEEEE">
                <TD WIDTH="60%">EDIT:
		
		<A HREF="virtual_edit_virt.php<?php //if (!empty($selected_host)) { echo "?selected_host=$selected_host"; } ?> " NAME="VIRTUAL SERVER">VIRTUAL SERVER</A>
		&nbsp;|&nbsp;

                <A HREF="virtual_edit_real.php<?php //if (!empty($selected_host)) { echo "?selected_host=$selected_host"; } ?> " CLASS="tabon" NAME="REAL SERVER">REAL SERVER</A>
		&nbsp;|&nbsp;

                <A HREF="virtual_edit_services.php<?php //if (!empty($selected_host)) { echo "?selected_host=$selected_host"; } ?> " NAME="MONITORING SCRIPTS">MONITORING SCRIPTS</A></TD>

		<TD WIDTH="30%" ALIGN="RIGHT"><A HREF="virtual_main.php">MAIN PAGE</A></TD>
        </TR>
</TABLE>

<P>
-->
	<FORM NAME="real_server_edit" METHOD="GET" ENCTYPE="application/x-www-form-urlencoded" ACTION="virtual_edit_real_edit.php">
<TABLE WIDTH="100px" BORDER="0" CELLSPACING="0" CELLPADDING="5">
        <TR><TD><DIV CLASS = "HeaderDefault"><DIV CLASS = "HeaderText"><?php if($s) echo "Add"; else echo "Edit";?> VPN SERVER</DIV></DIV></TD></TR>
	<TR><TD CLASS = "TdLine"><HR CLASS = "Line"></TD></TR>
	<TR><TD>
	<TABLE style = "padding-left:15px;width:500px;">
		<TR>
			<TD>Server Name: </TD>
			<TD><INPUT TYPE="TEXT" NAME="name" CLASS = "Text" VALUE=<?php echo $serv[$selected_host][$selected]['server'] ?>></TD>
		</TR>
		<TR>
			<TD>Server IP Address: </TD>
			<TD><INPUT TYPE="TEXT" NAME="address" CLASS = "Text" VALUE=<?php echo $serv[$selected_host][$selected]['address'] ?>></TD>
		</TR>
<!--		<TR>
			<TD> Netmask </TD>
			<TD>
				<SELECT NAME="nmask">
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "0.0.0.0") { echo "SELECTED"; } ?>> Unused
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.255.255") { echo "SELECTED"; } ?>> 255.255.255.255
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.255.252") { echo "SELECTED"; } ?>> 255.255.255.252
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.255.248") { echo "SELECTED"; } ?>> 255.255.255.248
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.255.240") { echo "SELECTED"; } ?>> 255.255.255.240
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.255.224") { echo "SELECTED"; } ?>> 255.255.255.224
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.255.192") { echo "SELECTED"; } ?>> 255.255.255.192
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.255.128") { echo "SELECTED"; } ?>> 255.255.255.128
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.255.0")   { echo "SELECTED"; } ?>> 255.255.255.0

					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.252.0")   { echo "SELECTED"; } ?>> 255.255.252.0
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.248.0")   { echo "SELECTED"; } ?>> 255.255.248.0
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.240.0")   { echo "SELECTED"; } ?>> 255.255.240.0
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.224.0")   { echo "SELECTED"; } ?>> 255.255.224.0
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.192.0")   { echo "SELECTED"; } ?>> 255.255.192.0
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.128.0")   { echo "SELECTED"; } ?>> 255.255.128.0
					<OPTION <?php if ($serv[$selected_host][$selected]['nmask'] == "255.255.0.0")   { echo "SELECTED"; } ?>> 255.255.0.0
				</SELECT>
			</TD>
		</TR>

		<TR>
			<TD>Port: </TD>
			<TD><INPUT TYPE="TEXT" NAME="port" CLASS = "Text" VALUE=<?php// echo $serv[$selected_host][$selected]['port'] ?>><small>(Leave blank to default to Virtual Server's Application Port)</small></TD>
		</TR>-->
		<TR>
			<TD>Server Weight: </TD>
			<TD><INPUT TYPE="TEXT" NAME="weight" CLASS = "Text" VALUE=<?php echo $serv[$selected_host][$selected]['weight'] ?>></TD>
		</TR>
	</TABLE>
	
	<?php	
		/* Welcome to the magic show */
		echo "<INPUT TYPE=HIDDEN NAME=selected_host VALUE=$selected_host>";
		echo "<INPUT TYPE=HIDDEN NAME=selected VALUE=$selected >";
	?>
<HR style = "margin-left:10px">

<TABLE style = "padding-left:10px" BORDER="0" CELLSPACING="0" CELLPADDING="5">
		<TR>
			<TD><BUTTON TYPE="SUBMIT" NAME="edit_action" CLASS = "ButtonNormalAppearance" VALUE="SAVE" ONCLICK="return real(real_server_edit)"><?php if($s) echo "SAVE"; else echo "MODIFY";?></BUTTON></TD>
			<TD><BUTTON TYPE="SUBMIT" NAME="edit_action" CLASS = "ButtonNormalAppearance" VALUE="CANCEL">CANCEL</BUTTON>
</TD></TR>
<?php open_file ("w+"); write_config(""); ?>
</TD></TR></TABLE>
</FORM>
</BODY>
</HTML>
