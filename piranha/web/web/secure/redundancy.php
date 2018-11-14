<?php
	/* try and make this page non cacheable */
	header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");             // Date in the past
	header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");// always modified
	header("Cache-Control: no-cache, must-revalidate");           // HTTP/1.1
	header("Pragma: no-cache");                                   // HTTP/1.0

	require('parse.php'); /* read in the config! Hurragh! */
	global $enable;

	$prim['heartbeat'] = 1; /* argh! - permently set afaik */

	// echo "[$redundancy_action] [$enable] [$redundant] [$redundant_private] [$hb_interval] [$dead_after] [$hb_port]<BR>";
	$redundancy_act = "";
	if (isset($_GET['redundancy_action'])) {
		$redundancy_act = $_GET['redundancy_action'];
	}

	if ($redundancy_act == "CANCEL") {
		/* Redirect browser to editing page */
		header("Location: global_settings.php");
		/* Make sure that code below does not get executed when we redirect. */
		exit;
	}
	if ($redundancy_act == "SAVE") {
		if (isset($_GET['redundant'])) {
			$prim['backup'] = $_GET['redundant'];
		}
		if (isset($_GET['redundant_private'])) {
			$prim['backup_private'] = $_GET['redundant_private'];
		}
		if (isset($_GET['hb_interval'])) {
			$prim['keepalive'] = $_GET['hb_interval'];
		}
		if (isset($_GET['dead_after'])) {
			$prim['deadtime'] = $_GET['dead_after'];
		}
		if (isset($_GET['hb_port'])) {
			$prim['heartbeat_port'] = $_GET['hb_port'];
		}
		if (isset($_GET['monitor_links'])) {
			if ($_GET['monitor_links'] == "on") {
				$prim['monitor_links'] = "1";
			} else { 
				$prim['monitor_links'] = "0";
			}
		} else { 
			$prim['monitor_links'] = "0";
		}
		if (isset($_GET['syncdaemon'])) {
			if ($_GET['syncdaemon'] == "on") {
				$prim['syncdaemon'] = "1";
			} else { 
				$prim['syncdaemon'] = "0";
			}
		} else { 
			$prim['syncdaemon'] = "0";
		}
		$selected_host = 1;
		while($selected_host < 3) {
		$virt[$selected_host]['reentry']		=	$_GET['reentry'];
                $virt[$selected_host]['timeout']		=	$_GET['timeout'];
                $virt[$selected_host]['quiesce_server']		=	$_GET['quiesce_server'];
                $virt[$selected_host]['load_monitor']		=	$_GET['load'];
                $sched = $_GET['sched'];
                switch ($sched) {
                        case "Round robin"					:	$sched="rr"; break;
                        case "Weighted least-connections"			:	$sched="wlc"; break;
                        case "Weighted round robin"				:	$sched="wrr"; break;
                        case "Least-connection"					:	$sched="lc"; break;
                        case "Locality-Based Least-Connection Scheduling"	:	$sched="lblc"; break;
                        case "Locality-Based Least-Connection Scheduling (R)"	:	$sched="lblcr"; break;
                        case "Destination Hash Scheduling"			:	$sched="dh"; break;
                        case "Source Hash Scheduling"				:	$sched="sh"; break;
                        default							:	$sched="wlc"; break;
                }
                $virt[$selected_host]['scheduler']		=	$sched;
                $virt[$selected_host]['persistent']		=	$_GET['persistent'];
                $pmask = $_GET['pmask'];
                if ($pmask != "Unused" ) {
                        $virt[$selected_host]['pmask']		=	$pmask;
                } else {
                        $virt[$selected_host]['pmask']		=	"";
                }
		$selected_host++;
		}
		open_file ("w+"); 
		write_config("");

		header("Location: global_settings.php");

		/*
		$prim['backup_private']		= $_GET['redundant_private'];
		$prim['keepalive'] 		= $_GET['hb_interval'];
		$prim['deadtime'] 		= $_GET['dead_after'];
		$prim['heartbeat_port'] 	= $_GET['hb_port'];
		*/
	}

	if ($prim['backup_active'] == "") {
		$prim['backup_active'] = 0;
	}		

	if (($enable == "1") || ($enable == "0")) {
		$prim['backup_active']		= (1 - $enable) ;
	}

	if ($prim['backup'] == "") {		$prim['backup'] = "0.0.0.0"; }
	if ($prim['backup_private'] == "") {	$prim['backup_private'] = ""; }
	if ($prim['keepalive'] == "") {		$prim['keepalive'] = "6"; }
	if ($prim['deadtime'] == "") {		$prim['deadtime'] = "18"; }
	if ($prim['heartbeat_port'] == "") { 	$prim['heartbeat_port'] = "539";}

	if ($redundancy_act == "RESET" ) {
		$prim['backup'] 	= "0.0.0.0";
		$prim['backup_private']	= "";
		$prim['keepalive'] 	= "6";
		$prim['deadtime']	= "18";
		$prim['heartbeat_port']	= "539";
	}
	
	if ((isset($_GET['full_enable'])) &&
	    ($_GET['full_enable'] == "ENABLE")) {
		$prim['backup_active'] = "1";
	}

	if ($redundancy_act=="DISABLE") {
		$prim['backup_active'] = "0";
	}
?>

<HTML>
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML Strict Level 3//EN">

<HEAD>
<TITLE>Propalms (Advanced Configuration)</TITLE>
<link href = "appearance.css" rel = "stylesheet" type = "text/css"/>
<link rel="StyleSheet" href="help.css" type="text/css"/>
<script type="text/javascript" language="javascript" src="functions.js"></script>
<script type="text/javascript">
function checkform()
{
//	echo "hello()";
//	hello(document.advanced);
//	alert("inside checkform");
	if(!advance(document.getElementById("advanced"))) {
		return false;
	}

<?php
	open_file ("w+"); 
	write_config("");
?>

	document.advanced.submit();
}
</script>
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
<table width="99%">
<tr valign="top"><td>
<TABLE WIDTH = "99%">
        <TR><TD width="80%"><DIV CLASS = "HeaderDefault"><DIV CLASS = "HeaderText">Advanced HA Configuration</DIV></DIV></TD></TR>
</TABLE>
<TABLE WIDTH = "99%">
	<TR><TD CLASS = "TdLine"><HR CLASS = "Line"></TD></TR>
</TABLE>
<TABLE WIDTH = "99%">
	<TR><TD width="80%" valign="top">
<FORM NAME="advanced" METHOD="GET" ENCTYPE="application/x-www-form-urlencoded">
<TABLE WIDTH="400px">
	<TR><TD>
		<fieldset CLASS = "LB" style = "width:400px;height:160px">
		<TABLE WIDTH="100%">
        		<TR><TD COLSPAN = "2"><STRONG>High Availability Settings</STRONG></TD></TR>

	<?php
/*		if ($prim['backup_active'] == "1") {
			echo "<FONT COLOR=green>active</FONT>";
		} else {
			echo "<FONT COLOR=\"#cc0000\">inactive</FONT>";
		}*/
	?> 
		</TABLE>
<?php 
	if (isset($_GET['full_enable']) &&
	    ($_GET['full_enable']=="ENABLE")) {
		$prim['backup_active'] = "1";
	}
		 $prim['backup_active'] = "1";
	if ($prim['backup_active'] == "1") { ?>

<!--	<HR>-->
	<TABLE>	
<!--		<TR>
			<TD> Redundant server public IP:</TD> 
			<TD> <INPUT TYPE="TEXT" NAME="redundant" CLASS = "Text" VALUE=
			<?php
//			if ($prim['backup'] != "") {
//				echo $prim['backup'];
//			};
//			echo ">";
			?>
			</TD>
		</TR>
<?php
/*	if ($prim['primary_private'] != "") { ?>
		
		<TR>
			<TD> Redundant server private IP:</TD> 
			<TD> <INPUT TYPE="TEXT" NAME="redundant_private" CLASS = "Text" VALUE=
			<?php
			if ($prim['backup_private'] != "") {
				echo $prim['backup_private'];
			};
			echo ">";
*/			?>
			</TD>
		</TR>-->
<?php// }; ?>		
<!--		<TR>
			<TD COLSPAN="3"> <HR SIZE="1" WIDTH="100%" NOSHADE></TD>
		</TR>
-->	
		<TR>
			<TD>Heartbeat interval (seconds):</TD>
			<TD><INPUT TYPE="TEXT" NAME="hb_interval" CLASS = "Text" VALUE=
			<?php
			if ($prim['keepalive'] != "") {
				echo $prim['keepalive'];
			};
			echo ">";
			?></TD>
		</TR>
		<TR>
			<TD>Assume dead after (seconds):</TD>
			<TD><INPUT TYPE="TEXT" NAME="dead_after" CLASS = "Text" VALUE=
			<?php
			if ($prim['deadtime'] != "") {
				echo $prim['deadtime'];
			};
			echo ">";
			?></TD>
		</TR>
		<TR>
			<TD>Heartbeat runs on port:</TD>
			<TD><INPUT TYPE="TEXT" NAME="hb_port" CLASS = "Text" VALUE=
			<?php
			if ($prim['heartbeat_port'] != "") {
				echo $prim['heartbeat_port'];
			}
			echo ">";
			?></TD>
		</TR>
		<TR>
			<TD>Monitor NIC links for failures:</TD>
			<TD><INPUT TYPE="checkbox" NAME="monitor_links" CLASS = "Boolean" 
			<?php
			if ($prim['monitor_links'] == "1") {
				echo "CHECKED";
			};
			echo ">";
			?></TD>
		</TR>
		<TR>
			<TD>Syncdaemon:</TD>
			<TD><INPUT TYPE="checkbox" NAME="syncdaemon" CLASS = "Boolean" 
			<?php
			if ($prim['syncdaemon'] == "1") {
				echo "CHECKED";
			};
			echo ">";
			?></TD>
		</TR>
	</TABLE>
</fieldset>
</TD></TR>
<TR><TD></TD></TR>
<?php } ?>

<?php
//        $selected_host = $_GET['selected_host'];
//	if($selected_host == "") {
		$selected_host = 1;
//	}
	$vev_action = "";

	if (isset($_GET['vev_action'])) {
		$vev_action = $_GET['vev_action'];
	}
	if (isset($_GET['network'])) {
		$network = $_GET['network'];
		if($network == "NAT" || $network == "Tunneling") {
//	alert("NAT and Tunneling are currently unavailable");

		}
	}
//	if ($vev_action == "CANCEL") {
		/* Redirect browser to editing page */
//		header("Location: virtual_main.php?selected_host=$selected_host");
		/* Make sure that code below does not get executed when we redirect. */
/*		exit;
	}

	if (($selected_host == "")) {
		header("Location: virtual_main.php");
		exit;
	}

	if ($vev_action == "EDIT") {
		/* Redirect browser to editing page */
//		header("Location: virtual_edit_services.php?selected_host=$selected_host");
		/* Make sure that code below does not get executed when we redirect. */
/*		exit;
	}
	
	/* try and make this page non cacheable */
/*	header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");             // Date in the past
	header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");// always modified
	header("Cache-Control: no-cache, must-revalidate");           // HTTP/1.1
	header("Pragma: no-cache");                                   // HTTP/1.0

	require('parse.php'); /* read in the config! Hurragh! */

/*        $temp = explode(" ", $virt[$selected_host]['address']);

	if ( $vev_action == "ACCEPT" ) {

		/* we don't allow for deletions from here */
/*                $hostname = $_GET['hostname'];
		if ($hostname == "")	{
			$hostname = $virt[$selected_host]['virtual'];
		} else {
			/* lets just squeeze out those spaces that would choke the parser */
/*			$virt[$selected_host]['virtual'] = str_replace (" ", "_", $hostname);
		}

                $virt[$selected_host]['port']			=	$_GET['port'];
                // $virt[$selected_host]['address']		=	$temp[0];
                $virt[$selected_host]['protocol']		=	$_GET['protocol'];
                $virt[$selected_host]['reentry']		=	$_GET['reentry'];
                $virt[$selected_host]['timeout']		=	$_GET['timeout'];
                $virt[$selected_host]['quiesce_server']		=	$_GET['quiesce_server'];
                $virt[$selected_host]['load_monitor']		=	$_GET['load'];
                $sched = $_GET['sched'];
                switch ($sched) {
                        case "Round robin"					:	$sched="rr"; break;
                        case "Weighted least-connections"			:	$sched="wlc"; break;
                        case "Weighted round robin"				:	$sched="wrr"; break;
                        case "Least-connection"					:	$sched="lc"; break;
                        case "Locality-Based Least-Connection Scheduling"	:	$sched="lblc"; break;
                        case "Locality-Based Least-Connection Scheduling (R)"	:	$sched="lblcr"; break;
                        case "Destination Hash Scheduling"			:	$sched="dh"; break;
                        case "Source Hash Scheduling"				:	$sched="sh"; break;
                        default							:	$sched="wlc"; break;
                }
                $virt[$selected_host]['scheduler']		=	$sched;
                $virt[$selected_host]['persistent']		=	$_GET['persistent'];
                $pmask = $_GET['pmask'];
                if ($pmask != "Unused" ) {
                        $virt[$selected_host]['pmask']		=	$pmask;
                } else {
                        $virt[$selected_host]['pmask']		=	"";
                }
                $vip_nmask = $_GET['vip_nmask'];
                if ($vip_nmask != "Unused" ) {
                        $virt[$selected_host]['vip_nmask']	=	$vip_nmask;
                } else {
                        $virt[$selected_host]['vip_nmask']	=	"";
                }

                $virt[$selected_host]['fwmark']		=	$_GET['fwmark'];

                $temp[0] = $_GET['address'];
                $temp[1] = $_GET['device'];
                $virt[$selected_host]['sorry_server']       =       $_GET['sorry_server'];
                $virt[$selected_host]['address']      		=       $_GET['address'] . " " . $_GET['device'];
	}
*/
?>
<TR><TD>
<fieldset CLASS = "LB" style = "width:400px">
<TABLE>
        <TR><TD COLSPAN = "2"><STRONG>Load Balancer Service Settings</STRONG></TD></TR>
</TABLE>

<TABLE WIDTH="100%">
<!--        <TR><TD><DIV CLASS = "HeaderDefaultLB"><DIV style = "font-size:15px">LoadBalancer Service Settings</DIV></DIV></TD></TR>
	<TR><TD CLASS = "TdLine"><HR CLASS = "Line"></TD></TR>-->

<!--	<TR>
		<TD>Name:</TD>
		<TD><INPUT TYPE="TEXT" NAME="hostname" CLASS = "Text" VALUE= <?php echo $virt[$selected_host]['virtual'] ; ?>></TD>
	</TR>-->
<!--	<TR>

		<TD>Application port:</TD>
		<TD><INPUT TYPE="TEXT" NAME="port" CLASS = "Text" VALUE=<?php echo  $virt[$selected_host]['port'] ?>></TD>
	</TR>
	<TR>
		<TD>Protocol:</TD>
		<TD>
			<SELECT NAME="protocol" CLASS = "Select">
				<OPTION <?php if (($virt[$selected_host]['protocol'] == "tcp") || 
					       ($virt[$selected_host]['protocol'] == "")) { echo "SELECTED"; } ?>> tcp
				<OPTION <?php if ($virt[$selected_host]['protocol'] == "udp") { echo "SELECTED"; } ?>> udp
			</SELECT>
		</TD>

	</TR>

	<TR>
		<TD>Virtual IP Address: </TD>
		<TD><INPUT TYPE="TEXT" NAME="address" CLASS = "Text" VALUE=<?php echo $temp[0] ?>></TD>
	</TR>
	<TR>
		<TD> Virtual IP Network Mask:</TD>
		<TD>
			<SELECT NAME="vip_nmask" CLASS = "Select">
				<?php if (!isset($virt[$selected_host]['vip_nmask'])) { 
					$virt[$selected_host]['vip_nmask'] = "0.0.0.0";
				} ?>

				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "0.0.0.0") { echo "SELECTED"; } ?>> Unused
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.255.255") { echo "SELECTED"; } ?>> 255.255.255.255
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.255.252") { echo "SELECTED"; } ?>> 255.255.255.252
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.255.248") { echo "SELECTED"; } ?>> 255.255.255.248
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.255.240") { echo "SELECTED"; } ?>> 255.255.255.240
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.255.224") { echo "SELECTED"; } ?>> 255.255.255.224
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.255.192") { echo "SELECTED"; } ?>> 255.255.255.192
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.255.128") { echo "SELECTED"; } ?>> 255.255.255.128
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.255.0")   { echo "SELECTED"; } ?>> 255.255.255.0

				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.252.0")   { echo "SELECTED"; } ?>> 255.255.252.0
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.248.0")   { echo "SELECTED"; } ?>> 255.255.248.0
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.240.0")   { echo "SELECTED"; } ?>> 255.255.240.0
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.224.0")	{ echo "SELECTED"; } ?>> 255.255.224.0
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.192.0")	{ echo "SELECTED"; } ?>> 255.255.192.0

				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.128.0")	{ echo "SELECTED"; } ?>> 255.255.128.0
				<OPTION <?php if ($virt[$selected_host]['vip_nmask'] == "255.255.0.0")	{ echo "SELECTED"; } ?>> 255.255.0.0

			</SELECT>
		</TD>
	</TR>
	<TR>
		<TD>Sorry Server: </TD>
		<TD><INPUT TYPE="TEXT" NAME="sorry_server" CLASS = "Text" VALUE=<?php echo $virt[$selected_host]['sorry_server'] ?>></TD>
	</TR>
	<TR>
		<TD>Firewall Mark: </TD>
		<TD> <INPUT TYPE="TEXT" NAME="fwmark" CLASS = "Text" VALUE="<?php if (isset($virt[$selected_host]['fwmark'])) {
								      echo $virt[$selected_host]['fwmark']; } ?>"></TD>
	</TR>

	<TR>
		<TD>Device: </TD>
		<TD> <INPUT TYPE="TEXT" NAME="device" CLASS = "Text" VALUE="<?php echo $temp[1]; ?>"></TD>
	</TR>
-->	<TR>
		<TD>Re-entry Time(Seconds): </TD>
		<TD> <INPUT TYPE="TEXT" NAME="reentry" CLASS = "Text" VALUE=<?php echo $virt[$selected_host]['reentry'] ?>></TD>
	</TR>
	<TR>
		<TD>Service timeout(Seconds): </TD>
		<TD> <INPUT TYPE="TEXT" NAME="timeout" CLASS = "Text" VALUE=<?php echo $virt[$selected_host]['timeout'] ?>></TD>
	</TR>
	<TR>
		<TD>Quiesce server:</TD>
		<TD>

		<input type="radio" name="quiesce_server" value="1" <?php if ($virt[$selected_host]['quiesce_server'] == "1")		{ echo "CHECKED"; } ?> > Yes
		<input type="radio" name="quiesce_server" value="0" <?php if (($virt[$selected_host]['quiesce_server'] == "0" ) || ( $virt[$selected_host]['quiesce_server'] == "" ) )	{ echo "CHECKED"; } ?> > No

		</TD>
	</TD>	
	<!-- <TR>
		<TD> Load monitoring tool:</TD>
		<TD>
		<SELECT NAME="load" CLASS = "Select">
			<OPTION <?php if ($virt[$selected_host]['load_monitor'] == "none")		{ echo "SELECTED"; } ?> > none
			<OPTION <?php if ($virt[$selected_host]['load_monitor'] == "rup")		{ echo "SELECTED"; } ?> > rup
			<OPTION <?php if ($virt[$selected_host]['load_monitor'] == "ruptime")	{ echo "SELECTED"; } ?> > ruptime
		</SELECT>
		</TD>
	</TR> -->
	<TR>
		<TD> Scheduling: </TD>
		<TD>

		<SELECT NAME="sched" CLASS = "Select">
			<OPTION <?php if ($virt[$selected_host]['scheduler'] == "rr")	{ echo "SELECTED"; } ?>> Round robin
			<OPTION <?php if ($virt[$selected_host]['scheduler'] == "wlc")	{ echo "SELECTED"; } ?>> Weighted least-connections
			<OPTION <?php if ($virt[$selected_host]['scheduler'] == "wrr")	{ echo "SELECTED"; } ?>> Weighted round robin
			<OPTION <?php if ($virt[$selected_host]['scheduler'] == "lc")	{ echo "SELECTED"; } ?>> Least-connection
			<OPTION <?php if ($virt[$selected_host]['scheduler'] == "lblc")	{ echo "SELECTED"; } ?>> Locality-Based Least-Connection Scheduling
			<OPTION <?php if ($virt[$selected_host]['scheduler'] == "lblcr")	{ echo "SELECTED"; } ?>> Locality-Based Least-Connection Scheduling (R)
			<OPTION <?php if ($virt[$selected_host]['scheduler'] == "dh")	{ echo "SELECTED"; } ?>> Destination Hash Scheduling
			<OPTION <?php if ($virt[$selected_host]['scheduler'] == "sh")	{ echo "SELECTED"; } ?>> Source Hash Scheduling
		</SELECT>
		</TD>
	</TR>

	<TR>
		<TD> Persistence (Seconds):</TD>
		<TD><INPUT TYPE="TEXT" NAME="persistent" CLASS = "Text" VALUE=<?php echo $virt[$selected_host]['persistent'] ?>></TD>
	</TR>
	<!-- <TR>
		<TD> Persistence Network Mask:</TD>
		<TD>
		<SELECT NAME="pmask" CLASS = "Select">
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "") { echo "SELECTED"; } ?>> Unused
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.255.255")	{ echo "SELECTED"; } ?>> 255.255.255.255
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.255.252")	{ echo "SELECTED"; } ?>> 255.255.255.252
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.255.248")	{ echo "SELECTED"; } ?>> 255.255.255.248
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.255.240")	{ echo "SELECTED"; } ?>> 255.255.255.240
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.255.224")	{ echo "SELECTED"; } ?>> 255.255.255.224
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.255.192")	{ echo "SELECTED"; } ?>> 255.255.255.192
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.255.128") 	{ echo "SELECTED"; } ?>> 255.255.255.128
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.255.0")   	{ echo "SELECTED"; } ?>> 255.255.255.0

			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.252.0")   	{ echo "SELECTED"; } ?>> 255.255.252.0
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.248.0")   	{ echo "SELECTED"; } ?>> 255.255.248.0
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.240.0")   	{ echo "SELECTED"; } ?>> 255.255.240.0
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.224.0")	{ echo "SELECTED"; } ?>> 255.255.224.0
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.192.0")	{ echo "SELECTED"; } ?>> 255.255.192.0
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.128.0")	{ echo "SELECTED"; } ?>> 255.255.128.0
			<OPTION <?php if ($virt[$selected_host]['pmask'] == "255.255.0.0")	{ echo "SELECTED"; } ?>> 255.255.0.0

		</SELECT>
		</TD>
	</TR> -->
</TABLE>

<?php echo "<INPUT TYPE=HIDDEN NAME=selected_host VALUE=$selected_host>" ?>

<!--<DIV CLASS = "TdLine"><HR CLASS = "Line"></DIV>-->
<!--<TABLE BORDER="0" CELLSPACING="1" CELLPADDING="5">
        <TR>
                <TD>
                        <BUTTON TYPE="Submit" NAME="vev_action" CLASS = "ButtonNormalAppearance" VALUE="ACCEPT">SAVE</BUTTON>
                        <SPAN CLASS="taboff"> Click here to apply changes to this page</SPAN>
                </TD>

<table><tr>
  		<TD>
                        <BUTTON TYPE="Submit" NAME="vev_action" CLASS = "ButtonNormalAppearance" VALUE="CANCEL" href = "virtual_main.php">CANCEL</BUTTON>
                        <SPAN CLASS="taboff"> Click here to apply changes to this page</SPAN>
                </TD>

        </TR>
</TABLE>-->
<!--<?php// echo "<INPUT TYPE=HIDDEN NAME=selected_host VALUE=$selected_host>" ?>-->

<?php// open_file ("w+"); write_config(""); ?>

</fieldset>
</TD></TR>
<TR><TD></TD></TR>
<TR><TD>
<fieldset CLASS = "LB" style = "width:400px">
<TABLE width = "100%">
        <TR><TD COLSPAN = "2"><STRONG>Cluster Type</STRONG></TD></TR>
	<TR><TD></TD></TR>
	<TR>
		<TD>Routing Type:</TD>
<!--		<TD>
		<SELECT NAME="network">
				<OPTION <?php if ($prim['network'] == "nat") { echo "SELECTED"; } ?>> NAT
				<OPTION <?php if ($prim['network'] == "direct") { echo "SELECTED"; } ?>> Direct Routing
				<OPTION <?php if ($prim['network'] == "tunnel") { echo "SELECTED"; } ?>> Tunneling
		</SELECT>
		</TD>-->
		<TD>
<table align = "middle"><tr><td>	<!--<BUTTON TYPE="SUBMIT" NAME="network" CLASS = "ButtonNormalAppearance" VALUE="NAT">NAT</BUTTON></td><td>-->
		<BUTTON STYLE = "width: 100px;" NAME="network" CLASS = "ButtonNormalAppearance" VALUE="Direct Routing" disabled="disabled">Direct Routing</BUTTON></td><!--<td>
		<BUTTON TYPE="SUBMIT" NAME="network" CLASS = "ButtonNormalAppearance" VALUE="Tunneling">Tunneling</BUTTON></td>--></tr></table>
	</TD>
	</TR> 
	<?php/*if (isset($_GET['network']) && ($_GET['network'] == "NAT")) { ?>
	 <!-- <TR>
		<TD>NAT Router IP:</TD>
		<TD><INPUT TYPE="TEXT" NAME="NATRtrIP" CLASS = "Text" VALUE="<?php
			$ip = explode(" ", $prim['nat_router']);
			echo $ip[0];
			//echo $prim['...???? WHAT??
		?>"></TD>
	</TR>
	<TR>
		<TD>NAT Router netmask:</TD>
		<TD>
			<SELECT NAME="nat_nmask" CLASS = "Select">
				<OPTION <?php if ($NATRtrNmask == "255.255.255.255") { echo "SELECTED"; } ?>> 255.255.255.255
				<OPTION <?php if ($NATRtrNmask == "255.255.255.252") { echo "SELECTED"; } ?>> 255.255.255.252
				<OPTION <?php if ($NATRtrNmask == "255.255.255.248") { echo "SELECTED"; } ?>> 255.255.255.248
				<OPTION <?php if ($NATRtrNmask == "255.255.255.240") { echo "SELECTED"; } ?>> 255.255.255.240
				<OPTION <?php if ($NATRtrNmask == "255.255.255.224") { echo "SELECTED"; } ?>> 255.255.255.224
				<OPTION <?php if ($NATRtrNmask == "255.255.255.192") { echo "SELECTED"; } ?>> 255.255.255.192
				<OPTION <?php if ($NATRtrNmask == "255.255.255.128") { echo "SELECTED"; } ?>> 255.255.255.128
				<OPTION <?php if ($NATRtrNmask == "255.255.255.0")   { echo "SELECTED"; } ?>> 255.255.255.0
				<OPTION <?php if ($NATRtrNmask == "255.255.252.0")   { echo "SELECTED"; } ?>> 255.255.252.0
				<OPTION <?php if ($NATRtrNmask == "255.255.248.0")   { echo "SELECTED"; } ?>> 255.255.248.0
				<OPTION <?php if ($NATRtrNmask == "255.255.240.0")   { echo "SELECTED"; } ?>> 255.255.240.0
				<OPTION <?php if ($NATRtrNmask == "255.255.224.0")   { echo "SELECTED"; } ?>> 255.255.224.0
				<OPTION <?php if ($NATRtrNmask == "255.255.192.0")   { echo "SELECTED"; } ?>> 255.255.192.0
				<OPTION <?php if ($NATRtrNmask == "255.255.128.0")   { echo "SELECTED"; } ?>> 255.255.128.0
				<OPTION <?php if ($NATRtrNmask == "255.255.0.0")     { echo "SELECTED"; } ?>> 255.255.0.0

			</SELECT>
		</TD>
	</TR>
	<TR>
		<TD>NAT Router device:</TD>
		<TD><INPUT TYPE="TEXT" NAME="NATRtrDev" CLASS = "Text" VALUE="<?php
	 		$dev = explode(" ", $prim['nat_router']);
		 	if (isset($dev[1]))
			 	echo $dev[1];
			// echo $prim['..??
	?>"></TD>
	</TR> -->
	<?}*/?>
</TD></TR>
</TABLE>
</fieldset>
</TD></TR>
<TR><TD>
<TABLE>
        <TR>
		<TD>
<?php open_file ("w+"); write_config("");?>
			<BUTTON NAME="redundancy_action" CLASS = "ButtonNormalAppearance" VALUE="SAVE" onclick="return checkform()">SAVE</BUTTON>
		</TD>
        	<TD>
			<BUTTON TYPE="Submit" NAME="redundancy_action" CLASS = "ButtonNormalAppearance" VALUE="CANCEL" href = "global_settings.php">CANCEL</BUTTON>
		</TD>
	</TR>
</TABLE>

<?php open_file ("w+"); write_config(""); 
#echo  "File information Backup Server $prim['backup'] ">>/tmp/phplog
?>

</TD></TR>
</TABLE>
</FORM>
</td></tr></table>
</TD>
<TD width="20%" class="td_background" style="padding-left:10px" valign="top">
    <div class="help_detail">
	<br />
	<font class="help_desc">Advanced HA Configuration</font>
	<br />
	<br />

        <font class="help_item">High Availability Settings</font>
        <br />To configure High Availability Settings.
        <br />        
        <br />
        
		<font class="help_item">Heartbeat Interval</font>
        <br />Time interval for backup load balancer to check functional status of primary load balancer.
        <br />
        <br />
        
		<font class="help_item">Assume dead after</font>
        <br />Backup Load Balancer will initiate failover, if primary load balancer does not respond for this number of seconds.
        <br />
        <br />
        
		<font class="help_item">Hearbeat runs on port</font>
        <br />Port on which heartbeat communicates with primary load balancer.
        <br />
        <br />
		<font class="help_item">Monitor NIC links for failures</font>
        <br />Check to enable monitoring NIC Links for any network failures.
        <br />
        <br />
		<font class="help_item">Syncdaemon</font>
        <br />High availability service checks whether all the required services are running on VPN servers or not.
        <br />
        <br />
		<font class="help_item">Load Balancer service settings</font>
        <br />To configure Load Balancer service settings.
        <br />
        <br />
		<font class="help_item">Re-entry Time</font>
        <br />Length of time before active load balancer attempts to bring a real server back into the pool after failure.
        <br />
        <br />
        
		<font class="help_item">Service Time-out</font>
        <br />Length of time before a real server is considered dead and removed from the pool.
        <br />
        <br />
		<font class="help_item">Quiesce server</font>
	        <br />If selected,then Whenever a new real server comes online,the least connection table is reset to zero.
        <br />
        <br />
		<font class="help_item">Scheduling</font>
        <br />Select your preferred scheduling algorithm from drop-down menu.
        <br />
        <br />
		<font class="help_item">Persistence</font>
        <br />The time Administrator needs persistent connections to the virtual server during client transactions.
        <br />
        <br />
		<font class="help_item">Cluster Type</font>
        <br />Currently supported network type for HA cluster is Direct Routing.
        <br />
        <br />

    </div>
</TD></TR>
</TABLE>
</BODY>
</HTML>
