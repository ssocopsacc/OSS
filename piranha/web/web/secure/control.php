<?php
	global $virt;
	$control_action = "";
	$auto_update = "";
	$rate = "";

	if (isset($_GET['control_action'])) {
        	$control_action = $_GET['control_action'];
	}
	if (isset($_GET['auto_update'])) {
        	$auto_update = $_GET['auto_update'];
	}
	if (isset($_GET['rate'])) {
        	$rate = $_GET['rate'];
	}

	if ($auto_update == 1) {
        	if ($rate == '' || $rate < 10) { 
			$rate=10; 
		}
        }
	if ($control_action == "CHANGE PASSWORD") {
		header("Location: passwd.php");
		exit;
	}
		
	header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");             // Date in the past
	header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");// always modified
	header("Cache-Control: no-cache, must-revalidate");           // HTTP/1.1
	header("Pragma: no-cache");                                   // HTTP/1.0
	
	require('parse.php'); /* read in the config! Hurragh! */
	$temp = explode(" ",$virt[1]['address']);
	if ($auto_update == "1") {
		echo "<META HTTP-EQUIV=\"REFRESH\" CONTENT=\"$rate;control.php?auto_update=1&rate=$rate\"> ";
	}
	if ($prim['service'] == "") {
		$prim['service'] = "lvs";
	}
	$cmd = "ip addr sh dev ".$temp[1]." | grep 'inet ' | grep -v '".$temp[0]."' | awk '{print $2}'";
	exec($cmd,&$ip[],&$ret_val);
	$address = explode("/",$ip[0][0]);
	$addr = trim($address[0]);
/*	$i=0;
	while($ip[0][$i] != NULL) {
		$temp = explode("/",$ip[0][$i]);
		echo "ip=".$temp[0];
		$i++;
	}
*/
?>


<HTML>
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML Strict Level 3//EN">

<HEAD>
<TITLE>Propalms (Status Page)</TITLE>
<link href = "appearance.css" rel = "stylesheet" type = "text/css" />
<link rel="StyleSheet" href="help.css" type="text/css"/>
<script type="text/javascript" language="javascript" src="functions.js"></script>
<script type="text/javascript" language="javascript">
function Number()
{
	if(document.stat.auto_update.checked == true) {
		var data = document.stat.rate.value;
		if(data == "") { alert("Enter time interval"); return false;}
		if(!isNumber(data)) { alert("Enter valid time interval"); return false;}
		if(data < 10) {alert("valid time interval is above 10 Secs."); return false;}
		return true;
	}
	else { return true;}
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


</STYLE>-->

</HEAD>

<BODY>
<TABLE width="99%">
<TR width="50%"><TD>

<!--<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="5">
	<TR BGCOLOR="#CC0000"> <TD class = "propalmsTableTdDefault"> <B>PIRANHA</B> CONFIGURATION TOOL </TD>
	<TD ALIGN=right CLASS="logo">
            <A HREF="introduction.html" CLASS="logolink">
            INTRODUCTION</A> | <A HREF="help.php" CLASS="logolink">
            HELP</A></TD>
	</TR>
</TABLE>

<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="5">
        <TR>
                <TD>&nbsp;<BR><FONT SIZE="+2" COLOR="#FFFFFF">CONTROL / MONITORING</FONT><BR>&nbsp;</TD>
        </TR>
</TABLE>-->

<?php
	// echo "Query = $QUERY_STRING";
?>
<!--
<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="0"><TR><TD BGCOLOR="#FFFFFF">

<TABLE WIDTH="100%" BORDER="0" CELLSPACING="1" CELLPADDING="5">
        <TR BGCOLOR="#666666">
                <TD WIDTH="25%" ALIGN="CENTER" BGCOLOR="#FFFFFF"> <A HREF="control.php" NAME="Control/Monitoring" CLASS="tabon"><B>CONTROL/MONITORING</B></A> </TD>
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="global_settings.php" NAME="Global Settings" CLASS="taboff"><B>GLOBAL SETTINGS</B></A> </TD>
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="redundancy.php" NAME="Redundancy" CLASS="taboff"><B>REDUNDANCY</B></A> </TD>
                <TD WIDTH="25%" ALIGN="CENTER"> <A HREF="virtual_main.php" NAME="Virtual" CLASS="taboff"><B>VIRTUAL SERVERS</B></A> </TD>
        </TR>

</TABLE>-->

<TABLE WIDTH = "50%">
	<TR><TD width="80%"><DIV CLASS = "HeaderDefault"><DIV CLASS = "HeaderText">Status</DIV></DIV></TD></TR>
</TABLE>

<TABLE WIDTH = "99%">
 	<TR><TD CLASS = "TdLine"><HR CLASS = "Line" align="left" /></TD></TR>
</TABLE>

<TABLE WIDTH = "50%">
 	<TR><TD width="80%" valign="top">
  		<FORM  name = "stat" METHOD="GET" ENCTYPE="application/x-www-form-urlencoded" ACTION="control.php">
   			<TABLE style="WIDTH:400px">
   				<TR><TD>
					<fieldset CLASS = "LB">
     						<TABLE WIDTH = "100%">
     							<TR><TD><B>Cluster Status</B></TD></TR>
     							<TR><TD></TD></TR>	
							<TR><TD>
		<?php
		function check_vpn_server($ipaddrs,$port)
		{
		//	echo $ipaddrs "::" $port;
			$retstr="Server Down";
			$vpnsock = socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
			socket_set_nonblock($vpnsock);
			$error = NULL;
			$attemps = 0;
			$timeout = 10;
			$ret;
			while(!($ret=socket_connect($vpnsock,$ipaddrs,$port)) && $attemps++ < $timeout) {
				$error = socket_last_error();
				if($error != SOCKET_EINPROGRESS && $error != SOCKET_EALREADY) {
					$retstr = "Server Down";
					socket_close($vpnsock);
					return $retstr;
				}
				usleep(1000);
			}
			if(!$ret) {
				$retstr = "Server Down";
				socket_close($vpnsock);
				return $retstr;
			}
			if($ret==true)
				{
						socket_close($vpnsock);
						$retstr="Server Running";
						//return ;
				}
			socket_set_block($vpnsock);
			return $retstr;

		}
		//sleep(10);
		//read_config();
		$retval=1;
		exec("/etc/rc.d/init.d/pulse status",$lines,$retval);
		
/*		if ($retval == 0) { 
			echo "High Availibility Service : <FONT COLOR=\"green\"> running </FONT><br>";
		} else {
			echo "High Availibility Service :<FONT COLOR=\"#cc0000\"> stopped </FONT><br>";
		}
*/
		$flag = 0;
		$check = 0;
		$col_pri = 0;
		$col_back = 0;
		$state_pri = 0;
		$state_back = 0;
//		echo ` /etc/sysconfig/ha/getactive.sh`;
//code added by sham kota
		$status = explode(":",`/etc/sysconfig/ha/getactive.sh`);
		$stat=trim($status[1]);
		if($stat == "Stopped") {
			$check = 1;
		}
		else {
			if($stat == "Active") {
				if($addr == $prim['primary']) {
					$col_pri = 1;
					$col_back = 3;
				}
				if($addr == $prim['backup']) {
					$col_back = 1;
					$col_pri = 3;
				}
			}
			else {
				if($stat == "Standby") {
					if($addr == $prim['primary']) {
						$col_pri = 2;
						$col_back = 4;
					}
					if($addr == $prim['backup']) {
						$col_back = 2;
						$col_pri = 4;
					}
				}
			}
		}
//
		echo "<br><b>Load Balancer Servers: </b><br>";
//<TABLE CLASS = TableDefault><TR><TH CLASS=TableHeadColumnDefault>Name</TH><TH CLASS=TableHeadColumnDefault>Status</TH><TH CLASS=TableHeadColumnDefault>State</TH><TH CLASS=TableHeadColumnDefault>Active LB</TH></TR>";
		if( $prim['primary'] != "" && $prim['primary'] != "0.0.0.0") {
		$flag = 1;
		$serverStat = "Server Down";
		if($col_pri == 1 || $col_pri == 2) {
			$serverStat = "Server Running";
		}
		else {
			if($check == 0) {
				$serverStat=check_vpn_server( $prim['primary'],80);
			}
		}
		echo "<TABLE CLASS = TableDefault><TR><TH CLASS=TableHeadColumnDefault>IP Address</TH><TH CLASS=TableHeadColumnDefault>Status</TH><TH CLASS=TableHeadColumnDefault>State</TH><TH CLASS=TableHeadColumnDefault>LB Status</TH></TR>";
		echo "<TR><TD class=TableTdDefault>";
		echo $prim['primary'];
		echo "</TD>";
// 		echo "</TD><TD class="."TableTdDefault"."></TD>";
		if($serverStat == "Server Running") {
			$state_pri = 1;
			echo "<TD CLASS=TableTdDefault><img src=/secure/green.PNG style=width:25px;height:25px/>";
		}
		else {
//			$col_pri = 3;
			echo "<TD CLASS=TableTdDefault><img src=/secure/red.PNG style=width:25px;height:25px/>";
		}
//		echo $serverStat; 
 		echo "</TD><TD class="."TableTdDefault".">";

		echo $serverStat; 
		echo "</TD>";
		if($col_pri == 0) {
			echo "<TD CLASS=TableTdDefault>Inactive</TD>";
		}
		else {
			if($col_pri == 1 || $col_pri == 2) {
				if($state_pri == 1) {
					echo "<TD CLASS=TableTdDefault>Active</TD>";
				}
				else {
					echo "<TD CLASS=TableTdDefault>Inactive</TD>";
				}
			}
			else {
				if($col_pri == 3 || $col_pri == 4) {
					if($state_pri == 1) {
						echo "<TD CLASS=TableTdDefault>Stand By</TD>";
					}
					else {
						echo "<TD CLASS=TableTdDefault>Inactive</TD>";
					}
				}
			}
		}
		echo "</TR>";
		}
		if( $prim['backup'] != "" && $prim['backup'] != "0.0.0.0") {
		$flag = 2;
		echo "<TR><TD class="."TableTdDefault".">"; 
		echo $prim['backup'];
		echo "</TD>";
		$serverStat = "Server Down";
//		echo"</TD><TD class="."TableTdDefault"."></TD>";
		if($col_back == 1 || $col_back == 2) {
                        $serverStat = "Server Running";
                }
                else {
			if($check == 0) {
				$serverStat=check_vpn_server( $prim['backup'],80);
			}
		}
		if($serverStat == "Server Running") {
			$state_back = 1;
			echo "<TD CLASS=TableTdDefault><img src=/secure/green.PNG style=width:25px;height:25px/>";
		}
		else {
			echo "<TD CLASS=TableTdDefault><img src=/secure/red.PNG style=width:25px;height:25px/>";
		}
//		echo $serverStat; 
		echo"</TD><TD class="."TableTdDefault".">";
		echo $serverStat; 
		echo "</TD>";
		if($col_back == 0) {
			echo "<TD CLASS=TableTdDefault>Inactive</TD>";
		}
		else {
			if($col_back == 1 || $col_back == 2) {
				if($state_back == 1) {
					echo "<TD CLASS=TableTdDefault>Active</TD>";
				}
				else {
					echo "<TD CLASS=TableTdDefault>Inactive</TD>";
				}
			}
			else {
				if($col_back == 3 || $col_back == 4) {
					if($state_back == 1) {
						echo "<TD CLASS=TableTdDefault>Stand By</TD>";
					}
					else {
						echo "<TD CLASS=TableTdDefault>Inactive</TD>";
					}
				}
			}
		}
		echo "</TR></TABLE>";
		}
		if($flag == 1) { echo  "</TABLE>"; }
		if($flag == 0) {
/*			echo "<TABLE><TR>";
			echo "<TD class="."TableTdDefault".">";echo  "There are no Load Balancer servers configured!!!!!!!!!"	. "</TD> <TD>"; echo"</TD> </TR></TABLE>";
*/
			echo "<fieldset>";
			echo "There are no Load Balancer servers configured.";
			echo "</fieldset>";

		}
		
		$loop=1;
		$selected_host=1;
		$port[2];
		$port[0] = $virt[$selected_host]['port'];
		$port[1] = $virt[$selected_host+1]['port'];
		$flag_bit1 = 0; $flag_bit2 = 0;
		$show = 0;
		    echo "<br><b>VPN Server Statistics:</b><br>";
   		     while ((isset($serv[$selected_host][$loop]['server'])) && ($serv[$selected_host][$loop]['server'] != "" )) 
			{
				if($show == 0) {
				 echo "<TABLE CLASS = TableDefault><TR><TH class=TableHeadColumnDefault>IP Address</TH><TH class="."TableHeadColumnDefault".">Status</TH><TH class=TableHeadColumnDefault>State</TH></TR>";
				$show++;
				}
				if($serv[$selected_host][$loop]['address'] != "0.0.0.0") {
				$flag_bit1 = 0; $flag_bit2 = 0;
				$serveStat=check_vpn_server($serv[$selected_host][$loop]['address'],$port[0]);
				if($serveStat != "Server Running") {
					$flag_bit1 = 1;
				}
				$serveStat=check_vpn_server($serv[$selected_host][$loop]['address'],$port[1]);
				if($serveStat != "Server Running") {
					$flag_bit2 = 1;
				}

				echo "<TR>";
				echo "<TD class=TableTdDefault>";
				echo $serv[$selected_host][$loop]['address']. "</TD>";
				if($flag_bit2 == 0 && $flag_bit1 == 0) {
				echo "<TD CLASS=TableTdDefault><img src=/secure/green.PNG style=width:25px;height:25px/></TD><TD CLASS=TableTdDefault>";
				echo "Server Running";
				}
				else {
				echo "<TD CLASS=TableTdDefault><img src=/secure/red.PNG style=width:25px;height:25px/></TD><TD CLASS=TableTdDefault>";
				echo "Server Down";
				}
				echo"</TD></TR>";
			}
				$loop++;
			}
//			echo "</TABLE>";
			if($loop == 1) {
				echo "<fieldset>";
				echo "There are no VPN servers configured.";
				echo "</fieldset>";
			}
			else {
				echo "</TABLE>";
			}
	?>
							</TD></TR>
						</TABLE>
					</fieldset>
    				</td></tr>
    				<tr><td>
     					<fieldset CLASS = "LB" style="margin-top:5px;">
      						<TABLE style="width:100%">
      							<TR><TD><B>Monitor</B></TD></TR>
      							<TR><TD></TD></TR>
							<TR><TD>
	       							<INPUT TYPE="CHECKBOX" NAME="auto_update" VALUE="1" <?php if ($auto_update == 1) { echo "CHECKED"; } ?> onclick ="return Number()" > Auto update &nbsp;Update Interval: <INPUT TYPE="TEXT" NAME="rate" SIZE=3 VALUE=
		<?php 
			if (($auto_update == "1") && ($rate == "")) {
				$rate="10" ;
			}
			echo $rate ;
			
		?>
	> seconds<BR>
<!--	Rates lower than 10 seconds are not recommended as, when the page updates, you will lose any<BR>
	modifications you have made which have not been actioned using the 'Accept' button<P>
-->
	<!--<INPUT class = "ButtonNormalAppearance" TYPE="SUBMIT" NAME="refresh" VALUE="Update information now">-->
							</TD></TR>
      						</TABLE>
					</fieldset>
    				</td></tr>
				<tr><td>
     					<BUTTON CLASS = "ButtonNormalAppearance" TYPE = "submit" NAME = "refresh" VALUE = "Update" onclick = "return Number()" STYLE = "width:150px;margin-top:5px;">Update information now</BUTTON>
<?php if ( $prim['service'] == "lvs" ) { ?>

<!--	<TABLE WIDTH="100%" BORDER="0" CELLSPACING="1" CELLPADDING="5">
        <TR>
                <TD CLASS="title">CURRENT LVS ROUTING TABLE</TD>
        </TR>
	</TABLE>
	<TABLE WIDTH="100%"> <TR> <TD> <TT>
	<?php
		#echo `/tmp/getactive.sh`
		#echo `/sbin/ipvsadm -Ln` ;
		#ipvsadm -Ln is not effective as non-root, so we pull the data from /proc
		# (all this code is to replace the hex ip:port with the more standard form)
		$fn="/proc/net/ip_vs";
		if ( is_readable($fn)) {
                    $fd=fopen($fn,"r");
                    while (!feof ($fd)) {
                        $line = fgets($fd, 4096);
                        if ( ereg("([[:xdigit:]]{2})([[:xdigit:]]{2})([[:xdigit:]]{2})([[:xdigit:]]{2}):([[:xdigit:]]{4})",$line,$parts)) {
                            $ip = join(".",array_map("hexdec",array_slice($parts,1,4)));
                            $port = hexdec($parts[5]);
                            $line = str_replace($parts[0],$ip.":".$port,$line );
                        }
                        echo htmlentities(rtrim($line))."<br>";
                    }
                    fclose($fd);
		}

	?>
	</TT> </TD> </TR> </TABLE>
	
	<TABLE WIDTH="100%">
        <TR><TD CLASS="title">CURRENT LVS PROCESSES</TD></TR>
	</TABLE>
	
	<TABLE WIDTH="100%"> <TR> <TD> <TT>
	<?php echo nl2br(htmlspecialchars(`/bin/ps auxw | /bin/egrep "pulse|lvs|send_arp|nanny|fos|ipvs" | /bin/grep -v grep`)); ?>
	&nbsp;	
	</TT> </TD> </TR> </TABLE>


<?php } else { ?>

	<TABLE WIDTH="100%" BORDER="0" CELLSPACING="1" CELLPADDING="5">
        <TR>
                <TD CLASS="title">CURRENT FOS PROCESSES</TD>
        </TR>
	</TABLE>

	<TABLE WIDTH="100%"> <TR> <TD>
	<PRE><?php echo `/bin/ps auxw | /bin/egrep "pulse|lvs|send_arp|nanny|fos|ipvs" | /bin/grep -v grep`; ?></PRE>
	&nbsp;	
	</TD> </TR> </TABLE>
	
<?php } ?>

	<TABLE WIDTH="100%" BORDER="0" CELLSPACING="0" CELLPADDING="5" >
 		<TR>
 
               	
		<TD>
                        <INPUT TYPE="Submit" NAME="control_action" VALUE="ACCEPT"> <SPAN CLASS="taboff">  Click here to apply changes to this page</SPAN>
                </TD>
		End of comment 
		<TD ALIGN=right>
			<BUTTON CLASS = "ButtonNormalAppearance" TYPE = "submit" NAME = "control_action" VALUE = "CHANGE PASSWORD" STYLE = "width:150px">Change Password</BUTTON>
 			<INPUT TYPE="Submit" NAME="control_action" VALUE="CHANGE PASSWORD"> <SPAN CLASS="taboff">-->
				</TD></TR>
    			</TABLE>
		</FORM>
	</TD></TR>
</TABLE>
</TD><TD align="right">
	</TD><TD width="20%" class="td_background" style="padding-left:10px" valign="top">
    <div class="help_detail">
	<br />
		<font class="help_desc">Status</font>
        <br />
        <br />

	        <font class="help_item">Cluster Status</font>
        <br />Display status information of Cluster.
        <br />        
        <br />
        
		<font class="help_item">Load Balancer Servers</font>
        <br />Displays status of Primary and Backup Load Balancer servers.
        <br />
        <br />
        
		<font class="help_item">VPN Server Statistic</font>
        <br />Displays status of VPN servers.
        <br />
        <br />
        
		<font class="help_item">Monitor</font>
        <br />Updates status at user request.
        <br />
        <br />
		<font class="help_item">Auto Update</font>
        <br />Set the time interval to update automatically.
        <br />
        <br />	
		<font class="help_item">Update Information Now</font>
        <br />Click to update status information manually.
        <br />
        <br />

    </div>
</TD></TR>
</BODY>
</HTML>
