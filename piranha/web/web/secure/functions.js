
var pagelimit=10;
var dtCh= "/";
var minYear=2004;
var maxYear=2020;
var apppath;
function CloseNoConfirm ()
{
   //Old Code Commented
   /*win = top;
   win.opener = top;
   win.close(); */
   //Old Code Commented

   window.open('','_self','');
   window.close();
}
function hello(form)
{
	alert("hello()  hi"+document.forms[0].elements["hb_interval"].value+"called");
}
//hello();
function timeoutFunc()
{
	window.setTimeout(self.close(), 5000);
}

function checkServerDomainName(e)
{
        var state=1; //initial
	var  i;
	var ch;
	for(i=0; i<e.length; i++)	{
	       ch=e.charAt(i);

	       switch(state)  {

	       case 1:            //Initial state
	              if('0'<=ch && ch<='9') state=2;
	              else if('a'<=ch && ch<='z') state=3;
		      else if('A'<=ch && ch<='Z') state=4;
		      else state=8; //even errors are holy
                      break;
               case 2:       //0-9
	              if('0'<=ch && ch<='9') state=2;
	              else if('a'<=ch && ch<='z') state=3;
		      else if('A'<=ch && ch<='Z') state=4;
		      else if(ch=='-') state=5;
		      else if(ch=='_') state=5;
		      else if (ch=='.') state=6;
		      else state=8; //even errors are holy
		      break;
               case 3:       //a-z
	              if('0'<=ch && ch<='9') state=2;
	              else if('a'<=ch && ch<='z') state=3;
		      else if('A'<=ch && ch<='Z') state=4;
		      else if(ch=='-') state=5;
		      else if(ch=='_') state=5;
		      else if (ch=='.') state=6;

		      else state=8; //even errors are holy
             	      break;
               case 4:       //A-Z
	              if('0'<=ch && ch<='9') state=2;
	              else if('a'<=ch && ch<='z') state=3;
		      else if('A'<=ch && ch<='Z') state=4;
		      else if(ch=='-') state=5;
		      else if(ch=='_') state=5;
		      else if (ch=='.') state=6;
		      else state=8; //even errors are holy
                      break;
               case 5:       //_
	              if('0'<=ch && ch<='9') state=2;
	              else if('a'<=ch && ch<='z') state=3;
		      else if('A'<=ch && ch<='Z') state=4;
		      else state=8; //even errors are holy
		      break;
               case 6:       //_
	              if('0'<=ch && ch<='9') state=2;
	              else if('a'<=ch && ch<='z') state=3;
		      else if('A'<=ch && ch<='Z') state=4;
		      else state=8; //even errors are holy
            	      break;
	  }
	  if(state==8) return false;
	}
	if(state==1 || state==8 || state==5 || state==6)
	//means it has never entered for loop, or error, or minus or period
	          return false;
	 else state=7;
	 return true;
}

function selApps()
{
	var str="";

	/*for(i=0;i<document.ag_creatForm.list_app.length; i++)
	{
		str=document.ag_creatForm.list_app.options[i].text+","+str;
	}*/
	for(i=0;i<document.forms[0].list_app.length; i++)
	{
		str=document.forms[0].list_app.options[i].text+","+str;
	}
	newwindow=window.open('selAppsForZone.cgi?type=0&Apps='+str,"","width=480,height=310,titlebar=0,scrollbars=yes,resizable=0","");

}

function addPolicies()
{
	if((document.ag_creatForm.zone_name.value == "  <Type in profile name>") || (document.ag_creatForm.zone_name.value == "") ) 
	{
		alert("Please enter Profile Name.");
		return false;
	}
	var str="";
	for(i=0;i<document.ag_creatForm.list_subpolocies.length;i++)
	{
		str=document.ag_creatForm.list_subpolocies.options[i].text+","+str;
	}
	newwindow=window.open('zoneManager.cgi?type=2&Policy='+str,"","width=450,height=310,titlebar=0,scrollbars=yes,resizable=0","");
}

function editPolicies()
{
	var str="";
	for(i=0;i<document.frm_editzone.list_subpolocies.length;i++)
	{
		str=document.frm_editzone.list_subpolocies.options[i].text+","+str;
	}
	newwindow=window.open('zoneManager.cgi?type=2&Policy='+str,"","width=450,height=310,titlebar=0,scrollbars=yes,resizable=0","");
}



function addPolicy(){

    var elSel = window.opener.document.getElementById('list_subpolocies');
	//window.opener.document.ag_creatForm.list_subpolocies.length=0;
	window.opener.document.forms[0].list_subpolocies.length=0;
	
for(i=0;i<document.frm_addpolicy.list_right.length;i++)
	{
    var elOptNew = window.opener.document.createElement('option');
    elOptNew.text = document.frm_addpolicy.list_right.options[i].text;
    elOptNew.value = document.frm_addpolicy.list_right.options[i].text;

var index = (elOptNew.selectedIndex == 0)? 0: elOptNew.selectedIndex;

	try {
      elSel.add(elOptNew, index); // standards compliant; doesn't work in IE
        }
    catch(ex) {
          elSel.add(elOptNew); // IE only
    }

}
CloseNoConfirm();
}

function disablesubmit(form)
{
	for (var i = 0; i < document.forms[0].elements.length; i++)
	{
		if (document.forms[0].elements[i].type.toLowerCase() == 'submit')
		{
			document.forms[0].elements[i].disabled = true;
			return true;
		}
	}
}
function DoneXml(form)
{
	var str="FcsPage.cgi?type=3";
	var strmain=str;
	window.location.href=strmain;
}


function isNum(num)
{
        var c,i,x=0;
        if(num.length==0) return false;
        for(i=0;i<num.length;i++)
        {
                c=num.charAt(i);
			if(i==0 && c == '0')
			{
				x=1;
				break;
			}
           if(((c > '9')||(c < '0'))&&(c='.')&&(c='-'))
		{
           		x=1;
				break;
		}
		else
		x=0;
        }
	if(x==1)
	return false;
	else
	return true;
}
/*function check1(e)
{
if (e.match(/[\&\?\!\#-\'\*\+\--9\=\?A-Z\^-\~\%]+\@[\&\?\!\#-\'\*\+\--9\=\?A-Z\^-\~\%]+\.[\%\&\?\!\#-\'\*\+\--9\=\?A-Z\^-\~]{2,3}/) != e)
	return false;
	else
	return true;
}*/

function isPort(e)
{
	if(e >=65536)
		return false;
	return true;
}

function check(e)
{
	var num1=isNum(e);
	var v=(num1)?parseFloat(e):0;
	if(!num1)
    {
         return false;
    }
 return true;
}
function isEmpty(s)
{
	return ((s == null) || (s.length == 0))
}
function isDigit (c)
{
	return ((c >= "0") && (c <= "9"))
}
function isLetter (c)
{
	return ( ((c >= "a") && (c <= "z")) || ((c >= "A") && (c <= "Z")) )
}
function isCommaEqualTo(c)
{
	return ((c==",") || (c=="="))
}

function isFullStop(c)
{
	return (c==".")
}
function isSpace(c)
{
	return (c==" ")
}

function isCharacter(c)
{
	return ((c=="_") || (c=="-"))
}
function isOnlyNumeric(s)
{
	var i;
	for (i = 0; i < s.length; i++)
	{
		var c = s.charAt(i);
		if (!isDigit(c) )
//			return false;
alert("Only numbers");
s.value="";

	}
	return true;
	
}

function isNumb(val)
{
	var i,flag=0;
	var s=val.value;
	for (i = 0; i<s.length; i++)
	{
		var c = s.charAt(i);
		if (!isDigit(c) )
		{
			flag=1;
			break;
		}
	}

	if(flag==1)
	{
		alert("Enter Numeric Data");
		val.value="";
	}
}

function isServerName(s)
{
	var i;
	if (isEmpty(s))
		return false;
/*	if(isOnlyNumeric(s)) //Commented 'coz there r some issues with this function
		return false;

	for (i = 0; i < s.length; i++)
	{
		var c = s.charAt(i);
		if (! (isLetter(c) || isDigit(c)|| isFullStop(c) || isCharacter(c)) )
		return false;
	}*/
	return true;
}

function isAlphanumeric (s)
{
	var i;
	if (isEmpty(s))
	{
		return false;
	}

	for (i = 0; i < s.length; i++)
	{
		var c = s.charAt(i);
		if (! (isLetter(c) || isDigit(c)|| isFullStop(c) || isCharacter(c) || c == '@') )
		return false;
	}
	return true;
}
function isStrictlyAlphanumeric (s) //Added by Ganesh for password validation
{
	var i;
	if (isEmpty(s))
	{
		return false;
	}

	for (i = 0; i < s.length; i++)
	{
		var c = s.charAt(i);
		if (!isLetter(c) && !isDigit(c))
		return false;
	}
	return true;
}
function isAlphanumericWithSpace(s)
{
	var i;
	if (isEmpty(s))
	{
		return false;
	}

	for (i = 0; i < s.length; i++)
	{
		var c = s.charAt(i);
		if (! (isLetter(c) || isDigit(c)|| isFullStop(c) || isCharacter(c) || isSpace(c)))
		return false;
	}
	return true;
}

function DisableTextField(form)
{
	document.forms[0].elements["fesName"].disabled =true;
}

function checkBlankAndWild(e)
{
	if(isEmpty(e))
		return false;
	var arremail= new Array(32,46,45,64,47,48,49,50,51,52,53,54,55,56,57,58,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122);
	var l=e.length;
	var arrlen=arremail.length;
	var space=0;
	for(var x=0;x!=l;x++)
	{
		var c=e.charAt(x);
		var match=0;
		if(x==0)
		{
			if(c==' ')
				space=1;
			if (space == 1)
				return false;
		}
		for(var i=0;i!=arrlen;i++)
		{
			var d=	String.fromCharCode(arremail[i]);
			if(c==d)
				match = 1;
		}
		if (match == 0)
			return false;
	}
	return true;
}
function verifyForm1(form)
	{
	   	var CA =document.forms[0].elements["log_check1"].value;
		return true;
	}

function verifyEditZone(form)
{
	var val = document.forms[0].quarantinezone.checked;
	var val1 = document.forms[0].mandatoryzone.checked;

	if((val == false) && (val1 == false))
	{
		for(i=0;i<document.forms[0].hlist_level.length;i++)
		{

			if(document.forms[0].zone_level.selectedIndex+1==document.forms[0].hlist_level.options[i].value)	
			{
				alert("Profile with the selected Security Level already exists.\n         Please select a different Security Level.");
				return false;
			}
		
		}
		if(document.forms[0].list_subpolocies.length == 0)
		{
			alert("Please add at least an End Point Security Policy");
			return false;
		}
	}

	if(val1 == true)
	{
		if(document.forms[0].list_subpolocies.length == 0)
		{
			alert("Please add at least an End Point Security Policy");
			return false;
		}
	}

/*	var zd=document.forms[0].elements["zone_desc"].value;
	if(isEmpty(zd)){
	alert("Profile Description is Empty");
	return false;
	}*/

	var cache_clean=document.forms[0].elements["cachecleanup"].checked;

	var count=0;

	if(cache_clean == true)
	{
		var cache=document.forms[0].elements["cache"].checked;
		if(cache == true)
		{
			count=count+1;
			if(document.forms[0].elements["cache_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Internet Cache'");
				return false;
			}
		}

		var cookie=document.forms[0].elements["cookie"].checked;
		if(cookie == true)
		{
			count=count+1;
			if(document.forms[0].elements["cookie_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Cookies'");
				return false;
			}
		}

		var history=document.forms[0].elements["history"].checked;
		if(history == true)
		{
			count=count+1;
			if(document.forms[0].elements["history_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Browsing History'");
				return false;
			}
		}

		var addr=document.forms[0].elements["addr"].checked;
		if(addr == true)
		{
			count=count+1;
			if(document.forms[0].elements["addr_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Typed URLs'");
				return false;
			}
		}

		var addr=document.forms[0].elements["run"].checked;
		if(addr == true)
		{
			count=count+1;
			if(document.forms[0].elements["run_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Desktop Run History'");
				return false;
			}
		}

		var addr=document.forms[0].elements["recent"].checked;
		if(addr == true)
		{
			count=count+1;
			if(document.forms[0].elements["recent_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Recent File History'");
				return false;
			}
		}

		var addr=document.forms[0].elements["recycle"].checked;
		if(addr == true)
		{
			count=count+1;
			if(document.forms[0].elements["recycle_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Recycle Bin Contents'");
				return false;
			}
		}

	/*	var password=document.forms[0].elements["password"].checked;
		if(password == true)
		{
			count=count+1;
			if(document.forms[0].elements["password_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Passwords'");
				return false;
			}
		}*/

		if(count == 0)
		{
			alert("Please check any of the Cache Cleanup options");
			return false;
		}
	}

	copy_value(form);

}

function addIps(ip)
{
    var elSel = window.opener.document.getElementById('list_ipaddresses');

    var elOptNew = window.opener.document.createElement('option');
    elOptNew.text = ip ;
    elOptNew.value = ip;
	var index = (elOptNew.selectedIndex == 0)? 0: elOptNew.selectedIndex;

    var i=0;
	var j=0;
	var s=ip;
	var ip_addr=new Array();

	for (var i = 0, j = 0; i <= s.length; i++)
	{
		var c = s.charAt(i);

		if((c=="|") || (i == s.length))
		{
			j=0;

			elOptNew.text=ip_addr.join("");
			elOptNew.value=ip_addr.join("");

			if(checkPreviousOptions(elOptNew.text) == true)
			{
				try
				{
					elSel.options[elSel.options.length] = new Option(elOptNew.value, elOptNew.value);
	    	   	}
				catch(ex)
				{
    				var elOptNew1 = window.opener.document.createElement('option');
					elOptNew1.text=ip_addr.join("");
					elOptNew1.value=ip_addr.join("");
	
   					elSel.add(elOptNew1); // IE only
				}
			}

			ip_addr = [];
			continue;
		}
		ip_addr[j]=c;
		j++;
	}

}

function checkIP(ip)
{
	var ip_sub = new Array();
	var val;
	var lastChar;

	if(ip.length > 15)
	{
//		if(temp == 1)
			alert("IP Address length cannot exceed 15");
		return false;
	}

	for(var i = 0, j = 0, dotCount = 0; i <= ip.length; i++)
	{
		var c = ip.charAt(i);

		if((c==".") || (i == ip.length))
		{
			if(c==".")
			{
				if(ip_sub[j-1]==".")
				{
//					if(temp == 1)
						alert ("                Invalid IP Address format.\n                       e.g. 192.168.10.1");
					return false;
				}
				dotCount++;
			}

			val = ip_sub.join("");
			if(j > 3)
			{
//				if(temp == 1)
					alert ("                Invalid IP Address format.\n                       e.g. 192.168.10.1");
				return false;
			}
			j=0;
			if((val > 255) || (val < 0))
			{
//				if(temp == 1)
					alert ("Invalid IP Address format. Value should not exceed 255.");
				return false;
			}
			ip_sub = [];
			continue;
		}
		else
		{
			if(!((c >= "0") && (c <= "9")))
			{
				var msg = '       "'+c+'"'+' is not allowed.';
//				if(temp == 1)
					alert(msg);
				return false;
			}
			ip_sub[j]=c;
			j++;
		}
	}
	if(dotCount != 3)
	{
//		if(temp == 1)
			alert ("                Invalid IP Address format.\n                       e.g. 192.168.10.1");
		return false;
	}
	return true;
}

/*
function checkRange(ipFrom, ipTo)
{
	var fromIp = new Array(4);
	var toIp = new Array(4);
	var temp = new Array();

	for(var ii = 0, jj = 0, kk = 0; ii <= ipFrom.length; ii++)
	{
		var c = ipFrom.charAt(ii);
		if((c==".") || (ii == ipFrom.length))
		{
			fromIp[kk] = (temp.join(""));
			//alert(fromIp[kk]);
			kk++;
			jj = 0;
		}
		else
		{
			temp[jj] = c;
			jj++;
		}
	}

	for(var ii = 0, jj = 0, kk = 0; ii <= ipTo.length; ii++)
	{
		var c = ipTo.charAt(ii);
		if((c==".") || (ii == ipTo.length))
		{
			toIp[kk] = (temp.join(""));
			//alert(toIp[kk]);
			kk++;
			jj = 0;
		}
		else
		{
			temp[jj] = c;
			jj++;
		}
	}

	if(parseInt(fromIp[0]) > parseInt(toIp[0]))
	{
		return false;
	}

	for(var ii = 0; ii < 4; ii++)
	{
		if(parseInt(fromIp[ii]) == parseInt(toIp[ii]))
		{
			if((ii != 3) && (parseInt(toIp[ii+1]) < parseInt(fromIp[ii+1])))
			{
				return false;
			}
		}
	}

	return true;
}
*/


function checkRange(ipFrom, ipTo)
{
	/*alert(ipFrom);
	ipFrom = replaceAllDots(ipFrom, ".", "\",\"");
	ipFrom = "\""+ipFrom+"\""
	alert(ipFrom);
	
	alert(ipTo);
	ipTo = replaceAllDots(ipTo, ".", ",");	
	alert(ipTo);

	var fromIp = ipFrom;

	alert(fromIp[0]);
	alert(fromIp[1]);
	alert(fromIp[2]);
	alert(fromIp[3]);

	return false;*/

	var fromIp = new Array(4);
	var toIp = new Array(4);

	var temp0 = new Array();
	var temp1 = new Array();
	var temp2 = new Array();
	var temp3 = new Array();

	var tempTo0 = new Array();
	var tempTo1 = new Array();
	var tempTo2 = new Array();
	var tempTo3 = new Array();

	for(var ii = 0, jj = 0, kk = 0; ii <= ipFrom.length; ii++)
	{
		var c = ipFrom.charAt(ii);
		if((c==".") || (ii == ipFrom.length))
		{
			if(kk == 0)
				fromIp[kk] = (temp0.join(""));
			if(kk == 1)
				fromIp[kk] = (temp1.join(""));
			if(kk == 2)
				fromIp[kk] = (temp2.join(""));
			if(kk == 3)
				fromIp[kk] = (temp3.join(""));
			kk++;
			jj = 0;
		}
		else
		{
			if(kk == 0)
				temp0[jj] = c;
			if(kk == 1)
				temp1[jj] = c;
			if(kk == 2)
				temp2[jj] = c;
			if(kk == 3)
				temp3[jj] = c;
			jj++;
		}
	}

	/*alert(fromIp);
	alert(fromIp[0]);
	alert(fromIp[1]);
	alert(fromIp[2]);
	alert(fromIp[3]);*/

	for(var ii = 0, jj = 0, kk = 0; ii <= ipTo.length; ii++)
	{
		var c = ipTo.charAt(ii);
		if((c==".") || (ii == ipTo.length))
		{
			if(kk == 0)
				toIp[kk] = (tempTo0.join(""));
			if(kk == 1)
				toIp[kk] = (tempTo1.join(""));
			if(kk == 2)
				toIp[kk] = (tempTo2.join(""));
			if(kk == 3)
				toIp[kk] = (tempTo3.join(""));
			kk++;
			jj = 0;
		}
		else
		{
			if(kk == 0)
				tempTo0[jj] = c;
			if(kk == 1)
				tempTo1[jj] = c;
			if(kk == 2)
				tempTo2[jj] = c;
			if(kk == 3)
				tempTo3[jj] = c;
			jj++;
		}
	}

	/*alert(toIp);
	alert(toIp[0]);
	alert(toIp[1]);
	alert(toIp[2]);
	alert(toIp[3]);*/

	if(parseInt(fromIp[0]) > parseInt(toIp[0]))
	{
		return false;
	}

	for(var ii = 0; ii < 4; ii++)
	{
		if(parseInt(fromIp[ii]) == parseInt(toIp[ii]))
		{
			if((ii != 3) && (parseInt(toIp[ii+1]) < parseInt(fromIp[ii+1])))
			{
				return false;
			}
		}
	}

	return true;
}

function submitformInAddIP(form)
{
	var ip_addr=new Array();
	var ip;
	var s=document.forms[0].elements["ip_address"].value;
	var statusVal=document.forms[0].elements["status_value"].value;


	if(statusVal == 1)
	{
		s = replaceAllNewLine(s);	
		if(s=="")
		{
			alert("IP Address is Empty");
			return false;
		}

		for (var i = 0, j = 0; i <= s.length; i++)
		{
			var c = s.charAt(i);

			if((c=="|") || (i == s.length))
			{
				ip=ip_addr.join("");
				j=0;
				ip_addr = [];
	
				if(ip.length > 0)
				{
					if(checkIP(ip, "1")==false)
					{
						return false;
					}
				}
				continue;
			}
			ip_addr[j]=c;
			j++;
		}
	}
	else if(statusVal == 2)
	{
		var ipFrom=document.forms[0].elements["ip_addr_from"].value;
		var ipTo=document.forms[0].elements["ip_addr_to"].value;

		if(ipFrom == "")
		{
			alert("'IP Address From' is Empty");
			return false;
		}
		if(checkIP(ipFrom, "0")==false)
		{
			alert("'IP Address From' is not a valid IP Address");
			return false;
		}
		if(ipTo == "")
		{
			alert("'IP Address To' is Empty");
			return false;
		}
		if(checkIP(ipTo, "0")==false)
		{
			alert("'IP Address To' is not a valid IP Address");
			return false;
		}
		if(checkRange(ipFrom, ipTo)==false)
		{
			alert("Enter a Valid IP Range");
			return false;
		}
	}

	return true;
}


function submitformInAddMAC(form)
{
	var s=document.forms[0].elements["mac_id"].value;

	//alert(s.length % 18)
	if(((s.length % 18) != 0) && ((s.length % 18) != 17))
	{
		alert("MAC Address format is incomplete.");
		return false;
	}

	if(s=="")
	{
		alert("MAC Address is Empty");
		return false;
	}

	for (i = 0, j = 0; i < s.length; i++)
	{
		var c = s.charAt(i);
		if(j==17)
		{
			if(c!="|")
			{
				alert("Problem in format\ne.g. MAC1|MAC2|MAC3");
				return false;
			}
			j=0;
		}
		else
		{
			if((j==2) || (j==5) || (j==8) || (j==11) || (j==14))
			{
				if(c!=":")
				{
					alert("Problem in format\ne.g. 00:11:22:33:44:55 ");
					return false;
				}
			}
			j++;
			if(!isDigit(c))
			{
				if(!( ((c >= "a") && (c <= "f")) || ((c >= "A") && (c <= "F")) || (c == ":") ))
				{
					var str='        \"'+c+'\"'+' is not allowed';
					alert(str);
					return false;
				}
			}
		}
	}
	return true;
}

function copy_groups_realm(form)
{
	var elSel = document.getElementById('blocked_groups');

	for(i=0;i<form.blocked_groups.length;i++)
	{
		elSel.options[i].selected=true;
	}
}



function verifyEditRealmForm(form)
{
	var count = document.forms[0].serverCount.value;
	var count1 = document.forms[0].authorServerCount.value;
	//alert(count);


	var server1 = document.forms[0].list_authservers_1.value;

	if(count > 1)
		var server2 = document.forms[0].list_authservers_2.value;
	if(count > 2)
		var server3 = document.forms[0].list_authservers_3.value;
	if(count > 3)
		var server4 = document.forms[0].list_authservers_4.value;
	if(count > 4)
		var server5 = document.forms[0].list_authservers_5.value;


	var author_server1 = document.forms[0].list_author_server_1.value;
	if(count1 > 1)
		var author_server2 = document.forms[0].list_author_server_2.value;

/*	alert(server1);
	alert(server2);
	alert(server3);
	alert(server4);
	alert(server5);*/

/*	alert(author_server1);
	alert(author_server2);*/

	if(count == 2)
	{
		server3=0;
		server4=0;
		server5=0;
	}

	if(count == 3)
	{
		server4=0;
		server5=0;
	}

	if(count == 4)
	{
		server5=0;
	}

	if(count > 4)
	{
		if((server5 == server1) || (server5 == server2) || (server5 == server3) || (server5 == server4))
		{
			alert('Choose a different Server for \'Server at Priority 5\'');
			return false;
		}
	}

	if(count > 3)
	{
		if((server4 == server1) || (server4 == server2) || (server4 == server3))
		{
			alert('Choose a different Server for \'Server at Priority 4\'');
			return false;
		}
	}

	if(count > 2)
	{
		if((server3 == server1) || (server3 == server2))
		{
			alert('Choose a different Server for \'Server at Priority 3\'');
			return false;
		}
	}

	if(count > 1)
	{
		if((server2 == server1))
		{
			alert('Choose a different Server for \'Server at Priority 2\'');
			return false;
		}
	}

	if(count1 > 1)
	{
		if(author_server1 == author_server2)
		{
			alert('Choose a different Authorization Server for \'Authorization Server 2\'');
			return false;
		}
	}


	copy_groups_realm(form);
}

function verifyRouteAdd(form)
{
	var destination = document.forms[0].elements["dest"].value;
	var gateway = document.forms[0].elements["gw"].value;
	var netmask = document.forms[0].elements["mask"].value;
	var metricval = document.forms[0].elements["metric"].value;

	if(!isValidIPAddressNoAlert(destination) && (destination != 'default') && (destination != 'Default') && (destination != "0.0.0.0"))
	{
		alert("Please enter a Valid IP Address for Destination.");
		return false;
	}

	if(!isEmpty(gateway))
		if(!isValidIPAddressNoAlert(gateway) && (gateway != "0.0.0.0"))
		{
			alert("Please enter a Valid IP Address for Gateway.");
			return false;
		}

	if(!isEmpty(netmask))
		if(!isValidIPAddressNoAlert(netmask) && (netmask != "0.0.0.0"))
		{
			alert("Please enter a Valid Netmask.");
			return false;
		}


	if(!isEmpty(metricval))
	if(!isDigit(metricval) || isValidIPAddressNoAlert(metricval))
	{
		alert("Metric Value should be between 0 to 16.");
		return false;
	}
	if((metricval < 0) || (metricval > 16))
	{
		alert("Metric Value should be between 0 to 16.");
		return false;
	}

	document.forms[0].submit();

	return true;
}

function verifyCreateZone(form)
{

	if((document.forms[0].zone_name.value == "  <Type in profile name>") || (document.forms[0].zone_name.value == "") ) 
	{
		alert("Please enter Profile Name.");
		return false;
	}

	var val = document.forms[0].quarantinezone.checked;

	var val1 = document.forms[0].mandatoryzone.checked;

	if((val == false) && (val1 == false))
	{
		for(i=0;i<document.forms[0].hlist_level.length;i++)
		{
		
			if(document.forms[0].zone_level.selectedIndex+1==document.forms[0].hlist_level.options[i].value)	
			{
				alert("Profile with the selected Security Level already exists.\n         Please select a different Security Level.");
				return false;
			}
		
		}
		if(document.forms[0].list_subpolocies.length == 0)
		{
			alert("Please add at least an End Point Security Policy");
			return false;
		}
	}

	if(val1 == true)
	{
		if(document.forms[0].list_subpolocies.length == 0)
		{
			alert("Please add at least an End Point Security Policy");
			return false;
		}
	}

	var zn=document.forms[0].elements["zone_name"].value;
	if(isEmpty(zn)){
	alert("Profile Name is Empty");
	return false;
	}

	//document.forms[0].elements["zone_name"].value = zn.replace(/ /i, '_');
	var temp = document.forms[0].elements["zone_name"].value;

	if(temp != "  <Type in profile name>")
	{
		temp = replaceAll(temp, " ", "_");	
		document.forms[0].elements["zone_name"].value = temp;
	}
	
	/*	var zd=document.forms[0].elements["zone_desc"].value;
	if(isEmpty(zd)){
	alert("Profile Description is Empty");
	return false;
	}*/

	var cache_clean=document.forms[0].elements["cachecleanup"].checked;

	var count=0;

	if(cache_clean == true)
	{
		var cache=document.forms[0].elements["cache"].checked;
		if(cache == true)
		{
			count=count+1;
			if(document.forms[0].elements["cache_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Internet Cache'");
				return false;
			}
		}

		var cookie=document.forms[0].elements["cookie"].checked;
		if(cookie == true)
		{
			count=count+1;
			if(document.forms[0].elements["cookie_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Cookies'");
				return false;
			}
		}

		var history=document.forms[0].elements["history"].checked;
		if(history == true)
		{
			count=count+1;
			if(document.forms[0].elements["history_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Browsing History'");
				return false;
			}
		}

		var addr=document.forms[0].elements["addr"].checked;
		if(addr == true)
		{
			count=count+1;
			if(document.forms[0].elements["addr_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Typed URLs'");
				return false;
			}
		}

		var addr=document.forms[0].elements["run"].checked;
		if(addr == true)
		{
			count=count+1;
			if(document.forms[0].elements["run_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Desktop Run History'");
				return false;
			}
		}

		var addr=document.forms[0].elements["recent"].checked;
		if(addr == true)
		{
			count=count+1;
			if(document.forms[0].elements["recent_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Recent File History'");
				return false;
			}
		}

		var addr=document.forms[0].elements["recycle"].checked;
		if(addr == true)
		{
			count=count+1;
			if(document.forms[0].elements["recycle_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Recycle Bin Contents'");
				return false;
			}
		}

	/*	var password=document.forms[0].elements["password"].checked;
		if(password == true)
		{
			count=count+1;
			if(document.forms[0].elements["password_select"].value==0)
			{
				alert("Please select a Deletion Mode for 'Clear Passwords'");
				return false;
			}
		}*/

		if(count == 0)
		{
			alert("Please check any of the Cache Cleanup options");
			return false;
		}
	}

	if(isNumber(document.forms[0].zone_name.value) == true)
	{
		document.forms[0].zone_name.value = document.forms[0].zone_name.value+'_Profile';
	}

	copy_value(form);

}

function verifyAddFirewallPolicy(form) {
	var apn=document.forms[0].elements["fw_policy_name"].value;
	if(isEmpty(apn)){
	alert("Firewall Policy Name Empty");
	return false;
	}

	var aproname=document.forms[0].elements["product_name"].value;
	var vendor=document.forms[0].elements["vendor_name"].value;

	if((vendor != "Any Firewall Product") && (aproname == "Select Product"))
	{
		alert('Please select a Product');
		return false;
	}
	
	var rtp =document.forms[0].elements["isEnable"].checked;
	if(rtp){
		var rtpm=document.forms[0].elements["isEnable_message"].value;
		if(isEmpty(rtpm)){
			alert("Firewall enable message is empty");
			return false;
		}
		if(!checkValid(rtpm))
		{
			alert('Enter valid Firewall enable message');
			return false;
		}
	}

	var avproname=document.forms[0].elements["product_name"].value;
	avproname=replaceAllAmpersand(avproname, "&", "|");
	document.CreateFirewallPolicy.product_name.options[document.CreateFirewallPolicy.product_name.selectedIndex].value = avproname;

	var avvendor=document.forms[0].elements["vendor_name"].value;
	avvendor=replaceAllAmpersand(avvendor, "&", "|");
	document.CreateFirewallPolicy.vendor_name.options[document.CreateFirewallPolicy.vendor_name.selectedIndex].value = avvendor;
}

function verifyEditFirewallPolicy(form)
{
	var rtp =document.forms[0].elements["isEnable"].checked;
	if(rtp){
		var rtpm=document.forms[0].elements["isEnable_message"].value;
		if(isEmpty(rtpm)){
			alert("Firewall message is empty");
			return false;
		}
		if(!checkValid(rtpm))
		{
			alert('Enter valid Firewall enable message');
			return false;
		}
	}
}

function verifyAddAvirusPolicy(form)
{

	var apn=document.forms[0].elements["av_policy_name"].value;
	if(isEmpty(apn)){
	alert("Antivirus Policy Name Empty");
	return false;
	}

	var aproname=document.forms[0].elements["product_name"].value;
	var vendor=document.forms[0].elements["vendor_name"].value;

	if((vendor != "Any Antivirus Product") && (aproname == "Select Product"))
	{
		alert('Please select a Product');
		return false;
	}

   	var ud =document.forms[0].elements["upto_date"].checked;
	if(ud){
		var udm=document.forms[0].elements["upto_date_message"].value;
		if(isEmpty(udm))
		{
			alert("Product uptodate message is empty");
			return false;
		}
		if(!checkValid(udm))
		{
			alert('Enter valid Product uptodate message');
			return false;
		}
	}
	var du =document.forms[0].elements["def_update"].checked;
	if(du){
		var dcv=document.forms[0].elements["def_comparision_value"].value;
		if(isEmpty(dcv)){
			alert("Please enter a value for Days/Weeks");
			return false;
		}
		var dm=document.forms[0].elements["def_message"].value;
		if(isEmpty(dm)){
			alert("Virus definition update message is empty");
			return false;
		}
		if(!checkValid(dm))
		{
			alert('Enter valid Virus definition update message');
			return false;
		}
	}
	
	var ls=document.forms[0].elements["last_scan"].checked;
	if(ls){
		var lsv=document.forms[0].elements["last_scan_value"].value;
		if(isEmpty(lsv)){
			alert("Please enter a value for Days/Weeks");
			return false;
		}
		var lsm=document.forms[0].elements["last_scan_message"].value;
		if(isEmpty(lsm)){
			alert("Last scan message is empty");
			return false;
		}
		if(!checkValid(lsm))
		{
			alert('Enter valid Last scan message');
			return false;
		}
	}
	
	var rtp =document.forms[0].elements["rtp"].checked;
	if(rtp){
		var rtpm=document.forms[0].elements["rtp_message"].value;
		if(isEmpty(rtpm)){
			alert("Real Time Protection message is empty");
			return false;
		}
		if(!checkValid(rtpm))
		{
			alert('Enter valid Real Time Protection message');
			return false;
		}
	}

	var avproname=document.forms[0].elements["product_name"].value;
	avproname=replaceAllAmpersand(avproname, "&", "|");
	document.CreateAVPolicy.product_name.options[document.CreateAVPolicy.product_name.selectedIndex].value = avproname;

	var avvendor=document.forms[0].elements["vendor_name"].value;
	avvendor=replaceAllAmpersand(avvendor, "&", "|");
	document.CreateAVPolicy.vendor_name.options[document.CreateAVPolicy.vendor_name.selectedIndex].value = avvendor;

	return true;
}

function verifyEditAvirusPolicy(form)
{
   	var ud =document.forms[0].elements["upto_date"].checked;
	if(ud){
		var udm=document.forms[0].elements["upto_date_message"].value;
		if(isEmpty(udm)){
			alert("Product uptodate message is empty");
			return false;
		}
		if(!checkValid(udm))
		{
			alert('Enter valid Product uptodate message');
			return false;
		}
	}
	var du =document.forms[0].elements["def_update"].checked;
	if(du){
		var dcv=document.forms[0].elements["def_comparision_value"].value;
		if(isEmpty(dcv)){
			alert("Please enter a value for Days/Weeks");
			return false;
		}
		var dm=document.forms[0].elements["def_message"].value;
		if(isEmpty(dm)){
			alert("Virus definition update message is empty");
			return false;
		}
		if(!checkValid(dm))
		{
			alert('Enter valid Virus definition update message');
			return false;
		}
	}
	
	var ls=document.forms[0].elements["last_scan"].checked;
	if(ls){
		var lsv=document.forms[0].elements["last_scan_value"].value;
		if(isEmpty(lsv)){
			alert("Please enter a value for Days/Weeks");
			return false;
		}
		var lsm=document.forms[0].elements["last_scan_message"].value;
		if(isEmpty(lsm)){
			alert("Last scan message is empty");
			return false;
		}
		if(!checkValid(lsm))
		{
			alert('Enter valid Last scan message');
			return false;
		}
	}
	
	var rtp =document.forms[0].elements["rtp"].checked;
	if(rtp){
		var rtpm=document.forms[0].elements["rtp_message"].value;
		if(isEmpty(rtpm)){
			alert("Real Time Protection message is empty");
			return false;
		}
		if(!checkValid(rtpm))
		{
			alert('Enter valid Real Time Protection message');
			return false;
		}
	}


	return true;
}

function verifyAddASpywarePolicy(form)
{
	var apn=document.forms[0].elements["as_policy_name"].value;
	if(isEmpty(apn)){
	alert("AntiSpyware Policy Name Empty");
	return false;
	}

	var aproname=document.forms[0].elements["product_name"].value;
	var vendor=document.forms[0].elements["vendor_name"].value;

	if((vendor != "Any Antispyware Product") && (aproname == "Select Product"))
	{
		alert('Please select a Product');
		return false;
	}

   	var ud =document.forms[0].elements["upto_date"].checked;
	if(ud){
		var udm=document.forms[0].elements["upto_date_message"].value;
		if(isEmpty(udm)){
			alert("Product uptodate message is empty");
			return false;
		}
		if(!checkValid(udm))
		{
			alert('Enter valid Product uptodate message');
			return false;
		}
	}
	var du =document.forms[0].elements["def_update"].checked;
	if(du){
		var dcv=document.forms[0].elements["def_comparision_value"].value;
		if(isEmpty(dcv)){
			alert("Please enter a value for Days/Weeks");
			return false;
		}
		var dm=document.forms[0].elements["def_message"].value;
		if(isEmpty(dm)){
			alert("Spyware definition update message is empty");
			return false;
		}
		if(!checkValid(dm))
		{
			alert('Enter valid Spyware definition update message');
			return false;
		}
	}
	
	var ls=document.forms[0].elements["last_scan"].checked;
	if(ls){
		var lsv=document.forms[0].elements["last_scan_value"].value;
		if(isEmpty(lsv)){
			alert("Please enter a value for Days/Weeks");
			return false;
		}
		var lsm=document.forms[0].elements["last_scan_message"].value;
		if(isEmpty(lsm)){
			alert("Last scan message is empty");
			return false;
		}
		if(!checkValid(lsm))
		{
			alert('Enter valid Last scan message');
			return false;
		}
	}
	
	var rtp =document.forms[0].elements["rtp"].checked;
	if(rtp){
		var rtpm=document.forms[0].elements["rtp_message"].value;
		if(isEmpty(rtpm)){
			alert("Real Time Protection message is empty");
			return false;
		}
		if(!checkValid(rtpm))
		{
			alert('Enter valid Real Time Protection message');
			return false;
		}
	}
	var avproname=document.forms[0].elements["product_name"].value;
	avproname=replaceAllAmpersand(avproname, "&", "|");
	document.CreateASPolicy.product_name.options[document.CreateASPolicy.product_name.selectedIndex].value = avproname;

	var avvendor=document.forms[0].elements["vendor_name"].value;
	avvendor=replaceAllAmpersand(avvendor, "&", "|");
	document.CreateASPolicy.vendor_name.options[document.CreateASPolicy.vendor_name.selectedIndex].value = avvendor;


}

function verifyEditASpywarePolicy(form)
{
   	var ud =document.forms[0].elements["upto_date"].checked;
	if(ud){
		var udm=document.forms[0].elements["upto_date_message"].value;
		if(isEmpty(udm)){
			alert("Product uptodate message is empty");
			return false;
		}
		if(!checkValid(udm))
		{
			alert('Enter valid Product uptodate message');
			return false;
		}
	}
	var du =document.forms[0].elements["def_update"].checked;
	if(du){
		var dcv=document.forms[0].elements["def_comparision_value"].value;
		if(isEmpty(dcv)){
			alert("Please enter a value for Days/Weeks");
			return false;
		}
		var dm=document.forms[0].elements["def_message"].value;
		if(isEmpty(dm)){
			alert("Spyware definition update message is empty");
			return false;
		}
		if(!checkValid(dm))
		{
			alert('Enter valid Spyware definition update message');
			return false;
		}
	}
	
	var ls=document.forms[0].elements["last_scan"].checked;
	if(ls){
		var lsv=document.forms[0].elements["last_scan_value"].value;
		if(isEmpty(lsv)){
			alert("Please enter a value for Days/Weeks");
			return false;
		}
		var lsm=document.forms[0].elements["last_scan_message"].value;
		if(isEmpty(lsm)){
			alert("Last scan message is empty");
			return false;
		}
		if(!checkValid(lsm))
		{
			alert('Enter valid Last scan message');
			return false;
		}
	}
	
	var rtp =document.forms[0].elements["rtp"].checked;
	if(rtp){
		var rtpm=document.forms[0].elements["rtp_message"].value;
		if(isEmpty(rtpm)){
			alert("Real Time Protection message is empty");
			return false;
		}
		if(!checkValid(rtpm))
		{
			alert('Enter valid Real Time Protection message');
			return false;
		}
	}

}

function verifyForm(form)
{
	var disable = false;
	var e1=document.forms[0].elements["fcs_tcpPort"].value;
	var ep=document.forms[0].elements["fcs_tcpPortProxy"].value;
	var e2=document.forms[0].elements["fcs_regPort"].value;
	var esm=document.forms[0].elements["fcs_smtpServer"].value;
	var es=document.forms[0].elements["fcs_smtpPort"].value;
	var el=document.forms[0].elements["fcs_logPort"].value;
	var pxyName=document.forms[0].elements["fcs_proxyName"].value;
	var dbuname=document.forms[0].elements["db_username"].value;
	var dbp=document.forms[0].elements["db_password"].value;
	var dbunamel=document.forms[0].elements["log_username"].value;
	var dbpl=document.forms[0].elements["log_password"].value;
	var ed=document.forms[0].elements["log_port"].value;
	var e=document.forms[0].elements["log_hostname"].value;
	var cd=document.forms[0].elements["ca_days"].value;
	var cn=document.forms[0].elements["ca_companyName"].value;
	var coun=document.forms[0].elements["ca_country"].value;
	var cs=document.forms[0].elements["ca_state"].value;
	var cc=document.forms[0].elements["ca_city"].value;
	var sn=document.forms[0].elements["so_name"].value;
	var se=document.forms[0].elements["so_emailId"].value;
	var suid=document.forms[0].elements["so_uid"].value;
	var spwd=document.forms[0].elements["so_passwd"].value;
	var invalid = " "; // Invalid character is a space

	if (disable)
		return false;

	if(!isPort(e1)||!check(e1)||isEmpty(e1))
	{
		alert ( 'Enter valid Server Port ');
		return false;
	}
	if(!isPort(ep)||!check(ep)||isEmpty(ep))
	{
		alert ( 'Enter valid Server Proxy Port');
		return false;
	}
	if(!isPort(e2)||!check(e2)|| isEmpty(e2))
	{
		alert ( ' Enter valid Administration port. ');
		return false;
	}
	if(!isPort(el)||!check(el)||isEmpty(el))
	{
		alert ( 'Enter valid logger Port');
		return false;
	}
	if(!isServerName(esm))
	{
		alert ('Please enter valid SMTP Server.');
		return false;
	}
	if(!isPort(es)||!check(es)|| isEmpty(es))
	{
		alert ('Enter valid SMTP Port.');
		return false;
	}
  	if (!isEmpty(pxyName))
  	{
    		if (!checkBlankAndWild(pxyName))
    		{
      			alert('Proxy Server Name should not contain special characters');
      			return false;
    		}
 	  	if (pxyName.indexOf(invalid) > -1)
    		{
 	    		alert("Spaces are not allowed in Proxy Server Name");
 		    	return false;
 	  	}
  	}
	if(isEmpty(dbuname))
	{
  		alert('Please Enter Database user name.');
		return false;
	}

	if(isEmpty(dbp))
	{
  		alert('Please Enter Database user password.');
		return false;
	}

	if(isEmpty(dbunamel))
	{
  		alert('Please Enter logger database user name.');
		return false;
	}
	if(isEmpty(dbpl))
	{
  		alert('Please Enter Logger Database user password.');
		return false;
	}
	if(!isPort(ed)||!check(ed)|| isEmpty(ed))
	{
		alert ('Please enter valid logger database Port. ');
		return false;
	}
	if((e1==ep)||(e1==e2)||(e1==es)||(e1==ed)||(e1==el)||(ep==e2)||(ep==es)||(ep==ed)||(ep==el) ||(e2==es)||(e2==ed)||(e2==el)||(es==ed)||(es==el))
	{
		alert ( 'Ports cannot have same value.');
		return false;
	}
	if(!isServerName(e))
	{
		alert ( 'Please enter valid Logger Database hostname.');
		return false;
	}

	if(!checkBlankAndWild(cn))
	{
		alert ('Enter valid Company Name ');
		return false;
	}

	if(coun == '0')
	{
		alert ('Select a Country');
		return false;
	}

	if(cn.length > 256)
	{
		alert ( 'Company Name cannot have more than 256 characters');
		return false;
	}

	if(!checkBlankAndWild(cs))
	{
		alert ('Enter valid State Name ');
		return false;
	}
	if(cs.length > 256)
	{
		alert ( 'State Name cannot have more than 256 characters');
		return false;
	}
	if(!checkBlankAndWild(cc))
	{
		alert ('Enter valid City Name ');
		return false;
	}
	if(cc.length > 256)
	{
		alert ( 'City Name cannot have more than 256 characters');
		return false;
	}
	if(isEmpty(cd))
	{
		alert ( 'Empty Days not allowed.');
		return false;
	}
	if(!check(cd))
	{
		alert ( 'Days should have numeric value.');
		return false;
	}
	if(sn.length > 256)
	{
		alert ( 'Name cannot have more than 256 characters');
		return false;

	}
	if(!checkBlankAndWild(sn))
	{
		alert ( 'Please enter valid Name');
		return false;
	}
	if(!check1(se))
	{
		alert ( 'Please enter valid Email ID');
		return false;
	}
	if (isEmpty(se))
		return false;

	/*if (!verifyHSPassword(suid, spwd))
    	{
         return false;
    	}*/
        if(! ( isEmpty(suid) && isEmpty(spwd) ) )
        {
                if( isEmpty(suid) )
                {
                alert("Please enter User ID");
                return false;
                }

		for(var i=0;i<suid.length; i++)
		{
                	if(!isLetter(suid.charAt(i)) && !isDigit(suid.charAt(i)) && suid.charAt(i)!="_")
                	{
                		alert("User ID should not contain any special characters except '_'");
                		return false;
                	}
		}

                if(isEmpty(spwd))
                {
                	alert("Please enter password");
                	return false;
                }

		if(spwd.length<6 || spwd.length>16)
                {
                	alert("Password length must be atleast 6 characters and atmost 16 characters");
                	return false;
                }

        	if (!verifyPassword(spwd))
        	{
	          	return false;
        	}
        }
        else
        {
                if(confirm("Basic Authentication User ID and Password not supplied. Do you want to continue?")
== false)
                return false;
        }

  disable = true;
  return true;
}

function EnrolledSelected(form)
{
	var e=form.ENROLLED.selectedIndex;
	form.Go.disabled = true;
	form.Add.disabled = false;
	if(e==2)
	{
		form.Go.disabled = false;
		form.Add.disabled = true;
	}
}

function goBack(form)
{
	var str="FcsPage.cgi"
	window.location.href=str;
}

function verifyFCSbutton(form)
{
	var s=document.forms[0].elements["Application"].value;
	var ds=document.forms[0].elements["DestinationServer"].value;
	var dp=document.forms[0].elements["DestinationPort"].value;
	var lp=document.forms[0].elements["listenPort"].value;
	var e=document.forms[0].elements["ENROLLED"].value;
	var str="FcsPage.cgi?type=4&Application=";
	var str1=str+s;
	var str2=str1+"&DestinationServer=";
	var str3=str2+ds;
	var str4=str3+"&DestinationPort=";
	var str5=str4+dp;
	var str6=str5+"&listenPort=";
	var str7=str6+lp;
	var str8=str7+"&ENROLLED=";
	var str9=str8+e;

	window.location.href=str9;
}

function verifyFCS(form)
{
	var s=document.forms[0].elements["Application"].value;
	if(!isAlphanumeric(s))
	{
		alert('Wild characters and Spaces are not allowed in Application ');
		return false;
	}
	var s1=document.forms[0].elements["DestinationServer"].value;
	if(!isServerName(s1))
	{
		alert('Wild characters,Nulls and Spaces are not allowed in Hostname ');
		return false;
	}
	var e=document.forms[0].elements["DestinationPort"].value;
	if(isEmpty(e))
	{
		alert ('Port field is Empty');
		return false;
	}
	if(!check(e))
	{
		alert ( 'Port should have numeric value  ');
		return false;
	}
	var e1=document.forms[0].elements["listenPort"].value;
	if(isEmpty(e1))
	{
		alert ('Port field is Empty');
		return false;
	}
	if(!check(e1))
	{
		alert ( 'Port should have numeric value  ');
		return false;
	}

	return true;
}

function verifyAuthServerSearchForm(form)
{

	var e1=trim(document.forms[0].server_name.value);
	form.elements["server_name"].value=e1;
	var len=e1.length;
	if(len > 255)
	{
		alert('Field value length should be less than 256 characters');
		return false;
	}

	if(isEmpty(e1))
	{
		 alert("Please enter search criteria");
		return false;
	}
	return true;
}



function verifygetseal(form)
{

	var e1=trim(document.forms[0].EName.value);
	form.elements["EName"].value=e1;
	var len=e1.length;
	if(len > 255)
	{
		alert('Field value length should be less than 256 characters');
		return false;
	}

	if(isEmpty(e1))
	{
		 alert("Please enter search criteria");
		return false;
	}
	/*if(document.forms[0].ldapcheck.checked==true)
		document.forms[0].type.value=21;
	else*/
		document.forms[0].type.value=6;
	return true;
}

function getValueForUser(form)
{
	/*if(document.forms[0].ldapcheck.checked==true)
		document.forms[0].type.value=21;
	else*/
		document.forms[0].type.value=6;
	return true;
}

function GroupValue(form)
{
	/*if(document.forms[0].ldapcheck.checked==true)
                document.forms[0].type.value=9;
        else*/
                document.forms[0].type.value=5;
        return true;
}

function verifysessionseal(form)
{

	var e1=trim(document.forms[0].EName.value);
	form.elements["EName"].value=e1;
	var len=e1.length;
	if(len > 255)
	{
		alert('Field value length should be less than 256 characters');
		return false;
	}

	if(isEmpty(e1))
	{
		 alert("Please enter search criteria");
		return false;
	}
	document.forms[0].type.value=18;
	return true;
}



function verifygetLdapseal(form)
{

	var e1=trim(document.forms[0].EName.value);
	form.elements["EName"].value=e1;
	var len=e1.length;
	if(len > 255)
	{
		alert('Field value length should be less than 256 characters');
		return false;
	}

	if(isEmpty(e1))
	{
		 alert("Please enter search criteria");
		return false;
	}
	document.forms[0].type.value=21;
	return true;
}

function isServerBased(form)
{
/*	inval=document.forms[0].app_type.value;

	if(	document.forms[0].ServerBased.checked==false || document.forms[0].app_type.options[inval].text!="OTHERS" )
	{		document.forms[0].app_path.value="";
			document.forms[0].app_path.disabled=true;
	}
	else
		document.forms[0].app_path.disabled=false;*/
	return true;
}
function iscluster(form)
{

        if(     document.forms[0].app_iscluster.checked==false )
	{
                        document.forms[0].IsSessionCaching.disabled=true;
        }
        else
                document.forms[0].IsSessionCaching.disabled=false;
        return true;
}

function iscluster1(form)
{

        if(     document.forms[0].appIscluster.checked==false )
	{
                        document.forms[0].IsSessionCaching.disabled=true;
        }
        else
                document.forms[0].IsSessionCaching.disabled=false;
        return true;
}
function isldapuser(form)
{
	if(document.forms[0].user_ldapcheck.checked==true)
	{
		if(document.forms[0].user_role.value!="4")
		{	alert('only Low security Users are allowed');
			return false;
		}
                //document.forms[0].user_bmcheck.disabled=true;
                document.forms[0].user_passcheck.disabled=true;
                document.forms[0].user_passexp.disabled=true;
                document.forms[0].user_disacc.disabled=true;
		if(document.forms[0].user_role.value=="4")
		document.forms[0].user_role.disabled=true;


	}
	else{
		//document.forms[0].user_bmcheck.disabled=false;
                document.forms[0].user_passcheck.disabled=false;
                document.forms[0].user_passexp.disabled=false;
                document.forms[0].user_disacc.disabled=false;
		document.forms[0].user_role.disabled=false;

}

}
function isldapgroup(form)
{
	if(document.forms[0].ldapcheck.checked==true)
	{
		document.forms[0].user_desc.disabled=true;
		document.forms[0].check.disabled=true;
	}
	else
	{	document.forms[0].user_desc.disabled=false;
		document.forms[0].check.disabled=false;
	}
}


function isPasswdChange(form)
{

	if(	document.forms[0].user_checknpass.checked==false  ){
			document.forms[0].user_newpass.disabled=true;
			document.forms[0].user_conpass.disabled=true;
	}
	else{

	if(	document.forms[0].user_isposs.value==1  ){
		document.forms[0].user_newpass.disabled=false;
		document.forms[0].user_conpass.disabled=false;
	}
	else{
		alert("Sorry you dont have enough privilege");
		return false;
	}
	}
	return true;
}

function LocalApp(form)
{
	if(document.forms[0].ServerBased.checked==true &&  document.forms[0].app_type.options[inval].text=="OTHERS" )
 return true;
 else
   return false;
}
function IsLdapUser(form)
{
if(document.forms[0].IsLdapUser.checked==true)
{
	var str='userManger.cgi?type=17';
	return true;
}
else

	return false;
}
function isServerBased2(form)
{
	if( document.forms[0].ServerBased.checked==false )
         {
		        apppath = document.forms[0].app_path.value;
			document.forms[0].app_path.value="";
			document.forms[0].app_path.disabled=true;
	}
	else
          {
			document.forms[0].app_path.value=apppath;
			document.forms[0].app_path.disabled=false;
          }
	return true;
}



function pinMatch(form)
{
	var invalid = " "; // Invalid character is a space
 	var minLength = 6; // Minimum length
	var maxLength=16;//Maxlength
 	var pw1 = form.PIN.value;
 	var pw2 = form.R_PIN.value;
	var sp=form.SECRE_PASS.value;
	var csr=form.CSR.value;
	if(sp == '' || csr== '')
	{
  		alert('Empty fields are not allowed .');
  		return false;
	}
	var e=form.PIN.value;
	if(!checkBlankAndWild(e))
	{
		alert ( 'Wild Characters are not allowed in PIN ');
		return false;
	}
	var len1= form.PIN.value.length;
 	if (pw1 == '' || pw2 == '')
	{
  		alert('Please enter your PIN twice.');
  		return false;
 	}


	if(len1 < minLength || len1 > maxLength)
	{
 		alert('Your PIN must be maximum ' + maxLength + ' and minimum '+ minLength +' characters long.');
 		return false;
 	}

 	if (form.PIN.value.indexOf(invalid) > -1)
	{
 		alert("spaces are not allowed.");
 		return false;
 	}

	else
	{
 		if (pw1 != pw2)
		{
 			alert ("You did not enter the same new PIN twice. Please re-enter your PIN.");
 			return false;
  		}
		else
		{
			 if(disablesubmit)
 				return true;
        	}

 	}

}

function numChecked(form)
{
	if(form.checkall.checked)
		isChecked = true;
 	else
 		isChecked = false;
 	if(form.check.length > 0)
 		for(var i = 0; i < form.check.length;i++)
 			 form.check[i].checked = isChecked;
 	else
 		form.check.checked = isChecked;
}

function EnterUser(form)
{
 	if(form.check.length > 0)
	{
		for(var i = 0; i < form.check.length;i++)
	 	{
			if(form.check[i].checked)
		  	{
			  	document.forms[0].elements[type].value=2; return true;
		  	}
	  	}
	  	alert('Please select any user');
	  	return false;
  	}
 	else
  	{
		if(form.checkall.checked)
	 	{
			document.forms[0].elements[type].value=2;
			return true;
	  	}
 	 	if(form.check.checked)
	  	{
			document.forms[0].elements[type].value=2;
			return true;
	  	}
	  	alert('Please select any user');
	  	return false;
  	}
  	document.forms[0].elements[type].value=2;
  	return true;
}

function disableButton(form)
{
	var maxrows=parseInt(form.ROWS.value);
	if(maxrows < 5)
 	{
		document.forms[0].elements[NEXT].disabled = true;
		return false;
	}
}
function displayElements(form)
{
	for(var i=0;i <document.forms[0].elements.length;i++)
	{
		alert(document.forms[0].elements[i].name+'    '+document.forms[0].elements[i].value);
	}

}

function Next(form)
{	var pagelimit=50;
	var minlimit=parseInt(document.forms[1].MIN_LIMIT.value,10);
 	var maxlimit=parseInt(document.forms[1].MAX_LIMIT.value,10);
 	var maxrows=parseInt(document.forms[1].rows.value,10);
 	var trecords=parseInt(document.forms[1].trecords.value,10);
 	var maxrecord=parseInt(document.forms[1].records.value,10);

	var sumtotal=minlimit+maxlimit;
 	var totallimit=parseInt(sumtotal,10);
	var remtotal=maxrows-totallimit;
 	var rem=parseInt(remtotal,10);

	if(trecords==maxrecord)
		return false;
	if(maxrecord <pagelimit)
		return false;
	if(maxrecord ==maxrows)
		return false;
 	if(rem <= 0)
		return false;
	document.forms[1].MIN_LIMIT.value=minlimit+pagelimit;
	document.forms[1].MAX_LIMIT.value=pagelimit;

  	document.forms[1].type.value=6;

	document.forms[1].submit();
	return true;
}


function NextLdap(form)
{
	var minlimit=parseInt(document.forms[1].MIN_LIMIT.value,10);
 	var maxlimit=parseInt(document.forms[1].MAX_LIMIT.value,10);
 	var maxrows=parseInt(document.forms[1].rows.value,10);
 	var trecords=parseInt(document.forms[1].trecords.value,10);
 	var maxrecord=parseInt(document.forms[1].records.value,10);

	var sumtotal=minlimit+maxlimit;
 	var totallimit=parseInt(sumtotal,10);
	var remtotal=maxrows-totallimit;
 	var rem=parseInt(remtotal,10);

	if(trecords==maxrecord)
		return false;
	if(maxrecord <pagelimit)
		return false;
	if(maxrecord ==maxrows)
		return false;
 	if(rem <= 0)
		return false;
	document.forms[1].MIN_LIMIT.value=minlimit+pagelimit;
	document.forms[1].MAX_LIMIT.value=pagelimit;

  	document.forms[1].type.value=21;

	document.forms[1].submit();
	return true;
}

function Previous(form)
{	var pagelimit=50;
	var minlimit=parseInt(document.forms[1].MIN_LIMIT.value,10);
 	var maxlimit=parseInt(document.forms[1].MAX_LIMIT.value,10);
 	var maxrows=parseInt(document.forms[1].rows.value,10);
 	if(minlimit==0 )
		   	return false;
	document.forms[1].MIN_LIMIT.value=minlimit-pagelimit;
	document.forms[1].MAX_LIMIT.value=pagelimit;
  	document.forms[1].type.value=6;
	document.forms[1].submit();
	return true;
}


function PreviousLdap(form)
{
	var minlimit=parseInt(document.forms[1].MIN_LIMIT.value,10);
 	var maxlimit=parseInt(document.forms[1].MAX_LIMIT.value,10);
 	var maxrows=parseInt(document.forms[1].rows.value,10);
 	if(minlimit==0 )
		   	return false;
	document.forms[1].MIN_LIMIT.value=minlimit-pagelimit;
	document.forms[1].MAX_LIMIT.value=pagelimit;
  	document.forms[1].type.value=21;
	document.forms[1].submit();
	return true;
}


function isEmpty(s)
{
	return ((s == null) || (s.length == 0)||(s=='')) ;
}

function emailcheck(val)
{
	var error = 'Please enter valid Email ID.';
	if (val == '')
	{
		alert(error);
		return false;
	}
	var emailLength = parseInt(val.length);
	var atIdx = parseInt(val.indexOf ('@',0));
	var dotIdx = parseInt(val.lastIndexOf('.'));

	if(dotIdx < atIdx)
	{
		alert(error);
		return false;
	}
	if((atIdx == -1) || (dotIdx == -1))
	{
		alert(error);
		return false;
	}
	if(dotIdx +1 == emailLength)
	{
		alert(error);
		return false;
	}
	return true;
}


function checkmail(e)
{
	var arremail= new Array(32,47,45,46,64,48,49,50,51,52,53,54,55,56,57,58,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122);
	var l=e.length;
	var arrlen=arremail.length;
	var space=0;
	for(var x=0;x!=l;x++)
	{
		var c=e.charAt(x);
		var match=0;
		if(x==0)
		{
			if(c==' ')
				space=1;
			if (space == 1)
				return false;
		}
		for(var i=0;i!=arrlen;i++)
		{
			var d=	String.fromCharCode(arremail[i]);
			if(c==d)
				match = 1;
		 }
		if (match == 0)
			return false;
	}
	return true;
}

var disableUser=false;
function verifyUserCreation(form)
{
	if(disableUser)
		return false;
	if(!verifyUserCreationFirst(this.form))
		return false;
	CheckForSelectedUserGrp(this.form);
	//Checkforldapuser(this.form);
	disableUser=true;
	return true;

}
function verifysearch(form)
{
 document.forms[0].type.value="20";
return true;
}

function Checkforldapuser(form)
{
	if(document.forms[0].user_ldapcheck.checked==true)
		document.forms[0].type.value="19";
}

function validateCurrentDate(day, month, year ,dayNow, monthNow, yearNow)
{
	var str = "The Current Date of VPN is : "+dayNow+"/"+monthNow+"/"+yearNow+"\nPlease change the Account Expiry Date to a higher value.";

	var day1 = parseInt(day);
	var month1 = parseInt(month);
	var year1 = parseInt(year);
	var dayNow1 = parseInt(dayNow);
	var monthNow1 = parseInt(monthNow);
	var yearNow1 = parseInt(yearNow);


	if(year1 < yearNow1)
	{
		alert(str);
		return false;
	}
	else if(year1 == yearNow1)
	{
		if(month1 < monthNow1)
		{
			alert(str);
			return false;
		}
		else if(month1 == monthNow1)
		{
			if(day1 < dayNow1)
			{
				alert(str);
				return false;
			}
			else if(day1 == dayNow1)
			{
				cnf = confirm("The Account Expiry Date is equal to Today's Date.\nAs a result the Account will be disabled immediately.\nDo you want to continue?");

				if(cnf)
				{
					return true;
 				}
				else
					return false;
			}
		}
	}
	return true;
}

function validateDate(day, month, year)
{
	if( (month == 2) || (month == 4)  || (month == 6) || (month == 9) || (month == 11) )
	{
		if(day == 31)
		{
			switch (month)
			{
				case '2':
					alert('31 is not a valid date for Feb');
					break;
				case '4':
					alert('31 is not a valid date for Apr');
					break;
				case '6':
					alert('31 is not a valid date for Jun');
					break;
				case '9':
					alert('31 is not a valid date for Sep');
					break;
				case '11':
					alert('31 is not a valid date for Nov');
					break;
			}
			return false;
		}
	}

	if(month == 2)
	{
		if((year%4) != 0) // Not a Leap Year
		{
			if(day > 28)
			{
				var str = 'Date '+day+' is not valid in Feb '+year;
				alert(str);
				return false;
			}
		}
		else	//Leap Year
		{
			if(day > 29)
			{
				var str = 'Date '+day+' is not valid in Feb '+year;
				alert(str);
				return false;
			}
		}
	}
	return true;
}

function verifyUserCreationFirst(form)
{
	var n=document.forms[0].user_name.value;
	n=replaceAll(n," ","")
	document.forms[0].user_name.value=n;
	var e=document.forms[0].user_emailId.value;
	var e1=document.forms[0].user_emailIdcc.value;
	var r=document.forms[0].user_role.value;
	var c=document.forms[0].user_class.value;
	var h=document.forms[0].user_hostname.value;
	var uid=document.forms[0].user_id.value;
	var passwd=document.forms[0].user_password.value;

	var day=document.forms[0].dd.value;
	var month=document.forms[0].mm.value;
	var year=document.forms[0].yy.value;

	var dayNow=document.forms[0].curDay.value;
	var monthNow=document.forms[0].curMon.value;
	var yearNow=document.forms[0].curYear.value;


        var lsUser ="Low Security User";
        var hsUser="High Security User";
	var invalid = " "; // Invalid character is a space
	var noUserIdCheck=0;

	if(c==1)
	{
		if(r==0)
		{
			alert('User Security Officer cannot have class of Machine type ');
			return false;
		}
		else if(r==1)
		{
			alert('User Administrator cannot have class of Machine type ');
			return false;
		}
		else if(r==4)
		{
			alert('Low Security Users cannot have class of Machine type ');
			return false;

		}
		noUserIdCheck=1;
	}
	if((isEmpty(e))||(isEmpty(h))||(isEmpty(n)))
	{
		alert ( 'Empty fields not allowed  ');
		return false;
	}
	/*if(!isServerName(h))
	{
		alert ('Please enter valid Host Name.');
		return false;
	}*/

	if(!checkmail(n))
	{
		alert ( 'Please enter valid user name ');
		return false;
	}
	if(n.length >256)
	{
		alert ( 'Please enter valid user name ');
		return false;
	}
	if(!emailcheck(e))
		return false;
	if(!checkmail(e)|| !check1(e))
	{
		alert ( 'Please enter correct Email ID');
		return false;
	}
	if(!emailcheck(e1))
		return false;
	if(!checkmail(e1)||!check1(e1))
	{
		alert ( 'Please enter correct Email ID');
		return false;
	}
	if(!checkmail(h))
	{
		alert ( 'Please enter correct Host Name');
		return false;
	}


	if(r > 2)
	{
		if(day != 0)
		{
			if(month == 0)
			{
				alert('Please select Month for Account Expiry');
				return false;
			}
			if(year == 0)
			{
				alert('Please select Year for Account Expiry');
				return false;
			}

			if(validateDate(day, month, year) == false)
			{
				return false;
			}

			if(validateCurrentDate(day, month, year ,dayNow, monthNow, yearNow) == false)
			{
				return false;
			}
		}
	}

			//	return false;
  	if (r == 4)
  	{
//Added on 12/April/04 by kiran
	if(c==1)
	{
		alert('Low security User cannot have class of Machine type');
		return false;
	}
//END
      	if (isEmpty(uid))
      	{
          alert('Please specify User ID');
          return false;
      	}


	for(var i=0; i<uid.length; i++)
	{
                if(!isLetter(uid.charAt(i)) && !isDigit(uid.charAt(i)) && uid.charAt(i)!='_')
                {
                        alert("User ID cannot contain special characters except '_'");
                        return false;
                }
	}
      	if (isEmpty(passwd))
      	{
          alert('Please specify password');
          return false;
      	}
	if(passwd.length<6 ||  passwd.length>16)
	{
		alert("Password must be 6 characters atleast and 16 characters atmost");
		return false;
	}

      	if (!verifyUserID(uid))
      	{
          	return false;
      	}

	/*if(document.forms[0].user_ldapcheck.checked==true)
	{
      	if (!verifyLdapPassword(passwd))
      	{
        	return false;
      	}
	}
	else
	{*/
      	if (!verifyPassword(passwd))
      	{
        	return false;
      	}
	//}
  	}

	else if(r<=3&& c!=1)
	{
		if (isEmpty(uid))
			{
          			alert('Please specify User ID');
				return false;

			}
		if (isEmpty(passwd))
			{
          			alert('Please specify password');
				return false;


			}
               	if(!isEmpty(uid) && !isEmpty(passwd))
		{
                	if(!verifySUIDSPWD(uid, passwd))
                		return false;
        	}
             /*   else if(isEmpty(uid) && isEmpty(passwd))
		{
			if(noUserIdCheck==1)
				return true;
                        if(confirm("Basic Authentication User ID and Password are not supplied. Do you wish to continue?")==true)
			return true;
                        else return false;
                } */
		if (!verifyHSPassword(uid, passwd))
       			return false;
        }
  	else if (!verifyHSPassword(uid, passwd))
        	return false;

	return true;
}

function verifyUserID(uid)
{
      var maxLength=50;
      var invalid = " "; // Invalid character is a space

      /*if (!checkBlankAndWild(uid))
      {
		      alert ( 'Wild characters are not allowed in User ID');
          return false;
      }*/

	for(var i=0;i<uid.length; i++)
	{
		if(!isLetter(uid.charAt(i)) && !isDigit(uid.charAt(i)) && uid.charAt(i)!="_")
		{
		alert("User ID should not contain any special characters except '_'");
		return false;
		}
	}
 	if (uid.indexOf(invalid) > -1)
    	{
 	    	alert("Spaces are not allowed in User ID");
 	        return false;
 	}
        if (uid.length > maxLength)
        {
 	    	alert('Maximum length for User ID is 50 characters');
     	        return false;
        }
      return true;
}

function verifyHSPassword(uid, passwd)
{
      if (((!isEmpty(uid)) && (isEmpty(passwd))) || ((isEmpty(uid)) && (!(isEmpty(passwd)))))
      {
        alert('Please specify both UserId and password or none');
        return false;
      }
      if (!isEmpty(uid))
      {
        if (!verifyUserID(uid))
        {
          return false;
        }

      }
      if (!isEmpty(passwd))
      {
        if (!verifyPassword(passwd))
        {
          return false;
        }
      }
      return true;
}
function verifyPassword(passwd)
{
      var minLength=6;
      var maxLength=16;

	    var plen=passwd.length;
	    var invalid = " "; // Invalid character is a space

    	//if(!checkBlankAndWild(passwd))
    	/*if(!isStrictlyAlphanumeric(passwd))
	{
		alert ( 'Password should not contain Wild characters.');
		return false;
    	}*/
	if(plen < minLength || plen > maxLength)
	{
 		alert('User Password must be maximum ' + maxLength + ' and minimum '+ minLength +' characters long.');
 	 	return false;
 	}
 	if (passwd.indexOf(invalid) > -1)
    	{
 		alert("Spaces are not allowed in Password.");
 		return false;
 	}
      return true;
}
function verifyLdapPassword(passwd)
{
      var minLength=6;
      var maxLength=16;

	    var plen=passwd.length;
	    var invalid = " "; // Invalid character is a space

    	//if(!checkBlankAndWild(passwd))
 //   	if(!isStrictlyAlphanumeric(passwd))
//	{
//		alert ( 'Password should not contain Wild characters.');
//		return false;
  //  	}
	if(plen < minLength || plen > maxLength)
	{
 		alert('User Password must be maximum ' + maxLength + ' and minimum '+ minLength +' characters long.');
 	 	return false;
 	}
 	if (passwd.indexOf(invalid) > -1)
    	{
 		alert("Spaces are not allowed in Password.");
 		return false;
 	}
      return true;
}
function CheckForSelectedUserGrp(form)
{
	for(var i=0;i<document.forms[0].mySelectDisable.length;i++)
	{
		document.forms[0].mySelectDisable.options[i].selected=true;
	}
}
function AddUserGroupToUsers(form)
{
	if(!verifyUserCreationFirst(this.form))
     	return false;
	var r=document.forms[0].user_role.value;
   var uid=document.forms[0].user_id.value;
   if((!uid)&&r!=4)
   	var str ='userManager.cgi?type=2';
  	else  if (r==4)
   	var str='userManager.cgi?type=13';
  	else
    	var str='userManager.cgi?type=14';
	/*if(document.forms[0].user_ldapcheck.checked==true)
	var str='userManager.cgi?type=28';*/
	newwindow=window.open(str,"","width=600,height=250,titlebar=0,scrollbars=yes,resizable=0","");
   return true;
}


var NS4 = (navigator.appName == "Netscape" && parseInt(navigator.appVersion) < 5);

function post_value(){
    var elSel = window.opener.document.getElementById('list_subpolocies');
	//window.opener.document.ag_creatForm.list_subpolocies.length=0;
	window.opener.document.forms[0].list_subpolocies.length=0;
	
for(i=0;i<document.frm_addpolicy.list_right.length;i++)
	{
	var elOptNew = window.opener.document.createElement('option');
    elOptNew.text = document.frm_addpolicy.list_right.options[i].text;
    elOptNew.value = document.frm_addpolicy.list_right.options[i].text;
	

var index = (elOptNew.selectedIndex == 0)? 0: elOptNew.selectedIndex;

	try {
      elSel.add(elOptNew, index); // standards compliant; doesn't work in IE
        }
    catch(ex) {
          elSel.add(elOptNew); // IE only
    }

}
}

function copy_ip_value(form)
{
	var elSel = document.getElementById('list_ipaddresses');
	for(i=0;i<form.list_ipaddresses.length;i++)
	{
		elSel.options[i].selected=true;
	}
}


function copy_mac_value(form)
{
	var elSel = document.getElementById('list_macaddresses');
	for(i=0;i<form.list_macaddresses.length;i++)
	{
		elSel.options[i].selected=true;
	}
}

function verifyIPPolicy(form)
{
	var pn=document.forms[0].elements["ip_policy_name"].value;
	if(isEmpty(pn))
	{
		alert("IP Policy Name is Empty");
		return false;
	}

	var status1=document.getElementById("status_value").value;
	if(status1 == 0)
	{
		alert("Select Allow or Block");
		return false;
	}
	else if(status1 == 1)
	{
		var status_en=document.getElementById("status_en_value").value;
		if(status_en == 0)
		{
			alert("Select any one under Allow");
			return false;
		}
	}
	else if(status1 == 2)
	{
		var status_dis=document.getElementById("status_dis_value").value;
		if(status_dis == 0)
		{
			alert("Select any one under Block");
			return false;
		}
	}

	if(form.list_ipaddresses.length == 0)
	{
		alert("Add at least one IP Address");
		return false;
	}

	copy_ip_value(form);

	return true;
}


function verifyMACPolicy(form)
{
	var pn=document.forms[0].elements["mac_policy_name"].value;
	if(isEmpty(pn))
	{
		alert("MAC Policy Name is Empty");
		return false;
	}

	var status_val = document.forms[0].prev_status.value;

	if(status_val == 1)
	{
		var status1=document.getElementById("status_value").value;
		if(status1 == 0)
		{
			alert("Select Allow");
			return false;
		}
	}
	else if(status_val == 2)
	{
		var status1=document.getElementById("status_value").value;
		if(status1 == 0)
		{
			alert("Select Block");
			return false;
		}
	}

	var status1=document.getElementById("status_value").value;
	if(status1 == 0)
	{
		alert("Select Allow or Block");
		return false;
	}
	else if(status1 == 1)
	{
		var status_en=document.getElementById("status_en_value").value;
		if(status_en == 0)
		{
			alert("Select any one under Allow");
			return false;
		}
	}
	else if(status1 == 2)
	{
		var status_dis=document.getElementById("status_dis_value").value;
		if(status_dis == 0)
		{
			alert("Select any one under Block");
			return false;
		}
	}

	if(form.list_macaddresses.length == 0)
	{
		alert("Add at least one MAC Address");
		return false;
	}

	copy_mac_value(form);

	return true;
}

function verifyEditMACPolicy(form)
{
	var pn=document.forms[0].elements["mac_policy_name"].value;
	if(isEmpty(pn))
	{
		alert("MAC Policy Name is Empty");
		return false;
	}

	var previous_status = document.forms[0].prev_status.value;

	var status1=document.getElementById("status_value").value;

	var count=document.getElementById("count_value").value;

	if(status1 == 0)
	{
		alert("Select Allow or Block");
		return false;
	}
	else if(status1 == 1)
	{
		var status_en=document.getElementById("status_en_value").value;
		if(status_en == 0)
		{
			alert("Select any one under Allow");
			return false;
		}
	}
	else if(status1 == 2)
	{
		var status_dis=document.getElementById("status_dis_value").value;
		if(status_dis == 0)
		{
			alert("Select any one under Block");
			return false;
		}
	}

	if((previous_status != status1) && (count > 1))
	{
		cnf = confirm("You are going to change the Access Restriction of this Sub-Policy\nThis will be changed in all the Sub-Policies.Do you want to Continue?")
		if(!cnf)
		{
			return false;
 		}
	}

	if(form.list_macaddresses.length == 0)
	{
		alert("Add at least one MAC Address");
		return false;
	}

	copy_mac_value(form);

	return true;
}



function copy_value(form){

	var elSel = document.getElementById('list_subpolocies');

	for(i=0;i<form.list_subpolocies.length;i++)
	{
		elSel.options[i].selected=true;
	}
	
	var elSelapp = document.getElementById('list_app');

	for(i=0;i<form.list_app.length;i++)
	{
		elSelapp.options[i].selected=true;
	}
}

function delOption(){
    var elSel = document.getElementById('list_left');
for(j=0;j<document.frm_addpolicy.list_right.length;j++)
{
	for(i=0;i<document.frm_addpolicy.list_left.length;i++)
	{
		if(document.frm_addpolicy.list_left.options[i].text==document.frm_addpolicy.list_right.options[j].text)
		{
			var elOptNew = document.createElement('option');
		  //  elOptNew.text = document.frm_addpolicy.list_right.options[j].text
		    //elOptNew.value = document.frm_addpolicy.list_right.options[j].text
	
			var index = (elOptNew.selectedIndex == 0)? 0: elOptNew.selectedIndex;

			try {
			      elSel.remove(i,index); // standards compliant; doesn't work in IE
		        }
    		catch(ex) {
		          elSel.remove(i); // IE only
			    }
				
		}
	}
}
}



function addOption(theSel, theText, theValue)
{
	var newOpt = new Option(theText, theValue);

	var selLength = theSel.length;
	theSel.options[selLength] = newOpt;
}

function deleteOption(theSel, theIndex)
{
	var selLength = theSel.length;
	if(selLength>0)
	{
		theSel.options[theIndex] = null;
	}
}

function checkOptions(theSel,theText)
{

	var alrLength=theSel.length;
	var alrCount=0;
	for (alrCount = 0; alrCount< alrLength; alrCount++)
	{
		if(theText==theSel.options[alrCount].text)
			return false;

	}
	return true;
}


function copyOptionsRealm(theSelFrom, theSelTo, form)
{
	var selLength = theSelFrom.length;
	var selectedText = new Array();
	var selectedValues = new Array();
	var selectedCount = 0;
	var i;

	if(theSelFrom.length==0)
	{
		alert('No group(s) to Block');
		return false;
	}

	for(i=selLength-1; i>=0; i--)
	{
		if(theSelFrom.options[i].selected)
		{
			selectedText[selectedCount] = theSelFrom.options[i].text;
			selectedValues[selectedCount] = theSelFrom.options[i].value;
			deleteOption(theSelFrom, i);
			selectedCount++;
		}
	}
	if(selectedCount==0)
	{
		alert('No group(s) selected to Block');
		return false;
	}

	for(i=selectedCount-1; i>=0; i--)
	{
		if(checkOptions(theSelTo,selectedText[i]))
			addOption(theSelTo, selectedText[i], selectedValues[i]);
	}

	if(theSelFrom.length==0)
		document.forms[0].block.disabled=true;
	else
		document.forms[0].block.disabled=false;

	if(theSelTo.length==0)
		document.forms[0].allow.disabled=true;
	else
		document.forms[0].allow.disabled=false;

	return false;
}

function moveOptionsRealm(theSelFrom, theSelTo, form)
{
	var selLength = theSelFrom.length;
	var selectedText = new Array();
	var selectedValues = new Array();
	var selectedCount = 0;

	var i;
	if(theSelFrom.length==0)
	{
		alert('No group(s) to Allow');
		return false;
	}

	for(i=selLength-1; i>=0; i--)
	{
		if(theSelFrom.options[i].selected)
		{
			selectedText[selectedCount] = theSelFrom.options[i].text;
			selectedValues[selectedCount] = theSelFrom.options[i].value;
			deleteOption(theSelFrom, i);
			selectedCount++;
		}
	}

	if(selectedCount==0)
	{
		alert('No group(s) selected to Allow');
		return false;
	}

	for(i=selectedCount-1; i>=0; i--)
	{
		if(checkOptions(theSelTo,selectedText[i]))
			addOption(theSelTo, selectedText[i], selectedValues[i]);
	}

	if(theSelFrom.length==0)
		document.forms[0].allow.disabled=true;
	else
		document.forms[0].allow.disabled=false;

	if(theSelTo.length==0)
		document.forms[0].block.disabled=true;
	else
		document.forms[0].block.disabled=false;

	return false;
}









function copyOptions(theSelFrom, theSelTo)
{

	var selLength = theSelFrom.length;
	var selectedText = new Array();
	var selectedValues = new Array();
	var selectedCount = 0;


	var i;

	// Find the selected Options in reverse order

	for(i=selLength-1; i>=0; i--)
	{
		if(theSelFrom.options[i].selected)
		{
			selectedText[selectedCount] = theSelFrom.options[i].text;
			selectedValues[selectedCount] = theSelFrom.options[i].value;
			deleteOption(theSelFrom, i);
			selectedCount++;
		}
	}
	if(selectedCount==0)
	{
		alert('No data selected to Add');
		return false;
	}

	// Add the selected text/values in reverse order.
	// This will add the Options to the 'to' Select
	// in the same order as they were in the 'from' Select.
	for(i=selectedCount-1; i>=0; i--)
	{
		if(checkOptions(theSelTo,selectedText[i]))
			addOption(theSelTo, selectedText[i], selectedValues[i]);
	}

	return false;
}

function moveOptions(theSelFrom, theSelTo)
{

	var selLength = theSelFrom.length;
	var selectedText = new Array();
	var selectedValues = new Array();
	var selectedCount = 0;

	var i;
	if(theSelFrom.length==0)
	{
		alert('No data to Delete');
		return false;
	}

	// Find the selected Options in reverse order
	// and delete them from the 'from' Select.
	for(i=selLength-1; i>=0; i--)
	{
		if(theSelFrom.options[i].selected)
		{
			selectedText[selectedCount] = theSelFrom.options[i].text;
			selectedValues[selectedCount] = theSelFrom.options[i].value;
			deleteOption(theSelFrom, i);
			selectedCount++;
		}
	}
	for(i=selectedCount-1; i>=0; i--)
	{
		if(checkOptions(theSelTo,selectedText[i]))
			addOption(theSelTo, selectedText[i], selectedValues[i]);
	}

	return false;
}

function CancelClick()
{
  // this -1 return value means that the Cancel button was clicked
  window.returnValue = -1;
  CloseNoConfirm();
}
function GoToFirstPage(form)
{
	window.location.href="userManager.cgi?type=5";
	return true;
}

function sendValToMainPageSingle(theSelFrom)
{
	var selLength = theSelFrom.length;
	var selectedText = new Array();
	var selectedValues =new Array();
	var selectedCount = 0;
	var i;

	for(i=selLength-1; i>=0; i--)
        {
                selectedText[selectedCount] = theSelFrom.options[i].text;
                selectedValues[selectedCount] = theSelFrom.options[i].value;
                selectedCount++;
        }


	window.opener.document.forms[0].mySelectDisable.length=selectedCount;

        for(i=selectedCount-1; i>=0; i--)
        {
        	addOptionToParent(selectedText[i], selectedValues[i],i);
        }
        	CloseNoConfirm();
        return false;
}
function sendValToMainPage(theSelFrom,theSelFrom1)
{

	var selLength = theSelFrom.length;
	var selectedText = new Array();
	var selectedValues = new Array();
	var selectedCount = 0;
	var selLength1 =theSelFrom1.length;

	var i;
	var j;
	// Find the all Options in reverse order

	for(i=selLength-1; i>=0; i--)
	{
		selectedText[selectedCount] = theSelFrom.options[i].text;
		selectedValues[selectedCount] = theSelFrom.options[i].value;
		selectedCount++;
	}


       for(j=selLength1-1; j>=0; j--)
        {
                selectedText[selectedCount] = theSelFrom1.options[j].text;
                selectedValues[selectedCount] = theSelFrom1.options[j].value;
                selectedCount++;
        }





	window.opener.document.forms[0].mySelectDisable.length=selectedCount;

	for(i=selectedCount-1; i>=0; i--)
	{
		addOptionToParent(selectedText[i], selectedValues[i],i);
	}
		CloseNoConfirm();
   	return false;
}

function sendValToMainPageAppGrp(theSelFrom,theSelFrom1)
{

	var selLength = theSelFrom.length;
	var selectedText = new Array();
	var selectedValues = new Array();
	var selectedCount = 0;
	var selLength1 = theSelFrom1.length;


	var i;
	var j;

	// Find the all Options in reverse order
	for(i=selLength-1; i>=0; i--)
	{
		selectedText[selectedCount] = theSelFrom.options[i].text;
		selectedValues[selectedCount] = theSelFrom.options[i].value;
		selectedCount++;
	}

	for(j=selLength1-1; j>=0; j--)
	{
		selectedText[selectedCount] = theSelFrom1.options[j].text;
		selectedValues[selectedCount] = theSelFrom1.options[j].value;
		selectedCount++;
	}
	window.opener.document.forms[0].mySelectDisable.length=selectedCount;

	for(i=selectedCount-1; i>=0; i--)
	{
		addOptionToParent(selectedText[i], selectedValues[i],i);
	}
    CloseNoConfirm();
   return false;
}

function addOptionToParent(theText, theValue,i)
{

	window.opener.document.forms[0].mySelectDisable.options[i].text=theText;
	window.opener.document.forms[0].mySelectDisable.options[i].value=theValue;
	window.opener.document.forms[0].mySelectDisable.options[i].selected=false;

}


function goToApplicationGroup(form)
{
	//if(!verifyUserCreation(this.form))
	//	return false;
	var mySelectDisableLength=document.forms[0].mySelectDisable.length;
	if(mySelectDisableLength < 1)
	{
		alert('No User Group Selected for this user');
		return false;

	}
	var defaultUserGrp=document.forms[0].mySelectDisable.options[mySelectDisableLength-1].text;
	var str='userManager.cgi?type=3&UserGroup='+defaultUserGrp;
	newwindow=window.open(str,"Window2","width=775,height=500,titlebar=1,scrollbars=yes,resizable=1");
	//newwindow=window.open("SpecifyAccessUsrToAppGrp.xml","Window2","width=750,height=500");
    	//if(window.focus)  {newwindow.focus()}
	return true;

}


function addOptionToChild(theText, theValue,i)
{

	document.forms[0].mySelect3.options[i].text=theText;
	document.forms[0].mySelect3.options[i].value=theValue;

}

function ShowUserGroup(form)
{
	//Populating User Name in Child window and disabling it

	var userName=window.opener.document.forms[0].user_name.value;

	document.forms[0].user_name.disabled = true;
	document.forms[0].user_name.value=userName;

	//Populating select drop down
	var selLength = window.opener.document.forms[0].mySelectDisable.length;
	var selectedText = new Array();
	var selectedValues = new Array();
	var selectedCount = 0;

	var i;

	// Find the all Options in reverse order

	for(i=selLength-1; i>=0; i--)
	{
		selectedText[selectedCount] = window.opener.document.forms[0].mySelectDisable.options[i].text;
		selectedValues[selectedCount] = window.opener.document.forms[0].mySelectDisable.options[i].value;
		selectedCount++;
	}

	document.forms[0].mySelect3.length=selectedCount;

	for(i=selectedCount-1; i>=0; i--)
	{
	//Populating combo box
		addOptionToChild(selectedText[i], selectedValues[i],i);
	}
	var selIndex=document.forms[0].Index.value;
	document.forms[0].mySelect3.options[selIndex].selected=true;

}

function GetNewAppGrp(form)
{
	var SelIndex=document.forms[0].mySelect3.selectedIndex;
	var UsrGrp=document.forms[0].mySelect3.options[SelIndex].value;

	var str='userManager.cgi?type=3&UserGroup='+UsrGrp+'&SelectedIndex='+SelIndex;
	newwindow=window.open(str,"Window2","width=1000,height=500,menubar=no,resizable=yes,scrollbars=yes,toolbar=no");
}
function SubmitAppGrp(form)
{
	alert(document.forms[0].SelectedAppGrp.value);
	var str='';
	for(var i=0;i <document.forms[0].elements.length;i++)
	{
		var delimit='&';
		var seprator='=';
		var key=document.forms[0].elements[i].name;
		var val=document.forms[0].elements[i].value;
		str=str+delimit+key+seprator+val;
	}
	window.opener.document.forms[0].childForm.value=str;
	document.forms[0].type.value=4;
	CloseNoConfirm();

}


function MarkCheck(form)
{
	displayElements(this.form);
}

function verifyApplication(form)
{
	if(!verifyApplicationFirst(this.form))
		return false;
	CheckForSelectedAppGrp(this.form);
	return true;

}

function verifyDynamicPortKeyDown(form)
{
// If Enter key was pressed,  then go to the validation
        if(event.keyCode==13)
                return verifyDynamicPort(form);
        return true;
}
function verifyDynamicPort(form)
{
	var SelIndex=0;
	var port;
	var prePort;
	myString=document.forms[0].dynports.value;
	prePort=document.forms[0].regport.value;
//	myString=trim(myString);
//	prePort=trim(prePort);
	myString=replaceAll(myString," ","")
	document.forms[0].dynports.value=myString;
	do
	{
	   port=myString.substr(0,myString.indexOf(","));
	   if(!dynamicPortCheck(port,prePort))
		return false;
	   myString=myString.substr(myString.indexOf(",")+1,myString.length);
	   SelIndex=myString.indexOf(",");
	}while(parseInt(SelIndex)!=-1);
	port=myString.substr(0,myString.length);
	if(!dynamicPortCheck(port,prePort))
		return false;
}
function dynamicPortCheck(port,prePort)
{
	var SelIndex=0;
	if(port.toLowerCase()==prePort.toLowerCase())
	{
		alert("Some ports number already uses");
		return false;
	}
	if(!isOnlyNumeric(port))
	{
	     //alert("port should be number");
	     alert("Port number should be a numeric value");
	     return false;
	}
	SelIndex=parseInt(port);
	if(SelIndex<=0)
	{
	//	alert(" Port shoule be greater than 0");
		alert("Port number should be greater than 0");
		return false;
	}
	if(!isPort(port))
	 {
//		alert("port should n't greater than 65536");
		alert("Enter valid port number");
		return false;
	 }
	  return true;
}
function CheckForSelectedAppGrp(form)
{
	//if(document.forms[0].sal.checked && document.forms[0].mySelectDisable.length==0)
//	{
		//alert('No Application Group Selected');
//		return false;
//	}
	for(var i=0;i<document.forms[0].mySelectDisable.length;i++)
	{
		document.forms[0].mySelectDisable.options[i].selected=true;
	}
}

function AddApplicationGroup(form)
{
//kiran
	//if(!document.forms[0].sal.checked)
//	{
//		alert("Applications requiring Basic Authentication cannot be added to Application Groups");
//		return false;
//	}
//end
	if(!verifyApplicationFirst(this.form))
		return false;
		var str='Application.cgi?type=1';
		newwindow=window.open(str,"","width=600,height=400,titlebar=0,scrollbars=yes,resizable=0","");
	return true;
}

function USERREPORT(form)
        {
                var str='LogBrowser.cgi?type=9';
                newwindow=window.open(str,"");
                return true;
        }
function ACLREPORT(form)
        {
                var str='LogBrowser.cgi?type=11';
                newwindow=window.open(str,"");
                return true;
        }
function AppREPORT(form)
        {
                var str='LogBrowser.cgi?type=10';
                newwindow=window.open(str,"");
                return true;
        }
function OpenREPCA(form)
        {
                var str='LogBrowser.cgi?type=8';
                //newwindow=window.open(str,"");
				window.location.href=str;
                return true;
        }
function BALogREP(form)
        {
                var str='LogBrowser.cgi?type=7';
                newwindow=window.open(str,"");
                return true;
        }

function Userlog(form)
        {
                var str='LogBrowser.cgi?type=13';
                //newwindow=window.open(str,"");
				window.location.href=str;
                return true;
        }

function Epslog(form)
        {
                var str='LogBrowser.cgi?type=15';
                //newwindow=window.open(str,"");
				window.location.href=str;
                return true;
        }
function Adminlog(form)
        {
                var str='LogBrowser.cgi?type=16';
				window.location.href=str;
                return true;
        }

function BAUserlog(form)
        {
                var str='LogBrowser.cgi?type=14';
                newwindow=window.open(str,"");
                return true;
        }
function isUnderscore(c)
{
	return (c=="_")
}

function firstCharNum(e)
{
	var c=e.charAt(0);
	if(isDigit(c))
		return true;
	else
		return false;
}

function checkValid(e)
{
	var arremail= new Array(38,39,47,44,35,33,58,59,60,61,62,96,123,125,126,127,37);
	var l=e.length; var space=0;
	for(var x=0;x!=l;x++)
	{
		var c=e.charAt(x);
		if(x==0)
		{
			if(c==' ')
			space=1;
		}
		l=arremail.length;
		for(var i=0;i!=l;i++)
		{
			var d=String.fromCharCode(arremail[i]);
			if (c.match(d))
				return false;
			else if(space==1)
				return false;
		}
	}

	return true;
}


function checknotIp(e)
{
	for (i = 0; i < e.length; i++)
	{
		var c = e.charAt(i);
		if (isLetter(c))
			return true;
	}
	return false;
}

function disableremote_ves_server(form)
{
        document.forms[0].elements["remote_ves_server"].disabled=true;
        return true;
}

function disableappName(form)
{
        document.forms[0].elements["app_name"].disabled=true;
        return true;
}



function SaveExistingValues(form)
{
	document.forms[0].elements["type"].value="1";
	if(form.checkOne.checked)
	{
		document.forms[0].elements["EXE"].value="1";
	}
	else
	{
		document.forms[0].elements["EXE"].value="0";
	}

	if(form.checkALL.checked)
	{
		document.forms[0].elements["enrolleeID"].value="0";
	}
	else
	{
		document.forms[0].elements["enrolleeID"].value="1";
	}
	document.forms[0].elements["type"].value="9";
	var s=document.forms[0].elements["app_name"].value;
	if(s.length > 255) { alert('Enter value of Application name less than 255 characters'); return false;}

	if(isEmpty(s))
	{
		alert('Enter Application Name');
		return false;
	}
	if(!checkValid(s))
	{
		alert('Enter valid Application Name');
		return false;
	}
	if(!isAlphanumeric(s))
	{
		alert('Spaces and invalid characters are not allowed in Application Name');
		return false;
	}

	var ds=document.forms[0].elements["app_address"].value;
	if(isEmpty(ds))
	{
		alert('Enter Application Address ');
		return false;
	}

	if(!checknotIp(ds))
	{
		alert('Enter valid Application Address. < IP address not allowed>');
		return false;
	}
	var dp=document.forms[0].elements["app_port"].value;
	if(isEmpty(dp))
	{
		alert('Enter Application Port ');
		return false;
	}
	if(!check(dp)||(dp >= 65536))
	{
		alert('Enter valid Application Port ');
		return false;
	}

	var rs=document.forms[0].elements["remote_ves_server"].value;
	if (rs == 'N/A') rs='';
	var ty=form.Type.selectedIndex;
	if(!isEmpty(rs))
	{
			if (ty != 2) { alert(' If Remote Chained Server is entered, type should be Chained');  return false; }
	}
	else { if(ty == 2) { alert('You need to Enter Remote Chained Server for Type Chained'); return false; } }


	return true;
}




function  trim(inputString)
{
   var retValue = inputString;
   var ch = retValue.substring(0, 1);
   while (ch == " ")
    {
    // Check for spaces at the beginning of the string
      retValue = retValue.substring(1, retValue.length);
      ch = retValue.substring(0, 1);
   }
   ch = retValue.substring(retValue.length-1, retValue.length);
   while (ch == " ")
    {
      // Check for spaces at the end of the string
      retValue = retValue.substring(0, retValue.length-1);
      ch = retValue.substring(retValue.length-1, retValue.length);
   }
   while (retValue.indexOf("  ") != -1)
    {
      // Note that there are two spacesin the string - look for multiple spaces within the string
      retValue = retValue.substring(0, retValue.indexOf("  ")) +retValue.substring(retValue.indexOf("  ")+1, retValue.length);

   }
   return retValue; // Return the trimmed string back to the user
} // Ends the "trim" function



function replaceAll(inputString,OldChar,NewChar)
{
  newString=new String(inputString)
  while(newString.indexOf(" ") != -1)
  {
	newString=newString.replace(OldChar,NewChar)
   }
   return (newString)
}

function replaceAllAmpersand(inputString,OldChar,NewChar)
{
  newString=new String(inputString)
  while(newString.indexOf("&") != -1)
  {
	newString=newString.replace(OldChar,NewChar)
   }
   return (newString)
}

function replaceAllNewLine(s)
{
		var str=new Array();
		for (var i = 0, j = 0; i <= s.length; i++)
		{
			var c = s.charAt(i);

			if((c!="\n") && (c!="\r"))
			{
				str[j]=c;
				j++;
			}
		}
		var newStr;
		newStr=str.join("");

   return (newStr);
}

function checkClusterIPs(ipaddr)
{
      var parts = ipaddr.split(",");
      for (var i=0; i<parts.length; i++)
      {
              if(!checkValid(parts[i]))
              {
                      alert('Enter valid Application Address');
                      return false;
              }
              if(!checkServerDomainName(parts[i]))
              {
                      alert('Enter valid  Application  Address');
                      return false;
              }
      }
      return true;
}

function verifyApplicationFirst(form)
{
	var s=document.forms[0].elements["app_name"].value;
	var cs='<Type in Application Name>';
	if(s==cs)
	{
		alert('Enter Application Name');
		return false;
	}

//	s=trim(s);
	document.forms[0].elements["app_name"].value=s;
	var ds=document.forms[0].elements["app_address"].value;
	var dp=document.forms[0].elements["app_port"].value;
	var rs=document.forms[0].elements["remote_ves_server"].value;
	var ur=document.forms[0].elements["app_url"].value;
	var appDesc=document.forms[0].elements["app_desc"].value;
	var appType=document.forms[0].elements["app_type"].value;
	//var ds2=document.forms[0].elements["app_address2"].value;
	//var dp2=document.forms[0].elements["app_port2"].value;
	//var ap=document.forms[0].elements["app_path"].value;

	appUrl=new String(ur);
	mystring=new String(s);
	if (mystring.indexOf("DYNAMIC") == 0)
	{
		alert('Application name should not start with the word DYNAMIC');
		return false;
	}
	if (mystring.indexOf(".") >= 0)
	{
		alert('Application name should not contain "."');
		return false;
	}

	if(document.forms[0].appCompression.checked)
		document.forms[0].elements["COMPRESSION"].value="1";
	else
		document.forms[0].elements["COMPRESSION"].value="0";

	if(document.forms[0].check.checked)
		document.forms[0].elements["DYNAMIC"].value="1";
	else
		document.forms[0].elements["DYNAMIC"].value="0";

	if(document.forms[0].check1.checked)
		document.forms[0].elements["DYNAMIC1"].value="1";
	else
		document.forms[0].elements["DYNAMIC1"].value="0";

	if(s.length > 50)
	{
		alert('Enter value of Application name less than or equal to 50 characters');
		return false;
	}

	if(isEmpty(s))
	{
		alert('Enter Application Name');
		return false;
	}

	if(!checkValid(s) )
	{
		alert('Enter valid Application Name');
		return false;
	}
	if(firstCharNum(s))
	{
	//	alert('First Char of Application Name should not be numeric');
		alert('First character of the application name should not be a numeric');
		return false;
	}
	if(!isAlphanumericWithSpace(s))
	{
		alert('Invalid characters are not allowed in Application Name');
		return false;
	}
	var lowerCase = s.toLowerCase();
	if(lowerCase.match("_smtp"))
	{
		alert('_smtp or _SMTP is a key word  and cannot be used in Application Name');
		return false;
	}
	if( !checkValid(appDesc) )
	{
		alert('Enter valid Application Description');
		return  false;
	}

	/*if( document.forms[0].app_path.disabled==true)
         {
		if(isEmpty(ds) )
		{
			alert('Enter Application Address ');
			return false;
		}

         }*/
	/*if( isEmpty(ap) &&  document.forms[0].app_path.disabled==false)
	{
		alert('Application Path can not be Empty');
		return false;
	}*/

	//if(isEmpty(ds) || (appType==7 && isEmpty(ds2))  )
	/*if(document.forms[0].app_iscluster.checked)//LBM
        {
	    if( document.forms[0].app_path.disabled==true){
		if(dp == 21 || appType == 3)
		{
			alert('FTP application cannot be clustered');
			return false;
		}
                if(!checkClusterIPs(ds))
                        return false;
		if(appType==7   && !checkClusterIPs(ds2))
		        return false;
            }
        }
        else
        {
	    if( document.forms[0].app_path.disabled==true){
		if(!checkValid(ds) )
		{
			alert('Enter valid Application Address');
			return false;
		}

		if(!checkServerDomainName(ds) || (appType==7   && !checkServerDomainName(ds2)))
		{
			alert('Enter valid  Application  Address');
			return false;
		}
             }
	}

	if( document.forms[0].app_path.disabled==true){
	if(isEmpty(dp))
	{
		alert('Enter Application Port ');
		return false;
	}
	if(!check(dp)||(dp >= 65536))
	{
		alert('Enter valid Application Port ');
		return false;
	}
      }*/
	if(!check(dp)||(dp >= 65536))
	{
		alert('Enter valid Application Port ');
		return false;
	}

	//if(appType  == 7 )
	//if(!check(dp2)||(dp2 >= 65536))
	//{
	//	alert('Enter valid Application Port');
	//	return false;
	//}

	if (rs == null || rs == 'N/A')
		rs='';

	if(document.forms[0].check_chained.checked)

	{
		if(isEmpty(rs))
		{
			alert('If chained application, Remote Chained Server Name should not be empty');
			document.forms[0].remote_ves_server.focus();
			return false;
		}
		if(!isServerName(rs))
		{
			alert ('Please enter valid Remote Chained Server Name.');
			return false;
		}
		document.forms[0].elements["Type"].value=2;

		var s2=document.forms[0].elements["app_name"].value;
		s2=replaceAll(s2," ","")
		document.forms[0].elements["app_name"].value=s2;
		return true;
	}
	else
	{
		document.forms[0].elements["Type"].value=0;
	}
  if ( isValidRemoteVes(rs) == false 	|| rs.indexOf("&")>=0)
  {
      alert('Spaces and invalid character not allowed for Remote Ves Server');
			return false;
  }

  if(appUrl.indexOf("%") != -1)
  {
      alert("Application URL should not contain %");
      return false;
  }

 /* if(appUrl.indexOf("/")==0)
  {
      alert("Application URL should not begin with /");
      return false;
  }

  if(!checkValid(appUrl))
  {
	alert("Please enter valid Application URL.");
	return false;
	}*/

	var s1=document.forms[0].elements["app_name"].value;
	s1=replaceAll(s1," ","")
	document.forms[0].elements["app_name"].value=s1;
	return true;
}

function UserButton(form)
{
	document.forms[0].elements["type"].value="5";
	var s=document.forms[0].elements["app_name"].value;

	if(isEmpty(s))
	{
		alert('Enter Application Name');
		return false;
	}

	if(!checkValid(s))
	{
		alert('Enter valid Application Name');
		return false;
	}
	if(!isAlphanumeric(s))
	{
		alert('Spaces and invalid characters are not allowed in Application Name');
		return false;
	}

	var ds=document.forms[0].elements["app_address"].value;
	if(isEmpty(ds))
	{
		alert('Enter Application Address ');
		return false;
	}

	if(!checkValid(ds))
	{
		alert('Enter valid Application Address');
		return false;
	}

	var dp=document.forms[0].elements["app_port"].value;
	if(isEmpty(dp))
	{
		alert('Enter Application Port ');
		return false;
	}
	if(!check(dp)||(dp >= 65536))
	{
		alert('Enter valid Application Port ');
		return false;
	}
	return true;
}


function ModifyApplication(form)
{

	 if(document.forms[0].elements.length < 4)
		{
			alert('No Record to Modify');
			return false;
		}
	document.forms[0].elements["type"].value="8";

	if(form.check.length > 0)
	{ var j=0;
		for(var i = 0; i < form.check.length;i++)
		{
			if(form.check[i].checked)
			{ j++;
			}
		}
		if(j > 1)
		{
			alert('Please select only one Application for Modification');
			return false;
		}

		if( j==0)
		{
			alert('Please select Application for Modification');
			return false;
		}

		else
		{
			return true;
		}

	}
	else
	{
		if(form.check.checked)
		{
			return true;
		}
	}
	alert('Please select Application for Modification');
	return false;

}


function DeleteApplication(form)
{
	if(document.forms[0].elements.length < 4)
	{
		alert('No Record to Delete');
		return false;
	}
	if(form.check.length > 0)
	{
		for(var i = 0; i < form.check.length;i++)
		{
			if(form.check[i].checked)
			{
				document.forms[0].elements["type"].value="2";
				return true;
			}
		}
		alert('Please select any Application for deletion');
		return false;
	}
	else
	{
		if(form.check.checked)
		{
				document.forms[0].elements["type"].value="2";
				return true;
		}
		alert('Please select any Application');
		return false;
	}
	document.forms[0].elements["type"].value="2";
	return true;
}

function EnterApplication(form)
{
	if(form.check.length > 0)
	{
		for(var i = 0; i < form.check.length;i++)
		{
			if(form.check[i].checked)
			{
				return true;
			}
		}
		alert('Please select any user');
		return false;
	}
	else
	{
		if(form.check.checked)
			return true;
		alert('Please select any user');
		return false;
	}
	document.forms[0].elements["type"].value="1";
	return true;
}



///Application Group Related Functions

function verifyAppGrp(form)
{
        var e=form.elements["ag_name"].value;
	e=replaceAll(e," ","")
//	e=trim(e);
        form.elements["ag_name"].value=e;

        if(!(e))
        {
                alert ( 'Please enter Application Group Name ');
                return false;
        }
	if(e.length > 50 )
	{
		alert('Enter value of Application Group name less than or equal to 50 characters');
		return false;
	}
	if(!checkValid(e))
	{
		alert('Enter valid Application Group Name');
		return false;
	}
	if(!isAlphanumericWithSpace(e))
	{
        	alert('Spaces and invalid character are not allowed in Application Group Name');
		return false;
	}
        return true;
}

function verifyAccTime(form)
{
        var e=form.elements["at_name"].value;
	e=replaceAll(e," ","")
	//e=trim(e);
        form.elements["at_name"].value=e;
        if(!(e))
        {
                alert ( 'Please enter Access Filter Name ');
                return false;
        }
	if(e.length > 50 )
	{
		alert('Enter value of Access Filter name less than or equal to 50 characters');
		return false;
	}
	if(!checkValid(e))
	{
		alert('Enter valid Access Filter Name');
		return false;
	}
	if(!isAlphanumericWithSpace(e))
	{
		alert('Spaces and invalid characters not allowed for Access Filter Name');
		return false;
	}


        var tz=form.at_timezone.selectedIndex;

        var sh=form.at_starthourservice.selectedIndex;

        var eh=form.at_endhourservice.selectedIndex;
        var sm=form.at_startminservice.selectedIndex;

        var em=form.at_endminservice.selectedIndex;

        if ( e )
        {
         if ( tz == 0 )
         {
          alert('Select Time Zone ');
          return false;
         }

        }

        if( tz != 0 )
        {
         if( (eh==0) &&  (sh==0) && (em == 0) && (sm == 0) )
         {
          alert('Select Start Time and End Time ');
          return false;
         }
        }
        if(eh < sh)
        { alert('End Time Should be greater than Start Time');
          return false;
        }
        if((eh == sh) && (sm > em))
        { alert('End Time Should be greater than Start Time');
          return false;
        }

        if((eh == sh) && (sm > em))
        { alert('End Time Should be greater than Start Time');
          return false;
        }
        if( (eh!=0) || (sh!=0) )
        {
         if(tz==0)
         { alert('Select Time Zone');
         return false;
         }
        }
	if((eh == sh) && (em == sm)) {
          alert('Start Time and End Time cannot be the same');
          return false;
        }
         return true;
}

function verifyModAccTime(form)
{
        var tz=form.at_timezone.value;

        var sh=parseInt(form.at_starthourservice.value, 10);

        var eh=parseInt(form.at_endhourservice.value, 10);
        var sm=parseInt(form.at_startminservice.value, 10);

        var em=parseInt(form.at_endminservice.value, 10);

        if( tz != 0 )
        {
         if( (eh==0) &&  (sh==0) && (em == 0) && (sm == 0))
         {
          alert('Select Start Time and End Time ');
          return false;
         }
        }
        if(eh < sh)
        { alert('End Time Should be greater than Start Time');
          return false;
        }
        if((eh == sh) && (sm > em))
        { alert('End Time Should be greater than Start Time');
          return false;
        }

        if((eh == sh) && (sm > em))
        { alert('End Time Should be greater than Start Time');
          return false;
        }
        if( (eh!=0) || (sh!=0) )
        {
         if(tz==0)
         { alert('Select Time Zone');
         return false;
         }
        }
	      if((eh == sh) && (em == sm))
        {
          alert('Start Time and End Time cannot be the same');
          return false;
        }
        return true;
}

function verifyUserGrpManager(form)
{
        var e=form.elements["usergrp_name"].value;
	e=replaceAll(e," ","")
	//e=trim(e)
        form.elements["usergrp_name"].value=e;

        var e1=form.elements["user_desc"].value;
        if(!(e))
        {
                alert ( 'Enter User Group Name ');
                return false;
        }
	if(e.length >  50 )
	{
		alert('Enter value of User Group name less than or equal to 50 characters');
		return false;
	}
	if(e1.length > 255)
	{
		alert('Enter User Group Description less than 200 characters');
		return false;
	}
	if(!IsText(e1,1))
	{
		alert('Enter valid Description');
		return false;
	}
	if(!checkValid(e))
	{
		alert('Enter valid User Group Name');
		return false;
	}
	if(!isAlphanumericWithSpace(e))
	{
        	alert('Spaces and special characters are not allowed for User Group Name');
		return false;
	}
		//if(document.forms[0].ldapcheck.checked==true)
		//document.forms[0].type.value=7;
        return true;
}

function DeleteUser(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
				if (!confirm("Are you sure you want to delete these user(s)?"))
				{
				return false;
				}
  				document.forms[1].type.value=7;
				return true;
			}
		}
		alert('Please select any User for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
			if (!confirm("Are you sure you want to delete this user?"))
			{
			return false;
			}
  			document.forms[1].type.value=7;
			return true;
		}
		alert('Please select any User');
		return false;
	}
  	document.forms[1].type.value=7;
	return true;
}

function DeleteLdapUser(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
				if (!confirm("Are you sure you want to delete these user(s)?"))
				{
				return false;
				}
  				document.forms[1].type.value=27;
				return true;
			}
		}
		alert('Please select any User for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
			if (!confirm("Are you sure you want to delete this user?"))
			{
			return false;
			}
  			document.forms[1].type.value=27;
			return true;
		}
		alert('Please select any User');
		return false;
	}
  	document.forms[1].type.value=27;
	return true;
}


function ModifyUser(form)
{
  	document.forms[1].type.value=8;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one User for Modification');
			return false;
		}

		if( j==0)
		{
			alert('Please select User for Modification');
			return false;
		}
		else
			return true;

	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select User for Modification');
	return false;
}

function ModifyLdapUser(form)
{
  	document.forms[1].type.value=22;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one User for Modification');
			return false;
		}

		if( j==0)
		{
			alert('Please select User for Modification');
			return false;
		}
		else
			return true;

	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select User for Modification');
	return false;
}

function verifySelectedAppGrps(form)
{

	document.forms[1].SelectedAuthServer.value = document.forms[0].auth_types.value;

    var displayText="";

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
  		    if(document.forms[1].check[i].checked)
                    { // the app grp is selected...
                        if (j != 0) displayText = displayText+",";
                        var gIndex = document.forms[1].GrpName1[i].selectedIndex;
                        var fIndex = document.forms[1].filters[i].selectedIndex;
			j++;
                    }
		}
		if(j >= 1)
		{
			return true;
		}

		if( j==0)
		{
			alert('Please select Application Group');
           //document.forms[0].sel_app_grps.value = "";
			return false;
		}
		else
		{
			return true;
		}

	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select Application Group ');
        //document.forms[1].sel_app_grps.value = "";
	return false;
}

function ModifyUserGroupToUsers(form)
{
//	var enrolleeID=document.forms[0].enrolleeID.value;
	var registerID=document.forms[0].registerID.value;
	var r=document.forms[0].user_role.value;
	var uid=document.forms[0].user_id.value;


  	if (r=='Low Security User')
  	{
   	var registerID=document.forms[0].registerID.value;
     // var str='userManager.cgi?type=12&enrolleeID='+enrolleeID;
      var str='userManager.cgi?type=12&registerID='+registerID;
  // 	var enrolleeID=document.forms[0].enrolleeID.value;
   //   var str='userManager.cgi?type=12&enrolleeID='+enrolleeID;
			newwin	 = window.open(str,"","width=570,height=280,titlebar=0,scrollbars=yes,resizable=no","");
	}
	else if(r!=='Low Security User')
	{
		if(uid=='Not Specified')
		{
		//	var str='userManager.cgi?type=9&enrolleeID='+enrolleeID;
			var str='userManager.cgi?type=9&registerID='+registerID;
			newwin	 = window.open(str,"","width=570,height=280,titlebar=0,scrollbars=yes,resizable=no","");
		}
		else
		{
		//	var str='userManager.cgi?type=15&enrolleeID='+enrolleeID;
			var str='userManager.cgi?type=15&registerID='+registerID;
			newwin	 = window.open(str,"","width=570,height=280,titlebar=0,scrollbars=yes,resizable=no","");
		}
	}
	return true;
}

function ModifyLdapUserGroupToUsers(form)
{

	var uid=document.forms[0].user_id.value;
	var str='userManager.cgi?type=29&user_id=' + uid;

           var left = Math.floor( (screen.availWidth - screen.availWidth) / 4);
           var top = Math.floor( (screen.availHeight - screen.availHeight) / 4);
      var width=(screen.availWidth)-320;
      var height=(screen.availHeight)-320;
      var winParms = "top=" + top + ",left=" + left + ",height=" + height + ",width=" + width;
           var parms="menubar=no,resizable=yes,titlebar=yes,scrollbars=yes,toolbar=no";
           if (parms)
           winParms += "," + parms;
           newwindow=window.open(str,"",winParms);
      return true;
}
function verifyModifyUser(form)
{
	var n=document.forms[0].user_name.value;
	var e=document.forms[0].user_emailId.value;
	var role=document.forms[0].user_role.value;
    var w=document.forms[0].user_newpass.value;

	var day=document.forms[0].dd.value;
	var month=document.forms[0].mm.value;
	var year=document.forms[0].yy.value;

	var dayNow=document.forms[0].curDay.value;
	var monthNow=document.forms[0].curMon.value;
	var yearNow=document.forms[0].curYear.value;

	if((isEmpty(e))||(isEmpty(n)))
	{
		alert ( 'Empty fields not allowed  ');
		return false;
	}
	if(!checkmail(n))
	{
		alert ( 'Please enter valid user name ');
		return false;
	}
	if(n.length >256)
	{
		alert ( 'Please enter valid user name ');
		return false;
	}
	if(!emailcheck(e))
		return false;
	if(!checkmail(e))
	{
		alert ( 'Please enter correct Email ID');
		return false;
	}
	if (document.forms[0].user_checknpass.checked ==true)
	{
       	if(!(document.forms[0].user_newpass.value==document.forms[0].user_conpass.value))
		{
			alert ( 'Passwords do not match');
			return false;
		}

		if(!verifyPassword(w))
			return false;
	}

	if((role=="Low Security User") || (role=="High Security User"))
	{
		if(day != 0)
		{
			if(month == 0)
			{
				alert('Please select Month for Account Expiry');
				return false;
			}
			if(year == 0)
			{
				alert('Please select Year for Account Expiry');
				return false;
			}

			if(validateDate(day, month, year) == false)
			{
				return false;
			}

			if(validateCurrentDate(day, month, year ,dayNow, monthNow, yearNow) == false)
			{
				return false;
			}
		}
	}

	for(var i=0;i<document.forms[0].mySelectDisable.length;i++)
	{
		document.forms[0].mySelectDisable.options[i].selected=true;
	}
	document.forms[0].type.value=10;
	return true;
}

function verifyModifyLdapUser(form)
{
	var n=document.forms[0].user_name.value;
	var e=document.forms[0].user_emailId.value;
	if((isEmpty(e))||(isEmpty(n)))
	{
		alert ( 'Empty fields not allowed  ');
		return false;
	}
	if(!checkmail(n))
	{
		alert ( 'Please enter valid user name ');
		return false;
	}
	if(n.length >256)
	{
		alert ( 'Please enter valid user name ');
		return false;
	}
	if(!emailcheck(e))
		return false;
	if(!checkmail(e))
	{
		alert ( 'Please enter correct Email ID');
		return false;
	}
       	if(!(document.forms[0].user_newpass.value==document.forms[0].user_conpass.value))
	{
		alert ( 'Passwords do not match');
		return false;
	}
	for(var i=0;i<document.forms[0].mySelectDisable.length;i++)
	{
		document.forms[0].mySelectDisable.options[i].selected=true;
	}
	document.forms[0].type.value=23;
	return true;
}
function getApp(form)
{

	var e1=trim(document.forms[0].EName.value);
	form.elements["EName"].value=e1;
	var len=e1.length;
	if(len > 255)
	{
		alert('Field value length should be less than 256 characters');
		return false;
	}
	if(isEmpty(e1))
	{
		 alert("Please enter search criteria");
		return false;
	}
	document.forms[0].type.value=4;
	return true;
}

function NextApp(form)
{
	var minlimit=parseInt(document.forms[1].MIN_LIMIT.value,10);
 	var maxlimit=parseInt(document.forms[1].MAX_LIMIT.value,10);
 	var maxrows=parseInt(document.forms[1].rows.value,10);
 	var trecords=parseInt(document.forms[1].trecords.value,10);
 	var maxrecord=parseInt(document.forms[1].records.value,10);

	var sumtotal=minlimit+maxlimit;
 	var totallimit=parseInt(sumtotal,10);
	var remtotal=maxrows-totallimit;
 	var rem=parseInt(remtotal,10);

	if(trecords==maxrecord)
		return false;
	if(maxrecord <pagelimit)
		return false;
	if(maxrecord ==maxrows)
		return false;
 	if(rem <= 0)
		return false;
	document.forms[1].MIN_LIMIT.value=minlimit+pagelimit;
	document.forms[1].MAX_LIMIT.value=pagelimit;

  	document.forms[1].type.value=4;

	document.forms[1].submit();
	return true;
}

function PreviousApp(form)
{
	var minlimit=parseInt(document.forms[1].MIN_LIMIT.value,10);
 	var maxlimit=parseInt(document.forms[1].MAX_LIMIT.value,10);
 	var maxrows=parseInt(document.forms[1].rows.value,10);
 	if(minlimit==0 )
		   	return false;
	document.forms[1].MIN_LIMIT.value=minlimit-pagelimit;
	document.forms[1].MAX_LIMIT.value=pagelimit;
  	document.forms[1].type.value=4;
	document.forms[1].submit();
	return true;
}

function DeleteZone(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
                         if (!confirm("Are you sure you want to delete these Profile(s)?"))
                         {
                               return false;
                         }
  				document.forms[1].type.value=11;
				return true;
			}
		}
		alert('Please select any Profile for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
                  if (!confirm("Are you sure you want to delete this Profile?"))
                  {
                     return false;
                  }
  			document.forms[1].type.value=11;
			return true;
		}
		alert('Please select any Profile');
		return false;
	}
  	document.forms[1].type.value=11;
	return true;
}

function DeleteAuthServer(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
                         if (!confirm("Are you sure you want to delete these Authentication Server(s)?"))
                         {
                               return false;
                         }
  				document.forms[1].type.value=34;
				return true;
			}
		}
		alert('Please select any Authentication Server for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
                  if (!confirm("Are you sure you want to delete this Authentication Server?"))
                  {
                     return false;
                  }
  			document.forms[1].type.value=34;
			return true;
		}
		alert('Please select any Authentication Server');
		return false;
	}
  	document.forms[1].type.value=34;
	return true;
}

function DelRoute(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
                if (!confirm("Are you sure you want to delete these Routes(s)?"))
                {
                   return false;
                }
  				document.forms[1].type.value=21;
				return true;
			}
		}
		alert('Please select any Route for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
            if (!confirm("Are you sure you want to delete this Route?"))
			{
				return false;
			}
  			document.forms[1].type.value=21;
			return true;
		}
		alert('Please select any Route');
		return false;
	}
  	document.forms[1].type.value=21;
	return true;
}

function DeletePolicy(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
                         if (!confirm("Are you sure you want to delete these Policies(s)?"))
                         {
                               return false;
                         }
  				document.forms[1].type.value=34;
				return true;
			}
		}
		alert('Please select any Policy for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
                  if (!confirm("Are you sure you want to delete this Policy?"))
                  {
                     return false;
                  }
  			document.forms[1].type.value=34;
			return true;
		}
		alert('Please select any Policy');
		return false;
	}
  	document.forms[1].type.value=34;
	return true;
}



function DeleteZone(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
                         if (!confirm("Are you sure you want to delete these Profile(s)?"))
                         {
                               return false;
                         }
  				document.forms[1].type.value=11;
				return true;
			}
		}
		alert('Please select any Profile for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
                  if (!confirm("Are you sure you want to delete this Profile?"))
                  {
                     return false;
                  }
  			document.forms[1].type.value=11;
			return true;
		}
		alert('Please select any Profile');
		return false;
	}
  	document.forms[1].type.value=11;
	return true;
}


function DeleteApp(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
                         if (!confirm("Are you sure you want to delete these Application(s)?"))
                         {
                               return false;
                         }
  				document.forms[1].type.value=5;
				return true;
			}
		}
		alert('Please select any Application for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
                  if (!confirm("Are you sure you want to delete this Application?"))
                  {
                     return false;
                  }
  			document.forms[1].type.value=5;
			return true;
		}
		alert('Please select any Application');
		return false;
	}
  	document.forms[1].type.value=5;
	return true;
}

function ModifyZone(form)
{
  	document.forms[1].type.value=7;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one Profile for Modification');
			return false;
		}

		if( j==0)
		{
			alert('Please select a Profile for Modification');
			return false;
		}
		else
			return true;
	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select a Profile for Modification');
	return false;
}

function ModifyPolicy(form)
{
  	document.forms[1].type.value=32;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one Policy for Modification');
			return false;
		}

		if( j==0)
		{
			alert('Please select a Policy for Modification');
			return false;
		}
		else
			return true;
	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select a Policy for Modification');
	return false;
}




function ModifyAuthServer(form)
{
  	document.forms[1].type.value=32;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one Authentication Server for Modification');
			return false;
		}

		if( j==0)
		{
			alert('Please select an Authentication Server for Modification');
			return false;
		}
		else
			return true;
	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select an Authentication Server for Modification');
	return false;
}

function ModifyApp(form)
{
  	document.forms[1].type.value=6;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one Application for Modification');
			return false;
		}

		if( j==0)
		{
			alert('Please select Application for Modification');
			return false;
		}
		else
			return true;
	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select Application for Modification');
	return false;
}
function ModifyApplicationGrpToApps(form)
{
	var pass;
	var str;
	var appName=document.forms[0].appName.value;
	var remoteVes=document.forms[0].remote_ves_server.value;
// kiran
        //if(!document.forms[0].sal.checked)
       // {
	//	alert("Applications requiring Basic Authentication cannot be added to Application Groups");
     //           return false
       // }
//end
	if (remoteVes == 'N/A')
	{
		str='Application.cgi?type=7&appName='+appName;
	}
	else
	{
		pass=appName+'.'+remoteVes;
		str='Application.cgi?type=7&appName='+pass;
	}

	newwindow=window.open(str,"","width=570,height=380,titlebar=0,scrollbars=yes,resizable=no","");
    //if(window.focus)  {newwindow.focus()}
	return true;
}

function getAuthType(form)
{
	if(document.forms[0].sal.checked)
		document.forms[0].oldAuth.value="1";
        else
		document.forms[0].oldAuth.value="0";
	document.forms[0].appAdd.focus();
        return true;
}

function verifyModifyApplication(form) //LBM
{
	document.forms[0].type.value=8;
	for(var i=0;i<document.forms[0].mySelectDisable.length;i++)
	{
		document.forms[0].mySelectDisable.options[i].selected=true;
	}
	var appType=document.forms[0].elements["appType"].value;
	var ds=document.forms[0].elements["appAdd"].value;
	var dp=document.forms[0].elements["appPort"].value;
	var appDesc=document.forms[0].elements["appDesc"].value;
	//var ap=document.forms[0].elements["app_path"].value;

	if(appType==7)
	{
		var ds2=document.forms[0].elements["appAdd2"].value;
		var dp2=document.forms[0].elements["appPort2"].value;
	}
	//if(appType==6)
	var ur=document.forms[0].elements["appUrl"].value;
	appUrl=new String(ur);

	if(document.forms[0].appCompression.checked)
		document.forms[0].elements["COMPRESSION"].value="1";
	else
		document.forms[0].elements["COMPRESSION"].value="0";

	if(document.forms[0].check.checked)
		document.forms[0].elements["DYNAMIC"].value="1";
	else
		document.forms[0].elements["DYNAMIC"].value="0";

	if(document.forms[0].check1.checked)
		document.forms[0].elements["DYNAMIC1"].value="1";
	else
		document.forms[0].elements["DYNAMIC1"].value="0";

	if( document.forms[0].app_path.disabled==true){
		if(isEmpty(ds) 	|| (appType  == 7 && isEmpty(ds2)))
		{
			alert('Enter Application Address ');
			return false;
		}
           }

	if(document.forms[0].appIscluster.checked)//LBM
        {

		 if(dp == 21 || appType == 3)
		  {
		       alert('FTP application cannot be clustered');
		        return false;
		  }

                if(!checkClusterIPs(ds))
                        return false;
		if(appType==7   && !checkClusterIPs(ds2))
		        return false;
			}
        else

        {

	if( document.forms[0].app_path.disabled==true){
		if(!checkValid(ds) || ( appType==7	&& !checkValid(ds2)))
		{
			alert('Enter valid Application Address');
			return false;
		}

		if(!checkServerDomainName(ds)  ||  (appType==7	&& !checkServerDomainName(ds2)))
		{
			alert('Enter valid  Application  Address');
			return false;
		}
           }

	}
	/*if( isEmpty(ap) &&  document.forms[0].app_path.disabled==false)
	{
		alert('Application Path can not be Empty');
		return false;
	}*/

	if( document.forms[0].app_path.disabled==true){
		if(isEmpty(dp)  	|| (appType==7 && isEmpty(dp2)))
		{
			alert('Enter Application Port ');
			return false;
		}

		if(!isNum(dp)||(dp >= 65536))
		{
			alert('Enter valid Application Port ');
			return false;
		}
         }

	if(appType==7)
	{
		if(!isNum(dp2)||(dp2 >= 65536))
		{
			alert('Enter valid Application Port ');
			return false;
		}
	}

	var rs=document.forms[0].elements["remote_ves_server"].value;
    remote_ves_server=new String(rs);
	if (rs == 'N/A')
		rs='';


	if(!checkValid(appDesc)){
		alert('Enter valid Application Description');
		return false;
	}

  if(appUrl.indexOf("%") != -1)
  {
      alert("Application URL should not contain %");
      return false;
  }
	return true;
}

function verifyclientTimeKeyDown(form)
{
// If Enter key was pressed,  then go to the validation
	if(event.keyCode==13)
		return verifyclientTime(form);
	return true;
}


function verifypasswordexpKeyDown(form)
{
// If Enter key was pressed,  then go to the validation
	if(event.keyCode==13)
		return verifyPasswordExpiry(form);
	return true;
}

function verifyclientTime(form)
{
	var e=document.forms[0].timeout.value ;
	document.forms[0].type.value=1;
    if(e == '')
    {
    	alert('Empty fields are not allowed .');
       	return false;
    }
    if(isEmpty(e))
    {
    	alert ('Time field is empty');
        return false;
    }
   if(e == '0')
    {
//	alert('Client Logout time should be Minimum 1 minutes and Maximum 60 minutes');
	alert('Client logout time should be minimum 1 minute and maximum 3600 minutes');
       	return false;
    }

   if(!check(e))
    {
    	//alert ( 'Time Field should have Numeric Value');
	alert('Client logout time should be minimum 1 minute and maximum 3600 minutes');
       	return false;
     }
	var num=parseInt(e,10);
	var maxLength=3600;
	var minLength=0;
	if((num  > parseInt( maxLength,10))||(num  < parseInt( minLength,10)))
	{
	  //  	alert('Client Logout time should be Minimum 1 minutes and Maximum '+maxLength+' minutes');
		alert('Client logout time should be minimum 1 minute and maximum 3600 minutes');
       		return false;
	}
    return true;
}


function verifyPasswordExpiry(form)
{
	var e=document.forms[0].exptime.value ;
	document.forms[0].type.value=1;
    if(e == '')
    {
    	alert('Empty fields are not allowed .');
       	return false;
    }
    if(isEmpty(e))
    {
    	alert ('Time field is empty');
        return false;
    }
   /*if(e == '0')
    {
//	alert('Password expiry time should be Minimum 1 day and Maximum 120 days');
	alert('Password expiry time should be minimum 1 day and maximum 120 days');
       	return false;
    }*/

   /*if(!check(e))
    {
    	//alert ( 'Time Field should have Numeric Value');
	alert('Password expiry time should be minimum 1 day and maximum 120 days');
       	return false;
     }*/
	var num=parseInt(e,10);
	var maxLength=120;
	var minLength=0;
	if((num  > parseInt( maxLength,10))||(num  < parseInt( minLength,10)))
	{
	  //  	alert('Client Logout time should be Minimum 1 minutes and Maximum '+maxLength+' minutes');
		alert('Password expiry time should be minimum 1 day and maximum 120 days');
       		return false;
	}
    return true;
}


function disableit(form)
{
 	document.forms[0].dbUser.disabled=true;
 	return true;
}

function DBSelected(form)
{
	document.forms[0].dbUser.disable=true;
	var e=document.forms[0].database.selectedIndex;
	if(e==2)
		document.forms[0].dbUser.value=document.forms[0].dbUser1.value;
	else if(e==1)
		document.forms[0].dbUser.value=document.forms[0].dbUser2.value;
	else if(e==0)
		document.forms[0].dbUser.value='';
	return true;
}


function verifyDBPassword(form)
{
	var minLength = 6;
	var maxLength=16 ;
	var du=form.dbUser.value;
	var op=form.oldPass.value;
	var np=form.newPass.value;
	var rp=form.renewPass.value;
	var e=form.database.selectedIndex;

	if(e==0)
	{
		alert('Select any database');
		return false;
	}

	if(isEmpty(du))
	{
		alert('Empty user name not allowed.');
		return false;
	}

	if(isEmpty(op))
	{
		alert('Empty password not allowed.');
		return false;
	}
	var len1= op.length;

	/*if(len1 < minLength || len1 > maxLength )
	{
		alert('Old Password must be maximum ' + maxLength + ' and minimum '+ minLength +' characters long.');
		return false;
	} */
	if(!isAlphanumeric(op))
	{
		alert('Spaces and invalid characters are not allowed in password.');
		return false;
	}
	var len1= np.length;
	if(isEmpty(np))
	{
		alert('Empty password not allowed.');
		return false;
	}
	/*if(len1 < minLength || len1 > maxLength )
	{
		alert('New Password must be maximum ' + maxLength + ' and minimum '+ minLength +' characters long.');
		return false;
	}*/
	if(!isAlphanumeric(np))
	{
		alert('Spaces and invalid characters are not allowed in password.');
		return false;
	}

	var len1= rp.length;
	if(isEmpty(rp))
	{
		alert('Empty password not allowed.');
		return false;
	}
	/*if(len1 < minLength || len1 > maxLength )
	{
		alert('Re-entered Password must be maximum ' + maxLength + ' and minimum '+ minLength +' characters long.');
		return false;
	}*/
	if(!isAlphanumeric(rp))
	{
		alert('Spaces and invalid characters are not allowed in password.');
		return false;
	}
	if(np==op)
	{
		alert('New Password and Old Password are matching.');
		return false;
	}

	if(rp!=np)
	{
		alert('New Password and Re Entered Password are not matching.');
		return false;
	}
	return true;

}
function checklen(s)
{
	var namel = parseInt(s.length);
	if(namel > 250)
	return true;
}
function SizeofFile(form)
{
	var name=document.forms[0].RegFile.value;
	var len=document.forms[0].RegFile.length;
	var SlashIdx = parseInt(name.lastIndexOf('.'));
	var name1;
	name1=name.substring(SlashIdx+1);
	if((name1=='as')||(name1=='xml') ||(name1=='XML'))
	    return true;
	alert(' Not a valid Seal Extension');
	return false;
}

function verifyRegenerationSeal(form)
{
	var e1=document.forms[0].EName.value ;
	var e=document.forms[0].EnrolleeID.value;

	 if(!checkBlankAndWild(e1))
	{
		 alert ('Please enter valid Name');
		 return false;
	}
	 if(checklen(e1))
	{
		 alert ('Please enter valid Name');
		 return false;
	}
	if(e1 == '')
	{
		 alert('Empty fields are not allowed .');
		 return false;
	}

	if(e == '')
	{
		 alert('Empty fields are not allowed .');
		 return false;
	}
	if(isEmpty(e))
	{
		 alert ('Enrollee Id field is Empty');
		 return false;
	}
	if(!isOnlyNumeric(e))
	{
		 alert ( 'Enrollee Id should have numeric value  ');
		 return false;
	}
	return true;
}

function GetNonExistingAppGrp(form,a)
{
	var SelIndex=0;
	var str='';
	SelIndex=parseInt(document.forms[1].app_grps.selectedIndex,10);
	
	SelAuth=document.forms[0].auth_types.value;

	var UsrGrp=document.forms[1].app_grps.options[SelIndex].value;
	if(a==0)
		//str='aclManager.cgi?type='+a+'&UserGroup='+UsrGrp+'&SelectedIndex='+SelAuth;
		str='aclManager.cgi?type='+a+'&UserGroup='+UsrGrp+'&SelectedIndex='+SelIndex+'&SelAuth='+SelAuth;
	else
		//str='aclManager.cgi?type='+a+'&UserGroup='+UsrGrp+'&SelectedIndex='+SelIndex;
		str='aclManager.cgi?type='+a+'&UserGroup='+UsrGrp+'&SelectedIndex='+SelIndex+'&SelAuth='+SelAuth;
	window.location.href=str;
}

function parseDynPortValue(form)
{
	var SelIndex=0;
	var SelIndex1=0;
	SelIndex=parseInt(document.forms[0].Serverlist.selectedIndex);
	SelIndex1=parseInt(document.forms[0].app_protocol.selectedIndex);
	var port=document.forms[0].Serverlist.options[SelIndex].value;
	var proto=document.forms[0].app_protocol.options[SelIndex1].value;
	myString = new String(port);
	if (proto == 0)
	{
		port=myString.substr(myString.indexOf("@")+1,myString.length);
		myString1 = new String(port);
		port=myString1.substr(0,myString1.indexOf("#"));
		document.forms[0].dynports.value=port;
	}
	else if (proto == 1)
	{
		port=myString.substr(myString.indexOf("#")+2,myString.length);
		document.forms[0].dynports.value=port;
	}
	else
		document.forms[0].dynports.value="bad";

	port=myString.substr(0,myString.indexOf("@"));
	document.forms[0].server.value=port;
}

function forceLogout(form)
{

	 var bIdentifiedUserRecord=false;
	 if(document.ListUser.check.length > 0)
     {
                var j=0;
                for(var i = 0; i < document.ListUser.check.length;i++)
                {
                        if(document.ListUser.check[i].checked)
						{
							if(bIdentifiedUserRecord==false)
							{

								document.frmForceLogout.UserId.value=document.ListUser.userID[i].value;
								document.frmForceLogout.EnrollId.value=document.ListUser.enrolleeID[i].value;
								document.frmForceLogout.Mac.value=document.ListUser.mac[i].value;
								document.frmForceLogout.Role.value=document.ListUser.role[i].value;
								bIdentifiedUserRecord=true;
							}
                            j++;
						}

                }
                if(j > 1)
                {
                        alert('Please select only one User for force Logout');
                        return false;
                }

                if( j==0)
                {
                        alert('Please select User for force Logout');
                        return false;
                }

        }
        else
        {
                if(document.ListUser.check.checked)
				{

					document.frmForceLogout.UserId.value=document.ListUser.userID.value;
					document.frmForceLogout.EnrollId.value=document.ListUser.enrolleeID.value;
					document.frmForceLogout.Mac.value=document.ListUser.mac.value;
					document.frmForceLogout.Role.value=document.ListUser.role.value;
					bIdentifiedUserRecord=true;

				}
        }
		if(bIdentifiedUserRecord)
		{
			document.frmForceLogout.submit();
			return true;
		}
        alert('Please select User for force Logout');
	 	return false;
}

function ShowPreviousUserSet()
{
	document.frmForceLogout.command.value=3;
	document.frmForceLogout.submit();
}

function ShowNextUserSet()
{
	document.frmForceLogout.command.value=4;
	document.frmForceLogout.submit();
}


function AddverifyADSinfo(form)
{
	var sn=form.servername.value;
	var hn=form.hname.value;
	var po=form.port.value;
	var adn=form.admindn.value;
	var pwd=form.adminpwd.value;
	var bdn=form.basedn.value;
	var attr=form.UsrSrchAttr.value;
	var attrgrp=form.UsrGrpSrchAttr.value;

	if(isEmpty(sn))
	{
		alert('Empty Server Name not allowed.');
		return false;
	}

	if(sn == 'Native')
	{
		alert("Server Name cannot be 'Native'.");
		return false;
	}

	if(isEmpty(hn))
	{
		alert('Empty Host Name not allowed.');
		return false;
	}

	if(!isAlphanumeric(hn))
	{
		alert('Wild characters and spaces are not allowed in Host Name.');
		return false;
	}
	if(!isServerName(hn))
	{
		alert ('Please enter valid Host Name.');
		return false;
	}

	if(!isPort(po)||!check(po)||isEmpty(po))
	{
		alert('Not a valid Port number.');
		return false;
	}

	if(isEmpty(adn))
	{
		alert('Empty Admin Bind Name not allowed.');
		return false;
	}
	if(!isProperDN(adn))
	{
		alert('Enter valid Admin Bind Name.');
		return false;
	}

	if(isEmpty(pwd))
	{
		alert('Empty Password not allowed.');
		return false;
	}

	if(isEmpty(bdn))
	{
		alert('Empty Base DN not allowed.');
		return false;
	}
	if(!isProperDN(bdn))
	{
		alert('Enter valid Base DN.');
		return false;
	}

	if(isEmpty(attr))
	{
		alert('Empty User Search Attribute not allowed.');
		return false;
	}
	if(!isAlphanumeric(attrgrp))
	{
		alert('Wild characters and spaces are not allowed in User Group Search Attribute .');
		return false;
	}
	if(isEmpty(attrgrp))
	{
		alert('Empty User Group Search Attribute not allowed.');
		return false;
	}
	return true;
}





//used by Basic Auth
function verifyADSinfo(form)
{
	var hn=form.hname.value;
	var po=form.port.value;
	var adn=form.admindn.value;
	var pwd=form.adminpwd.value;
	var bdn=form.basedn.value;
	var attr=form.UsrSrchAttr.value;
	var attrgrp=form.UsrGrpSrchAttr.value;

	
	if(isEmpty(hn))
	{
		alert('Empty Host Name not allowed.');
		return false;
	}

	if(!isAlphanumeric(hn))
	{
		alert('Wild characters and spaces are not allowed in Host Name.');
		return false;
	}
	if(!isServerName(hn))
	{
		alert ('Please enter valid Host Name.');
		return false;
	}

	if(!isPort(po)||!check(po)||isEmpty(po))
	{
		alert('Not a valid Port number.');
		return false;
	}

	if(isEmpty(adn))
	{
		alert('Empty Admin Bind Name not allowed.');
		return false;
	}
	if(!isProperDN(adn))
	{
		alert('Enter valid Admin Bind Name.');
		return false;
	}

	if(isEmpty(pwd))
	{
		alert('Empty Password not allowed.');
		return false;
	}

	if(isEmpty(bdn))
	{
		alert('Empty Base DN not allowed.');
		return false;
	}
	if(!isProperDN(bdn))
	{
		alert('Enter valid Base DN.');
		return false;
	}

	if(isEmpty(attr))
	{
		alert('Empty User Search Attribute not allowed.');
		return false;
	}
	if(!isAlphanumeric(attrgrp))
	{
		alert('Wild characters and spaces are not allowed in User Group Search Attribute .');
		return false;
	}
	if(isEmpty(attrgrp))
	{
		alert('Empty User Group Search Attribute not allowed.');
		return false;
	}
	return true;
}

//used by Basic Auth
function verifyRadiusinfo(form)
{
	var sn=form.servername.value;
	var hn=form.hname.value;
	var po=form.port.value;
	var sec=form.secret.value;

	if(isEmpty(sn))
	{
		alert('Empty Server Name not allowed.');
		return false;
	}

	if(sn == 'Native')
	{
		alert("Server Name cannot be 'Native'.");
		return false;
	}

	if(isEmpty(hn))
	{
		alert('Empty Host Name not allowed.');
		return false;
	}

	if(!isAlphanumeric(hn))
	{
		alert('Wild characters and spaces are not allowed in Host Name.');
		return false;
	}

	if(isEmpty(po))
	{
		alert('Empty Port not allowed.');
		return false;
	}

	if(!isNum(po))
	{
		alert('Port number should be numeric.');
		return false;
	}

	if(isEmpty(sec))
	{
		alert('Empty shared secret not allowed.');
		return false;
	}

	return true;
}

function verifyCrtAppGrpFormKeyDown(form)
{
        if(event.keyCode==13)
	{

                var str= form.elements["ag_name"].value;
                str=trim(str);
                form.elements["ag_name"].value=str;
                if(str=="")
		{
                        alert("Please enter Application group name");
                        return false;
                }
                else
                {
                return  verifyAppGrp(form);
                }
                return true;
        }
        else
                return true;
}
function VerifyCrtAccTimeFormKeyDown(form)
{
        if(event.keyCode==13)
	{

                var str= form.elements["at_name"].value;
                str=trim(str);
                form.elements["at_name"].value=str;
                if(str=="")
		{
                        alert("Please enter Access Filter Name");
                        return false;
                }
		if (verifyAccTime(form))
                return true;
		else
		return false;
        }
        else
                return true;
}

function verifyFormKeyDown(criteria)
{
        if(event.keyCode==13)
	{
                var str= criteria.value;
                str=trim(str);
                criteria.value=str;
                if(str=="")
		{
                 	alert("Please enter search criteria");
                        return false;
                }
                 return true;
        }
        else
                return true;
}

// ---- Adding Kiosk Application Validation functions

function isValidRemoteVes(s)
{
	var i;
	for (i = 0; i < s.length; i++)
	{
		var c = s.charAt(i);
		if (! (isLetter(c) || isDigit(c)|| isFullStop(c) || isCharacter(c) ))
		return false;
	}
	return true;
}

function verifyKioskApp(form)
{
	var s=document.forms[0].elements["app_name"].value;
	s=replaceAll(s," ","")
	document.forms[0].elements["app_name"].value=s;

	var appType=document.forms[0].elements["app_type"].value;
	var ds=document.forms[0].elements["app_address"].value;
	var dp=document.forms[0].elements["app_port"].value;
 	var ds2=document.forms[0].elements["app_address2"].value;
	var dp2=document.forms[0].elements["app_port2"].value;
	var rs=document.forms[0].elements["remote_ves_server"].value;
	var ty=document.forms[0].elements["Type"].selectedIndex;
	var ur=document.forms[0].elements["app_url"].value;
	var appDesc=document.forms[0].elements["app_desc"].value;
	appUrl=new String(ur);

	if(s.length > 50)
	{
		alert('Enter value of Application name less than or equal to 50 characters');
		return false;
	}

	if(isEmpty(s))
	{
		alert('Enter Application Name');
		return false;
	}

	if(!checkValid(s) )
	{
		alert('Enter valid Application Name');
		return false;
	}
	if( !checkValid(appDesc) ){
		alert('Enter valid Application Description');
		return  false;
	}

	if(firstCharNum(s))
	{
		alert('First character of the application name should not be a numeric');
		return false;
	}
	if(!isAlphanumericWithSpace(s))
	{
		alert('Invalid characters are not allowed for Application Name');
		return false;
	}
	if(isEmpty(ds) || (appType==7 && isEmpty(ds2))  )
	{
		alert('Enter Application Address ');
		return false;
	}
	if(!checkValid(ds) || (appType==7 && !checkValid(ds2)))
	{
		alert('Enter valid Application Address');
		return false;
	}

	if(!checkServerDomainName(ds) || (appType==7   && !checkServerDomainName(ds2)))
	{
		alert('Enter valid  Application  Address');
		return false;
	}
	if(isEmpty(dp))
	{
		alert('Enter Application Port ');
		return false;
	}
	if(!check(dp)||(dp >= 65536))
	{
		alert('Enter valid Application Port');
		return false;
	}
	if(appType  == 7 )
	if(!check(dp2)||(dp2 >= 65536))
	{
		alert('Enter valid Application Port');
		return false;
	}
	if (rs == null || rs == 'N/A')
	if (rs == null || rs == 'N/A')
		rs='';

	if(!isEmpty(rs))
	{
		if (ty != 1)
		{
			alert(' If Remote Chained Server is entered,type should be Chained');
			return false;
		}
	}
	else
	{
		if(ty == 1)
		{
			alert('You need to Enter Remote Chained Server for Type Chained');
			return false;
		}
	}

  if ( isValidRemoteVes(rs) == false 	|| rs.indexOf("&")>=0)
  {
      alert('Spaces and invalid character not allowed for Remote Ves Server');
			return false;
  }
  if(appUrl.indexOf("/")==0)
  {
      alert("Application URL should not begin with /");
      return false;
  }

  if(!checkValid(appUrl))	{
	alert("Please enter valid Application URL.");
	return false;
  }

 /*
	if(document.forms[0].check.checked)
		document.forms[0].elements["check"].value="1";
  else
		document.forms[0].elements["check"].value="0";

	if(document.forms[0].check.checked)
	{
    var type = parseInt(appType);
    if ( type > 0  )
    {
			alert("Is Secure Web Application Flag not supported for non Web Applications");
			return false;
		}
	}
 */
	return true;
}

function verifyKAppSrchForm(form)
{

	var e1=trim(document.forms[0].AppName.value);
	form.elements["AppName"].value=e1;
	var len=e1.length;
	if(len > 255)
	{
		alert('Field value length should be less than 256 characters');
		return false;
	}
	if(isEmpty(e1))
	{
		 alert("Please enter search criteria");
		return false;
	}
	document.forms[0].type.value=4;
	return true;
}

function verifyModifyKioskApp(form)
{
	var appType=document.forms[0].elements["appType"].value;
	var ds=document.forms[0].elements["appAdd"].value;
	var dp=document.forms[0].elements["appPort"].value;
	if(appType==7)
	{
	var ds2=document.forms[0].elements["appAdd2"].value;
	var dp2=document.forms[0].elements["appPort2"].value;
	}
	var rs=document.forms[0].elements["remote_ves_server"].value;
	var ty=document.forms[0].elements["Type"].selectedIndex;
	var appDesc=document.forms[0].elements["appDesc"].value;
	if(appType==6)
	var ur=document.forms[0].elements["appUrl"].value;

	appUrl=new String(ur);
	//alert('appDesc');
	if(!checkValid(appDesc)){
		alert('Enter valid Application Description');
		return false;
	}
	if(isEmpty(ds) 	|| (appType  == 7 && isEmpty(ds2)))
	{
		alert('Enter Application Address ');
		return false;
	}
	if(!checkValid(ds) || ( appType==7	&& !checkValid(ds2)))
	{
		alert('Enter valid Application Address');
		return false;
	}

	if(!checkServerDomainName(ds)  ||  (appType==7	&& !checkServerDomainName(ds2)))
	{
		alert('Enter valid  Application  Address');
		return false;
	}
	if(isEmpty(dp)  	|| (appType==7 && isEmpty(dp2)))
	{
		alert('Enter Application Port ');
		return false;
	}
	if(!check(dp)||(dp >= 65536))
	{
		alert('Enter valid Application Port ');
		return false;
	}
	if(appType==7)

	if(!check(dp2)||(dp2 >= 65536))
	{
		alert('Enter valid Application Port ');
		return false;
	}

	if (rs == null || rs == 'N/A')
		rs='';

	if(!isEmpty(rs))
	{
		if (ty != 1)
		{
			alert(' If Remote Chained Server is entered,type should be Chained');
			return false;
		}
	}
	else
	{
		if(ty == 1)
		{
			alert('You need to Enter Remote Chained Server for Type Chained');
			return false;
		}
	}
  if ( isValidRemoteVes(rs) == false )
  {
      alert('Spaces and invalid character not allowed for Remote Ves Server');
			return false;
  }

  if(appType== 6 && appUrl.indexOf("/")==0)
  {
      alert("Application URL should not begin with /");
      return false;
  }
 /*
	if(document.forms[0].check.checked)
		document.forms[0].elements["check"].value="1";
  else
		document.forms[0].elements["check"].value="0";

	if(document.forms[0].check.checked)
	{
    var type = parseInt(appType);
    if ( type > 0  )
    {
			alert("Is Secure Web Application Flag not supported for non Web Applications");
			return false;
		}
	}
 */
	return true;
}

function ModifyKioskApp(form)
{
	document.forms[1].type.value=5;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;
		}
		if(j > 1)
		{
			alert('Please select only one Kiosk Application for Modification');
			return false;
		}
		if( j==0)
		{
			alert('Please select Kiosk Application for Modification');
			return false;
		}
		else
			return true;
	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select Kiosk Application for Modification');
	return false;
}

function DeleteKioskApp(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
        if (!confirm("Are you sure you want to delete these Kiosk Application(s)?"))
        {
            return false;
        }
  			document.forms[1].type.value=7;
				return true;
			}
		}
		alert('Please select any Kiosk Application for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
       if (!confirm("Are you sure you want to delete this Kiosk Application?"))
       {
          return false;
       }
 			document.forms[1].type.value=7;
			return true;
		}
		alert('Please select any Application');
		return false;
	}
 	document.forms[1].type.value=7;
	return true;
}

function disableAccountExp(form)
{
	if(document.forms[0].user_role.value < 2)
	{
		document.forms[0].dd.disabled=true;
		document.forms[0].mm.disabled=true;
		document.forms[0].yy.disabled=true;
	}
	else if(document.forms[0].user_role.value > 2)
	{
		document.forms[0].dd.disabled=false;
		document.forms[0].mm.disabled=false;
		document.forms[0].yy.disabled=false;
	}

}

function disableHostName(form)
{
	if(document.forms[0].user_class.value==1)
	{
        document.forms[0].user_hostname.value="";
        document.forms[0].user_hostname.disabled=false;
		document.forms[0].user_id.value="";
		document.forms[0].user_password.value="";
		document.forms[0].user_id.disabled=true;
		document.forms[0].user_password.disabled=true;

        return ;
    }
   	else if(document.forms[0].user_class.value==0)
	{
		document.forms[0].user_id.disabled=false;
		document.forms[0].user_password.disabled=false;
        document.forms[0].user_hostname.value="127.0.0.1";
        document.forms[0].user_hostname.disabled=true;
        return ;
    }
}

function verifySUIDSPWD(suid, spwd)
{
	for(var i=0; i<suid.length; i++)
	{
        	if(!isLetter(suid.charAt(i)) && !isDigit(suid.charAt(i)) && suid.charAt(i)!='_')
        	{
                	alert("User ID should not contain special characters except '_'");
                	return false;
        	}
	}

        if(spwd.length<6 || spwd.length>16)
        {
		alert("Password must be 6 characters atleast and 16 characters atmost");
        	return false;
        }

	return true;
}

function checkOpener(form)
{
	if(window.opener == null)
	{
		var str='userManager.cgi?type=11';
        	window.location.href=str;
		return false;
	}
	return true;
}
function checkOpener1(form)
{
	if(window.opener == null)
	{
		var str='Application.cgi?type=12';
        	window.location.href=str;
		return false;
	}
	return true;
}
function disable_chained()
{
        if(document.forms[0].check_chained.checked)
        {
                document.forms[0].remote_ves_server.disabled=false;
                document.forms[0].remote_ves_server.value="";
                return ;
        }
        else if(!document.forms[0].check_chained.value)
        {
                document.forms[0].remote_ves_server.disabled=true;
                document.forms[0].remote_ves_server.value="";
                return ;
        }
}
function verifyProxyServer(form)
{
	var ds=document.forms[0].elements["pxySName"].value;
	if(!checkValid(ds))
	{
		alert('Enter valid proxy server name');
		return false;
	}
	return true;
}

function SelectData(form)
{
	form.elements["type"].value="1";
	var e=document.forms[0].elements["UName"].value;
	var d=document.forms[0].elements["DName"].value;
	 if (isEmpty(e) || isEmpty(d))
	{
		 alert('Empty fields are not allowed');
		 return false;
	}

	if((e.length > 1024)||(d.length >1024))
	{
		 alert('Exceeding field value limits ');
		 return false;
	}
	return true
}

function EscrowData(form)
{
	 document.forms[0].elements["type"].value="9";
	var d=document.forms[0].DName.value;
	 if (isEmpty(d))
	{
		 alert("Please enter search criteria");
		 return false;
	}

	if(d.length >1024)
	{
		 alert('Exceeding field Value limits ');
		 return false;
	}
	return true
}

function LimitSize(form)
{

	if(document.forms[0].Reason.value.length >= 100)
		 alert('Maximum limit of entering text exceeded');
}

function onLoadApproved(form)
{
	if(document.forms[0].STATUS.length > 0)
	{
		for(var i = 0; i < document.forms[0].STATUS.length;i++)
		{
			 var e=document.forms[0].STATUS[i].value;
			 if(e==3)
			 	document.forms[0].check[i].disabled=true;
		 }
	 }
 }
function CommonEscrow(form,ch)
{
	 if(ch==0)
	{
		var d=document.forms[0].Reason.value;
		 if (isEmpty(d))
		{
			 alert('Please Enter Reason');
			 return false;
		}
		if(!IsText(d,0))
		{
			 alert('Enter valid charaters in Reason');
			 return false;
		}
		/* if (d.length >=100)
		{
			 alert('Please enter reason less than 100 characters ');
			 return false;
		}
		*/
	}

	if(document.forms[0].check.length > 0)
        {
                for(var i = 0; i < document.forms[0].check.length;i++)
                {
                         if(document.forms[0].check[i].checked)
				 return true;
		}
                 alert('Please select Document');
                 return false;
	}
         else
	{
		if(document.forms[0].check.checked)
			return true;
		alert('Please select Document');
		return false;
	}
	return true;
}

function submitEscrow(form)
{
	document.forms[0].elements["type"].value="2";
	if(!CommonEscrow(this.form,0))
		return false;
	else
		return true ;
}

function DeleteEscrow(form)
{
	 document.forms[0].elements["type"].value="5";
	if(!CommonEscrow(this.form,1))
		return false;
	 else
		 return true ;
}

function DenyEscrow(form)
{
	document.forms[0].elements["type"].value="4";
	if(!CommonEscrow(this.form,0))
		return false;
	 else
		 return true ;
}
function ApproveEscrow(form)
{
	document.forms[0].elements["type"].value="3";
	if(!CommonEscrow(this.form,0))
		return false;
	 else
		 return true ;
}

function isDotDash(c)
{
	return ((c == "_") && (c == "."))

}

function CheckIp(re,ipaddr)
{
	if (re.test(ipaddr))
	{
		var parts = ipaddr.split(".");
		if (parseInt(parseFloat(parts[0])) == 0) { return false; }
		for (var i=0; i<parts.length; i++)
		{
			if (parseInt(parseFloat(parts[i])) > 255)
				return false;

		}
		return true;
	}
	else
		return false;

}


//it validates normal ip addresses
//function isValidIPAddress(ipaddr)
//{
//	var re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
//	if(!CheckIp(re,ipaddr))
//		return false;
//	alert('ret true');
//	return true;
//}
// it validates ip address like 10.10.8-22.3-43
function isValidIPRange1(ipaddr)
{
	var re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\-\d{1,3}$/;
	if(!CheckIp(re,ipaddr))
		return false;
		alert('ret true1');
	return true;

}
function isValidIPRange2(ipaddr)
{
	var re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}$/;
	if(!CheckIp(re,ipaddr))
		return false;
		alert('ret true2');
	return true;

}

function isValidIPRange3(ipaddr)
{
	var re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}$/;
	if(!CheckIp(re,ipaddr))
		return false;
		alert('ret true3');
	return true;

}

function IpRangeValidation(form)
{
	var range=document.forms[0].elements["IpRange"].value;

	if(isEmpty(range) && !isValidIPAddress(range) && !isValidIPRange1(range) && !isValidIPRange2(range) && !isValidIPRange3(range))
	{
		alert('Enter valid IP address');
		return false;

	}
	return true;

}
function AddAppToAppGroup(form)
{
	var str='selApps.cgi';
        newwindow=window.open(str,"","width=520,height=280,titlebar=0,scrollbars=yes,resizable=0","");
        return true;


}
function isBrowserTypeChange(form)
{
	var inval=0;
   	inval=document.forms[0].app_type.value;

	//alert(document.forms[0].app_type.options[inval].text);
   	if(parseInt(inval)!=10)
   		{
			if (inval==8)
			inval=7;
//Changing the inval to 7 for getting the text if the inval is 8, Since, in option it has only seven members in array it is not been able to get name as file share and giving js error.

   			if(document.forms[0].app_type.options[inval].text=="OTHERS")
      	 			document.forms[0].appCompression.disabled=false;
      			else
			{
      	 			document.forms[0].appCompression.disabled=true;
				document.forms[0].appCompression.checked=false;
			}
			//isMailSelected(form);
			//isServerBased(form);
 		}
}

function SendIp(form)
{
	//alert(form.innerHTML);

	document.forms[1].elements["type"].value="9";
	document.forms[1].Ip.value=form.innerHTML;
	document.body.style.cursor = "wait";
	document.forms[1].submit();
}


function SendRange(form)
{
	//var speed=2;
	//var marqueecontents = '<font face="Arial"><strong>Waiting....................</strong></font>';

	//alert(form.innerHTML);
	
	document.forms[0].elements["type"].value="8";
	document.forms[0].IpRange.value=form.innerHTML;
	document.body.style.cursor = "wait";
	document.forms[0].submit();
	//document.forms[0].write( '<marquee scrollAmount=' + speed + ' style="width:100">' + marqueecontents + '</marquee>' );
}

function CreateAutoApp(form)
{
	document.forms[2].elements["type"].value="10";
	var totalStr='';
	var stuff=0;
	var j=0;
	var count=0;
	var strFront='';
	var strBack='';
	var strFinal='';
	var IpAdd=document.forms[2].elements["appAdd"].value;
	var IpRange=document.forms[2].elements["IpRange"].value;
	var OS=document.forms[2].elements["OS"].value;
	var str1='FormString=AutoConfiguration.cgi?type=13&Ip='+IpAdd+'&IpRange='+IpRange+'&OS='+OS+'&';



	strFront='AutoConfiguration.cgi?type=10&appAdd='+IpAdd+'&';

	for(var i = 0; i < document.forms[2].check.length;i++)
	{
		if(document.forms[2].check[i].checked)
			count=i;
	}
	for(var i=0;i <document.forms[2].elements.length;i++)
	{
		if(document.forms[2].elements[i].name=='check')
		{
			stuff=0;
			if(j==count)
			{
				stuff=1;
			}
			j++;
		}

		if(stuff)
		{
			strBack=strBack+document.forms[2].elements[i].name+'='+document.forms[2].elements[i].value+'&';
		}
	}

	for(var i=0;i <document.forms[2].elements.length;i++)
	{
		strFinal=strFinal+document.forms[2].elements[i].name+'='+document.forms[2].elements[i].value+'&';

	}
	totalStr=strFront+strBack+str1+strFinal;
	if(document.forms[2].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[2].check.length;i++)
		{
			if(document.forms[2].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one service for creation');
			return false;
		}

		if( j==0)
		{
			alert('Please select service for creation');
			return false;
		}
		else
		{
			var parms="menubar=no,resizable=yes,scrollbars=yes,toolbar=no";
			var left = Math.floor( (screen.availWidth - screen.availWidth) / 2);
			var top = Math.floor( (screen.availHeight - screen.availHeight) / 2);
			var width=(screen.availWidth)-20;
			var height=(screen.availHeight)-20;
			var winParms = "top=" + top + ",left=" + left + ",height=" + height + ",width=" + width;
			if (parms)
				winParms += "," + parms;
			var win	 = window.open(totalStr, "Window1", winParms);
			if (parseInt(navigator.appVersion) >= 4)
			{
				win.window.focus();
			}
			return true;
		}
	}
	else
	{
		if(document.forms[2].check.checked)
			return true;
	}
			alert('Please select service for creation');
	return false;

}

function checkIpRange(form)
{
	 if(Ipvalid(form))
        {
                var fav1=document.forms[0].fa1.value;
                var fav2=document.forms[0].fa2.value;
                var fav3=document.forms[0].fa3.value;
                var fav4=document.forms[0].fa4.value;

                var lav1=document.forms[0].la1.value;
                var lav2=document.forms[0].la2.value;
                var lav3=document.forms[0].la3.value;
                var lav4=document.forms[0].la4.value;

              if(fav1!=lav1)
                {
                        alert("Range too big. \nRange cannot exceed 100 hosts");
                        return false
                }
                if(fav2!=lav2)
                {
                        alert("Range too big. \nRange cannot exceed 100 hosts");
                        return false
                }

                var ipDiff=parseInt(lav3)-parseInt(fav3);

                if(ipDiff>1)
                {
                        alert("Range too big. \nRange cannot exceed 100 hosts");
                        return false
                }

		if(ipDiff==1)
                        var totalIp=(255-parseInt(fav4)+1)+(parseInt(lav4)+1);
                else
                        var totalIp=parseInt(lav4)-parseInt(fav4)+1;

                if(totalIp>100)
                {
                        alert("Range too big. \nRange cannot exceed 100 hosts");
                        return false
                }
                return true;
        }
        return false;

}


function Ipvalid(form)
{
	var fav1=document.forms[0].fa1.value;
	var fav2=document.forms[0].fa2.value;
	var fav3=document.forms[0].fa3.value;
	var fav4=document.forms[0].fa4.value;
	var lav1=document.forms[0].la1.value;
	var lav2=document.forms[0].la2.value;
	var lav3=document.forms[0].la3.value;
	var lav4=document.forms[0].la4.value;
	var smv1=document.forms[0].sm1.value;
	var smv2=document.forms[0].sm2.value;
	var smv3=document.forms[0].sm3.value;
	var smv4=document.forms[0].sm4.value;

	if(!validate_octet(fav1, "Start IP Address, 1st Octet",0))
		return false;
	if(!validate_octet(fav2, "Start IP Address, 2nd Octet",0))
		return false;
	if(!validate_octet(fav3, "Start IP Address, 3rd Octet",0))
		return false;
	if(!validate_octet(fav4,"Start IP Address, 4th Octet",0))
		return false;
	if(!validate_octet(lav1, "End IP Address, 1st Octet",1))
		return false;
	if(!validate_octet(lav2, "End IP Address, 2nd Octet",1))
		return false;
	if(!validate_octet(lav3, "End IP Address, 3rd Octet",1))
		return false;
	if(!validate_octet(lav4, "End IP Address, 4th Octet",1))
		return false;
	if(isEmpty(lav1))
	{
		if((!isEmpty(lav2))||(!isEmpty(lav3))|| (!isEmpty(lav4)))
		{
			alert('Start IP Address, 1st Octet cannot be empty if 2nd Octet,3rd Octet and/or 4th Octet are filled');
			return false
		}
	}
	if(isEmpty(lav2))
	{
		if((!isEmpty(lav1))||(!isEmpty(lav3))|| (!isEmpty(lav4)))
		{
			alert('Start IP Address, 2nd Octet cannot be empty if 1st Octet,3rd Octet and/or 4th Octet are filled');
			return false
		}
	}
	if(isEmpty(lav3))
	{
		if((!isEmpty(lav2))||(!isEmpty(lav1))|| (!isEmpty(lav4)))
		{
			alert('Start IP Address, 3rd Octet cannot be empty if 1st Octet,2nd Octet and/or 4th Octet are filled');
			return false
		}
	}
	if(isEmpty(lav4))
	{
		if((!isEmpty(lav2))||(!isEmpty(lav1))|| (!isEmpty(lav3)))
		{
			alert('Start IP Address, 4th Octet cannot be empty if 1st Octet,2nd Octet and/or 3rd Octet are filled');
			return false
		}
	}


	if(!validate_octet(smv1, "Subnet Mask ,1st Octet",0))
		return false;
	 //Only values 0, 128, 192, 224, 240, 248, 252, 254, 255 are allowed in all blocks
	  // Example: 255.128.0.0 allowed, 255.17.0.0 not allowed
	  //validSubnetMask function is for the above validation

	if(!validSubnetMask(smv1))
		return false
	//In the first block the value 0 is not allowed

	if(smv1==0)
	{
		alert('Subnet Mask, 1st Octet cannot have value 0');
		return false;
	}
	//In the fourth block the values 254 and 255 are not allowed
	// Example: 0.0.0.0 / 255.255.255.254 / 255.255.255.255 not allowed
	if((smv4==254)||(smv4==255))
	{
		alert('Subnet Mask, 4th Octet cannot have values 254 and 255');
		return false
	}

	if(!validate_octet(smv2, "Subnet Mask, 2nd Octet",0))
		return false;
	if(!validSubnetMask(smv2))
		return false;
	if(!validate_octet(smv3, "Subnet Mask, 3rd Octet",0))
		return false;
	if(!validSubnetMask(smv3))
		return false;
	if(!validate_octet(smv4, "Subnet Mask, 4th Octet",0))
		return false;
	if(!validSubnetMask(smv4))
		return false;

	//Is a block containing a value unequal to 255, all blocks on the right side thereof must have the value 0.
	// Example: 224.0.0.0 allowed, 224.0.0.128 not allowed
	if(smv1!=255)
	{
		if((smv2!=0)||(smv3!=0)||(smv4!=0))
		{
			alert( 'Subnet Mask, 1st Octet containing a value not equal to 255, all octet on the right side thereof must have the value 0. ');
			return false;
		}
	}
	if(smv2!=255)
	{
		if((smv3!=0)||(smv4!=0))
		{
			alert( 'Subnet Mask, 2nd Octet containing a value not equal to 255, all octet on the right side thereof must have the value 0. ');
			return false;
		}
	}
	if(smv3!=255)
	{
		if((smv4!=0))
		{
			alert( 'Subnet Mask, 3rd Octet containing a value not equal to 255, all octer on the right side thereof must have the value 0. ');
			return false;
		}
	}
	//Is a block containing a value unequal to 0, all blocks on the left side thereof must have the value 255.
	 // Example: 255.255.248.0 allowed, 192.255.248.0 not allowed
	if(smv4!=0)
	{
		if((smv1!=255)||(smv2!=255)||(smv3!=255))
		{
			alert( 'Subnet Mask, 4th Octet containing a value not equal to 0, all octet on the left side thereof must have the value 255. ');
			return false;
		}
	}
	if(smv3!=0)
	{
		if((smv2!=255)||(smv1!=255))
		{
			alert( 'Subnet Mask, 3rd Octet containing a value not equal to 0, all octet on the left side thereof must have the value 255. ');
			return false;
		}
	}
	if(smv2!=0)
	{
		if((smv1!=255))
		{
			alert( 'Subnet Mask, 2nd Octet containing a value not equal to 0, all octet on the left side thereof must have the value 255. ');
			return false;
		}
	}
	var oct1=parseInt(fav1)*16777216;

	var oct2=parseInt(fav2)*65536;
	var oct3=parseInt(fav3)*256;
	var netoct=oct1+oct2+oct3+fav4;

	oct1=parseInt(lav1)*16777216;
	oct2=parseInt(lav2)*65536;
	oct3=parseInt(lav3)*256;
	var netoct1=oct1+oct2+oct3+lav4;
	var Intoct1=parseInt(netoct);
	var Intoct2=parseInt(netoct1);
	//if(Intoct2< Intoct1)
	//{
	//	alert('Start IP address cannot be greater than End IP address');
	//	return false;
	//}

	var favbin1=toBin(fav1);
	var favbin2=toBin(fav2);
	var favbin3=toBin(fav3);
	var favbin4=toBin(fav4);
	var lavbin1=toBin(lav1);
	var lavbin2=toBin(lav2);
	var lavbin3=toBin(lav3);
	var lavbin4=toBin(lav4);
	var smvbin1=toBin(smv1);
	var smvbin2=toBin(smv2);
	var smvbin3=toBin(smv3);
	var smvbin4=toBin(smv4);

	var netId1v1=favbin1&smvbin1;
	var netId1v2=favbin2&smvbin2;
	var netId1v3=favbin3&smvbin3;
	var netId1v4=favbin4&smvbin4;

	var netId2v1=lavbin1&smvbin1;
	var netId2v2=lavbin2&smvbin2;
	var netId2v3=lavbin3&smvbin3;
	var netId2v4=lavbin4&smvbin4;

	var netID1=netId1v1+'.'+netId1v2+'.'+netId1v3+'.'+netId1v4;
	var netID2=netId2v1+'.'+netId2v2+'.'+netId2v3+'.'+netId2v4;

	if(netID1!=netID2)
	{
		alert(' Network ID of Start IP Address and End IP addresses is not matching');
		return false;
	}

	if((smv1!=255) && (smv2!=255) && (smv3!=255) && (smv4!=255))
	{
		if(parseInt(fav1) > parseInt(lav1))
		{
			alert('Start IP Address ,1st Octet cannot be greater than End IP Address ,1st Octet');
			return false;
		}
	}
	else if((smv2!=255) && (smv3!=255) && (smv4!=255))
	{
		if(parseInt(fav2) > parseInt(lav2))
		{
			alert('Start IP Address, 2nd Octet cannot be greater than End IP Address, 2nd Octet');
			return false;
		}
	}
	else if((smv3!=255) && (smv4!=255))
	{
		if(parseInt(fav3) > parseInt(lav3))
		{
			alert('Start IP Address, 3rd Octet cannot be greater than End IP Address Octet 3');
			return false;
		}
	}
	else if(smv4!=255)
	{
		if(parseInt(fav4) > parseInt(lav4))
		{
			alert('Start IP Address, 4th Octet cannot be greater than End IP Address, 4th Octet');
			return false;
		}
	}
	var st=document.forms[0].Description.value;
	if(st.length >= 50)
	{
		 alert('Description should be less than 50 characters');
		 return false;
	}
	if(!IsText(st,0))
	{
		alert('Enter valid Description');
		return false;
	}
	return true;
}

function validate_octet(octet, text_message, endIp)
{
	if ((octet < 0) || (octet > 255))
	{
		alert(text_message + ' value must be in the range 0 - 255');
		return false;
	}
	if(!isValid(octet,text_message,endIp))
		return false;
	return true;
}

// JavaScript sees numbers with leading zeros as octal values, so strip zeros
function stripZeros(inputStr)
{
	var result = inputStr;
	while (result.substring(0,1) == "0")
		result = result.substring(1,result.length);

	return result;
}

// general purpose function to see if a suspected numeric input
// is a positive integer

function isNumber(inputStr)
{
	for (var i = 0; i < inputStr.length; i++)
	{
		var oneChar = inputStr.substring(i, i + 1);
		if (oneChar < "0" || oneChar > "9")
			return false;
	}
	return true;
}

// function to determine if value is in acceptable range for this application

function inRange(inputStr)
{
	num = parseInt(inputStr);
	if ((num < 0) || (num > 255))
		return false;
	return true;
}

function isValid(inputStr,text_message,endIp)
{
	if(endIp==1)
	{
		if (isEmpty(inputStr))
			return true;
	}
	if (isEmpty(inputStr))
	{
		alert(text_message+' is Empty');
		return false;
	}
	if (!isNumber(inputStr))
	{
		alert('In '+text_message+' Please enter numbers only');
		return false;
	}
	if (!inRange(inputStr))
	{
		alert("Valid range is 0 - 255");
		return false;
	}
	return true;
}

	// Decimal to binary, returns an eight character string
function toBin(inVal)
{
	base = 2 ;
	num = parseInt(inVal);
	binNum = num.toString(base);
	// pad leading spaces with "0"
	binNum = padTextPrefix(binNum, "0", 8) ;
	return binNum;
}

	// equiv to padl()

function padTextPrefix (InString, PadChar, DefLength)
{
	if (InString.length >= DefLength)
		return (InString);
	OutString = InString;
	for (Count = InString.length; Count < DefLength; Count++)
	{
		OutString = PadChar + OutString;
	}
	return (OutString);
}
function validSubnetMask(sm)
{
	var match=0;

	var arrsubnetMask= new Array( 0, 128, 192, 224, 240, 248, 252, 254, 255);
	var arrlen=arrsubnetMask.length;
	for(var i=0;i!=arrlen;i++)
	{
		if(arrsubnetMask[i]==sm)
			return true
	}
	alert('Only values 0, 128, 192, 224, 240, 248, 252, 254, 255 are allowed in Subnet Mask Octet');
	return false;
}


function ModifyIP(form)
{
  	document.forms[1].type.value=6;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one IP Range for Modification');
			return false;
		}

		if( j==0)
		{
			alert('Please select IP Range for Modification');
			return false;
		}
		else
			return true;
	}
	else
	{
		if(document.forms[1].check.checked)
			return true;
	}
	alert('Please select IP Range for Modification');
	return false;
}

function DeleteIP(form)
{
	if(document.forms[1].check.length > 0)
	{
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(form.check[i].checked)
			{
                         if (!confirm("Are you sure you want to delete these IP Range(s)?"))
                         {
                               return false;
                         }
  				document.forms[1].type.value=5;
				return true;
			}
		}
		alert('Please select any IP Range for deletion');
		return false;
	}
	else
	{
		if(document.forms[1].check.checked)
		{
                  if (!confirm("Are you sure you want to delete this IP Range?"))
                  {
                     return false;
                  }
  			document.forms[1].type.value=5;
			return true;
		}
		alert('Please select any IP Range');
		return false;
	}
  	document.forms[1].type.value=5;
	return true;
}
function GoToMainPage(form)
{
	window.location.href="AutoConfiguration.cgi?type=12";
	return true;
}
function GoToCreatePage(form)
{
	window.location.href="AutoConfiguration.cgi?type=7";
	return true;
}
function LimitSize1(abc)
{
	return true;
}
function IsText(e,a)
{
//if a=0 means & not allowed
//and if it is 1 & is allowed
	var arremail;
	if(a==0)
		arremail= new Array(64,63,59,91,93,123,124,32,44,46,45,64,47,48,49,50,51,52,53,54,55,56,57,58,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122);
	else
		arremail= new Array(64,63,59,91,93,123,124,32,38,44,46,45,64,47,48,49,50,51,52,53,54,55,56,57,58,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122);

	var l=e.length;
	var arrlen=arremail.length;
	for(var x=0;x!=l;x++)
	{
		var c=e.charAt(x);
		var match=0;
		for(var i=0;i!=arrlen;i++)
		{
			var d=	String.fromCharCode(arremail[i]);
			if(c==d)
				match = 1;

		}
		if (match == 0)
		{
			return false;
		}
	}
	return true;
}

function LimitSizeDes(form)
{
	if(document.forms[0].Description.value.length >= 50)
		 alert('Maximum limit of entering text exceeded');
}

function NextPage(form,a)
{
	var minlimit=parseInt(document.forms[0].MIN_LIMIT.value,10);
 	var maxlimit=parseInt(document.forms[0].MAX_LIMIT.value,10);
 	var maxrows=parseInt(document.forms[0].rows.value,10);
 	var trecords=parseInt(document.forms[0].trecords.value,10);
 	var maxrecord=parseInt(document.forms[0].records.value,10);

	var sumtotal=minlimit+maxlimit;
 	var totallimit=parseInt(sumtotal,10);
	var remtotal=maxrows-totallimit;
 	var rem=parseInt(remtotal,10);

	if(trecords==maxrecord)
		return false;
	if(maxrecord <pagelimit)
		return false;
	if(maxrecord ==maxrows)
		return false;
 	if(rem <= 0)
		return false;
	document.forms[0].MIN_LIMIT.value=minlimit+pagelimit;
	document.forms[0].MAX_LIMIT.value=pagelimit;

  	//document.forms[0].type.value=1;
  	document.forms[0].type.value=a;

	document.forms[0].submit();
	return true;
}

function PreviousPage(form,a)
{
	var minlimit=parseInt(document.forms[0].MIN_LIMIT.value,10);
 	var maxlimit=parseInt(document.forms[0].MAX_LIMIT.value,10);
 	var maxrows=parseInt(document.forms[0].rows.value,10);
 	if(minlimit==0 )
		   	return false;
	document.forms[0].MIN_LIMIT.value=minlimit-pagelimit;
	document.forms[0].MAX_LIMIT.value=pagelimit;
  	//document.forms[0].type.value=1;
  	document.forms[0].type.value=a;
	document.forms[0].submit();
	return true;
}

function isMailSelected(form){

   if( document.forms[0].elements["app_type"].selectedIndex==7)
   {
      //displayElements(this.form);

      document.forms[0].elements["app_address2"].disabled=false;
      document.forms[0].elements["app_address2"].value="";
      document.forms[0].elements["app_port2"].disabled=false;
            document.forms[0].elements["app_port2"].value="";
      return true;
   }
   if ( document.forms[0].elements["app_port2"].disabled==false){

      document.forms[0].elements["app_address2"].disabled=true;
      document.forms[0].elements["app_address2"].value="NA";
      document.forms[0].elements["app_port2"].disabled=true;
      document.forms[0].elements["app_port2"].value="NA";
   }
   return true;
}
/* OLD Preboot verify function commented out -ATUL
function verifyprebootform(form)
{
	if(document.forms[0].elements["dns2"].value=="NONE")
		document.forms[0].elements["dns2"].value='';
	var sqlrpwd1=document.forms[0].elements["dbrpwd"].value;
	var sqlrpwd2=document.forms[0].elements["dbrpwd1"].value;
	var sqlupwd1=document.forms[0].elements["dbupwd"].value;
	var sqlupwd2=document.forms[0].elements["dbupwd1"].value;
	var rootpwd1=document.forms[0].elements["linuxrpwd"].value;
	var rootpwd2=document.forms[0].elements["linuxrpwd1"].value;
	var tz=document.forms[0].tz.selectedIndex;
        var dd=document.forms[0].dd.selectedIndex;
        var mm=document.forms[0].mm.selectedIndex;
        var yy=document.forms[0].yy.selectedIndex;
        var hh=document.forms[0].hh.selectedIndex;
        var min=document.forms[0].min.selectedIndex;

	if (!isValidIPAddress(form.IPAddress1.value)) return false;
        if (!isValidMask(form.mask1.value)) return false;
        if (!isValidIPAddress(form.gw.value)) return false;

        if (!isValidIPAddress(form.IPAddress0.value)) return false;
        if (!isValidMask(form.mask0.value)) return false;
	if (isEmpty(form.hname.value))
	{
		alert('Host name is empty');
		return false;
	}
	if (!isAlphanumeric(form.hname.value))
	{
		alert('Please enter valid host name');
		return false;
	}
	if (isEmpty(form.dns1.value))
	{
		alert('Primary DNS is empty');
		return false;
	}
        if (!isValidIPAddress(form.dns1.value)) return false;
	if (!isEmpty(form.dns2.value))
	{
        	if (!isValidIPAddress(form.dns2.value))
			return false;
	}
	if (sqlrpwd1.length<6 || sqlrpwd1.length>16)
    	{
		alert("Password length must be atleast 6 characters and atmost 16 characters");
	        return false;
    	}
	if (sqlrpwd1 != sqlrpwd2)
	{
		alert("MySQL root passwords do not match");
        	return false;
    	}
	if (sqlupwd1.length<6 || sqlupwd1.length>16)
    	{
		alert("Password length must be atleast 6 characters and atmost 16 characters");
	        return false;
    	}
	if (sqlupwd1 != sqlupwd2)
	{
		alert("MySQL user passwords do not match");
	        return false;
    	}
	if (dd == 0)
        {
                alert('Select Day ');
                return false;
        }
        if (mm == 0)
        {
                alert('Select Month ');
                return false;
        }
        if (yy == 0)
        {
                alert('Select Year ');
                return false;
        }
	var mm1=document.forms[0].mm.options[mm].value;
        var dd1=document.forms[0].dd.options[dd].value;
        var yy1=document.forms[0].yy.options[yy].value;
        var dt=mm1 + '/' + dd1 + '/' + yy1;
        if (!isDate(dt))
        {
                return false;
        }
        var hh1=document.forms[0].hh.options[hh].value;
        var min1=document.forms[0].min.options[min].value;
        if (hh1 == 24)
        {
                alert('Select Hour ');
                return false;
        }
        if (min1 == 60)
        {
                alert('Select Minute ');
                return false;
        }
        if (tz == 0)
        {
                alert('Select Time Zone ');
                return false;
        }
	if (rootpwd1.length<6 || rootpwd1.length>16)
    	{
		alert("Password length must be atleast 6 characters and atmost 16 characters");
	        return false;
    	}
	if (rootpwd1 != rootpwd2)
	{
		alert("Linux root passwords do not match");
        	return false;
    	}
	var fav1=document.forms[0].elements["ID1"].value;
	var fav2=document.forms[0].elements["ID2"].value;
	var fav3=document.forms[0].elements["ID3"].value;
	var fav4=document.forms[0].elements["ID4"].value;
	var fav5=document.forms[0].elements["ID5"].value;
	if((isEmpty(fav1))||(isEmpty(fav2)) || (isEmpty(fav3)) || (isEmpty(fav4)) || (isEmpty(fav5)))
	{
		alert('Enter Proper Product Key');
		return false;
	}
	var productkey=fav1+fav2+fav3+fav4+fav5;
	document.forms[0].elements["productkey"].value=	productkey;
	var cn=document.forms[0].elements["companyName"].value;
	if(!checkBlankAndWild(cn))
	{
		alert ('Enter valid Company Name ');
		return false;
	}
	//if (!confirm("System is going to reboot. Are you okay with your settings?"))
	//{
	//	return false;
	//}
	if (isEmpty(form.dns2.value))
	{
		document.forms[0].elements["dns2"].value="NONE";
	}

        return true;
}
*/
function checkipconflict(nicCount)
{
   var i, j,ipaddr;

   if(nicCount == 1) return true;

   for(i = 0;i < nicCount-1; i++)
   {
	for(j= i + 1;j < nicCount; j++)
	{
		if( document.forms[0].IPAddress[i].value ==  document.forms[0].IPAddress[j].value)
			return false;
	}
  }
  return true;
}
function verfiSysconf(form)
{

	var ipadd,submask,routegw,ethName ;
	var nCnt = form.NICcount.value;
	var nFlg = 0;

	for(var i = 0; i < nCnt; i++)
	{
		if( nCnt == 1 )
		{
				ethName = form.EthName.value;
				ipadd = form.IPAddress.value;
				submask = form.mask.value;
				routegw = form.gw.value;
	  	}
		else
		{
				ethName = document.forms[0].EthName[i].value;
				ipadd =  document.forms[0].IPAddress[i].value;
				submask = document.forms[0].mask[i].value;
				routegw = document.forms[0].gw[i].value;
		}
		if(ipadd == "NONE" ||  isEmpty(ipadd))
		{
				if( nCnt == 1 )
				{
						alert('Network interface not configured');
						return false;
				}
				document.forms[0].IPAddress[i].value = "NONE";
				document.forms[0].mask[i].value = "NONE";
				document.forms[0].gw[i].value = "NONE";
				continue;
		}

		nFlg = 1;

		if(!isValidIPAddress(ipadd))
		{
				//alert(ethName);
				alert('Enter valid IP address for '+ethName );
				//var s = "Enter valid IP address for interface "+document.forms[0].EthName[i].value;
				return false;
		}
		if(!isValidMask(submask))
		{
				alert('Enter valid Netmask for '+ethName);
				//alert('Enter valid mask ' + document.forms[0].mask[i].value );
				return false;
		}

		if(routegw == "NONE" || isEmpty(routegw))
		{
				if(nCnt == 1)
					form.gw.value = "NONE";
				else
					document.forms[0].gw[i].value = "NONE";
		}
		else if(!isValidIPAddress(routegw))
		{
			alert('Enter valid Gateway for '+ethName);
			return false;
		}
	}

	if( nFlg  == 0)
	{
	   alert('Network interfaces are not configured');
	   return false;
	}
        else
	{
		if(!checkipconflict(nCnt))
		{
		  alert('Network interface ip address should not be same');
		  return false;
		}
	}



	if (isEmpty(form.dgw.value))
	{
		alert('Default gateway is empty');
		return false;
	}

        if (!isValidIPAddress(form.dgw.value))
		{
			alert("Enter valid IP address for Default Gateway");
			return false;
		}




	if (isEmpty(form.dns1.value))
	{
		alert('Primary DNS is empty');
		return false;
	}
    if (!isValidIPAddress(form.dns1.value))
	{
		alert("Enter valid IP address for Primary DNS");
		return false;
	}

	if (isEmpty(form.dns2.value) || (form.dns2.value == "NONE"))
	{
		document.forms[0].elements["dns2"].value="";
	}

    if (!isEmpty(form.dns2.value))
    {
            if (!isValidIPAddress(form.dns2.value))
			{
				alert("Enter valid IP address for Secondary DNS");
	            return false;
			}
    }

    if(form.search.value == 'NONE')
    {
        form.search.value = '';
    }

   return true;
}

function verifyprebootform(form)
{
	if (isEmpty(form.hname.value))
	{
		alert('Host name is empty');
		return false;
	}
	if (!isAlphanumeric(form.hname.value))
	{
		alert('Please enter valid host name');
		return false;
	}

	if (isEmpty(form.dgw.value))
	{
		alert('Default gateway is empty');
		return false;
	}

        if (!isValidIPAddress(form.dgw.value))
		{
			alert("Enter valid IP address for Default Gateway");
			return false;
		}



	if (isEmpty(form.dns1.value))
	{
		alert('Primary DNS is empty');
		return false;
	}
    if (!isValidIPAddress(form.dns1.value))
	{
		alert("Enter valid IP address for Primary DNS");
		return false;
	}

	if (isEmpty(form.dns2.value) || (form.dns2.value == "NONE"))
	{
		document.forms[0].elements["dns2"].value="";
	}

    if (!isEmpty(form.dns2.value))
    {
            if (!isValidIPAddress(form.dns2.value))
			{
				alert("Enter valid IP address for Secondary DNS");
	            return false;
			}
    }

	var ipadd,submask,routegw,ethName ;
	var nCnt = form.NICcount.value;
	var nFlg = 0;

	for(var i = 0; i < nCnt; i++)
	{
		if( nCnt == 1 )
		{
				ethName = form.EthName.value;
				ipadd = form.IPAddress.value;
				submask = form.mask.value;
				routegw = form.gw.value;
	  	}
		else
		{
				ethName = document.forms[0].EthName[i].value;
				ipadd =  document.forms[0].IPAddress[i].value;
				submask = document.forms[0].mask[i].value;
				routegw = document.forms[0].gw[i].value;
		}
		if(ipadd == "NONE" ||  isEmpty(ipadd))
		{
				if( nCnt == 1 )
				{
						alert('Network interface not configured');
						return false;
				}
				document.forms[0].IPAddress[i].value = "NONE";
				document.forms[0].mask[i].value = "NONE";
				document.forms[0].gw[i].value = "NONE";
				continue;
		}

		nFlg = 1;

		if(!isValidIPAddress(ipadd))
		{
				//alert(ethName);
				alert('Enter valid IP address for '+ethName );
				//var s = "Enter valid IP address for interface "+document.forms[0].EthName[i].value;
				return false;
		}
		if(!isValidMask(submask))
		{
				alert('Enter valid Netmask for '+ethName);
				//alert('Enter valid mask ' + document.forms[0].mask[i].value );
				return false;
		}

		if(routegw == "NONE" || isEmpty(routegw))
		{
				if(nCnt == 1)
					form.gw.value = "NONE";
				else
					document.forms[0].gw[i].value = "NONE";
		}
		else if(!isValidIPAddress(routegw))
		{
			alert('Enter valid Gateway for '+ethName);
			return false;
		}
	}

	if( nFlg  == 0)
	{
	   alert('Network interfaces are not configured');
	   return false;
	}
        else
	{
		if(!checkipconflict(nCnt))
		{
		  alert('Network interface ip address should not be same');
		  return false;
		}
	}


        var tz=document.forms[0].tz.selectedIndex;
        var dd=document.forms[0].dd.selectedIndex;
        var mm=document.forms[0].mm.selectedIndex;
        var yy=document.forms[0].yy.selectedIndex;
        var hh=document.forms[0].hh.selectedIndex;
        var min=document.forms[0].min.selectedIndex;

	 if (dd == 0)
         {
                 alert('Select Day ');
                 return false;
         }
         if (mm == 0)
         {
                 alert('Select Month ');
                 return false;
         }
         if (yy == 0)
         {
                 alert('Select Year ');
                 return false;
         }
         var mm1=document.forms[0].mm.options[mm].value;
         var dd1=document.forms[0].dd.options[dd].value;
         var yy1=document.forms[0].yy.options[yy].value;
         var dt=mm1 + '/' + dd1 + '/' + yy1;
         if (!isDate(dt))
         {
                 return false;
         }
         var hh1=document.forms[0].hh.options[hh].value;
         var min1=document.forms[0].min.options[min].value;
         if (hh1 == 24)
         {
                 alert('Select Hour ');
                 return false;
         }
         if (min1 == 60)
         {
                 alert('Select Minute ');
                 return false;
         }
         if (tz == 0)
         {
                 alert('Select Time Zone ');
                 return false;
         }

	var  fav1=document.forms[0].elements["ID1"].value;
	var fav2=document.forms[0].elements["ID2"].value;
	var fav3=document.forms[0].elements["ID3"].value;
	var fav4=document.forms[0].elements["ID4"].value;
	var fav5=document.forms[0].elements["ID5"].value;
	var fav6=document.forms[0].elements["ID6"].value;


	if(form.lic_restore_val.value == 0)
	{
		alert("Please select 'Server License' or 'Restore from a Backup File'");
		return false;
	}


	if(form.lic_restore_val.value == 1)
	{

		var radioVal = document.forms[0].elements["status_value"].value;

		if(radioVal == 2)
		{
			if((isEmpty(fav1))||(isEmpty(fav2)) || (isEmpty(fav3)) || (isEmpty(fav4)) || (isEmpty(fav5)) || (isEmpty(fav6)))
			{
				alert('Enter Proper Product Key');
				return false;
			}
			var productkey=fav1+fav2+fav3+fav4+fav5+fav6;
			document.forms[0].elements["productkey"].value=productkey;
		}

		var cn=document.forms[0].elements["companyName"].value;
		if(!checkBlankAndWild(cn))
		{
			alert ('Enter valid Company Name ');
			return false;
		}
	}

	//if (!confirm("System is going to reboot. Are you okay with your settings?"))
	//{
	//	return false;
	//}
        return true;
}

function isValidIPAddressNoAlert(ipaddr)
{
        var re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	if (isEmpty(ipaddr))
	{
		return false;
	}

        if (re.test(ipaddr))
        {
                var parts = ipaddr.split(".");
                if (parseInt(parseFloat(parts[0])) == 0)
		{
			return false;
		}
                for (var i=0; i<parts.length; i++)
                {
                        if (parseInt(parseFloat(parts[i])) > 255)
			{
				return false;
			}
                }
                return true;
        }
        else
        {
                return false;
        }
}




function isValidIPAddress(ipaddr)
{
        var re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
	if (isEmpty(ipaddr))
	{
		//alert('IP Address is empty');
		return false;
	}

        if (re.test(ipaddr))
        {
                var parts = ipaddr.split(".");
                if (parseInt(parseFloat(parts[0])) == 0)
		{
			//alert('Please enter a valid IP Address');
			return false;
		}
                for (var i=0; i<parts.length; i++)
                {
                        if (parseInt(parseFloat(parts[i])) > 255)
			{
				//alert('Please enter a valid IP Address');
				return false;
			}
                }
                return true;
        }
        else
        {
		//alert('Please enter a valid IP Address');
                return false;
        }
}

function isValidMask(mask)
{
        //m[0] can be 128, 192, 224, 240, 248, 252, 254, 255
        //m[1] can be 128, 192, 224, 240, 248, 252, 254, 255 if m[0] is 255, else m[1] must be 0
        //m[2] can be 128, 192, 224, 240, 248, 252, 254, 255 if m[1] is 255, else m[2] must be 0
        //m[3] can be 128, 192, 224, 240, 248, 252, 254, 255 if m[2] is 255, else m[3] must be 0

	var correct_range = {128:1,192:1,224:1,240:1,248:1,252:1,254:1,255:1,0:1};
	var m = mask.split('.');

	for (var i = 0; i <= 3; i ++) {
		if (!(m[i] in correct_range)) {
			return false;
			break;
		}
	}
	
	if ((m[0] == 0) || (m[0] != 255 && m[1] != 0) || (m[1] != 255 && m[2] != 0) || (m[2] != 255 && m[3] != 0)) {
			return false;
	}
	
	return true;



/*        var re = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
		if (isEmpty(ipaddr))
		{
			alert('Subnet mask is empty');
			return false;
		}
        if (re.test(ipaddr))
        {
                var parts = ipaddr.split(".");
                if (parseInt(parseFloat(parts[0])) == 0)
				{
					alert('Please enter an valid subnet mask');
					return false;
				}
                for (var i=0; i<parts.length; i++)
                {
                        if (parseInt(parseFloat(parts[i])) > 255)
						{
							alert('Please enter an valid subnet mask');
							return false;
						}
                }
                return true;
        }
        else
        {
			alert('Please enter an valid subnet mask');
            return false;
        }*/
}

function isConfirm()
{
        if(confirm("Are you sure to change to factory Reset State?"))
                return true;
        else
                return false;
}
function RecoverPin(form)
{
  	//document.forms[1].type.value=8;

	if(document.forms[1].check.length > 0)
	{
		var j=0;
		for(var i = 0; i < document.forms[1].check.length;i++)
		{
			if(document.forms[1].check[i].checked)
				j++;

		}
		if(j > 1)
		{
			alert('Please select only one User for Reset Passphrase');
			return false;
		}

		if( j==0)
		{
			alert('Please select User for Reset Passphrase');
			return false;
		}
		else
		{
			if(userVerification(this.form))
				return true;
			else return false;
		}

	}
	else
	{
		if(document.forms[1].check.checked)
		{
			if(userVerification(this.form))
				return true;
			else return false;
		}
	}
	alert('Please select User for Reset Passphrase');
	return false;
}

function userVerification(form)
{
	var cnt=0;
	var elementLen=document.forms[1].elements.length;
	var checkLen=document.forms[1].check.length;
	for(var i = 0; i < checkLen;i++)
	{
		if(document.forms[1].check[i].checked)
		{
			for(var j = 0; j < elementLen;j++)
			{
				var fieldName=document.forms[1].elements[j].name;
				var fieldcheck='check';
				if(fieldName==fieldcheck)
				{
					if(i==cnt)
					{
						var EName=document.forms[1].elements[j+1].value;
					//	var Eid=document.forms[1].elements[j+2].value;
					var Eid=document.forms[1].elements[j+3].value;
					//var msg='You want to recover pin of '+EName +' having UserId '+Eid;
					var msg='You want to reset the passphrase of user '+EName+'. A new passphrase will be generated and sent to user\'s registered email ID. ';
				//		var msg='You want to recover pin of '+EName +' having UserId '+Eid;
                        			if(confirm(msg)==true)
						{
						//	var str='genSeal.cgi?type=1&EnrolleeID='+Eid+'&EName='+EName;
							var str='genSeal.cgi?type=1&registerID='+Eid;
        						window.location.href=str;
							return true;
						}
                        			else return false;
					}
					cnt++;
				}
			}

		}
	}
	if(document.forms[1].check.checked)
	{
		for(var j = 0; j < elementLen;j++)
		{
			var fieldName=document.forms[1].elements[j].name;
			var fieldcheck='check';
			if(fieldName==fieldcheck)
			{
				if(i==cnt)
				{
					var EName=document.forms[1].elements[j+1].value;
			//		var Eid=document.forms[1].elements[j+2].value;
					var Eid=document.forms[1].elements[j+3].value;
					//var msg='You want to recover pin of '+EName +' having UserId '+Eid;
					var msg='You want to reset the passphrase of user '+EName+'. A new passphrase will be generated and sent to user\'s registered email ID. ';
					//var msg='You want to recover password of User having UserId '+EName;
                       			if(confirm(msg)==true)
					{
					//	var str='genSeal.cgi?type=1&EnrolleeID='+Eid+'&EName='+EName;
						var str='genSeal.cgi?type=1&registerID='+Eid;
        					window.location.href=str;
						return true;
					}
                       			else return false;
				}
				cnt++;
			}
		}
	}
	return false;
}

function productVer(form,ID)
{
	var id1=document.forms[0].ID1.name;
	var id2=document.forms[0].ID2.name;
	var id3=document.forms[0].ID3.name;
	var id4=document.forms[0].ID4.name;
	var id5=document.forms[0].ID5.name;
	var id6=document.forms[0].ID6.name;
	var IDlen=ID.value.length;
	var IDnext
	var maxLen=3;
	if(ID.name==id1)
		IDnext=document.forms[0].ID2;
	if(ID.name==id2)
		IDnext=document.forms[0].ID3;
	if(ID.name==id3)
		IDnext=document.forms[0].ID4;
	if(ID.name==id4)
		IDnext=document.forms[0].ID5;
	if(ID.name==id5)
		IDnext=document.forms[0].ID6;
	if(ID.name==id6)
	{
		maxLen=5;
		if(IDlen > maxLen)
			return false;
	}

	if(IDlen > maxLen)
	{
		IDnext.focus();
		return false;
	}
	return true;

}

function verifyApplicationAuto(form)
{
	var count=0;
	var stuff=0;
	var j=0;

	var dis=0;
	//displayElements(this.form);
	if(!verifyApplicationFirst(this.form))
		return false;
	CheckForSelectedAppGrp(this.form);
	var str1=document.forms[0].elements["FormString"].value;
	document.forms[0].elements["type"].value=2;
	var ty=document.forms[0].elements["type"].value;
	document.forms[0].elements["FormString"].value='';
	document.forms[0].submit();
	window.opener.location.href=str1;
	//window.opener.focus();
	//window.opener.reload();
	return true;

}

function CancelRequest(form)
{
  document.forms[0].type.value=4;
	document.forms[0].submit();

}

function verifyCAcertForm(form)
{
	var PrivKey = form.CAPrivateKey.value;
    var CACert  = form.CACertificate.value;

	if (isEmpty(CACert))
	{
		alert('Enter CA Certificate');
		return false;
	}
	else
	{
    	var CACertIdx = parseInt(CACert.lastIndexOf('.'));
		var name2 = CACert.substring(CACertIdx+1);
		if(name2 != 'cer')
		{
			alert(' Enter CA Certificate extension as .cer');
			return false;
		}
	}

	if (isEmpty(PrivKey))
	{
		alert('Enter CA Private Key');
		return false;
	}
	else
	{
		var PrivKeyIdx = parseInt(PrivKey.lastIndexOf('.'));
		var name3 = PrivKey.substring(PrivKeyIdx+1);
		if((name3 != 'pem') && (name3 != 'key'))
		{
			alert(' Enter CA Private Key extension as .pem or .key');
			return false;
		}
	}
	return true;
}

function verifyUploadCertForm(form)
{
var PFXCert=form.Certificate.value;
        var CACert=form.CACertificate.value;
        var PinVal=form.Pin.value;
        var Address=form.RemoteHostAddress.value;


        if (isEmpty(CACert))
        {
                        alert('Enter CA Certificate');
                        return false;
        }
  else
  {
    var CACertIdx = parseInt(CACert.lastIndexOf('.'));
    var name2=CACert.substring(CACertIdx+1);
    if(name2 != 'cer')
    {
      alert(' Enter CA Certificate extension as .cer');
      return false;
    }
  }

 if (isEmpty(PFXCert))
        {
                        alert('Enter PFX Certificate');
                        return false;
        }
	 else
  {
    var PFXCertIdx = parseInt(PFXCert.lastIndexOf('.'));
    var name3=PFXCert.substring(PFXCertIdx+1);
    if(name3 != 'pfx')
    {
      alert(' Enter PFX Certificate extension as .pfx');
      return false;
    }
  }

        if (isEmpty(PinVal))
        {
                        alert('Enter PIN');
                        return false;
        }

        if (isEmpty(Address))
        {
                        alert('Enter Remote Host Address');
                        return false;
        }
}


function NoRightClick()
{

	var msg = "Right click on this link is not allowed.";
	if (event.button==2)
	{
		alert(msg);
		return false;
	}
	else
	{
		event.returnValue= false;
		return true;
	}
}

function isProperDN(s)
{
	var i;
	if (isEmpty(s))
		return false;

	for (i = 0; i < s.length; i++)
	{
		var c = s.charAt(i);
		if (! (isLetter(c) || isDigit(c)|| isFullStop(c) || isCharacter(c) || isSpace(c) ||isCommaEqualTo(c)))
		return false;
	}
	return true;
}

function ResetIPForm(form)
{
	//document.forms[0].reset();

	var status_val = document.forms[0].prev_status.value;

	if(status_val==0)
	{
		document.forms[0].elements["status_value"].value=0;
		document.forms[0].elements["status_en_value"].value=0;
		document.forms[0].elements["status_dis_value"].value=0;
		document.forms[0].elements["status_en_1"].disabled=true;
		document.forms[0].elements["status_en_2"].disabled=true;
		document.forms[0].elements["status_dis_1"].disabled=true;
		document.forms[0].elements["status_dis_2"].disabled=true;
	}

	if(status_val==1)
	{
		document.forms[0].elements["status_en_1"].checked=false;
		document.forms[0].elements["status_en_2"].checked=false;
	}

	if(status_val==2)
	{
		document.forms[0].elements["status_dis_1"].checked=false;
		document.forms[0].elements["status_dis_2"].checked=false;
	}

	document.forms[0].elements["ip_policy_name"].value="";
	form.list_ipaddresses.length=0;
}



function ResetMACForm(form)
{
	//document.forms[0].reset();

	var status_val = document.forms[0].prev_status.value;

	if(status_val==0)
	{
		document.forms[0].elements["status_value"].value=0;
		document.forms[0].elements["status_en_value"].value=0;
		document.forms[0].elements["status_dis_value"].value=0;
		document.forms[0].elements["status_en_1"].disabled=true;
		document.forms[0].elements["status_en_2"].disabled=true;
		document.forms[0].elements["status_dis_1"].disabled=true;
		document.forms[0].elements["status_dis_2"].disabled=true;
	}

	if(status_val==1)
	{
		document.forms[0].elements["status_en_1"].checked=false;
		document.forms[0].elements["status_en_2"].checked=false;
	}

	if(status_val==2)
	{
		document.forms[0].elements["status_dis_1"].checked=false;
		document.forms[0].elements["status_dis_2"].checked=false;
	}

	document.forms[0].elements["mac_policy_name"].value="";
	form.list_macaddresses.length=0;
}

function ResetAll(form)
{
	document.forms[0].reset();
/*
	var mySlength=document.forms[0].mySelectDisable.length;
	if(mySlength > 0)
	{
		for(var i=0;i<mySlength;i++)
		{
			document.forms[0].mySelectDisable.options[i].text='';
			document.forms[0].mySelectDisable.options[i].value='';
		}
	}
*/
	document.forms[0].elements["user_role"].disabled=false;
	document.forms[0].elements["user_id"].disabled=false;
	document.forms[0].elements["user_password"].disabled=false;

}

function ResetAllTemp(form)
{
   document.forms[0].reset();
   var mySlength=document.forms[0].mySelectDisable.length;
   if(mySlength > 0)
   {
       for(var i=0;i<mySlength;i++)
       {
       		 /*if(document.forms[0].user_ldapcheck.checked==true)
	         {
			if(document.forms[0].user_role.value!="4")
                     	{
                     		alert("only Low Security Users are allowed");
                     		return false;
                     	}
   		}*/
           document.forms[0].mySelectDisable.options[i].text='';
           document.forms[0].mySelectDisable.options[i].value='';

       }
   }
}

function SubmitKey(form)
{
	/*var fav1=document.forms[0].elements["ID1"].value;
	var fav2=document.forms[0].elements["ID2"].value;
	var fav3=document.forms[0].elements["ID3"].value;
	var fav4=document.forms[0].elements["ID4"].value;
	var fav5=document.forms[0].elements["ID5"].value;
	if((isEmpty(fav1))||(isEmpty(fav2)) || (isEmpty(fav3)) || (isEmpty(fav4)) || (isEmpty(fav5)))
	{
		alert('Enter Proper Old Product Key');
		return false;
	}
	var oldproductkey=fav1+fav2+fav3+fav4+fav5;
	document.forms[0].elements["oldproductkey"].value=oldproductkey;
*/
	var fav1=document.forms[0].elements["NID1"].value;
	var fav2=document.forms[0].elements["NID2"].value;
	var fav3=document.forms[0].elements["NID3"].value;
	var fav4=document.forms[0].elements["NID4"].value;
	var fav5=document.forms[0].elements["NID5"].value;
	var fav6=document.forms[0].elements["NID6"].value;
	if((isEmpty(fav1))||(isEmpty(fav2)) || (isEmpty(fav3)) || (isEmpty(fav4)) || (isEmpty(fav5)) || (isEmpty(fav6)))
	{
		alert('Enter Proper New Product Key');
		return false;
	}
	var newproductkey=fav1+fav2+fav3+fav4+fav5+fav6;
	//if(newproductkey==oldproductkey)
	//{
	//	alert('Old Product Key and New Product Key cannot be same');
	//	return false;
	//}
	document.forms[0].elements["newproductkey"].value=newproductkey;
	var cn=document.forms[0].elements["companyName"].value;
	if(!checkBlankAndWild(cn))
	{
		alert ('Enter valid Company Name ');
		return false;
	}
	return true;

}

function productVerNew(form,NID)
{
	var id1=document.forms[0].NID1.name;
	var id2=document.forms[0].NID2.name;
	var id3=document.forms[0].NID3.name;
	var id4=document.forms[0].NID4.name;
	var id5=document.forms[0].NID5.name;
	var id6=document.forms[0].NID6.name;
	var IDlen=NID.value.length;
	var IDnext
	var maxLen=3;
	if(NID.name==id1)
		IDnext=document.forms[0].NID2;
	if(NID.name==id2)
		IDnext=document.forms[0].NID3;
	if(NID.name==id3)
		IDnext=document.forms[0].NID4;
	if(NID.name==id4)
		IDnext=document.forms[0].NID5;
	if(NID.name==id5)
		IDnext=document.forms[0].NID6;
	if(NID.name==id6)
	{
		maxLen=5;
		if(IDlen > maxLen)
			return false;
	}

	if(IDlen > maxLen)
	{
		IDnext.focus();
		return false;
	}
	return true;
}

function isDate(dtStr)
{
        for (var i = 1; i <= 12; i++)
        {
                this[i] = 31;
                if (i==4 || i==6 || i==9 || i==11)
                {
                        this[i] = 30;
                }
                if (i==2)
                {
                        this[i] = 29;
                }
        }
        var daysInMonth = this;
        var pos1=dtStr.indexOf(dtCh);
        var pos2=dtStr.indexOf(dtCh,pos1+1);
        var strMonth=dtStr.substring(0,pos1);
        var strDay=dtStr.substring(pos1+1,pos2);
        var strYear=dtStr.substring(pos2+1);
        var febday;
        strYr=strYear;
        if (strDay.charAt(0)=="0" && strDay.length>1) strDay=strDay.substring(1);
        if (strMonth.charAt(0)=="0" && strMonth.length>1) strMonth=strMonth.substring(1);
        for (var i = 1; i <= 3; i++)
        {
                if (strYr.charAt(0)=="0" && strYr.length>1) strYr=strYr.substring(1);
        }
        month=parseInt(strMonth);
        day=parseInt(strDay);
        year=parseInt(strYr);
        febday = (((year % 4 == 0) && ( (!(year % 100 == 0)) || (year % 400 == 0))) ? 29 : 28 );

        if (strDay.length<1 || day<1 || day>31 || (month==2 && day>febday) || day > daysInMonth[month])
        {
                alert("Please enter a valid day");
                return false;
	}
        return true;
}
function check1(e)
{
if (e.match(/[\&\?\!\#-\'\*\+\--9\=\?A-Z\^-\~\%]+\@[\&\?\!\#-\'\*\+\--9\=\?A-Z\^-\~\%]+\.[\%\&\?\!\#-\'\*\+\--9\=\?A-Z\^-\~]{2,3}/) != e)
	return false;
	else
	return true;
}

function configure(form)
{
	var virtual_ip = document.forms[0].elements["PriLVSIP"].value;
	var netmask_ip = document.forms[0].elements["vip_nmask"].value;
	var primary_ip = document.forms[0].elements["PriPubIP"].value;
	var backup_ip = document.forms[0].elements["backupIP"].value;
	var device_name = document.forms[0].elements["deviceName"].value;
	if((isEmpty(virtual_ip)) || (isEmpty(primary_ip)) || (isEmpty(backup_ip)) || (isEmpty(device_name)))
	{
		alert('Enter value for all the fields');
		return false;
	}

	if(!isValidIPAddress(virtual_ip)) {alert("Enter valid virtual IP"); return false; }
	if(!isValidIPAddress(primary_ip)) {alert("Enter valid IP for Primary Load Balancer"); return false; }
	if(!isValidIPAddress(backup_ip)) {alert("Enter valid IP for Backup Load Balancer"); return false; }
	
	if((virtual_ip == primary_ip) || (primary_ip == backup_ip) || (virtual_ip == backup_ip)) {
		alert("IP Address repeated"); return false;
	}

	return true;
}

function advance(form)
{
	var heartbeat = document.forms[0].elements["hb_interval"].value;
	var dead_time = document.forms[0].elements["dead_after"].value;
	var heartbeat_port = document.forms[0].elements["hb_port"].value;
	var re_entry = document.forms[0].elements["reentry"].value;
	var service_timeout = document.forms[0].elements["timeout"].value;
	var persistence = document.forms[0].elements["persistent"].value;

	if((isEmpty(heartbeat))||(isEmpty(dead_time)) || (isEmpty(heartbeat_port)) || (isEmpty(re_entry)) || (isEmpty(service_timeout)) || (isEmpty(persistence)))
	{
		alert('Enter value for all the fields');
		return false;
	}

	if(!isNum(heartbeat)) {alert("Enter Positive integer value for Heartbeat interval field"); return false; }
	if(!isNum(dead_time)) {alert("Enter Positive integer value for Assume Dead After field"); return false; }
	if(!isNum(heartbeat_port)) {alert("Enter Positive integer value for Heartbeat Port NO. field"); return false; }
	if(!isNum(re_entry)) {alert("Enter Positive integer value for Re-entry Time field"); return false; }
	if(!isNum(service_timeout)) {alert("Enter Positive integer value for Service Timeout field"); return false; }
	if(!isNum(persistence)) {alert("Enter Positive integer value for Persistence field"); return false; }

	if(!(heartbeat >=5 && heartbeat <= 180)) { alert("Enter Positive integer value between 5-180 for Heartbeat interval field"); return false;}
	if(!(dead_time >=5 && dead_time <= 180)) { alert("Enter Positive integer value between 5-180 for dead after field"); return false;}
	if(!(heartbeat_port <=65536)) { alert("Enter Positive integer value less than 65536 for Heartbeat port field"); return false;}
	if(!(re_entry >=5 && re_entry <= 180)) { alert("Enter Positive integer value between 5-180 for re-entry time field"); return false;}
	if(!(service_timeout >=5 && service_timeout <= 180)) { alert("Enter Positive integer value between 5-180 for service timeout field"); return false;}
	if(!(persistence >=5 && persistence <= 120)) { alert("Enter Positive integer value between 5-120 for persistence field"); return false;}

	return true;
}
function real(form)
{
	var server_name = document.forms[0].elements["name"].value;
	var address = document.forms[0].elements["address"].value;
	var weight = document.forms[0].elements["weight"].value;

	if((isEmpty(server_name))||(isEmpty(address)) || (isEmpty(weight)))
	{
		alert('Enter value for all the fields');
		return false;
	}
	if(server_name == "[unnamed]") {alert("server name must be changed");return false;}
	if(!(isAlphanumeric(server_name))) {alert("server name must be AlphaNumeric");return false;}
	if(address == "0.0.0.0") {alert("address may not be 0.0.0.0");return false;}
	if(!isNumber(weight)) {alert("Enter Positive integer value for weight field"); return false; }
	if(!isValidIPAddress(address)) {alert("Enter valid IP address"); return false; }
	return true;
}
