<?php 
$str1 = "Hello";
$str2 = "hello";
echo strcmp($str1,$str2);
if(strcmp($str1,$str2)==0) 
{
	echo "matching";
}
else
{
	echo "not matching";
}
