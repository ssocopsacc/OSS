#include <stdio.h>
#include <stdint.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <curl/curl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>

#ifndef __USE_XOPEN_EXTENDED
# define __USE_XOPEN_EXTENDED
#endif

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>

#define SUCCESS 		1
#define FAILED			0

#ifndef NAME
#define NAME "ldap_proxy_otp"
#endif

#ifndef VERS
#define VERS "0.3.3"
#endif

#ifndef USER_AGENT
#define USER_AGENT NAME "/" VERS
#endif

#define debug(fmt, args...)      \
{\
		FILE *file_for_debug;   \
		struct stat filestat;   \
		if(0 == stat("/var/log/ads.log",&filestat)) \
		{       \
			file_for_debug = fopen("/var/log/ads.log", "ab+"); \
			if(file_for_debug) \
			{ \
				char sTime[32] = {0}; \
				time_t tNow = time(NULL); \
				strftime(sTime, sizeof(sTime)-1, "%d-%b-%Y %H:%M:%S", localtime(&tNow)); \
				fprintf(file_for_debug, "pid:%d(0x%x) %s " fmt "\n", getpid(), pthread_self(), sTime,##args); \
				fclose(file_for_debug); \
			} \
		} \
}

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

struct MemoryStruct {
	char* recvbuf;
	size_t recvbuf_size;
};

int load_confdetails();
int send_requestwithotp(char* username, int authdomainid, char* password, char* agentid, char* otptype, char* otpval, struct MemoryStruct* chunk,char* serverIp, int serverPort);
int send_request(char* username, int authdomainid, char* password, char* agentid, char* serverIp, int serverPort,struct MemoryStruct* chunk);
int pasre_response(struct MemoryStruct* chunk);
int do_otpauth(char* username,char* password, char* otpval);
int do_hyidauth(char* username, char* password);

	// vars
	//int authdomainid;
	//xmlChar *xmlbuffer = NULL;
	//int buffersize = -1;

static const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64encode_len(int len)
{
	return ((len + 2) / 3 * 4) + 1;
}

int Base64encode(char *encoded, const char *string, int len)
{
	int i;
	char *p;

	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		*p++ = basis_64[((string[i] & 0x3) << 4) |
			((int) (string[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
			((int) (string[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[string[i + 2] & 0x3F];
	}
	if (i < len) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		}
		else {
			*p++ = basis_64[((string[i] & 0x3) << 4) |
				((int) (string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return p - encoded;
}
/*
static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *stream) 
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL) {
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}
*/
size_t curl_wf(void *ptr, size_t size, size_t nmemb, void *s)
{
	size_t lastdataendptr = 0;

	struct MemoryStruct* stream = (struct MemoryStruct* )s;

	if(!stream)
		return 0;

	debug("curl_wf called !!");
	debug("curl_wf data: %s",ptr);
	
	if(0 == size*nmemb)
	{
		debug("size*nmemb is zero, size %d, nmemb %d", size, nmemb);
		return 0;
	}
	
	if(((nmemb * size) > (SIZE_MAX / nmemb)) ||
			((SIZE_MAX - stream->recvbuf_size) < (nmemb * size))) 
	{
		debug("size checks failed.");
		return 0;
	}
	
	if(!stream->recvbuf)
	{
		stream->recvbuf_size = 0;
		debug("recv buf is null, allocating, recvbuf_size during allocation %d", stream->recvbuf_size);
		if(!(stream->recvbuf = (char* )realloc(stream->recvbuf, (nmemb*size)+1)))
		{
			debug("recv buf allocation has failed.");
			return 0;
		}
		else
		{
			memset(stream->recvbuf, 0, (nmemb*size)+1);
			memcpy(stream->recvbuf, ptr, size*nmemb);
			stream->recvbuf_size = (nmemb*size);
			stream->recvbuf[stream->recvbuf_size] = 0;

			return(size*nmemb);
		}
	}

	if(!(stream->recvbuf = (char* )realloc(stream->recvbuf, stream->recvbuf_size + (nmemb * size))))
	{
		debug("recv buff's reallocation failed.");
		return 0;
	}
	else
	{
		debug("realloc success, appending more bytes to existing buffer.");
		lastdataendptr = stream->recvbuf_size;
		stream->recvbuf_size += (nmemb*size);
		memcpy(stream->recvbuf + lastdataendptr, ptr, size*nmemb);
		stream->recvbuf[stream->recvbuf_size] = 0;
		
		return(size*nmemb);
	}
}

bool docurlInitialization(CURL** eh, bool ishttps)
{
	debug("Inside docurlInitialization");
	if(ishttps)
	{
		if(0 != curl_global_init(CURL_GLOBAL_ALL))
		{
			debug("curl_global_init failed");
			return false;
		}
	}

	if(NULL == (*eh = curl_easy_init()))
	{
		debug("curl_easy_init failed!");
		return false;
	}

	debug("Value of https here is %d",ishttps);

	if(ishttps)
	{
		debug("Initializing SSL");
		curl_easy_setopt(*eh, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(*eh, CURLOPT_SSL_VERIFYHOST, 0);
	}
	
	debug("Leaving docurlInitialization, returning true")
	return true;
}

bool docurlSetOptions(CURL* eh, const char* url, char *post, struct MemoryStruct* chunk)
{

	/*	if( 1 == pam_otp_debug)
		{
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_VERBOSE, 1) )
		{
		debug(pamh,"curl_easy_setopt(eh, CURLOPT_VERBOSE, 1) failed.");
		return false;
		}

		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_DEBUGDATA, pamh) )
		{
		debug(pamh,"curl_easy_setopt(eh, CURLOPT_DEBUGDATA, pamh) failed.");
		return false;
		}
		if( CURLE_OK != curl_easy_setopt(eh, CURLOPT_DEBUGFUNCTION, curl_debug) )
		{
		debug(pamh,"curl_easy_setopt(eh, CURLOPT_DEBUGFUNCTION, curl_debug) failed.");
		return false;
		}
		}
		*/

	if(CURLE_OK != curl_easy_setopt(eh, CURLOPT_POSTFIELDS, post))
	{
		debug("curl_easy_setopt(eh, CURLOPT_POSTFIELDS, post) failed.");
		return false;
	}

	if(CURLE_OK != curl_easy_setopt(eh, CURLOPT_USERAGENT, USER_AGENT))
	{
		debug("curl_easy_setopt(eh, CURLOPT_USERAGENT, USER_AGENT) failed.");
		return false;
	}

	if(CURLE_OK != curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, curl_wf))
	{
		debug("curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, curl_wf) failed.");
		return false;
	}

	if(CURLE_OK != curl_easy_setopt(eh, CURLOPT_WRITEDATA, (void *)chunk))
	{
		debug("curl_easy_setopt(eh, CURLOPT_WRITEDATA, &chunk) failed.");
		return false;
	}

	if(CURLE_OK != curl_easy_setopt(eh, CURLOPT_URL, url))
	{
		debug("curl_easy_setopt(eh, CURLOPT_URL, url) failed.");
		return false;
	}

	if(CURLE_OK != curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, false))
	{
		debug("curl_setopt(eh, CURLOPT_SSL_VERIFYPEER, false) failed.");
		return false;
	}

	if(CURLE_OK != curl_easy_setopt(eh, CURLOPT_FAILONERROR, 1))
	{
		debug("curl_easy_setopt(eh, CURLOPT_FAILONERROR, 1) failed.");
		return false;
	}

	return true;
}

bool docurlAction(CURL* eh)
{
	debug("Inside docurlAction");
	int ret = curl_easy_perform(eh);
	if(ret != CURLE_OK)
	{

		debug("curl_easy_perform failed!");
		char msg[128] = {0};
		sprintf(msg,"curl action failed, response code is: %d", ret);
		debug("%s", msg);
		debug("%s", curl_easy_strerror(ret));
		return false;
	}

	debug("Leaving docurlAction, returning true");
	return true;
}

int createOTPXMLbuff(xmlChar **pxmlbuff, int *buffersize, char* user, char* passwd, char* agentid, int authdomainid, char* otp)
{
	xmlDocPtr doc = NULL;       /* document pointer */
	xmlNodePtr root_node = NULL, node = NULL, node1 = NULL;/* node pointers */
	xmlDtdPtr dtd = NULL;       /* DTD pointer */
	char buff[256];
	char encodedPass[256] = {0};
	char encodedUsername[256] = {0};
	int i, j;
	char domainid[16] = {0};

	sprintf(domainid, "%d", authdomainid);
	Base64encode(encodedPass,passwd,strlen(passwd));
	Base64encode(encodedUsername,user,strlen(user));

	pthread_mutex_lock( &mutex1 );
	LIBXML_TEST_VERSION;

	doc = xmlNewDoc(BAD_CAST "1.0");
	if(doc)
	{
		root_node = xmlNewNode(NULL, BAD_CAST "FCS");
		if(root_node)
		{
			xmlDocSetRootElement(doc, root_node);

			xmlNewChild(root_node, NULL, BAD_CAST "authdomainid", BAD_CAST domainid);
			xmlNewChild(root_node, NULL, BAD_CAST "UserName", BAD_CAST encodedUsername);
			xmlNewChild(root_node, NULL, BAD_CAST "Password", BAD_CAST encodedPass);
			xmlNewChild(root_node, NULL, BAD_CAST "agentID", BAD_CAST agentid);
			xmlNewChild(root_node, NULL, BAD_CAST "oobotpchannel", BAD_CAST "5");
			xmlNewChild(root_node, NULL, BAD_CAST "otpval", BAD_CAST otp);

			xmlChar *xmlbuff = NULL;
			xmlDocDumpFormatMemory(doc, &xmlbuff, buffersize, 1);
			if(xmlbuff)
				*pxmlbuff = xmlbuff;
			else
			{
				pthread_mutex_unlock( &mutex1 );
				return FAILED;
			}
		}

		if(doc)
		{
			xmlFreeDoc(doc);
			doc = NULL;
		}
	}

	pthread_mutex_unlock( &mutex1 );
	return SUCCESS;
}

int createXMLbuff(xmlChar **pxmlbuff, int *buffersize, char* user, char* passwd, char* agentid, int authdomainid)
{
	xmlDocPtr doc = NULL;       /* document pointer */
	xmlNodePtr root_node = NULL, node = NULL, node1 = NULL;/* node pointers */
	xmlDtdPtr dtd = NULL;       /* DTD pointer */
	char buff[256];
	char encodedPass[256] = {0};
	char encodedUsername[256] = {0};
	int i, j;
	char domainid[16] = {0};

	sprintf(domainid, "%d", authdomainid);
	Base64encode(encodedPass,passwd,strlen(passwd));
	Base64encode(encodedUsername,user,strlen(user));

	pthread_mutex_lock( &mutex1 );
	LIBXML_TEST_VERSION;

	doc = xmlNewDoc(BAD_CAST "1.0");
	if(doc)
	{
		root_node = xmlNewNode(NULL, BAD_CAST "FCS");
		if(root_node)
		{
			xmlDocSetRootElement(doc, root_node);

			xmlNewChild(root_node, NULL, BAD_CAST "authdomainid", BAD_CAST domainid);
			xmlNewChild(root_node, NULL, BAD_CAST "UserName", BAD_CAST encodedUsername);
			xmlNewChild(root_node, NULL, BAD_CAST "Password", BAD_CAST encodedPass);
			xmlNewChild(root_node, NULL, BAD_CAST "agentID", BAD_CAST agentid);
			xmlNewChild(root_node, NULL, BAD_CAST "appname", BAD_CAST "HyWorks");
			xmlNewChild(root_node, NULL, BAD_CAST "ConsentAuth", "1");

			xmlChar *xmlbuff = NULL;
			xmlDocDumpFormatMemory(doc, &xmlbuff, buffersize, 1);
			if(xmlbuff)
				*pxmlbuff = xmlbuff;
			else
			{
				pthread_mutex_unlock( &mutex1 );
				return FAILED;
			}
		}
		
		if(doc)
		{
			xmlFreeDoc(doc);
			doc = NULL;
		}
	}
	
	pthread_mutex_unlock( &mutex1 );
	return SUCCESS;
}

int xml_cleanup(xmlDocPtr doc, xmlChar *key)
{
	if(doc != NULL)
	{
		xmlFreeDoc(doc);
		doc = NULL;
	}

	if(key != NULL)
	{
		xmlFree(key);
		key = NULL;
	}
}

void get_otp_response_status(int status)
{
	char* message = NULL;

	switch(status)
	{
		case 1:
			message = "All success";
			break;
		case -5:
			message = "Your Account is disabled. Please Contact your Administrator.";
			break;
		case -6:
			message = "Your Password has Expired. Please Change your password.";
			break;
		case -7:
			message = "User is failed to authenticate.";
			break;
		case -19:
			message = "User is failed to authenticate.";
			break;
		case -51:
			message = "Invalid data from client.";
			break;
		case -52:
			message = "Failed to get agentId.";
			break;
		case -53:
			message = "No such authentication domain exist.";
			break;
		case -54:
			message = "Failed to do password decode.";
			break;
		case -55:
			message = "Failed to get OTP settings.";
			break;
		case -56:
			message = "Failed to validate OTP.";
			break;
		case -57:
			message = "Failed to send OTP.";
			break;
		case -58:
			message = "Failed to fetch mail Id.";
			break;
		case -59:
			message = "Failed to fetch mail Id.";
			break;
		default:
			message = "Authentication failed. Please try again.";
			break;
	}

	debug("response status:");
	debug("%s", message);
}

int pasre_response(struct MemoryStruct* chunk)
{
	char msg[1024] = {0};
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL;
	xmlChar *key = NULL;
	unsigned char* otpmessage = NULL;
	int status = 0;

	debug("Response read as %s\nLength %d", chunk->recvbuf, strlen(chunk->recvbuf));

	if(chunk->recvbuf)
		doc = xmlParseMemory(chunk->recvbuf, strlen(chunk->recvbuf));
	if(doc)
		cur = xmlDocGetRootElement(doc);
	if(!cur)
	{
		debug("stderr: empty response");
		goto error;
	}

	if(xmlStrcmp(cur->name, (const xmlChar *) "FCS"))
	{
		debug("stderr: document of the wrong type, root node != FCS");
		goto error;
	}

	cur = cur->xmlChildrenNode;
	while(cur != NULL)
	{
		if((!xmlStrcmp(cur->name, (const xmlChar *)"STATUS")))
		{
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			if(key)
				status = atoi((const char* )key);
			debug("OTP response code read as %d", status);
			get_otp_response_status(status);	
		}

		if((!xmlStrcmp(cur->name, (const xmlChar *)"otpmessage")))
		{
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			if(key)
				otpmessage = key;
		}
#if 0		
		if((!xmlStrcmp(cur->name, (const xmlChar *)"MESSAGE")))
		{
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			if(key)
				message = key;
		}
#endif		

		cur = cur->next;
	}

	if(status == SUCCESS)
		goto success;
error:
	debug("Ret failed !!");
	xml_cleanup(doc,key);
	return FAILED;

success:
	debug("Ret success !!");
	xml_cleanup(doc,key);
	return SUCCESS;
}

int curl_cleanup(xmlChar *xmlbuffer, CURL* eh)
{
	if(eh != NULL)
		curl_easy_cleanup(eh);
	if(xmlbuffer != NULL)
	{
		xmlFree(xmlbuffer);
	}
}

#if 0
int loadserverdetails()
{
	FILE *stream;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;

	stream = fopen("/tmp/hyid_cred", "r");
	if(stream == NULL) 
	{
		debug("loadserverdetails: Failed to open file \"/tmp/hyid_cred\".");
		return 0;	
	}
	
	while((nread = getline(&line, &len, stream)) != -1) 
	{
		debug("loadserverdetails: Retrieved line of length %zu:\n", nread);
		switch(i)
		{
			case 0:

			case 1:

		}
	}

	free(line);
	fclose(stream);
}
#endif

int send_request(char* username, int authdomainid, char* password, char* agentid, char* serverip, int serverport,struct MemoryStruct* chunk)
{
	debug("Inside send_request");
	bool ishttps = false;
	char url[512] = {0};

	xmlChar *xmlbuffer = NULL;
	int buffersize = -1;
	CURL* eh = NULL;

	if(SUCCESS != createXMLbuff(&xmlbuffer, &buffersize, username, password, agentid, authdomainid))
	{
		debug("Error in createXMLbuff.");
		goto curl_error;
	}

	debug("Trying to connect %s:%d", serverip, serverport);
	if(serverip && (serverport != -1))
		sprintf(url, "https://%s:%d/fes-bin/OTPAuth.cgi", serverip, serverport);
	else
	{
		debug("No server or port specified.");
		goto curl_error;
	}

	ishttps = true;

	if(!eh)
	{
		debug("easyhandle NULL, initializing it.");
		if(!docurlInitialization(&eh, ishttps))
		{
			debug("Error in docurlInitialization.");
			goto curl_error;
		}
		debug("After docurlInitialization\n");
		if(!eh)
		{
			debug("eh handle is still NULL");
			goto curl_error;
		}
	}
	
	debug("Calling docurlSetOptions\n");	
	if(!docurlSetOptions(eh, url, (char*)xmlbuffer, chunk))
	{
		debug("docurlSetRequestHeader failed.");
		goto curl_error;
	}
	
	debug("Calling docurlAction\n");

	if(!docurlAction(eh))
	{
		debug("docurlAction failed.");
		goto curl_error;
	}

	if(chunk->recvbuf)
	{
		debug("Send OTP request success. Response buffer got filled with data");
		curl_cleanup(xmlbuffer, eh);
		return SUCCESS;
	}
	else
	{
		debug("Send OTP request failed. Response buffer is still NULL");
		curl_cleanup(xmlbuffer, eh);
		return FAILED;
	}

curl_error:
	debug("CURL Error.");
	curl_cleanup(xmlbuffer, eh);
	return FAILED;
}

int send_requestwithotp(char* username, int authdomainid, char* password, char* agentid, char* otptype, char* otpval, struct MemoryStruct* chunk,char* serverip, int serverport)
{
	bool ishttps = false;
	char url[512] = {0};

	xmlChar *xmlbuffer = NULL;
	int buffersize = -1;
	CURL* eh = NULL;

	if(SUCCESS != createOTPXMLbuff(&xmlbuffer, &buffersize, username, password, agentid, authdomainid, otpval))
	{
		debug("Error in createOTPXMLbuff.");
		goto curl_error;
	}

	if(serverip && (serverport != -1))
		sprintf(url, "https://%s:%d/fes-bin/OTPAuth.cgi", serverip, serverport);
	else
	{
		debug("No server or port specified.");
		// xmlbuffer is not freed, it should go to error 
		goto curl_error;
	}

	debug("curl url formed is [%s]", url);
	ishttps = true;

	if(!eh)
	{
		debug("easyhandle NULL, initializing it.");
		if(!docurlInitialization(&eh, ishttps))
		{
			debug("Error in docurlInitialization.");
			goto curl_error;
		}

		if(!eh)
		{
			debug("eh handle is still NULL");
			goto curl_error;
		}
	}

	if(!docurlSetOptions(eh, url, (char*)xmlbuffer, chunk))
	{
		debug("docurlSetRequestHeader failed.");
		goto curl_error;
	}

	if(!docurlAction(eh))
	{
		debug("docurlAction failed.");
		goto curl_error;
	}

	if(chunk->recvbuf)
	{
		debug("Send OTP request success. Response buffer got filled with data");
		curl_cleanup(xmlbuffer, eh);
		return SUCCESS;
	}
	else
	{
		debug("Send OTP request failed. Response buffer is still NULL");
		curl_cleanup(xmlbuffer, eh);
		return FAILED;
	}

curl_error:
	debug("CURL Error.");
	curl_cleanup(xmlbuffer, eh);
	return FAILED;
}

bool seekat(FILE* fp, int offset)
{

	if(!fseek(fp,offset,SEEK_CUR))
		return true;

	return false;

}

bool getValueOfKey(char** value,int length,FILE* fp)
{
	///debug("Inside getValueOfKey, balue is %s\n",*value);
	debug("Inside getValueOfKey, balue is %s\n",*value);
	if(fgets(*value,length,fp) == NULL)
	{
		debug("fgets returned NULL");

		if(feof){
			
			debug("eof reached for while reading ads_config file");
			return false;
		}

		if(ferror(fp))
		{

			debug("read error in ads_config file");
                        return false;
		}
	
	}
	
	debug("After reading , value is %s\n",*value);
	return true;


}
bool getAdminUserFromADSConfig(char* adminCN){

	FILE* fp = NULL;
	fp = fopen("./ads_config","r");
	if(fp == NULL){
		debug("file open failed\n");
		return false;
	}
	//errorlog

	debug("Inside getAdminUserFromADSConfig, before seek filepoints at %d\n",ftell(fp));	
	
	if(seekat(fp,11)){
		if(!getValueOfKey(&adminCN,40,fp))
			return false;

		adminCN[strlen(adminCN)-1]=0;

	}
	debug("after reading cn  filepoints at %d, and adminCN is %s",ftell(fp),adminCN);

	if(fclose(fp) == EOF){
		return false;//returns 0 on success//fclose causes any buffered output to be written (possibly using fflush) and then closes th
		debug("fclose failed");
	}

	return true;

}


bool getADSConfigDetails(char* ipAddress,char* portNum, char* authDomain, char* tokenType, char* agentId)
{
	FILE* fp = NULL;
	fp = fopen("./ads_config","r");
	if(fp == NULL){
		debug("file open falied\n");
	}
	//errorlog

	debug("before seek filepoints at %d\n",ftell(fp));	
	
	char temp[128]={0};	
	//to skip reading first line of config file
	
	if(fgets(temp,100,fp) == NULL )
	{
		debug("eof reached/read error in file ads_config");
		return false;
	}
	
	debug("after seek to 2nd line filepoints at %d\n",ftell(fp));	
	
	if(seekat(fp,11)){

		if(!getValueOfKey(&ipAddress,20,fp))//n-1 chars are read
			return false;

		ipAddress[strlen(ipAddress)-1]=0;


	}
		
	debug("after reading ip filepoints at %d\n",ftell(fp));
		
	if(seekat(fp,13)){

		if(!getValueOfKey(&portNum,10,fp))//we want to read max 5 chars
			return false;
		portNum[strlen(portNum)-1]=0;
	
	}

	
	debug("after reading port filepoints at %d\n",ftell(fp));
	if(seekat(fp,13)){

		if(!getValueOfKey(&authDomain,20,fp))
			return false;
		authDomain[strlen(authDomain)-1]=0;
	}

	debug("after reading domsin filepoints at %d\n",ftell(fp));

	if(seekat(fp,10)){

		if(!getValueOfKey(&tokenType,20,fp))
			return false;
		tokenType[strlen(tokenType)-1]=0;

	}
	debug("after reading tt filepoints at %d\n",ftell(fp));

	if(seekat(fp,6)){

		if(!getValueOfKey(&agentId,40,fp))
			return false;
		agentId[strlen(agentId)-1]=0;


	}
	debug("after reading cn  filepoints at %d\n",ftell(fp));

	//eof would be set only if that character was read(requested)// not if just reached
	if(fclose(fp) == EOF)//returns 0 on success//fclose causes any buffered output to be written (possibly using fflush) and then closes strm
		debug("fclose failed");

	//errlog
	//ferror,feof,clearerr
	return true;

}

int do_otpauth(char* username,char* password, char* otpval)
{
	struct MemoryStruct chunk;
	
	chunk.recvbuf = NULL;
	chunk.recvbuf_size = 0;
	char authDomainId[20]={0};
	char agentid[30]={0};
	char otptype[20]={0};
	char serverIp[20]={0};
	char serverPort[10]={0};	
	
	if(!getADSConfigDetails(serverIp,serverPort,authDomainId,otptype,agentid))
	{
		debug("Failed to read config details from ads_config");

	}
	
	int authdomainid = atoi(authDomainId);
	int serverport = atoi(serverPort);

	debug("Inside otpauth. Username %s, password %s, authdomainid %d, agentid %s, otp %s, otptype %s, serverIp %s, serverPort %d", username, password, authdomainid, agentid, otpval,otptype, serverIp,serverport);
	
	if(send_requestwithotp(username, authdomainid, password, agentid, otptype, otpval, &chunk,serverIp,serverport))
	{
		if(chunk.recvbuf)
		{
			if(pasre_response(&chunk))
			{
				debug("OTP is successfully validated with server.");
				return 1;
			}
			else
				debug("pasre_response failed / OTP validation failed.");
		}
		else
			debug("chunk.recvbuf is NULL, failed.");	
	}
	else
		debug("send_requestwithotp failed.");

	debug("Not able to validate OTP. Sending Failed status to caller.");
	return 0;	
}

int do_hyidauth(char* username, char* password)
{

	debug("Inside do_hyidauth, calling getADSConfigDetails");
	struct MemoryStruct chunk;

	chunk.recvbuf = NULL;
	chunk.recvbuf_size = 0;
 	char authDomainId[20]={0};
	char agentid[30]={0};
	char otptype[20]={0};
	char serverIp[20]={0};
	char serverPort[10]={0};	
	
	if(!getADSConfigDetails(serverIp,serverPort,authDomainId,otptype,agentid))
	{
		debug("Failed to read config details from ads_config");

	}
	
	int authdomainid = atoi(authDomainId);
	int serverport = atoi(serverPort);

	debug("Inside otpauth. Username %s, password %s, authdomainid %d, agentid %s, serverIp %s, serverPort %d", username, password, authdomainid, agentid, serverIp,serverport);
	
	if(send_request(username, authdomainid, password, agentid, serverIp ,serverport, &chunk))
	{
		if(chunk.recvbuf)
		{
			if(pasre_response(&chunk))
			{
				debug("user is successfully validated with server.");
				return 1;
			}
			else
				debug("pasre_response failed / User validation failed.");
		}
		else
			debug("chunk.recvbuf is NULL, failed.");
	}
	else
		debug("send_request failed.");

	debug("Not able to validate user. Sending Failed status to caller.");
	return 0;
}
