commit b3319a29c4e80f5a8998627e29e3dca83bcb0a35
Author: Mateus Marques <mateusmarques2001@usp.br>
Date:   Wed Feb 18 19:53:18 2026 +0000

    bRO client 2006: 0x258 <-> 0x259 gameguard handshake, and char_direct_auth 0x64 login packet

diff --git a/src/char/char.c b/src/char/char.c
index 9b6dc00ed..02ba3a997 100644
--- a/src/char/char.c
+++ b/src/char/char.c
@@ -31,6 +31,9 @@
 #include <stdio.h>
 #include <stdlib.h>

+#include "../login/account.h"
+AccountDB *accounts = NULL;
+
 // private declarations
 #define CHAR_CONF_NAME	"conf/char_athena.conf"
 #define LAN_CONF_NAME	"conf/subnet_athena.conf"
@@ -110,6 +113,7 @@ struct char_session_data {
 	uint32 version;
 	uint8 clienttype;
 	char birthdate[10+1];  // YYYY-MM-DD
+	int pending_direct_login;  // 1 if this is a direct login via 0x64
 };

 int char_id_count = START_CHAR_NUM;
@@ -2190,23 +2194,36 @@ int parse_fromlogin(int fd)
 			uint8 clienttype = RFIFOB(fd,24);
 			RFIFOSKIP(fd,25);

-			if( session_isActive(request_id) && (sd=(struct char_session_data*)session[request_id]->session_data) &&
-				!sd->auth && sd->account_id == account_id && sd->login_id1 == login_id1 && sd->login_id2 == login_id2 && sd->sex == sex )
+			ShowInfo("Char server: Received 0x2713 for request_id=%d, result=%d\n", request_id, result);
+
+			if ( session_isActive(request_id) && (sd=(struct char_session_data*)session[request_id]->session_data) )
 			{
-				int client_fd = request_id;
-				sd->version = version;
-				sd->clienttype = clienttype;
-				switch( result )
+				if ( sd->pending_direct_login ||
+				     ( !sd->auth && sd->account_id == account_id && sd->login_id1 == login_id1 && sd->login_id2 == login_id2 && sd->sex == sex ) )
 				{
-				case 0:// ok
-					char_auth_ok(client_fd, sd);
-					break;
-				case 1:// auth failed
-					WFIFOHEAD(client_fd,3);
-					WFIFOW(client_fd,0) = 0x6c;
-					WFIFOB(client_fd,2) = 0;// rejected from server
-					WFIFOSET(client_fd,3);
-					break;
+					int client_fd = request_id;
+
+					// Update session with real values
+					sd->account_id = account_id;
+					sd->login_id1 = login_id1;
+					sd->login_id2 = login_id2;
+					sd->sex = sex;
+					sd->version = version;
+					sd->clienttype = clienttype;
+					sd->pending_direct_login = 0;  // Clear flag
+
+					switch( result )
+					{
+					case 0:// ok
+						char_auth_ok(client_fd, sd);
+						break;
+					case 1:// auth failed
+						WFIFOHEAD(client_fd,3);
+						WFIFOW(client_fd,0) = 0x6c;
+						WFIFOB(client_fd,2) = 0;// rejected from server
+						WFIFOSET(client_fd,3);
+						break;
+					}
 				}
 			}
 		}
@@ -3638,6 +3655,216 @@ static void char_delete2_cancel(int fd, struct char_session_data* sd)
 	char_delete2_cancel_ack(fd, char_id, 1);
 }

+#define ACCOUNT_TXT_DB_VERSION 20110114
+
+/// parse input string into the provided account data structure
+static bool mmo_auth_fromstr(struct mmo_account* a, char* str, unsigned int version)
+{
+        char* fields[32];
+        int count;
+        char* regs;
+        int i, n;
+
+        // zero out the destination first
+        memset(a, 0x00, sizeof(struct mmo_account));
+
+        // defaults for older format versions
+        safestrncpy(a->birthdate, "0000-00-00", sizeof(a->birthdate));
+
+        // extract tab-separated columns from line
+        count = sv_split(str, strlen(str), 0, '\t', fields, ARRAYLENGTH(fields), (e_svopt)(SV_TERMINATE_LF|SV_TERMINATE_CRLF));
+
+        if( version == ACCOUNT_TXT_DB_VERSION && count == 14 )
+        {
+                a->account_id = strtol(fields[1], NULL, 10);
+                safestrncpy(a->userid, fields[2], sizeof(a->userid));
+                safestrncpy(a->pass, fields[3], sizeof(a->pass));
+                a->sex = fields[4][0];
+                safestrncpy(a->email, fields[5], sizeof(a->email));
+                a->level = strtoul(fields[6], NULL, 10);
+                a->state = strtoul(fields[7], NULL, 10);
+                a->unban_time = strtol(fields[8], NULL, 10);
+                a->expiration_time = strtol(fields[9], NULL, 10);
+                a->logincount = strtoul(fields[10], NULL, 10);
+                safestrncpy(a->lastlogin, fields[11], sizeof(a->lastlogin));
+                safestrncpy(a->last_ip, fields[12], sizeof(a->last_ip));
+                safestrncpy(a->birthdate, fields[13], sizeof(a->birthdate));
+                regs = fields[14];
+        }
+        else
+        if( version == 20080409 && count == 13 )
+        {
+                a->account_id = strtol(fields[1], NULL, 10);
+                safestrncpy(a->userid, fields[2], sizeof(a->userid));
+                safestrncpy(a->pass, fields[3], sizeof(a->pass));
+                a->sex = fields[4][0];
+                safestrncpy(a->email, fields[5], sizeof(a->email));
+                a->level = strtoul(fields[6], NULL, 10);
+                a->state = strtoul(fields[7], NULL, 10);
+                a->unban_time = strtol(fields[8], NULL, 10);
+                a->expiration_time = strtol(fields[9], NULL, 10);
+                a->logincount = strtoul(fields[10], NULL, 10);
+                safestrncpy(a->lastlogin, fields[11], sizeof(a->lastlogin));
+                safestrncpy(a->last_ip, fields[12], sizeof(a->last_ip));
+                regs = fields[13];
+        }
+        else
+        if( version == 0 && count == 14 )
+        {
+                a->account_id = strtol(fields[1], NULL, 10);
+                safestrncpy(a->userid, fields[2], sizeof(a->userid));
+                safestrncpy(a->pass, fields[3], sizeof(a->pass));
+                safestrncpy(a->lastlogin, fields[4], sizeof(a->lastlogin));
+                a->sex = fields[5][0];
+                a->logincount = strtoul(fields[6], NULL, 10);
+                a->state = strtoul(fields[7], NULL, 10);
+                safestrncpy(a->email, fields[8], sizeof(a->email));
+                //safestrncpy(a->error_message, fields[9], sizeof(a->error_message));
+                a->expiration_time = strtol(fields[10], NULL, 10);
+                safestrncpy(a->last_ip, fields[11], sizeof(a->last_ip));
+                //safestrncpy(a->memo, fields[12], sizeof(a->memo));
+                a->unban_time = strtol(fields[13], NULL, 10);
+                regs = fields[14];
+        }
+        else
+        if( version == 0 && count == 13 )
+        {
+                a->account_id = strtol(fields[1], NULL, 10);
+                safestrncpy(a->userid, fields[2], sizeof(a->userid));
+                safestrncpy(a->pass, fields[3], sizeof(a->pass));
+                safestrncpy(a->lastlogin, fields[4], sizeof(a->lastlogin));
+                a->sex = fields[5][0];
+                a->logincount = strtoul(fields[6], NULL, 10);
+                a->state = strtoul(fields[7], NULL, 10);
+                safestrncpy(a->email, fields[8], sizeof(a->email));
+                //safestrncpy(a->error_message, fields[9], sizeof(a->error_message));
+                a->expiration_time = strtol(fields[10], NULL, 10);
+                safestrncpy(a->last_ip, fields[11], sizeof(a->last_ip));
+                //safestrncpy(a->memo, fields[12], sizeof(a->memo));
+                regs = fields[13];
+        }
+        else
+        if( version == 0 && count == 8 )
+        {
+                a->account_id = strtol(fields[1], NULL, 10);
+                safestrncpy(a->userid, fields[2], sizeof(a->userid));
+                safestrncpy(a->pass, fields[3], sizeof(a->pass));
+                safestrncpy(a->lastlogin, fields[4], sizeof(a->lastlogin));
+                a->sex = fields[5][0];
+                a->logincount = strtoul(fields[6], NULL, 10);
+                a->state = strtoul(fields[7], NULL, 10);
+                regs = fields[8];
+        }
+        else
+        {// unmatched row
+                return false;
+        }
+
+        // extract account regs
+        // {reg name<COMMA>reg value<SPACE>}*
+        n = 0;
+        for( i = 0; i < ACCOUNT_REG2_NUM; ++i )
+        {
+                char key[32];
+                char value[256];
+
+                regs += n;
+
+                if (sscanf(regs, "%31[^\t,],%255[^\t ] %n", key, value, &n) != 2)
+                {
+                        // We must check if a str is void. If it's, we can continue to read other REG2.
+                        // Account line will have something like: str2,9 ,9 str3,1 (here, ,9 is not good)
+                        if (regs[0] == ',' && sscanf(regs, ",%[^\t ] %n", value, &n) == 1) {
+                                i--;
+                                continue;
+                        } else
+                                break;
+                }
+
+                safestrncpy(a->account_reg2[i].str, key, 32);
+                safestrncpy(a->account_reg2[i].value, value, 256);
+        }
+        a->account_reg2_num = i;
+
+        return true;
+}
+
+static int char_direct_auth(const char* userid, const char* passwd, struct mmo_account* acc)
+{
+        FILE *fp;
+        char line[2048];
+        char filepath[256];
+        unsigned int version = 0;
+
+        // Try multiple possible paths
+        const char* paths[] = {
+                "save/account.txt",
+                "../save/account.txt",
+                "./save/account.txt",
+                "/opt/eathena/save/account.txt"
+        };
+
+        int i;
+        for (i = 0; i < 4; i++) {
+                fp = fopen(paths[i], "r");
+                if (fp != NULL) {
+                        strcpy(filepath, paths[i]);
+                        break;
+                }
+        }
+
+        if (fp == NULL) {
+                ShowError("char_direct_auth: Cannot open account.txt (tried multiple paths)\n");
+                return 0;
+        }
+
+        ShowInfo("char_direct_auth: Opened account file: %s\n", filepath);
+
+        // Read version first
+        if (fgets(line, sizeof(line), fp)) {
+                if (sscanf(line, "%u", &version) == 1) {
+                        // Got version
+                }
+        }
+
+        while (fgets(line, sizeof(line), fp)) {
+                struct mmo_account temp_acc;
+
+                if (line[0] == '/' && line[1] == '/')
+                        continue;
+
+                // Use the same parser as login server
+                if (!mmo_auth_fromstr(&temp_acc, line, version))
+                        continue;
+
+                if (strcmp(temp_acc.userid, userid) == 0) {
+                        ShowInfo("char_direct_auth: Found account %s (id=%d)\n", userid, temp_acc.account_id);
+
+                        // Check password
+                        if (strcmp(temp_acc.pass, passwd) != 0) {
+                                ShowInfo("char_direct_auth: Wrong password for %s\n", userid);
+                                fclose(fp);
+                                return 1;
+                        }
+
+                        // Check if banned
+                        if (temp_acc.state != 0) {
+                                ShowInfo("char_direct_auth: Account %s is banned (state=%d)\n", userid, temp_acc.state);
+                                fclose(fp);
+                                return 2;
+                        }
+
+                        // Copy account data
+                        memcpy(acc, &temp_acc, sizeof(struct mmo_account));
+                        fclose(fp);
+                        return -1;
+                }
+        }
+
+        ShowInfo("char_direct_auth: Account %s not found\n", userid);
+        fclose(fp);
+        return 0;
+}

 int parse_char(int fd)
 {
@@ -3676,6 +3903,142 @@ int parse_char(int fd)
 		cmd = RFIFOW(fd,0);
 		switch( cmd )
 		{
+                case 0x258:  // PACKET_CA_REQ_GAME_GUARD_CHECK
+                        if (RFIFOREST(fd) < 2)  // Packet is just 2 bytes
+                                return 0;
+
+                        // Send GameGuard ACK packet (0x259) with success flag
+                        WFIFOHEAD(fd, 3);
+                        WFIFOW(fd,0) = 0x259;  // PACKET_AC_ACK_GAME_GUARD
+                        WFIFOB(fd,2) = 1;      // ucAnswer = 1 (success)
+                        WFIFOSET(fd,3);
+
+                        // Skip the received packet
+                        RFIFOSKIP(fd,2);
+                        break;
+
+		case 0x64:  // Login packet sent to char server
+		{
+			char username[NAME_LENGTH];
+			char password[NAME_LENGTH];
+			uint32 version;
+			uint8 clienttype;
+			struct mmo_account acc;
+			int auth_result;
+
+			if (RFIFOREST(fd) < 55)
+				return 0;
+
+			version = RFIFOL(fd,2);
+			safestrncpy(username, (const char*)RFIFOP(fd,6), NAME_LENGTH);
+			safestrncpy(password, (const char*)RFIFOP(fd,30), NAME_LENGTH);
+			clienttype = RFIFOB(fd,54);
+
+			ShowInfo("Char server: Direct login attempt from %s\n", username);
+
+			auth_result = char_direct_auth(username, password, &acc);
+
+			if (auth_result == -1) {
+				ShowInfo("Char server: Direct login success for %s (account_id: %d)\n", username, acc.account_id);
+
+				// Create session
+				if (!sd) {
+					CREATE(session[fd]->session_data, struct char_session_data, 1);
+					sd = (struct char_session_data*)session[fd]->session_data;
+				}
+
+				sd->account_id = acc.account_id;
+				sd->login_id1 = rand();
+				sd->login_id2 = rand();
+				sd->sex = (acc.sex == 'M' ? 0 : 1);
+				sd->version = version;
+				sd->clienttype = clienttype;
+				sd->auth = true;
+				safestrncpy(sd->email, "no mail", 40);
+
+				// Now request account data from login server
+				if (login_fd > 0) {
+					WFIFOHEAD(login_fd,6);
+					WFIFOW(login_fd,0) = 0x2716;
+					WFIFOL(login_fd,2) = sd->account_id;
+					WFIFOSET(login_fd,6);
+				} else {
+					// No login server, can't get account data
+					ShowError("char_direct_auth: No login server connection\n");
+					session[fd]->session_data = NULL;
+					do_close(fd);
+				}
+
+			} else {
+				const char* msg = (auth_result == 0) ? "Account not found" :
+						 (auth_result == 1) ? "Wrong password" : "Account banned";
+				ShowWarning("Char server: Direct login failed for %s: %s\n", username, msg);
+
+				WFIFOHEAD(fd,3);
+				WFIFOW(fd,0) = 0x6c;
+				WFIFOB(fd,2) = 0;
+				WFIFOSET(fd,3);
+			}
+
+			RFIFOSKIP(fd,55);
+			break;
+		}
+
+		//case 0x64:  // Login packet sent to char server
+		//{
+		//	char username[NAME_LENGTH];
+		//	char password[NAME_LENGTH];
+		//	uint32 version;
+		//	uint8 clienttype;
+		//
+		//	if (RFIFOREST(fd) < 55)
+		//		return 0;
+		//
+		//	// Extract data
+		//	version = RFIFOL(fd,2);
+		//	safestrncpy(username, (const char*)RFIFOP(fd,6), NAME_LENGTH);
+		//	safestrncpy(password, (const char*)RFIFOP(fd,30), NAME_LENGTH);
+		//	clienttype = RFIFOB(fd,54);
+
+		//	ShowInfo("Char server: Login packet from %s, forwarding to login server (custom packet)\n", username);
+		//	if (login_fd < 0) {
+		//		// No login server, reject
+		//		WFIFOHEAD(fd,3);
+		//		WFIFOW(fd,0) = 0x6c;
+		//		WFIFOB(fd,2) = 0;
+		//		WFIFOSET(fd,3);
+		//		RFIFOSKIP(fd,55);
+		//		break;
+		//	}
+		//
+		//	if (sd) {
+		//		//Received again auth packet for already authentified account?? Discard it.
+		//		break;
+		//	}
+		//
+		//	CREATE(session[fd]->session_data, struct char_session_data, 1);
+		//	sd = (struct char_session_data*)session[fd]->session_data;
+		//	// Store the client FD in the session for later response
+  		//	sd->pending_direct_login = 1;
+		//	sd->auth = false;
+
+		//	// After creating the session but before sending to login server
+		//	ShowInfo("Char server: Created session for %s, waiting for auth response\n", username);
+		//	ShowInfo("Char server: Client fd=%d, login_fd=%d\n", fd, login_fd);
+		//
+		//	// Send custom auth request to login server (0x9999)
+		//	// Format: 0x9999 <char_fd>.L <version>.L <clienttype>.B <username>.24B <password>.24B
+		//	WFIFOHEAD(login_fd, 2 + 4 + 4 + 1 + 24 + 24);
+		//	WFIFOW(login_fd,0) = 0x9999;           // Custom packet ID
+		//	WFIFOL(login_fd,2) = fd;                // Char server fd for response
+		//	WFIFOL(login_fd,6) = version;           // Client version
+		//	WFIFOB(login_fd,10) = clienttype;       // Client type
+		//	memcpy(WFIFOP(login_fd,11), username, NAME_LENGTH);  // Username
+		//	memcpy(WFIFOP(login_fd,11+24), password, NAME_LENGTH);  // Password
+		//	WFIFOSET(login_fd, 2 + 4 + 4 + 1 + 24 + 24);
+		//	RFIFOSKIP(fd, 55); // assume no other packet was sent
+		//	break;
+		//}

 		// request to connect (CH_ENTER).
 		// 0065 <account id>.L <login id1>.L <login id2>.L <client type>.W <sex>.B
diff --git a/src/login/login.c b/src/login/login.c
index f4f9ac953..ce52e6c99 100644
--- a/src/login/login.c
+++ b/src/login/login.c
@@ -444,6 +444,98 @@ int parse_fromchar(int fd)
 		switch( command )
 		{

+		case 0x9999:  // Custom auth request from char server with username/password
+		{
+			if (RFIFOREST(fd) < 2 + 4 + 4 + 1 + 24 + 24)
+				return 0;
+
+			int char_fd = RFIFOL(fd,2);
+			uint32 version = RFIFOL(fd,6);
+			uint8 clienttype = RFIFOB(fd,10);
+			char username[NAME_LENGTH];
+			char password[NAME_LENGTH];
+
+			memcpy(username, RFIFOP(fd,11), NAME_LENGTH);
+			username[NAME_LENGTH-1] = '\0';  // Ensure null termination
+			memcpy(password, RFIFOP(fd,11+24), NAME_LENGTH);
+			password[NAME_LENGTH-1] = '\0';
+
+			ShowInfo("Login server: Custom auth request for user '%s' from char server\n", username);
+
+			// Create a temporary login session for authentication
+			struct login_session_data temp_sd;
+			memset(&temp_sd, 0, sizeof(temp_sd));
+			temp_sd.fd = -1;
+			safestrncpy(temp_sd.userid, username, NAME_LENGTH);
+			safestrncpy(temp_sd.passwd, password, NAME_LENGTH);
+			temp_sd.version = version;
+			temp_sd.clienttype = clienttype;
+			temp_sd.passwdenc = 0;
+
+			int result = mmo_auth(&temp_sd);
+
+			// Prepare response buffer
+			uint8 response[25];
+			memset(response, 0, sizeof(response));
+
+			ShowInfo("Login server: Sending 0x2713 response to char server (fd=%d, char_fd=%d)\n", fd, char_fd);
+
+			WBUFW(response,0) = 0x2713;
+
+			if (result == -1) {
+				ShowInfo("Login server: Auth success for %s (account_id: %d)\n",
+					 username, temp_sd.account_id);
+
+				// Create auth entry
+				struct auth_node* node;
+				CREATE(node, struct auth_node, 1);
+				node->account_id = temp_sd.account_id;
+				node->login_id1 = temp_sd.login_id1;
+				node->login_id2 = temp_sd.login_id2;
+				node->sex = temp_sd.sex;
+				node->ip = session[fd]->client_addr;
+				node->version = temp_sd.version;
+				node->clienttype = temp_sd.clienttype;
+				idb_put(auth_db, temp_sd.account_id, node);
+
+				WBUFL(response,2) = temp_sd.account_id;
+				WBUFL(response,6) = temp_sd.login_id1;
+				WBUFL(response,10) = temp_sd.login_id2;
+				WBUFB(response,14) = sex_str2num(temp_sd.sex);
+				WBUFB(response,15) = 0;  // Success
+				WBUFL(response,16) = char_fd;
+				WBUFL(response,20) = temp_sd.version;
+				WBUFB(response,24) = temp_sd.clienttype;
+			} else {
+				ShowWarning("Login server: Auth failed for %s (error: %d)\n", username, result);
+
+				WBUFL(response,2) = 0;
+				WBUFL(response,6) = 0;
+				WBUFL(response,10) = 0;
+				WBUFB(response,14) = 0;
+				WBUFB(response,15) = 1;  // Failure
+				WBUFL(response,16) = char_fd;
+				WBUFL(response,20) = 0;
+				WBUFB(response,24) = 0;
+			}
+
+			// Send the response
+			WFIFOHEAD(fd, 25);
+			memcpy(WFIFOP(fd,0), response, 25);
+			WFIFOSET(fd, 25);
+
+			// Flush to ensure it's sent
+			flush_fifo(fd);
+			sleep(1);  // Add this temporarily to test
+
+			ShowInfo("Login server: Response sent, keeping connection alive\n");
+
+			// Skip the packet
+			RFIFOSKIP(fd, 2 + 4 + 4 + 1 + 24 + 24);
+
+			break;
+		}
+
 		case 0x2712: // request from char-server to authenticate an account
 			if( RFIFOREST(fd) < 23 )
 				return 0;
@@ -1319,6 +1411,21 @@ int parse_login(int fd)
 		switch( command )
 		{

+                case 0x258:  // PACKET_CA_REQ_GAME_GUARD_CHECK
+                        if (RFIFOREST(fd) < 2)  // Packet is just 2 bytes (no additional data)
+                                return 0;
+
+                        // Send GameGuard ACK packet (0x259) with success flag
+                        WFIFOHEAD(fd, 3);
+                        WFIFOW(fd,0) = 0x259;  // PACKET_AC_ACK_GAME_GUARD
+                        WFIFOB(fd,2) = 1;      // ucAnswer = 1 (success)
+                        WFIFOSET(fd,3);
+
+                        // Skip the received packet
+                        RFIFOSKIP(fd,2);
+                        break;
+
+
 		case 0x0200:		// New alive packet: structure: 0x200 <account.userid>.24B. used to verify if client is always alive.
 			if (RFIFOREST(fd) < 26)
 				return 0;
