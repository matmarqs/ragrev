commit a36680ba870e2d25d04ad8650be56ab567c143bf
Author: Mateus Marques <mateusmarques2001@usp.br>
Date:   Fri Feb 20 23:43:18 2026 +0000

    Game was working, logged in into map server and played

diff --git a/athena-start b/athena-start
index ab5ac3de0..2e85d8137 100755
--- a/athena-start
+++ b/athena-start
@@ -4,9 +4,9 @@

 PATH=./:$PATH

-L_SRV=login-server_sql
-C_SRV=char-server_sql
-M_SRV=map-server_sql
+L_SRV=login-server
+C_SRV=char-server
+M_SRV=map-server

 print_start() {
 #    more << EOF
diff --git a/conf/battle/client.conf b/conf/battle/client.conf
index 51d1f6dc1..6127f8948 100644
--- a/conf/battle/client.conf
+++ b/conf/battle/client.conf
@@ -108,15 +108,15 @@ save_clothcolor: yes
 // Note: Both save_clothcolor and wedding_modifydisplay have to be enabled
 // for this option to take effect. Set this to yes if your cloth palettes
 // pack doesn't has wedding palettes (or has less than the other jobs)
-wedding_ignorepalette: no
+wedding_ignorepalette: yes

 // Do not display cloth colors for the Xmas class?
 // Set this to yes if your cloth palettes pack doesn't has Xmas palettes (or has less than the other jobs)
-xmas_ignorepalette: no
+xmas_ignorepalette: yes

 // Do not display cloth colors for the Summer class?
 // Set this to yes if your cloth palettes pack doesn't has Summer palettes (or has less than the other jobs)
-summer_ignorepalette: no
+summer_ignorepalette: yes

 // Set this to 1 if your clients have langtype problems and can't display motd properly
 motd_type: 0
diff --git a/conf/char_athena.conf b/conf/char_athena.conf
index 8e109f4da..cf94015f5 100644
--- a/conf/char_athena.conf
+++ b/conf/char_athena.conf
@@ -19,7 +19,7 @@ wisp_server_name: Server
 // The character server connects to the login server using this IP address.
 // NOTE: This is useful when you are running behind a firewall or are on
 // a machine with multiple interfaces.
-//login_ip: 127.0.0.1
+login_ip: 127.0.0.1

 // The character server listens on the interface with this IP address.
 // NOTE: This allows you to run multiple servers on multiple interfaces
@@ -32,7 +32,7 @@ login_port: 6900
 // Character Server IP
 // The IP address which clients will use to connect.
 // Set this to what your server's public IP address is.
-//char_ip: 127.0.0.1
+char_ip: 192.168.1.75

 // Character Server Port
 char_port: 6121
diff --git a/conf/login_athena.conf b/conf/login_athena.conf
index 7f1f40d4b..c0fec4bd7 100644
--- a/conf/login_athena.conf
+++ b/conf/login_athena.conf
@@ -71,7 +71,7 @@ start_limited_time: -1
 check_client_version: no

 // What version we would allow to connect? (if the options above is enabled..)
-client_version_to_connect: 20
+client_version_to_connect: 5

 // Store passwords as MD5 hashes instead of plaintext ?
 // NOTE: Will not work with clients that use <passwordencrypt>
diff --git a/conf/map_athena.conf b/conf/map_athena.conf
index 0b837b61f..c7363beb5 100644
--- a/conf/map_athena.conf
+++ b/conf/map_athena.conf
@@ -29,7 +29,7 @@ passwd: p1
 // The map server connects to the character server using this IP address.
 // NOTE: This is useful when you are running behind a firewall or are on
 // a machine with multiple interfaces.
-//char_ip: 127.0.0.1
+char_ip: 127.0.0.1

 // The map server listens on the interface with this IP address.
 // NOTE: This allows you to run multiple servers on multiple interfaces
@@ -42,7 +42,7 @@ char_port: 6121
 // Map Server IP
 // The IP address which clients will use to connect.
 // Set this to what your server's public IP address is.
-//map_ip: 127.0.0.1
+map_ip: 192.168.1.75

 // Map Server Port
 map_port: 5121
diff --git a/db/packet_db.txt b/db/packet_db.txt
index f53076392..78a65b3fa 100644
--- a/db/packet_db.txt
+++ b/db/packet_db.txt
@@ -33,7 +33,7 @@
 // Main packet version of the DB to use (default = max available version)
 // Client detection is faster when all clients use this version.
 // Version 23 is the latest Sakexe (above versions are for Renewal clients)
-packet_db_ver: 25
+packet_db_ver: 19
 //packet_db_ver: default


diff --git a/src/char/char.c b/src/char/char.c
index 02ba3a997..1f57eef35 100644
--- a/src/char/char.c
+++ b/src/char/char.c
@@ -3316,14 +3316,22 @@ int parse_frommap(int fd)

 			node = (struct auth_node*)idb_get(auth_db, account_id);
 			cd = search_character(account_id, char_id);
+
+			// DEBUG
+			ShowInfo("Char server: Auth check - node=%p, cd=%p, runflag=%d\n", node, cd, runflag);
+			if (node) {
+        			ShowInfo("Char server: node->account_id=%d, node->char_id=%d, node->login_id1=%d, node->sex=%d\n", node->account_id, node->char_id, node->login_id1, node->sex);
+			}
+			ShowInfo("Char server: Received - account_id=%d, char_id=%d, login_id1=%d, sex=%d\n", account_id, char_id, login_id1, sex);
+
 			if( runflag == SERVER_STATE_RUN &&
 				cd != NULL &&
 				node != NULL &&
 				node->account_id == account_id &&
-				node->char_id == char_id &&
-				node->login_id1 == login_id1 &&
-				node->sex == sex /*&&
-				node->ip == ip*/ )
+				node->char_id == char_id /* &&
+				   node->login_id1 == login_id1 && */
+				/* node->sex == sex && */
+				/* node->ip == ip */ )
 			{// auth ok
 				cd->sex = sex;

@@ -3331,7 +3339,7 @@ int parse_frommap(int fd)
 				WFIFOW(fd,0) = 0x2afd;
 				WFIFOW(fd,2) = 24 + sizeof(struct mmo_charstatus);
 				WFIFOL(fd,4) = account_id;
-				WFIFOL(fd,8) = node->login_id1;
+				WFIFOL(fd,8) = login_id1;
 				WFIFOL(fd,12) = node->login_id2;
 				WFIFOL(fd,16) = (uint32)node->expiration_time; // FIXME: will wrap to negative after "19-Jan-2038, 03:14:07 AM GMT"
 				WFIFOL(fd,20) = node->gmlevel;
@@ -3339,12 +3347,17 @@ int parse_frommap(int fd)
 				memcpy(WFIFOP(fd,24), cd, sizeof(struct mmo_charstatus));
 				WFIFOSET(fd, WFIFOW(fd,2));

+				ShowInfo("Char server: Sending auth OK response for account_id=%d, char_id=%d\n", account_id, char_id);
+
 				// only use the auth once and mark user online
 				idb_remove(auth_db, account_id);
 				set_char_online(id, char_id, account_id);
 			}
 			else
 			{// auth failed
+
+				ShowInfo("Char server: Sending auth failed response for account_id=%d, char_id=%d\n", account_id, char_id);
+
 				WFIFOHEAD(fd,19);
 				WFIFOW(fd,0) = 0x2b27;
 				WFIFOL(fd,2) = account_id;
diff --git a/src/common/mmo.h b/src/common/mmo.h
index 431a07e0a..384d8ae8a 100644
--- a/src/common/mmo.h
+++ b/src/common/mmo.h
@@ -45,7 +45,7 @@
 // 20111025 - 2011-10-25aRagexeRE+ - 0x6b, 0x6d

 #ifndef PACKETVER
-	#define PACKETVER 20100728
+	#define PACKETVER 20050912
 #endif

 // backward compatible PACKETVER 8 and 9
diff --git a/src/map/chrif.c b/src/map/chrif.c
index 897ee70a2..f9a3e4c9f 100644
--- a/src/map/chrif.c
+++ b/src/map/chrif.c
@@ -182,6 +182,8 @@ static bool chrif_sd_to_auth(TBL_PC* sd, enum sd_state state)
 	node->node_created = gettick(); //timestamp for node timeouts
 	node->state = state;

+	ShowInfo("chrif_sd_to_auth: Auth node created for account_id=%d, char_id=%d, state=%d, sd=%p\n", node->account_id, node->char_id, node->state, node->sd);
+
 	sd->state.active = 0;
 	idb_put(auth_db, node->account_id, node);
 	return true;
@@ -574,6 +576,7 @@ void chrif_authreq(struct map_session_data *sd)
 	WFIFOB(char_fd,14) = sd->status.sex;
 	WFIFOL(char_fd,15) = htonl(session[sd->fd]->client_addr);
 	WFIFOSET(char_fd,19);
+	ShowInfo("chrif_authreq: Auth request sent for account_id=%d, char_id=%d\n", sd->status.account_id, sd->status.char_id);
 	chrif_sd_to_auth(sd, ST_LOGIN);
 }

@@ -608,6 +611,8 @@ void chrif_authok(int fd)

 	char_id = status->char_id;

+	ShowInfo("chrif_authok: Received auth for account_id=%d, char_id=%d\n", account_id, char_id);
+
 	//Check if we don't already have player data in our server
 	//Causes problems if the currently connected player tries to quit or this data belongs to an already connected player which is trying to re-auth.
 	if ((sd = map_id2sd(account_id)) != NULL)
diff --git a/src/map/clif.c b/src/map/clif.c
index a36473473..ebb8d6cdd 100644
--- a/src/map/clif.c
+++ b/src/map/clif.c
@@ -8869,6 +8869,7 @@ void clif_parse_WantToConnection(int fd, TBL_PC* sd)

 	// Only valid packet version get here
 	packet_ver = clif_guess_PacketVer(fd, 1, NULL);
+	ShowInfo("clif_parse_WantToConnection: client fd=%d, version=%d\n", fd, packet_ver);

 	cmd = RFIFOW(fd,0);
 	account_id  = RFIFOL(fd, packet_db[packet_ver][cmd].pos[0]);
@@ -8877,7 +8878,7 @@ void clif_parse_WantToConnection(int fd, TBL_PC* sd)
 	client_tick = RFIFOL(fd, packet_db[packet_ver][cmd].pos[3]);
 	sex         = RFIFOB(fd, packet_db[packet_ver][cmd].pos[4]);

-	if( packet_ver < 5 || // reject really old client versions
+	if( 0 && (packet_ver < 5 || 1) || // (DO NOT) reject really old client versions
 			(packet_ver <= 9 && (battle_config.packet_ver_flag & 1) == 0) || // older than 6sept04
 			(packet_ver > 9 && (battle_config.packet_ver_flag & 1<<(packet_ver-9)) == 0)) // version not allowed
 	{// packet version rejected
