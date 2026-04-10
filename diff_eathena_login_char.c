// src/login/login.c -> parse_login
                case 0x258:  // PACKET_CA_REQ_GAME_GUARD_CHECK
                        if (RFIFOREST(fd) < 2)  // Packet is just 2 bytes (no additional data)
                                return 0;

                        login_log("GameGuard handshake from client (ip: %s)." RETCODE, ip);

                        // Send GameGuard ACK packet (0x259) with success flag
                        WFIFOHEAD(fd, 3);
                        WFIFOW(fd,0) = 0x259;  // PACKET_AC_ACK_GAME_GUARD
                        WFIFOB(fd,2) = 1;      // ucAnswer = 1 (success)
                        WFIFOSET(fd,3);

                        // Skip the received packet
                        RFIFOSKIP(fd,2);
                        break;

// src/char/char.c -> parse_char
                // Add this case in the switch statement, before the default case
                case 0x258:  // PACKET_CA_REQ_GAME_GUARD_CHECK
                        if (RFIFOREST(fd) < 2)  // Packet is just 2 bytes
                                return 0;

                        // Get client IP for logging
                        unsigned char *p = (unsigned char *) &session[fd]->client_addr.sin_addr;
                        char ip[16];
                        sprintf(ip, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

                        char_log("GameGuard handshake from client (ip: %s)." RETCODE, ip);

                        // Send GameGuard ACK packet (0x259) with success flag
                        WFIFOHEAD(fd, 3);
                        WFIFOW(fd,0) = 0x259;  // PACKET_AC_ACK_GAME_GUARD
                        WFIFOB(fd,2) = 1;      // ucAnswer = 1 (success)
                        WFIFOSET(fd,3);

                        // Skip the received packet
                        RFIFOSKIP(fd,2);
                        break;
