/*
 * Network.h
 *
 *  Created on: Aug 5, 2018
 *      Author: yoram
 */

#ifndef NETWORK_H_
#define NETWORK_H_


int NW_inint (char *ip_addr);
void NW_close (int sock);
void NW_Print_IP (char *buff, int len);
int NW_read (int sock, char *buff, size_t buffLen);


#endif /* NETWORK_H_ */


