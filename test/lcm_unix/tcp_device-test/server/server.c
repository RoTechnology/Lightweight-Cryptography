#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "LCM.h"
#define MAX 200
#define PORT 8080
#define SA struct sockaddr

void createBuffer(uint8_t *tosend, uint8_t *datatocopy, int start, int end)
{
	int i;
	int j = 0;
	for (i = start; i < end; i++)
	{
		tosend[i] = datatocopy[j];
		j++;
	}
}

// Function designed for chat between client and server.
void func(int sockfd)
{
	char buff[MAX];
	uint8_t tosend[MAX];
	message_t temp;
	int n;

	// infinite loop for chat
	for (;;) {
		bzero(buff, MAX);

		// read the message from client and copy it in buffer
		read(sockfd, buff, sizeof(buff));
		// print buffer which contains the client contents
		printf("\n\nFrom client: %s\n", buff);
		
		// if msg contains "Exit" then server exit and chat ended.
		if (strncmp("exit", buff, 4) == 0) {
			char exstr[5] = "exit";
			exstr[4] = '\0';
			write(sockfd, exstr, sizeof(exstr));
			printf("\n\nServer Exit...\n");
			break;
		}
		
		//call encryption
		int r = encrypt_message(&temp, buff);
		
		if (r == -1) {
        printf("\n\n    ENCRYPT ERROR");
        printf("\n||---------------------------------------------------------------------------------------||\n\n\n\n\n\n\n\n");
		}
		
		bzero(buff, MAX);
		n = 0;

		bzero(tosend, MAX);

		createBuffer(tosend, temp.mac, 0, 4); 
		createBuffer(tosend, temp.payload, 4, 20); 
		createBuffer(tosend, temp.kri, 20, 52);

	//	int size = TAKS_PAYLOAD_LEN + TAKS_KRI_LEN + TAKS_MAC_LEN;		
		//print(tosend, sizeof(tosend), "\n\n--- in buffer now: ");

		// send that buffer to client
		write(sockfd, tosend, sizeof(tosend));
	}
}

// Driver function
int main()
{
	int sockfd, connfd, len;
	struct sockaddr_in servaddr, cli;

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully created..\n");
	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);

	// Binding newly created socket to given IP and verification
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
		printf("socket bind failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully binded..\n");

	// Now server is ready to listen and verification
	if ((listen(sockfd, 5)) != 0) {
		printf("Listen failed...\n");
		exit(0);
	}
	else
		printf("Server listening..\n");
	len = sizeof(cli);

	// Accept the data packet from client and verification
	connfd = accept(sockfd, (SA*)&cli, &len);
	if (connfd < 0) {
		printf("server accept failed...\n");
		exit(0);
	}
	else
		printf("server accept the client...\n");

	// Function for chatting between client and server
	func(connfd);

	// After chatting close the socket
	close(sockfd);
}
