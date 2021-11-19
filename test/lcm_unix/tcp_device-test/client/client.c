#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "LCM.h"
#define MAX 200
#define PORT 8080
#define SA struct sockaddr


void createMessage(uint8_t* message, uint8_t* datatocopy, int start, int end)
{
	int i;
	int j = 0;
	for (i = start; i < end; i++)
	{
		message[j] = datatocopy[i];
		j++;
	}
}

void func(int sockfd)
{
	char buff[MAX];
	uint8_t received[MAX];
	message_t temp;
	char decrypted[TAKS_PAYLOAD_LEN];
	int n;

	for (;;) {
		bzero(buff, sizeof(buff));
		printf("\n\nEnter the string : ");
		n = 0;
		while ((buff[n++] = getchar()) != '\n');

		write(sockfd, buff, sizeof(buff));

		bzero(received, sizeof(received));
		
		read(sockfd, received, sizeof(received));

	//	int size = TAKS_PAYLOAD_LEN + TAKS_KRI_LEN + TAKS_MAC_LEN;
	//	print(received, sizeof(received), "\n\n--- from Server: ");

		if ((strncmp(received, "exit", 4)) == 0) {
			printf("\n\nClient Exit...\n");
			break;
		}
		 
		createMessage(temp.mac, received, 0, 4);
		createMessage(temp.payload, received, 4, 20);
		createMessage(temp.kri, received, 20, 52);

		//call encryption
		int r = decrypt(decrypted, &temp);

		if (r == -1) {
			printf("\n\n    DECRYPT ERROR"); 
			printf("\n----------------------------------------\n\n\n\n\n\n\n\n");
		}
	}
}

int main()
{
	int sockfd, connfd;
	struct sockaddr_in servaddr, cli;

	// socket create and varification
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
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(PORT);

	// connect the client socket to server socket
	if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
		printf("connection with the server failed...\n");
		exit(0);
	}
	else
		printf("connected to the server..\n");

	// function for chat
	func(sockfd);

	// close the socket
	close(sockfd);
}
