
#ifndef _WIN32_WINNT            
#define _WIN32_WINNT 0x0501 //Minimum requirement is: Windows Server 2003, Windows XP
#endif

#ifdef _MSC_VER
# define _POSIX_
#endif

#include <tchar.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <stdio.h>

#include <nsAPItypes.h>
#include <nsAPIdllimp.h>

int 
_tmain (int argc, _TCHAR* argv[])
{
  WSADATA wsaData;
  int res;
  struct addrinfo *result = NULL;
  struct addrinfo *ptr = NULL;
  struct addrinfo hints;
  int i = 0;
  SOCKET sock;

  res = WSAStartup (MAKEWORD (2, 2), &wsaData);

  if (res != 0) {
    printf ("<NSWS> E[0]: WSAStartup failed: %d\n", res);
    return 1;
  }
  
  fprintf (stdout, "<NSWS> Ok NsWine Slave starting up...\n");

  ZeroMemory( &hints, sizeof(hints) );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  res = getaddrinfo ("localhost", "8080", &hints, &result);
  if (res != 0) {
    
    fprintf (stderr, "<NSWS> E[0]: Host lookup failed with error: %d\n", res);
    
    WSACleanup ();
    return 1;
  }

  for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
    sock = socket (ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
     if (sock == INVALID_SOCKET) {
       continue;
     }
     
     res = connect (sock, ptr->ai_addr, ptr->ai_addrlen);

     if (res == 0)
       break;
     
     close (sock);

  }

  freeaddrinfo (result);
  
  if (ptr == NULL) {
     fprintf (stderr, "<NSWS> E[1]: Could not connect\n");
    return 1;
  }

  res = send (sock, "Foobar", strlen ("Foobar"), 0);
  
  close (sock);
  WSACleanup();

  return 0;
}
