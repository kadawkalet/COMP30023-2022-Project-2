#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <limits.h>

#define MULTITHREADED
#define IMPLEMENTS_IPV6

    /*  Sizes   */
#define CONNECTION_MAX  10      // Maximum connections accepted
#define BUFFER_SIZE     2000    // Size of buffer (used for requests/response)
#define FILE_TYPE_LEN   32      // Maximum file type length
#define OP_SIZE         4       // Maximum length of primitives
#define HTTP_SIZE       9       // Maximum length of HTTP/1.0

    /*  Status Codes  */
#define NOT_FOUND       404
#define OK              200

    /*  MIME Types and Extension  */
#define HTML_TYPE   "html"
#define HTML_MIME   "text/html"
#define CSS_TYPE    "css"
#define CSS_MIME    "text/css"
#define JS_TYPE     "js"
#define JS_MIME     "text/javascript"
#define JPG_TYPE    "jpg"
#define JPG_MIME    "image/jpeg"
#define UNKNOWN     "application/octet-stream"

/*  Define Responses for Request  */
#define GET                     "GET"
#define HTTP                    "HTTP/1.0"
#define NOT_FOUND_RESPONSE      "HTTP/1.0 404 NOT FOUND\r\n\r\n"
#define RESPONSE_HEADER         "HTTP/1.0 200 OK\r\nContent-Type: "

typedef struct {
    char* file_path;
    int code;
} request_t;

typedef struct {
    char* webroot_dir;
    int socket_file_desc;
    pthread_t thread;
} thread_input_t;

void *connection_handler(void *args);
request_t parse_request(char *raw_request, char *root_dir);
int check_path(char *file_path);
char *get_file_type(char *file_path);
char *build_response(request_t request);
void send_content(char *file_path, int socket_file_desc);
void respond(request_t request, int socket_file_desc);
bool isNumber(char number[]);
int is_regular_file(const char *path);
static void *safe_malloc(size_t size);
char *get_filename_ext(char *filename);

int main(int argc, char **argv) {
    // This program should take in 3 command line arguments:
    // Protocol number, port number and string path to root web dir
    // Main reads input and start the necessary servers
    // Check that the correct number of arguments have been supplied
    if (argc < 4) 
    {
        perror("ERROR, Incorrect numbers of arguments supplied.\n\
                Usage: server <protocol number> <port number> <path to content>\n");
        exit(1);
    }

    // Initialise variable storing command line arguments and required identifiers
    int prot_no, port_no; // port numbers & protocol number
    char root_dir[PATH_MAX]; // root web directory
    int sockfd, newsockfd;// sockets identifiers

    // Parsing args for Protocol number and port number
    // Check if they are positive integer
    if (isNumber(argv[1])){
        prot_no = atoi(argv[1]);
    } else {
        perror("Error invalid protocol number!");
        exit(1);
    }
    if (isNumber(argv[2])){
        port_no = atoi(argv[2]);
    } else {
        perror("Error invalid port number!");
        exit(1);
    }
    
    // Parsing args for web root
    char *res = realpath(argv[3], root_dir);

    // IP protocol implementation
    if (prot_no == 4) {
        // IPv4 Implementation
        // Creating a TCP socket for IPv4 protocol
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
		    perror("Error openig socket");
		    exit(1);
	    }

        // Create an address that we are going to listen on 
        struct sockaddr_in server_addr;
        bzero((char *) &server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port_no);

        int enable = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            perror("setsockopt");
            exit(1);
        }

        // Bind the address to the socket
        if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
            perror("ERROR on binding");
            exit(1);
        }

        // Listen on the socket
        listen(sockfd, CONNECTION_MAX);

        // Client Address
        struct sockaddr_storage client_addr;
        socklen_t client_addr_size;
        client_addr_size = sizeof client_addr;

        while(1) {
            // Accept connection
            newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
            if (newsockfd < 0) {
		        perror("ERROR on accept");
		        exit(1);
	        }

            // threads
            pthread_t thread_id;

            // Struct to hold variable for pthread
            thread_input_t *input = malloc(sizeof(*input));
            input->webroot_dir = strdup(root_dir);
            input->socket_file_desc = newsockfd;
            input->thread = thread_id;

            // // Create a thread to handle the connection.
            pthread_create(&thread_id, NULL, connection_handler, (void *) input);

            // Detach our thread once we've finished serving the connection.
            pthread_detach(thread_id);
        }   

    } else if (prot_no == 6) {
        // IPv6 Implementation
        // Creating a TCP socket for IPv6 protocol
        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
        if (sockfd < 0) {
		    perror("Error openig socket");
		    exit(1);
	    }

        // Create an address that we are going to listen on 
        struct sockaddr_in6 server_addr;
        bzero((char *) &server_addr, sizeof(server_addr));
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_addr = in6addr_any;
        server_addr.sin6_port = htons(port_no);

        int enable = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            perror("setsockopt");
            exit(1);
        }

        // Bind the address to the socket
        if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
            perror("ERROR on binding");
            exit(1);
        }

        // Listen on the socket
        listen(sockfd, CONNECTION_MAX);

        // Client Address
        struct sockaddr_storage client_addr;
        socklen_t client_addr_size;
        client_addr_size = sizeof client_addr;

        while(1) {
            // Accept connection
            newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_size);
            if (newsockfd < 0) {
		        perror("ERROR on accept");
		        exit(1);
	        }

            // threads
            pthread_t thread_id;

            // // Struct to hold variable for pthread
            thread_input_t *input = malloc(sizeof(*input));
            input->webroot_dir = strdup(root_dir);
            input->socket_file_desc = newsockfd;
            input->thread = thread_id;

            // // Create a thread to handle the connection.
            pthread_create(&thread_id, NULL, connection_handler, (void *) input);

            // Detach our thread once we've finished serving the connection.
            pthread_detach(thread_id);
            
        }
    } else {
        perror("Invalid protocol provided!");
        exit(1);
    }

    // Close our socket and free remaining variables.
    close(sockfd);
    free(res);

    return 0;
}

void *connection_handler(void *args) {
    // This handles incoming requests, parses them and responds with the
    // specified file or error code.
    int n;
    char buffer[BUFFER_SIZE];

    // Cast our void pointer back to struct so we can get the arguments
    // passed in from main()
    thread_input_t vars = *((thread_input_t *) args);

    // Read in characters from our client.
    // The maximum request size will be of BUFFER_SIZE.
    bzero(buffer, BUFFER_SIZE);
    n = read(vars.socket_file_desc, buffer, BUFFER_SIZE);
    
    // Check that we received the message successfully.
    if (n < 0) 
    {
        perror("ERROR reading from socket. Make sure you aren't sending\n\
                a request that is too large.");
        exit(1);
    }
    int i;
    while (1) 
    {
        i = 0;
        if (buffer[n-1] == '\n'
           && buffer[n-2] == '\r'
           && buffer[n-3] == '\n'
           && buffer[n-4] == '\r'){
               break;
        }
        if (buffer[n-1] == '\n'
           && buffer[n-2] == '\n'){
               break;
        }
        char buffer1[BUFFER_SIZE - n];
        i = read(vars.socket_file_desc, buffer1, BUFFER_SIZE - n);
        if (i < 0){
            perror("ERROR reading from socket. Make sure you aren't sending\n\
                a request that is too large.");
            exit(1);
        }
        n += i;
        if (n > BUFFER_SIZE){
            perror("ERROR reading from socket. Make sure you aren't sending\n\
                a request that is too large.");
            exit(1);
        }
        strcat(buffer, buffer1);
        buffer[n] = '\0';
    }

    // Parse the message from our client into a request.
    request_t request = parse_request(buffer, vars.webroot_dir);

    // Respond to the request accordingly.
    respond(request, vars.socket_file_desc);

    // Free memory
    free(vars.webroot_dir);
    free(args);
    // Close the connection and exit our thread.
    close(vars.socket_file_desc);
    pthread_exit(NULL);

}

request_t parse_request(char *raw_request, char *root_dir) {
    // This should take a request and parse it into the request_t struct.
    char *tmp_path;
    char *file_path;
    char primitive[OP_SIZE];
    char http[HTTP_SIZE];
    int test_code;
    request_t request;
    
    // safe_malloc all our strings.
    tmp_path = (char *) safe_malloc(sizeof(char) * strlen(raw_request));
    file_path = (char *) safe_malloc(sizeof(char) * strlen(raw_request));
    
    // If we don't get a GET request in a correct form (GET /index.html HTTP/1.0),
    // respond with 404 NOT FOUND response
    if (sscanf(raw_request, "%s %s %s%*[A-z0-9/:\n]", primitive, tmp_path, http) != 3) {
        request.code = NOT_FOUND;
        request.file_path = NULL;
        return request;
    }

    // Scan the request for the path.
    // It will ignore all characters after the primitive and the path.
    sscanf(raw_request, "%s %s %s%*[A-z0-9/:\n]", primitive, tmp_path, http);
    sprintf(file_path, "%s%s", root_dir, tmp_path);

    // If we don't have a GET request, respond with a 404 NOT FOUND response
    if (strcmp(primitive, GET) != 0) {
        request.code = NOT_FOUND;
        request.file_path = NULL;
        return request;
    }

    // If we have a GET request without correct HTTP i.e. HTTP/1.0, 
    // respond with a 404 NOT FOUND response
    if (strcmp(http, HTTP) != 0) {
        request.code = NOT_FOUND;
        request.file_path = NULL;
        return request;
    }

    // Check if our file actually exists on the server
    test_code = check_path(file_path);

    if (test_code == NOT_FOUND) {
        // 404 Error
        request.code = NOT_FOUND;
        request.file_path = NULL;
    }
    else if (test_code == OK) {
        // 200 good request
        request.code = OK;
        request.file_path = 
                    (char *) safe_malloc(sizeof(char) * strlen(raw_request));
        strcpy(request.file_path, file_path);
    }

    free(tmp_path);
    free(file_path);

    return request;
};

char *build_response(request_t request) {
    // This builds a response to send from a specified request

    char *file_type = NULL;
    char *response = NULL;
    
    if (request.code == 404) {
        // If we have a invalid path request, then return a 404 response
        response = safe_malloc(sizeof(char) * BUFFER_SIZE);
        sprintf(response, NOT_FOUND_RESPONSE);
    }
    else if (request.code == 200) {
        // Otherwise, return a 200 OK response
        file_type = get_file_type(request.file_path);
        response = safe_malloc(sizeof(char) * BUFFER_SIZE + FILE_TYPE_LEN);
        sprintf(response, "%s%s\r\n\r\n", RESPONSE_HEADER, file_type);
        // // Free our file type, since we don't need it anymore.
        free(file_type);
    }

    return response;
}

char *get_file_type(char* file_path) {
    // This function gets the file type of the requested file

    char *file_type, *file_name;

    file_type = safe_malloc(FILE_TYPE_LEN);

    // Check for file_name
    if (file_path[(strlen(file_path) - 1)] == '/')
        file_path[(strlen(file_path) - 1)] = '\0';

    (file_name = strrchr(file_path, '/')) ? ++file_name : (file_name = file_path);

    // Scan the specified file path for our file type
    char *tmp = get_filename_ext(file_name);

    // Translate the file type into the correct MIME format.
    if ((strcmp(tmp, HTML_TYPE) == 0)) {
        strcpy(file_type, HTML_MIME);
    }
    else if (strcmp(tmp, CSS_TYPE) == 0) {
        strcpy(file_type, CSS_MIME);
    }
    else if (strcmp(tmp, JS_TYPE) == 0) {
        strcpy(file_type, JS_MIME);
    }
    else if (strcmp(tmp, JPG_TYPE) == 0) {
        sprintf(file_type, JPG_MIME);
    } else {
        sprintf(file_type, UNKNOWN);
    }

    return file_type;
}

int check_path(char *file_path) {
    // This function checks if the file in the path exists.
    // It will return the necessary error code if the file does not exist,
    // otherwise return 200.

    if (fopen(file_path, "r") == NULL) {
        return NOT_FOUND;
    }
    else {
        if (fopen(file_path, "r") != NULL){
            int file_path_length = strlen(file_path);
            if (file_path[file_path_length - 1] == '/'){
                return NOT_FOUND;
            }
            for (int i = 0; i < file_path_length; i++){
                if (i + 3 < file_path_length) {
                    if (file_path[i] == '/'
                        && file_path[i + 1] == '.'
                        && file_path[i + 2] == '.'
                        && file_path[i + 3] == '/') {
                        return NOT_FOUND;
                    }
                }
                if (i + 3 == file_path_length) {
                    if (file_path[i] == '/'
                        && file_path[i + 1] == '.'
                        && file_path[i + 2] == '.') {
                        return NOT_FOUND;
                    }
                }
                if (i + 1 < file_path_length) {
                    if (file_path[i] == '/'
                        && file_path[i + 1] == '/'){
                        return NOT_FOUND;
                    }
                }
            }
        }
        // Check if the file_path leads to a folder or a file
        if (is_regular_file (file_path) != 0){
            return OK;
        }
        return NOT_FOUND;
    }
}

void respond(request_t request, int socket_file_desc) {
    // This function responds to the request!

    // First we build the header and write it
    char *response = build_response(request);
    write(socket_file_desc, response, strlen(response));

    // Then we send the file contents
    if (request.code == 200) {
        send_content(request.file_path, socket_file_desc);
    }

    // Free our strings
    free(request.file_path);
    free(response);
}

void send_content(char* file_path, int socket_file_desc) {
    // This function sends the contents of the requested file to the client

    // Open and check our file (with binary flag for images)
    FILE* file = fopen(file_path, "rb");
    assert(file);

    // Load the file into a buffer
    fseek(file, 0, SEEK_END);
    // Find the length of the file
    unsigned long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char *buffer = (unsigned char *) safe_malloc(length+1);

    // Read in our file to buffer
    fread(buffer,length,sizeof(unsigned char),file);

    // Write it to the socket!
    write(socket_file_desc, buffer, length);

    free(buffer);
    fclose(file);
}

bool isNumber(char number[]) {
    int i = 0;

    for (; number[i] != 0; i++){
        if (!isdigit(number[i]))
            return false;
    }
    return true;
}

int is_regular_file(const char *path) {
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

static void *safe_malloc(size_t size) {
    void *pointer = malloc(size);
    if (!pointer) {
        perror("Bad malloc, out of memory!\n");
        exit(1);
    }
    return pointer;
}

char *get_filename_ext(char *filename) {
    char *dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot + 1;
}
