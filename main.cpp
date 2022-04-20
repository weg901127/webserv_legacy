
#include <grp.h>
#include <pwd.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include "options.hpp"
#include <netdb.h>
#include <csignal>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <iostream>
#include <istream>
#include <map>
#include <vector>
//#include <string>

#define MAX_BACKLOG 5
#define DEFAULT_PORT "80"
#define LINE_BUF_SIZE 100
#define TIME_BUF_SIZE 64
#define BLOCK_BUF_SIZE 100
#define HTTP_MINOR_VERSION 1
#define SERVER_NAME "FT_WEBSERV"
#define SERVER_VERSION "0.1"
#include "HeaderFieldInfo.hpp"
typedef void (*sighandler_t)(int);

struct FileInfo {
    std::string path;
    long        size;
    int         ok;
};

//struct HTTPHeaderField {
//    std::string             name;
//    std::string             value;
//    struct HTTPHeaderField *next;
//};
typedef std::map<std::string, std::string> HTTPHeaderField;

struct HTTPRequest {
    int                     protocol_minor_version;
    std::string             method;
    std::string             path;
    HTTPHeaderField         header;
    std::string             body;
    long                    length;
};

static void log_exit(char *fmt, ...){
    va_list ap;

    va_start(ap, fmt);
    std::cerr << fmt << ap << std::endl;
    va_end(ap);
    exit(1);
}
static void trap_signal(int sig, sighandler_t handler) {
    struct sigaction act;

    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    if (sigaction(sig, &act, NULL) < 0)
        log_exit("sigaction() failed: ", strerror(errno));
}
static void signal_exit(int sig) {
    log_exit("exit by signal ", sig);
}
static void install_signal_handlers() {
    trap_signal(SIGPIPE, signal_exit);
}

static void read_request_line(struct HTTPRequest *req, std::istream &in) {
//    char buf[LINE_BUF_SIZE];
    std::string buf;

    getline(in, buf);
    //std::cout << buf << std::endl;

//    p = strchr(buf, ' ');
    std::size_t found;
    found = buf.find(' ');
    if (found != std::string::npos)
        std::cout << "first 'needle' found at: " << found << '\n';
    else
        std::cout << "not found"; //err
//    if (!p) log_exit("parse error on request line (1): ", buf);
    std::string tmp = buf.substr(0,found);
    buf = buf.substr(found + 1, std::string::npos);
    for (int i = 0; i < tmp.length(); i++) {
        tmp[i] = toupper(tmp[i]);
    }
    req->method = tmp;
//    std::cout << req->method << std::endl;
    //TODO 이거 꼭 필요한지 생각해보자!
    std::string path = buf;
    if ((found = path.find(' ')) == std::string::npos)
        log_exit("parse error on request line (2): ", path.c_str());
    //FIXME log_exit 수정!
    buf = path.substr(found + 1);
    path = path.substr(0,found);
//    std::cout << path << std::endl;
    req->path = path;

    std::cout << buf << std::endl;
    if (buf != "HTTP/1.1")
        log_exit("parse error on request line (3): ", path.c_str());
    req->protocol_minor_version = 1;
}

//static char*    lookup_header_field_value(struct HTTPRequest *req, char *name) {
//    struct HTTPHeaderField *h;
//
//    for (h = req->header; h; h = h->next) {
//        if (strcasecmp(h->name, name) == 0)
//            return h->value;
//    }
//    return NULL;
//}

//	fprintf(out, "Content-Length: %ld\r\n", info->size);
//static long content_length(struct HTTPRequest *req) {
//    char *val;
//    long len;
//
//    val = lookup_header_field_value(req, "Content-Length");
//    if (!val) return 0;
//    len = atol(val);
//    if (len < 0) log_exit("negative Content-Length value");
//    return len;
//}
//
static HTTPHeaderField read_header_field(std::istream& is) {
//    struct HTTPHeaderField *h;
    std::map<std::string, std::string> headerField;
    //TODO map이 정렬할 때의 시간복잡도 감안해보자!
    std::string buf;

//    h = new HTTPHeaderField;
//    h->name = (char *) malloc(sizeof (p - buf));
//    strcpy(h->name, buf);
    while (1) {
        getline(is, buf);
        if (buf.length() == 0)
            break;

        std::size_t found;
        found = buf.find(':');
        std::string name = buf.substr(0, found);
        std::string value = buf.substr(found + 1);
        headerField.insert(std::pair<std::string, std::string>(name, value));
    }

    for (std::map<std::string, std::string>::iterator first = headerField.begin();first != headerField.end(); ++first)
        std::cout << first->first << " " << first->second << std::endl;

//    if (!fgets(buf, LINE_BUF_SIZE, in)) {
//        log_exit("failed to read request header field: ", strerror(errno));
//    }
/*
    if ((buf[0] == '\n') || (strcmp(buf, "\r\n") == 0))
        return NULL;

    p = strchr(buf, ':');
    if (!p) log_exit("parse error on request header field: ", buf);
    *p++ = '\0';


    p += strspn(p, " \t");
    h->value = (char *) malloc(strlen(p) + 1);
    strcpy(h->value, p);
*/
    return headerField;
}
//
static struct HTTPRequest* read_request(std::istream &in) {
    struct HTTPRequest *req = new HTTPRequest;
    HTTPHeaderField h;

    read_request_line(req, in);
    read_header_field(in);
    /*
    while (std::is_empty<h = read_header_field(in)>) {
        h->next = req->header;
        req->header = h;
    }
     */
//    req->length = content_length(req);
}
//
//static char * build_fspath(char *docroot, char *urlpath) {
//    char *path;
//
//    path = (char *)malloc(strlen(docroot) + 1 + strlen(urlpath) + 1);
//    sprintf(path, "%s/%s", docroot, urlpath);
//    return path;
//}
//
//static struct FileInfo* get_fileinfo(char *docroot, char *urlpath) {
//    struct FileInfo *info;
//    struct stat st;
//
//    info = new struct FileInfo;
//    info->path = build_fspath(docroot, urlpath);
//    info->ok = 0;
//    if (lstat(info->path, &st) < 0) return info;
//    if (!S_ISREG(st.st_mode)) return info;
//    info->ok = 1;
//    info->size = st.st_size;
//    return info;
//}
//
//static void output_common_header_fields(struct HTTPRequest *req, FILE *out, char *status) {
//    time_t t;
//    struct tm   *tm;
//    char buf[TIME_BUF_SIZE];
//
//    t = time(NULL);
//    tm = gmtime(&t);
//    if (!tm) log_exit("gmtime() failed: %s", strerror(errno));
//    strftime(buf, TIME_BUF_SIZE, "%a, %d %b %Y %H:%M:%S GMT", tm);
//    fprintf(out, "HTTP/1.%d %s\r\n", HTTP_MINOR_VERSION, status);
//    fprintf(out, "Date: %s\r\n", buf);
//    fprintf(out, "Server: %s/%s\r\n", SERVER_NAME, SERVER_VERSION);
//    fprintf(out, "Connection: close\r\n");
//}
//
//static void do_file_response(struct HTTPRequest *req, FILE  *out, char *docroot) {
//    struct FileInfo *info;
//
//    info = get_fileinfo(docroot, req->path);
//    if (!info->ok) {
//        //free_fileinfo(docroot, req->path);
//        //not_found(req, out);
//        return ;
//    }
//    output_common_header_fields(req, out, "200 OK");
//    //fprintf(out, "Content-Type: %s\r\n", guess_content_type(info));
//	fprintf(out, "Content-Type: %s\r\n", "text/plain");
//	fprintf(out, "\r\n");
//	if (strcmp(req->method, "HEAD") != 0) {
//		int fd;
//		char buf[BLOCK_BUF_SIZE];
//		ssize_t n;
//
//		fd = open(info->path, O_RDONLY);
//		if (fd < 0)
//			log_exit("failed to open %s: %s", info->path, strerror(errno));
//		for (;;) {
//			n = read(fd, buf, BLOCK_BUF_SIZE);
//			if (n < 0)
//				log_exit("failed to read %s: %s", info->path, strerror(errno));
//			if (n == 0)
//				break;
//			if (fwrite(buf, 1, n, out) < n)
//				log_exit("failed to write to socket: %s", strerror(errno));
//		}
//		close(fd);
//	}
//	fflush(out);
//	//free_fileinfo(info);
//}
//
//static void respond_to(struct HTTPRequest *req, FILE *out, char *docroot) {
//    if (strcmp(req->method, "GET") == 0)
//        do_file_response(req, out, docroot);
//    else if (strcmp(req->method, "HEAD") == 0)
//        do_file_response(req, out, docroot);
////    else if (strcmp(req->method, "POST") == 0)
////        //method_not_allowed(req, out);
////    else
////        //not_implemented(req, out);out
//}

static void service(std::istream &in, FILE *out, char *docroot) {
    struct HTTPRequest *req;
    (void)docroot;

    req = read_request(in);
//    respond_to(req, out, docroot);
    //free_request(req);
}

//static int listen_socket(char *port) {
//    struct addrinfo hints, *res, *ai;
//    int err;
//
//    std::memset(&hints, 0, sizeof(struct addrinfo));
//    hints.ai_family = AF_INET;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_flags = AI_PASSIVE;
//    if ((err = getaddrinfo(NULL, port, &hints, &res)) != 0)
//        log_exit("",gai_strerror(err));
//    for (ai = res; ai; ai = ai->ai_next) {
//        int sock;
//
//        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
//        if (sock < 0) continue;
//        if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
//            close(sock);
//            continue;
//        }
//        freeaddrinfo(res);
//        return sock;
//    }
//    log_exit("failed to listen socket");
//    return -1;
//}
//
//static void setup_environment(char *root, char *user, char *group) {
//    struct passwd *pw;
//    struct group *gr;
//
//    if (!user || !group) {
//        std::cerr << "use both of --user and --group" << std::endl;
//        exit(1);
//    }
//    gr = getgrnam(group);
//    if (!gr) {
//        std::cerr << "no such group: " << group << std::endl;
//        exit(1);
//    }
//    if (setgid(gr->gr_gid) < 0) {
//        perror("setgid(2)");
//        exit(1);
//    }
//    if (initgroups(user, gr->gr_gid) < 0) {
//        perror("initgroups(2)");
//        exit(1);
//    }
//    pw = getpwnam(user);
//    if (!pw) {
//        std::cerr << "no such user: " << user << std::endl;
//        exit(1);
//    }
//    chroot(root);
//    if (setuid(pw->pw_uid) < 0) {
//        perror("setuid(2)");
//        exit(1);
//    }
//}
//
//static void server_main(int server_fd, char *docroot) {
//    for(;;) {
//        struct sockaddr_storage addr;
//        socklen_t addrlen = sizeof addr;
//        int sock;
//        int pid;
//
//        sock = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
//        if (sock < 0)
//            log_exit("accept(2) failed:");
//        pid = fork();
//        if (pid < 0) exit(3);
//        if (pid == 0) {
//            FILE *inf = fdopen(sock, "r");
//            FILE *outf = fdopen(sock, "w");
//
//            service(inf, outf, docroot);
//            exit(0);
//        }
//        close(sock);
//    }
//}

int main(int argc, char **argv) {
    HeaderFieldInfo k;
    std::cout << k[CONTENT_LENGTH] << std::endl;
//	if (argc != 2) {
//		fprintf(stderr, "Usage: %s <docroot>\n", argv[0]);
//		exit(1);
//	}
//	install_signal_handlers();
////TODO --> header가 invalid key 또는 value일때 nginx는 어떤 행동을 하는지 조사해보기
////    struct HTTPRequest *req = new HTTPRequest;
////    read_request_line(req, stdin);
//	service(std::cin, stdout, argv[1]);
    return 0;
}



































