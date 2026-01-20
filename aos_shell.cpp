#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <utime.h>
#include <dirent.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

using std::string;

struct Job {
    int jobId = 0;
    pid_t pgid = -1;          // process group id
    string cmdline;
    bool running = true;      // true = running, false = stopped
};

static std::map<int, Job> g_jobs;       // jobId -> Job
static int g_nextJobId = 1;

static pid_t g_shellPgid = -1;
static int g_shellTerminal = STDIN_FILENO;
static termios g_shellTmodes{};
static pid_t g_fgPgid = -1;            // current foreground process group

static void print_error(const string& msg) {
    std::cerr << "Error: " << msg;
    if (errno != 0) std::cerr << " (" << std::strerror(errno) << ")";
    std::cerr << "\n";
}

static void ignore_errno() {
    errno = 0;
}

static string trim(const string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Simple tokenizer (supports quotes "like this")
static std::vector<string> tokenize(const string& line) {
    std::vector<string> out;
    string cur;
    bool inQuotes = false;

    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (c == '"') {
            inQuotes = !inQuotes;
            continue;
        }
        if (!inQuotes && (c == ' ' || c == '\t')) {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static void update_jobs_nonblocking() {
    int status = 0;
    pid_t pid;
    // Reap any children that have changed state
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {
        pid_t pgid = getpgid(pid);

        for (auto& kv : g_jobs) {
            Job& j = kv.second;
            if (j.pgid == pgid) {
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    // Job finished
                    j.running = false;
                    // Remove after printing a short message
                    std::cout << "[" << j.jobId << "] done  " << j.cmdline << "\n";
                    g_jobs.erase(kv.first);
                } else if (WIFSTOPPED(status)) {
                    j.running = false;
                    std::cout << "[" << j.jobId << "] stopped  " << j.cmdline << "\n";
                } else if (WIFCONTINUED(status)) {
                    j.running = true;
                }
                break;
            }
        }
    }
}

// Forward Ctrl+C to foreground job
static void on_sigint(int) {
    if (g_fgPgid > 0) {
        kill(-g_fgPgid, SIGINT);
    }
}

// Forward Ctrl+Z to foreground job
static void on_sigtstp(int) {
    if (g_fgPgid > 0) {
        kill(-g_fgPgid, SIGTSTP);
    }
}

// SIGCHLD handler (keep it minimal, do not print here)
static volatile sig_atomic_t g_sigchld_flag = 0;
static void on_sigchld(int) {
    g_sigchld_flag = 1;
}

static void install_signal_handlers() {
    struct sigaction sa{};
    sa.sa_flags = SA_RESTART;

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, nullptr);

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_sigtstp;
    sigaction(SIGTSTP, &sa, nullptr);

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_sigchld;
    sigaction(SIGCHLD, &sa, nullptr);

    // Shell ignores SIGTTOU so tcsetpgrp calls do not stop the shell
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
}

static void init_shell_job_control() {
    g_shellTerminal = STDIN_FILENO;

    // Put shell in its own process group
    g_shellPgid = getpid();
    if (setpgid(g_shellPgid, g_shellPgid) < 0) {
        // Some systems already have pgid set; ignore if harmless
    }
    tcsetpgrp(g_shellTerminal, g_shellPgid);

    // Save terminal modes
    tcgetattr(g_shellTerminal, &g_shellTmodes);
}

static void give_terminal_to(pid_t pgid) {
    tcsetpgrp(g_shellTerminal, pgid);
}

static void take_terminal_back() {
    tcsetpgrp(g_shellTerminal, g_shellPgid);
    tcsetattr(g_shellTerminal, TCSADRAIN, &g_shellTmodes);
}

static void builtin_pwd() {
    char buf[4096];
    if (getcwd(buf, sizeof(buf)) == nullptr) {
        print_error("pwd failed");
        return;
    }
    std::cout << buf << "\n";
}

static void builtin_cd(const std::vector<string>& args) {
    const char* path = nullptr;
    if (args.size() < 2) {
        path = getenv("HOME");
        if (!path) path = ".";
    } else {
        path = args[1].c_str();
    }
    if (chdir(path) != 0) {
        print_error("cd failed");
    }
}

static void builtin_echo(const std::vector<string>& args) {
    for (size_t i = 1; i < args.size(); i++) {
        std::cout << args[i];
        if (i + 1 < args.size()) std::cout << " ";
    }
    std::cout << "\n";
}

static void builtin_clear() {
    // ANSI clear screen
    std::cout << "\033[2J\033[H";
    std::cout.flush();
}

static void builtin_ls() {
    DIR* dir = opendir(".");
    if (!dir) {
        print_error("ls failed to open directory");
        return;
    }
    std::vector<string> names;
    while (auto* ent = readdir(dir)) {
        string name = ent->d_name;
        if (name == "." || name == "..") continue;
        names.push_back(name);
    }
    closedir(dir);
    std::sort(names.begin(), names.end());
    for (const auto& n : names) std::cout << n << "\n";
}

static void builtin_cat(const std::vector<string>& args) {
    if (args.size() < 2) {
        print_error("cat requires a filename");
        return;
    }
    int fd = open(args[1].c_str(), O_RDONLY);
    if (fd < 0) {
        print_error("cat failed to open file");
        return;
    }
    char buf[4096];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t w = write(STDOUT_FILENO, buf, (size_t)r);
        (void)w;
    }
    close(fd);
}

static void builtin_mkdir(const std::vector<string>& args) {
    if (args.size() < 2) {
        print_error("mkdir requires a directory name");
        return;
    }
    if (::mkdir(args[1].c_str(), 0755) != 0) {
        print_error("mkdir failed");
    }
}

static void builtin_rmdir(const std::vector<string>& args) {
    if (args.size() < 2) {
        print_error("rmdir requires a directory name");
        return;
    }
    if (::rmdir(args[1].c_str()) != 0) {
        print_error("rmdir failed (directory must be empty)");
    }
}

static void builtin_rm(const std::vector<string>& args) {
    if (args.size() < 2) {
        print_error("rm requires a filename");
        return;
    }
    if (::unlink(args[1].c_str()) != 0) {
        print_error("rm failed");
    }
}

static void builtin_touch(const std::vector<string>& args) {
    if (args.size() < 2) {
        print_error("touch requires a filename");
        return;
    }
    const char* path = args[1].c_str();

    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        print_error("touch failed to create/open file");
        return;
    }
    close(fd);

    // Update timestamps to current time
    if (utime(path, nullptr) != 0) {
        print_error("touch failed to update timestamp");
    }
}

static void builtin_kill(const std::vector<string>& args) {
    if (args.size() < 2) {
        print_error("kill requires a pid");
        return;
    }
    char* end = nullptr;
    long pid = strtol(args[1].c_str(), &end, 10);
    if (!end || *end != '\0' || pid <= 0) {
        print_error("kill invalid pid");
        return;
    }
    if (::kill((pid_t)pid, SIGTERM) != 0) {
        print_error("kill failed");
    }
}

static void builtin_jobs() {
    if (g_jobs.empty()) {
        std::cout << "No background jobs\n";
        return;
    }
    for (const auto& kv : g_jobs) {
        const Job& j = kv.second;
        std::cout << "[" << j.jobId << "] "
                  << (j.running ? "running" : "stopped")
                  << " pgid=" << j.pgid
                  << "  " << j.cmdline << "\n";
    }
}

static Job* get_job_by_id(int jobId) {
    auto it = g_jobs.find(jobId);
    if (it == g_jobs.end()) return nullptr;
    return &it->second;
}

static void wait_for_foreground(pid_t pgid, const string& cmdline) {
    g_fgPgid = pgid;
    give_terminal_to(pgid);

    int status = 0;
    pid_t pid;
    // Wait until the process group stops or exits
    do {
        pid = waitpid(-pgid, &status, WUNTRACED);
    } while (pid > 0 && !WIFEXITED(status) && !WIFSIGNALED(status) && !WIFSTOPPED(status));

    take_terminal_back();
    g_fgPgid = -1;

    if (pid < 0) return;

    if (WIFSTOPPED(status)) {
        // Put it into jobs list as stopped
        Job j;
        j.jobId = g_nextJobId++;
        j.pgid = pgid;
        j.cmdline = cmdline;
        j.running = false;
        g_jobs[j.jobId] = j;
        std::cout << "[" << j.jobId << "] stopped  " << j.cmdline << "\n";
    }
}

static void builtin_fg(const std::vector<string>& args) {
    if (args.size() < 2) {
        print_error("fg requires a job_id");
        return;
    }
    int jobId = std::stoi(args[1]);
    Job* j = get_job_by_id(jobId);
    if (!j) {
        print_error("fg job not found");
        return;
    }

    // Continue it if stopped
    if (!j->running) {
        if (kill(-j->pgid, SIGCONT) != 0) {
            print_error("fg failed to continue job");
            return;
        }
        j->running = true;
    }

    string cmdline = j->cmdline;
    pid_t pgid = j->pgid;

    // Remove from jobs list while in foreground
    g_jobs.erase(jobId);

    wait_for_foreground(pgid, cmdline);
}

static void builtin_bg(const std::vector<string>& args) {
    if (args.size() < 2) {
        print_error("bg requires a job_id");
        return;
    }
    int jobId = std::stoi(args[1]);
    Job* j = get_job_by_id(jobId);
    if (!j) {
        print_error("bg job not found");
        return;
    }
    if (kill(-j->pgid, SIGCONT) != 0) {
        print_error("bg failed to continue job");
        return;
    }
    j->running = true;
    std::cout << "[" << j->jobId << "] running  " << j->cmdline << "\n";
}

static bool is_builtin(const string& cmd) {
    static const std::vector<string> builtins = {
        "cd","pwd","exit","echo","clear","ls","cat","mkdir","rmdir","rm","touch","kill",
        "jobs","fg","bg"
    };
    return std::find(builtins.begin(), builtins.end(), cmd) != builtins.end();
}

static void run_builtin(const std::vector<string>& args) {
    if (args.empty()) return;
    const string& cmd = args[0];

    if (cmd == "pwd") builtin_pwd();
    else if (cmd == "cd") builtin_cd(args);
    else if (cmd == "echo") builtin_echo(args);
    else if (cmd == "clear") builtin_clear();
    else if (cmd == "ls") builtin_ls();
    else if (cmd == "cat") builtin_cat(args);
    else if (cmd == "mkdir") builtin_mkdir(args);
    else if (cmd == "rmdir") builtin_rmdir(args);
    else if (cmd == "rm") builtin_rm(args);
    else if (cmd == "touch") builtin_touch(args);
    else if (cmd == "kill") builtin_kill(args);
    else if (cmd == "jobs") builtin_jobs();
    else if (cmd == "fg") builtin_fg(args);
    else if (cmd == "bg") builtin_bg(args);
}

static void exec_external(std::vector<string> args, bool background, const string& cmdline) {
    if (args.empty()) return;

    // Build argv for execvp
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& s : args) argv.push_back(const_cast<char*>(s.c_str()));
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) {
        print_error("fork failed");
        return;
    }

    if (pid == 0) {
        // Child: new process group
        setpgid(0, 0);

        // If foreground, take terminal control
        if (!background) {
            tcsetpgrp(STDIN_FILENO, getpid());
        }

        // Restore default signals in child
        signal(SIGINT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        execvp(argv[0], argv.data());

        // If execvp returns, it failed
        std::cerr << "Error: command not found: " << args[0] << "\n";
        _exit(127);
    }

    // Parent: set child pgid
    setpgid(pid, pid);

    if (background) {
        Job j;
        j.jobId = g_nextJobId++;
        j.pgid = pid;
        j.cmdline = cmdline;
        j.running = true;
        g_jobs[j.jobId] = j;

        std::cout << "[" << j.jobId << "] started pgid=" << j.pgid << "  " << j.cmdline << "\n";
    } else {
        wait_for_foreground(pid, cmdline);
    }
}

int main() {
    install_signal_handlers();
    init_shell_job_control();

    while (true) {
        // If SIGCHLD happened, update jobs in the main loop safely
        if (g_sigchld_flag) {
            g_sigchld_flag = 0;
            ignore_errno();
            update_jobs_nonblocking();
        }

        // Prompt
        std::cout << "aos-shell$ ";
        std::cout.flush();

        string line;
        if (!std::getline(std::cin, line)) {
            std::cout << "\n";
            break;
        }

        line = trim(line);
        if (line.empty()) continue;

        // Check background marker "&" at end
        bool background = false;
        if (!line.empty() && line.back() == '&') {
            background = true;
            line.pop_back();
            line = trim(line);
        }

        auto args = tokenize(line);
        if (args.empty()) continue;

        if (args[0] == "exit") {
            // Optional: terminate jobs (simple behavior)
            for (const auto& kv : g_jobs) {
                kill(-kv.second.pgid, SIGTERM);
            }
            break;
        }

        if (is_builtin(args[0])) {
            // Builtins run in shell process (so cd affects current shell)
            run_builtin(args);
            continue;
        }

        exec_external(args, background, line + (background ? " &" : ""));
    }

    return 0;
}
