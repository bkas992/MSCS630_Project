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

// Deliverable 2 extra headers 
#include <deque>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

// Deliverable 3 extra headers
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <atomic>

using std::string;

//----------------Deliverable 1: Shell + Process Mgmt-------------------
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

        for (auto it = g_jobs.begin(); it != g_jobs.end(); ++it) {
            Job& j = it->second;
            if (j.pgid == pgid) {
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    std::cout << "[" << j.jobId << "] done  " << j.cmdline << "\n";
                    g_jobs.erase(it);
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

// SIGCHLD handler (keep it minimal)
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
    setpgid(g_shellPgid, g_shellPgid);
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
        write(STDOUT_FILENO, buf, (size_t)r);
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
    do {
        pid = waitpid(-pgid, &status, WUNTRACED);
    } while (pid > 0 && !WIFEXITED(status) && !WIFSIGNALED(status) && !WIFSTOPPED(status));

    take_terminal_back();
    g_fgPgid = -1;

    if (pid < 0) return;

    if (WIFSTOPPED(status)) {
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

    if (!j->running) {
        if (kill(-j->pgid, SIGCONT) != 0) {
            print_error("fg failed to continue job");
            return;
        }
        j->running = true;
    }

    string cmdline = j->cmdline;
    pid_t pgid = j->pgid;

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

// -------------------- Deliverable 2: Scheduling Simulation --------------------------

enum class SimState { Ready, Running, Finished };

struct SimProcess {
    int pid = 0;
    string name;
    int priority = 10;            // lower number = higher priority
    long burstMs = 0;
    long remainingMs = 0;

    SimState state = SimState::Ready;

    std::chrono::steady_clock::time_point arrival;
    std::chrono::steady_clock::time_point firstRun;
    std::chrono::steady_clock::time_point finish;
    bool hasStarted = false;
};

static long ms_between(const std::chrono::steady_clock::time_point& a,
                       const std::chrono::steady_clock::time_point& b) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
}

class SchedulerSim {
public:
    void add(const string& name, long burstMs, int priority) {
        if (burstMs <= 0) burstMs = 1;
        if (priority < 0) priority = 0;

        SimProcess p;
        p.pid = nextPid_++;
        p.name = name;
        p.priority = priority;
        p.burstMs = burstMs;
        p.remainingMs = burstMs;
        p.arrival = std::chrono::steady_clock::now();
        p.state = SimState::Ready;

        {
            std::lock_guard<std::mutex> lk(mu_);
            procs_[p.pid] = p;
            rrQueue_.push_back(p.pid);
            push_prio_locked(p.pid);

            // Preempt request if priority scheduler is active
            if (prioRunning_ && currentPid_ != -1) {
                int curPrio = procs_[currentPid_].priority;
                if (priority < curPrio) preemptRequested_ = true;
            }
        }
        cv_.notify_all();

        std::cout << "simadd pid=" << p.pid
                  << " name=" << p.name
                  << " burstMs=" << p.burstMs
                  << " priority=" << p.priority << "\n";
    }

    void list() {
        std::lock_guard<std::mutex> lk(mu_);
        if (procs_.empty()) { std::cout << "No simulated processes\n"; return; }
        std::cout << "Simulated processes\n";
        for (const auto& kv : procs_) {
            const SimProcess& p = kv.second;
            std::cout << "pid=" << p.pid
                      << " name=" << p.name
                      << " prio=" << p.priority
                      << " remainingMs=" << p.remainingMs
                      << " state=" << state_str(p.state) << "\n";
        }
    }

    void clear() {
        stop_prio();
        std::lock_guard<std::mutex> lk(mu_);
        procs_.clear();
        rrQueue_.clear();
        heap_.clear();
        currentPid_ = -1;
        preemptRequested_ = false;
        std::cout << "simclear done\n";
    }

    void rr_run(long quantumMs) {
        if (quantumMs <= 0) quantumMs = 50;

        std::deque<int> q;
        {
            std::lock_guard<std::mutex> lk(mu_);
            q = rrQueue_;
        }
        if (q.empty()) { std::cout << "rr: no simulated processes\n"; return; }

        std::cout << "rr start quantumMs=" << quantumMs << "\n";

        while (!q.empty()) {
            int pid = q.front();
            q.pop_front();

            SimProcess* pptr = nullptr;
            {
                std::lock_guard<std::mutex> lk(mu_);
                auto it = procs_.find(pid);
                if (it == procs_.end()) continue;
                if (it->second.state == SimState::Finished) continue;

                it->second.state = SimState::Running;
                if (!it->second.hasStarted) {
                    it->second.hasStarted = true;
                    it->second.firstRun = std::chrono::steady_clock::now();
                }
                pptr = &it->second;
            }
            if (!pptr) continue;

            long runFor = std::min(quantumMs, pptr->remainingMs);
            std::cout << "rr running pid=" << pid
                      << " name=" << pptr->name
                      << " runMs=" << runFor
                      << " remainingBefore=" << pptr->remainingMs << "\n";

            std::this_thread::sleep_for(std::chrono::milliseconds(runFor));

            bool finished = false;
            {
                std::lock_guard<std::mutex> lk(mu_);
                SimProcess& p = procs_[pid];
                p.remainingMs -= runFor;
                if (p.remainingMs <= 0) {
                    p.remainingMs = 0;
                    p.state = SimState::Finished;
                    p.finish = std::chrono::steady_clock::now();
                    finished = true;
                } else {
                    p.state = SimState::Ready;
                }
            }

            if (finished) {
                std::cout << "rr finished pid=" << pid << " name=" << pptr->name << "\n";
            } else {
                q.push_back(pid);
            }
        }

        std::cout << "rr done\n";
        stats("Round Robin");
    }

    void prio_start(long tickMs) {
        if (tickMs <= 0) tickMs = 50;

        std::lock_guard<std::mutex> lk(mu_);
        if (prioRunning_) { std::cout << "prio already running\n"; return; }
        prioRunning_ = true;
        stopRequested_ = false;
        tickMs_ = tickMs;
        prioThread_ = std::thread([this]() { this->prio_loop(); });
        std::cout << "prio_start tickMs=" << tickMs_ << "\n";
    }

    void stop_prio() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!prioRunning_) return;
            stopRequested_ = true;
        }
        cv_.notify_all();
        if (prioThread_.joinable()) prioThread_.join();

        std::lock_guard<std::mutex> lk(mu_);
        prioRunning_ = false;
        currentPid_ = -1;
        preemptRequested_ = false;
        std::cout << "prio_stop done\n";
    }

    void prio_status() {
        std::lock_guard<std::mutex> lk(mu_);
        std::cout << "prio running=" << (prioRunning_ ? "yes" : "no");
        if (prioRunning_) std::cout << " currentPid=" << currentPid_;
        std::cout << "\n";
    }

    void stats(const string& title) {
        std::lock_guard<std::mutex> lk(mu_);
        if (procs_.empty()) { std::cout << "No metrics available\n"; return; }

        std::cout << "Metrics: " << title << "\n";
        std::cout << "pid  name  prio  burstMs  responseMs  turnaroundMs  waitingMs  state\n";

        long sumResp = 0, sumTurn = 0, sumWait = 0;
        int countFinished = 0;

        for (const auto& kv : procs_) {
            const SimProcess& p = kv.second;

            long responseMs = 0;
            if (p.hasStarted) responseMs = ms_between(p.arrival, p.firstRun);

            long turnaroundMs = 0;
            long waitingMs = 0;

            if (p.state == SimState::Finished) {
                turnaroundMs = ms_between(p.arrival, p.finish);
                waitingMs = turnaroundMs - p.burstMs;
                if (waitingMs < 0) waitingMs = 0;
                sumResp += responseMs;
                sumTurn += turnaroundMs;
                sumWait += waitingMs;
                countFinished++;
            }

            std::cout << p.pid << "  "
                      << p.name << "  "
                      << p.priority << "  "
                      << p.burstMs << "  "
                      << responseMs << "  "
                      << turnaroundMs << "  "
                      << waitingMs << "  "
                      << state_str(p.state) << "\n";
        }

        if (countFinished > 0) {
            std::cout << "Averages for finished processes\n";
            std::cout << "avgResponseMs=" << (sumResp / countFinished)
                      << " avgTurnaroundMs=" << (sumTurn / countFinished)
                      << " avgWaitingMs=" << (sumWait / countFinished) << "\n";
        } else {
            std::cout << "No finished processes yet for averages\n";
        }
    }

private:
    static const char* state_str(SimState s) {
        switch (s) {
            case SimState::Ready: return "ready";
            case SimState::Running: return "running";
            case SimState::Finished: return "finished";
        }
        return "unknown";
    }

    struct HeapItem {
        int priority;
        long long arrivalNs;
        int pid;
    };

    static bool heap_comp(const HeapItem& a, const HeapItem& b) {
        if (a.priority != b.priority) return a.priority > b.priority;
        return a.arrivalNs > b.arrivalNs;
    }

    void push_prio_locked(int pid) {
        const SimProcess& p = procs_[pid];
        long long arrivalNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
            p.arrival.time_since_epoch()).count();
        heap_.push_back({p.priority, arrivalNs, pid});
        std::push_heap(heap_.begin(), heap_.end(), heap_comp);
    }

    int pop_prio_locked() {
        if (heap_.empty()) return -1;
        std::pop_heap(heap_.begin(), heap_.end(), heap_comp);
        int pid = heap_.back().pid;
        heap_.pop_back();
        return pid;
    }

    void rebuild_heap_locked() {
        heap_.clear();
        for (const auto& kv : procs_) {
            const SimProcess& p = kv.second;
            if (p.state != SimState::Finished && p.remainingMs > 0) {
                push_prio_locked(p.pid);
            }
        }
    }

    bool has_ready_locked() const {
        for (const auto& kv : procs_) {
            const SimProcess& p = kv.second;
            if (p.state != SimState::Finished && p.remainingMs > 0) return true;
        }
        return false;
    }

    void prio_loop() {
        while (true) {
            int pidToRun = -1;

            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&]() { return stopRequested_ || has_ready_locked(); });
                if (stopRequested_) break;

                rebuild_heap_locked();

                if (currentPid_ == -1) {
                    pidToRun = pop_prio_locked();
                    currentPid_ = pidToRun;
                    if (pidToRun != -1) {
                        SimProcess& p = procs_[pidToRun];
                        p.state = SimState::Running;
                        if (!p.hasStarted) {
                            p.hasStarted = true;
                            p.firstRun = std::chrono::steady_clock::now();
                        }
                        std::cout << "prio running pid=" << p.pid
                                  << " name=" << p.name
                                  << " prio=" << p.priority
                                  << " remainingMs=" << p.remainingMs << "\n";
                    }
                } else {
                    pidToRun = currentPid_;
                }
            }

            if (pidToRun == -1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(tickMs_));

            bool finished = false;
            bool preempt = false;

            {
                std::lock_guard<std::mutex> lk(mu_);
                if (stopRequested_) break;

                SimProcess& p = procs_[pidToRun];
                if (p.remainingMs > 0) p.remainingMs -= tickMs_;
                if (p.remainingMs <= 0) {
                    p.remainingMs = 0;
                    p.state = SimState::Finished;
                    p.finish = std::chrono::steady_clock::now();
                    finished = true;
                    std::cout << "prio finished pid=" << p.pid << " name=" << p.name << "\n";
                }

                if (!finished && preemptRequested_) {
                    preemptRequested_ = false;
                    preempt = true;
                }

                if (finished) {
                    currentPid_ = -1;
                } else if (preempt) {
                    p.state = SimState::Ready;
                    push_prio_locked(p.pid);
                    currentPid_ = -1;
                    std::cout << "prio preempt pid=" << p.pid << " name=" << p.name << "\n";
                }
            }

            cv_.notify_all();
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;

    std::map<int, SimProcess> procs_;
    std::deque<int> rrQueue_;

    std::vector<HeapItem> heap_;

    int nextPid_ = 1;

    std::thread prioThread_;
    bool prioRunning_ = false;
    bool stopRequested_ = false;
    int currentPid_ = -1;
    bool preemptRequested_ = false;
    long tickMs_ = 50;
};

static SchedulerSim g_sched;

// -------------------- Deliverable 3: Memory Management --------------------
// Paging with FIFO and LRU replacement

struct PageKey {
    int pid;
    int page;

    bool operator==(const PageKey& other) const {
        return pid == other.pid && page == other.page;
    }

    bool operator!=(const PageKey& other) const {
        return !(*this == other);
    }
};

struct PageKeyHash {
    std::size_t operator()(const PageKey& k) const {
        return std::hash<int>()(k.pid) ^ std::hash<int>()(k.page);
    }
};

class MemoryManager {
public:
    MemoryManager(int frames = 4) : maxFrames(frames) {}

    void setAlgo(const string& a) {
        algo = a;
        frames.clear();
        pages.clear();
        lru.clear();
        accesses = 0;
        faults = 0;
        std::cout << "memory algorithm set to " << algo << "\n";
    }


    void access(int pid, int page) {
        PageKey key{pid, page};
        accesses++;

        if (pages.count(key)) {
            if (algo == "LRU") {
                for (auto it = lru.begin(); it != lru.end(); ++it) {
                    if (it->pid == key.pid && it->page == key.page) {
                        lru.erase(it);
                        break;
                    }
                }
                lru.push_back(key);
            }

            std::cout << "page hit pid=" << pid << " page=" << page << "\n";
            return;
        }

        faults++;
        std::cout << "page fault pid=" << pid << " page=" << page << "\n";

        if ((int)frames.size() >= maxFrames) {
            replace();
        }

        frames.push_back(key);
        pages.insert(key);
        if (algo == "LRU") lru.push_back(key);
    }

    void stats() const {
        std::cout << "memory stats\n";
        std::cout << "frames=" << maxFrames << "\n";
        std::cout << "accesses=" << accesses << "\n";
        std::cout << "faults=" << faults << "\n";
    }

private:
    int maxFrames;
    string algo = "FIFO";
    int accesses = 0;
    int faults = 0;

    std::vector<PageKey> frames;
    std::unordered_set<PageKey, PageKeyHash> pages;
    std::list<PageKey> lru;

    void replace() {
        PageKey victim;

        if (algo == "FIFO") {
            victim = frames.front();
            frames.erase(frames.begin());
        } else { // LRU
            victim = lru.front();
            lru.pop_front();

            for (auto it = frames.begin(); it != frames.end(); ++it) {
                if (it->pid == victim.pid && it->page == victim.page) {
                    frames.erase(it);
                    break;
                }
            }
        }

        pages.erase(victim);

        std::cout << "replaced pid=" << victim.pid
                << " page=" << victim.page << "\n";
    }
};

static MemoryManager g_mem;

// -------------------- Deliverable 3: Process Synchronization --------------------
// Producer Consumer using mutex and condition_variable

class ProducerConsumer {
public:
    ProducerConsumer(int size = 5) : maxSize(size) {}

    void start() {
        if (running) {
            std::cout << "producer consumer already running\n";
            return;
        }

        running = true;

        prod = std::thread(&ProducerConsumer::produce, this);
        cons = std::thread(&ProducerConsumer::consume, this);

        prod.detach();
        cons.detach();

        std::cout << "producer consumer started (non-blocking)\n";
    }


    void stop() {
        running = false;
        cv.notify_all();
        std::cout << "producer consumer stop requested\n";
    }


private:
    std::vector<int> buffer;
    int maxSize;
    std::atomic<bool> running{false};

    std::mutex mu;
    std::condition_variable cv;
    std::thread prod, cons;

    void produce() {
        int item = 0;
        while (running) {
            std::unique_lock<std::mutex> lock(mu);
            cv.wait_for(lock, std::chrono::milliseconds(200),
                        [&] { return buffer.size() < (size_t)maxSize || !running; });

            if (!running) break;

            buffer.push_back(item++);
            std::cout << "[PC] produced item\n";
            cv.notify_all();
        }
    }

    void consume() {
        while (running) {
            std::unique_lock<std::mutex> lock(mu);
            cv.wait_for(lock, std::chrono::milliseconds(300),
                        [&] { return !buffer.empty() || !running; });

            if (!running) break;

            buffer.pop_back();
            std::cout << "[PC] consumed item\n";
            cv.notify_all();
        }
    }
};

static ProducerConsumer g_pc;

static void sched_help() {
    std::cout << "Deliverable 2 scheduling commands\n";
    std::cout << "simadd <name> <burstMs> <priority>\n";
    std::cout << "simps\n";
    std::cout << "simclear\n";
    std::cout << "rr <quantumMs>\n";
    std::cout << "prio_start <tickMs>\n";
    std::cout << "prio_stop\n";
    std::cout << "prio_status\n";
    std::cout << "simstats\n";
    std::cout << "Note: lower priority number means higher priority\n";
}

static bool is_builtin(const string& cmd) {
    static const std::vector<string> builtins = {
        // Deliverable 1
        "cd", "pwd", "exit", "echo", "clear", "ls", "cat", "mkdir", "rmdir", "rm", "touch", "kill",
        "jobs", "fg", "bg",
        // Deliverable 2
        "help2", "simadd", "simps", "simclear", "rr", "prio_start", "prio_stop", "prio_status", "simstats",
        // Deliverable 3
        "memalgo", "memaccess", "memstats", "pc_start", "pc_stop"
    };
    return std::find(builtins.begin(), builtins.end(), cmd) != builtins.end();
}

static void run_builtin(const std::vector<string>& args) {
    if (args.empty()) return;
    const string& cmd = args[0];

    // ---------------- Deliverable 1 ----------------
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

    // ---------------- Deliverable 2 ----------------
    else if (cmd == "help2") sched_help();
    else if (cmd == "simadd") {
        if (args.size() < 4) {
            print_error("simadd requires: simadd <name> <burstMs> <priority>");
            return;
        }
        g_sched.add(args[1], std::stol(args[2]), std::stoi(args[3]));
    }
    else if (cmd == "simps") g_sched.list();
    else if (cmd == "simclear") g_sched.clear();
    else if (cmd == "rr") {
        if (args.size() < 2) {
            print_error("rr requires quantumMs");
            return;
        }
        g_sched.rr_run(std::stol(args[1]));
    }
    else if (cmd == "prio_start") {
        long tick = (args.size() >= 2) ? std::stol(args[1]) : 50;
        g_sched.prio_start(tick);
    }
    else if (cmd == "prio_stop") g_sched.stop_prio();
    else if (cmd == "prio_status") g_sched.prio_status();
    else if (cmd == "simstats") g_sched.stats("Current Simulation");

    // ---------------- Deliverable 3 ----------------
    else if (cmd == "memalgo") {
        g_mem.setAlgo(args[1]);
    }
    else if (cmd == "memaccess") {
        g_mem.access(std::stoi(args[1]), std::stoi(args[2]));
    }
    else if (cmd == "memstats") {
        g_mem.stats();
    }
    else if (cmd == "pc_start") {
        g_pc.start();
    }
    else if (cmd == "pc_stop") {
        g_pc.stop();
    }
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
        setpgid(0, 0);

        if (!background) {
            tcsetpgrp(STDIN_FILENO, getpid());
        }

        signal(SIGINT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        execvp(argv[0], argv.data());

        std::cerr << "Error: command not found: " << args[0] << "\n";
        _exit(127);
    }

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
        if (g_sigchld_flag) {
            g_sigchld_flag = 0;
            errno = 0;
            update_jobs_nonblocking();
        }

        std::cout << "aos-shell$ ";
        std::cout.flush();

        string line;
        if (!std::getline(std::cin, line)) {
            std::cout << "\n";
            break;
        }

        line = trim(line);
        if (line.empty()) continue;

        // Background marker
        bool background = false;
        if (!line.empty() && line.back() == '&') {
            background = true;
            line.pop_back();
            line = trim(line);
        }

        auto args = tokenize(line);
        if (args.empty()) continue;

        if (args[0] == "exit") {
            g_sched.stop_prio();
            for (const auto& kv : g_jobs) kill(-kv.second.pgid, SIGTERM);
            break;
        }

        if (is_builtin(args[0])) {
            run_builtin(args);
            continue;
        }

        exec_external(args, background, line + (background ? " &" : ""));
    }

    return 0;
}
