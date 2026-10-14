#define _GNU_SOURCE// srt-spawn: spawn helper for Linux. The Dart VM's exit-code thread reaps
// any child with waitpid(-1), so the status of a directly spawned command
// can be lost. This helper (the one the VM may reap) forks the real command
// and reports its exact wait status over a pipe.
//
// usage: srt-spawn STATUSFD FILE ARGV0 [ARG...]
// pipe protocol: 8 bytes {int32 pid, int32 errno} once the command has been
// exec'd (errno != 0: exec failed, pid 0), then 4 bytes {int32 wait status}.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static volatile pid_t child_pid;

static void forward(int sig) {
  pid_t p = child_pid;
  if (p > 0) kill(p, sig);
}

static void write_all(int fd, const void *buf, size_t n) {
  const char *p = buf;
  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR) continue;
      return;
    }
    p += w;
    n -= (size_t)w;
  }
}

int main(int argc, char **argv) {
  if (argc < 4) return 125;
  int sfd = atoi(argv[1]);
  fcntl(sfd, F_SETFD, FD_CLOEXEC);
  int ep[2];
  if (pipe2(ep, O_CLOEXEC) != 0) return 125;

  sigset_t all, old;
  sigfillset(&all);
  sigprocmask(SIG_BLOCK, &all, &old);
  pid_t pid = fork();
  if (pid < 0) {
    int msg[2] = {0, errno};
    write_all(sfd, msg, sizeof msg);
    return 125;
  }
  if (pid == 0) {
    sigprocmask(SIG_SETMASK, &old, NULL);
    close(ep[0]);
    execve(argv[2], argv + 3, environ);
    int e = errno;
    write_all(ep[1], &e, sizeof e);
    _exit(127);
  }
  close(ep[1]);
  child_pid = pid;
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = forward;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  for (int s = 1; s <= SIGRTMAX; s++) {
    if (s == SIGPIPE) continue;
    if (s == SIGKILL || s == SIGSTOP || s == SIGCHLD || s == SIGSEGV ||
        s == SIGBUS || s == SIGFPE || s == SIGILL)
      continue;
    struct sigaction cur;
    if (sigaction(s, NULL, &cur) == 0 && cur.sa_handler == SIG_IGN) continue;
    sigaction(s, &sa, NULL);
  }
  signal(SIGPIPE, SIG_IGN);
  sigprocmask(SIG_SETMASK, &old, NULL);

  int e = 0;
  ssize_t r;
  do {
    r = read(ep[0], &e, sizeof e);
  } while (r < 0 && errno == EINTR);
  if (r != (ssize_t)sizeof e) e = 0;
  int msg[2] = {e ? 0 : (int)pid, e};
  write_all(sfd, msg, sizeof msg);

  int status = 0;
  pid_t w;
  do {
    w = waitpid(pid, &status, 0);
  } while (w < 0 && errno == EINTR);
  sigprocmask(SIG_BLOCK, &all, NULL);
  child_pid = 0;
  sigprocmask(SIG_SETMASK, &old, NULL);
  if (w != pid) return 125;
  if (e == 0) write_all(sfd, &status, sizeof status);
  return 0;
}
