/*
 * Forked from https://github.com/NixOS/nixpkgs/blob/23.11/pkgs/build-support/libredirect/libredirect.c
 */

/*
 * https://github.com/NixOS/nixpkgs/blob/23.11/COPYING
 *
 * Copyright (c) 2003-2023 Eelco Dolstra and the Nixpkgs/NixOS contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <fts.h>
#include <ftw.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <paths.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static bool debug = false;

#define ERRORF(fmt, ...)                                        \
  fprintf(stderr, "NAC::ERROR| " fmt "\n", ## __VA_ARGS__);

#define DEBUGF(fmt, ...)                                        \
  do {                                                          \
    if (debug)                                                  \
    fprintf(stderr, "NAC::DEBUG| " fmt "\n", ## __VA_ARGS__); \
  } while (0)

#define MAX_REDIRECTS 128

struct dyld_interpose {
  const void * replacement;
  const void * replacee;
};
#define WRAPPER(ret, name) ret _libnac_wrapper_##name
#define LOOKUP_REAL(name) &name
#define WRAPPER_DEF(name) \
  __attribute__((used)) static struct dyld_interpose _libnac_interpose_##name \
  __attribute__((section("__DATA,__interpose"))) = { &_libnac_wrapper_##name, &name };

static int nrRedirects = 0;
static char * from[MAX_REDIRECTS];
static char * to[MAX_REDIRECTS];

static char *stateDirPath;
static char entitlementsPath[PATH_MAX]; // stateDirPath"/entitlements.xml"
static char altbinDirPath[PATH_MAX]; // stateDirPath"/altbin"

const char *entitlementsXML =
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
"<plist version=\"1.0\">\n"
"  <dict>\n"
"    <key>com.apple.security.cs.allow-dyld-environment-variables</key>\n"
"    <true/>\n"
"  </dict>\n"
"</plist>\n";

static int isInitialized = 0;

static void write_file(const char *path, const char *content)
{
  int fd = open(path, O_WRONLY | O_CREAT, 0644);
  if (fd < 0) {
    ERRORF("failed to open \"%s\": %s", path, strerror(errno));
    abort();
  }
  int rc = write(fd, content, strlen(content));
  close(fd);
  if (rc < 0) {
    ERRORF("failed to write \"%s\": %s", path, strerror(errno));
    abort();
  }
}

char **environ;

static void exec_cmd(const char *fmt, ...)
{
  va_list ap;
  va_start(ap,fmt);
  va_end(ap);
  char *cmd;
  if ((vasprintf(&cmd, fmt, ap) < 0) || cmd == NULL) {
    ERRORF("failed to call vasprintf: %s", strerror(errno));
    abort();
  }
  DEBUGF("Executing cmd `%s`", cmd);
  pid_t child_pid;
  char *argv[] = {
    "/bin/sh",
    "-c",
    cmd,
    NULL,
  };
  // system(3) cannot be used here due to recursion of exec_cmd.
  int (*posix_spawn_real) (pid_t *, const char *,
      const posix_spawn_file_actions_t *,
      const posix_spawnattr_t *,
      char * const argv[], char * const envp[]) = LOOKUP_REAL(posix_spawn);
  int rc = posix_spawn_real(&child_pid, argv[0], NULL, NULL, argv, environ);
  if (rc < 0) {
    ERRORF("failed to execute `%s`: %s", cmd, strerror(errno));
    abort();
  }
  int child_status;
  do {
    if ((rc = waitpid(child_pid, &child_status, WUNTRACED | WCONTINUED)) < 0 ) {
      ERRORF("failed to waitpid for `%s`: %s", cmd, strerror(errno));
      abort();
    }
    if (WIFEXITED(child_status)) rc = WEXITSTATUS(child_status);
  } while (!WIFEXITED(child_status));

  DEBUGF("Executed `%s` (%d)", cmd, rc);
  if (rc < 0) {
    ERRORF("failed to execute `%s`: %s", cmd, strerror(errno));
    abort();
  }
  free(cmd);
}

// FIXME: might run too late.
static void init() __attribute__((constructor));

static void init()
{
  if (isInitialized) return;

  if (getenv("_NAC_DEBUG") != NULL) {
    debug = true;
  }

  stateDirPath = getenv("_NAC_STATE_DIR");
  if (!stateDirPath || strlen(stateDirPath) == 0) {
    ERRORF("_NAC_STATE_DIR is unset");
    abort();
  };
  if (mkdir(stateDirPath, 0755) < 0 && errno != EEXIST) {
    ERRORF("failed to mkdir \"%s\": %s", stateDirPath, strerror(errno));
    abort();
  }

  strlcpy(entitlementsPath, stateDirPath, sizeof(entitlementsPath));
  strlcat(entitlementsPath, "/entitlements.xml", sizeof(entitlementsPath));
  write_file(entitlementsPath, entitlementsXML);

  strlcpy(altbinDirPath, stateDirPath, sizeof(altbinDirPath));
  strlcat(altbinDirPath, "/altbin", sizeof(altbinDirPath));
  if (mkdir(altbinDirPath, 0755) < 0 && errno != EEXIST) {
    ERRORF("failed to mkdir \"%s\": %s", altbinDirPath, strerror(errno));
    abort();
  }

  char * spec = getenv("_NAC_REDIRECTS");
  if (!spec) return;

  // Ensure we only run this code once.
  // We do not do `unsetenv("_NAC_REDIRECTS")` to ensure that redirects
  // also get initialized for subprocesses.
  isInitialized = 1;

  char * spec2 = malloc(strlen(spec) + 1);
  strcpy(spec2, spec);

  char * pos = spec2, * eq;
  while ((eq = strchr(pos, '='))) {
    *eq = 0;
    from[nrRedirects] = pos;
    pos = eq + 1;
    to[nrRedirects] = pos;
    nrRedirects++;
    if (nrRedirects == MAX_REDIRECTS) break;
    char * end = strchr(pos, ':');
    if (!end) break;
    *end = 0;
    pos = end + 1;
  }

}

// FIXME: handle relative paths
static const char * rewrite(const char * volatile path, char * buf)
{
  // Marking the path volatile is needed so the the following check isn't
  // optimized away by the compiler.
  if (path == NULL) return path;

  for (int n = 0; n < nrRedirects; ++n) {
    int len = strlen(from[n]);
    if (strncmp(path, from[n], len) != 0) continue;
    if (snprintf(buf, PATH_MAX, "%s%s", to[n], path + len) >= PATH_MAX)
      abort();
    return buf;
  }

  return path;
}

static char * rewrite_non_const(char * path, char * buf)
{
  // as long as the argument `path` is non-const, we can consider discarding
  // the const qualifier of the return value to be safe.
  return (char *)rewrite(path, buf);
}

// FIXME: handle relative paths
static const char * rewrite_rev(const char * volatile path, char * buf)
{
  // Marking the path volatile is needed so the the following check isn't
  // optimized away by the compiler.
  if (path == NULL) return path;

  for (int n = 0; n < nrRedirects; ++n) {
    int len = strlen(to[n]);
    if (strncmp(path, to[n], len) != 0) continue;
    if (snprintf(buf, PATH_MAX, "%s%s", from[n], path + len) >= PATH_MAX)
      abort();
    return buf;
  }

  return path;
}

static char * rewrite_rev_non_const(char * path, char * buf)
{
  // as long as the argument `path` is non-const, we can consider discarding
  // the const qualifier of the return value to be safe.
  return (char *)rewrite_rev(path, buf);
}

static bool has_shebang(const char * path)
{
  char buf[2];
  int fd = open(path, O_RDONLY);
  read(fd, buf, sizeof(buf));
  close(fd);
  return buf[0] == '#' && buf[1] == '!';
}

static const char * rewrite_exe(const char * volatile path, char * altbin)
{
  if (strstr(path, altbinDirPath) != NULL) return path; // Already processed
  char rewrite_altbin[PATH_MAX];
  const char *rewritten = rewrite(path, rewrite_altbin);
  if (rewritten == NULL) return NULL;
  char rewrite_altbin2[PATH_MAX];
  rewritten = realpath(rewritten, rewrite_altbin2);
  if (rewritten == NULL) abort();
  strlcpy(altbin, altbinDirPath, PATH_MAX);
  strlcat(altbin, "/", PATH_MAX);
  if (strlcat(altbin, rewritten, PATH_MAX) >= PATH_MAX) {
    ERRORF("file name is too long (%d): \"%s\" (-> \"%s\" -> \"%s\")", PATH_MAX, path, rewritten, altbin);
    abort();
  }
  if (access(altbin, F_OK) != 0) {
    exec_cmd("mkdir -p \"$(dirname '%s')\"", altbin);
    if (has_shebang(path)) {
      FILE *fp = fopen(path, "r");
      if (fp ==NULL) return path; // let caller fail
      char *shebang_line = NULL;
      size_t shebang_linecap = 0;
      ssize_t shebang_linelen;
      if ((shebang_linelen = getline(&shebang_line, &shebang_linecap, fp)) <= 0) {
        ERRORF("failed to get the shebang line for \"%s\": %s", path, strerror(errno));
        abort();
      }
      int shebang_wrapper_fd = open(altbin, O_WRONLY | O_CREAT, 0755);
      if (shebang_wrapper_fd < 0) {
        ERRORF("failed to open \"%s\": %s", altbin, strerror(errno));
        abort();
      }
      int rc;
      char sh_altbin[PATH_MAX];
      if (rewrite_exe("/bin/sh", sh_altbin) == NULL) abort();
      if ((rc = write(shebang_wrapper_fd, "#!", 2)) < 0 ) abort();
      if ((rc = write(shebang_wrapper_fd, sh_altbin, strlen(sh_altbin))) < 0 ) abort();
      if ((rc = write(shebang_wrapper_fd, "\n", 1)) < 0 ) abort();
      if ((rc = write(shebang_wrapper_fd, "exec ", strlen("exec "))) < 0 ) abort();
      if ((rc = write(shebang_wrapper_fd, shebang_line + 2, strlen(shebang_line) - 3 )) < 0 ) abort();
      if ((rc = write(shebang_wrapper_fd, " ", 1)) < 0 ) abort();
      if ((rc = write(shebang_wrapper_fd, path, strlen(path))) < 0 ) abort();
      if ((rc = write(shebang_wrapper_fd, " \"$@\"\n", strlen(" \"$@\"\n"))) < 0 ) abort();
      close(shebang_wrapper_fd);
      free(shebang_line);
      fclose(fp);
    } else {
      exec_cmd("cp -a '%s' '%s'", rewritten, altbin);
      exec_cmd("codesign --force --preserve-metadata=entitlements --sign - --entitlements '%s' '%s'", entitlementsPath, altbin);
    }
  }
  return altbin;
}

static int open_needs_mode(int flags)
{
  return flags & O_CREAT;
}

WRAPPER(int, open)(const char * path, int flags, ...)
{
  int (*open_real) (const char *, int, ...) = LOOKUP_REAL(open);
  int mode = 0;
  if (open_needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  char buf[PATH_MAX];
  return open_real(rewrite(path, buf), flags, mode);
}
WRAPPER_DEF(open)

WRAPPER(int, openat)(int dirfd, const char * path, int flags, ...)
{
  int (*openat_real) (int, const char *, int, ...) = LOOKUP_REAL(openat);
  int mode = 0;
  if (open_needs_mode(flags)) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  char buf[PATH_MAX];
  // FIXME: rewrite has to care about dirfd
  return openat_real(dirfd, rewrite(path, buf), flags, mode);
}
WRAPPER_DEF(openat)

WRAPPER(FILE *, fopen)(const char * path, const char * mode)
{
  FILE * (*fopen_real) (const char *, const char *) = LOOKUP_REAL(fopen);
  char buf[PATH_MAX];
  return fopen_real(rewrite(path, buf), mode);
}
WRAPPER_DEF(fopen)

WRAPPER(int, fstatat)(int dirfd, const char * pathname, struct stat * statbuf, int flags)
{
  int (*fstatat_real) (int, const char *, struct stat *, int) = LOOKUP_REAL(fstatat);
  char buf[PATH_MAX];
  // FIXME: rewrite has to care about dirfd
  return fstatat_real(dirfd, rewrite(pathname, buf), statbuf, flags);
}
WRAPPER_DEF(fstatat);

WRAPPER(int, stat)(const char * path, struct stat * st)
{
  int (*__stat_real) (const char *, struct stat *) = LOOKUP_REAL(stat);
  char buf[PATH_MAX];
  return __stat_real(rewrite(path, buf), st);
}
WRAPPER_DEF(stat)

WRAPPER(int, stat64)(const char * path, struct stat64 * st)
{
  int (*stat64_real) (const char *, struct stat64 *) = LOOKUP_REAL(stat64);
  char buf[PATH_MAX];
  return stat64_real(rewrite(path, buf), st);
}
WRAPPER_DEF(stat64)

WRAPPER(int, lstat)(const char * path, struct stat * st)
{
  int (*lstat_real) (const char *, struct stat *) = LOOKUP_REAL(lstat);
  char buf[PATH_MAX];
  return lstat_real(rewrite(path, buf), st);
}
WRAPPER_DEF(lstat)

WRAPPER(int, lstat64)(const char * path, struct stat64 * st)
{
  int (*lstat64_real) (const char *, struct stat64 *) = LOOKUP_REAL(lstat64);
  char buf[PATH_MAX];
  return lstat64_real(rewrite(path, buf), st);
}
WRAPPER_DEF(lstat64)

WRAPPER(int, access)(const char * path, int mode)
{
  int (*access_real) (const char *, int mode) = LOOKUP_REAL(access);
  char buf[PATH_MAX];
  return access_real(rewrite(path, buf), mode);
}
WRAPPER_DEF(access)

WRAPPER(int, posix_spawn)(pid_t * pid, const char * path,
    const posix_spawn_file_actions_t * file_actions,
    const posix_spawnattr_t * attrp,
    char * const argv[], char * const envp[])
{
  int (*posix_spawn_real) (pid_t *, const char *,
      const posix_spawn_file_actions_t *,
      const posix_spawnattr_t *,
      char * const argv[], char * const envp[]) = LOOKUP_REAL(posix_spawn);
  char buf[PATH_MAX];
  return posix_spawn_real(pid, rewrite_exe(path, buf), file_actions, attrp, argv, envp);
}
WRAPPER_DEF(posix_spawn)

WRAPPER(int, posix_spawnp)(pid_t * pid, const char * file,
    const posix_spawn_file_actions_t * file_actions,
    const posix_spawnattr_t * attrp,
    char * const argv[], char * const envp[])
{
  int (*posix_spawnp_real) (pid_t *, const char *,
      const posix_spawn_file_actions_t *,
      const posix_spawnattr_t *,
      char * const argv[], char * const envp[]) = LOOKUP_REAL(posix_spawnp);
  char buf[PATH_MAX];
  return posix_spawnp_real(pid, rewrite_exe(file, buf), file_actions, attrp, argv, envp);
}
WRAPPER_DEF(posix_spawnp)

WRAPPER(int, execv)(const char * path, char * const argv[])
{
  int (*execv_real) (const char * path, char * const argv[]) = LOOKUP_REAL(execv);
  char buf[PATH_MAX];
  return execv_real(rewrite_exe(path, buf), argv);
}
WRAPPER_DEF(execv)

char * resolve_path(const char *s, char *buf, const char *pathenv)
{
  if (s[0] == '/' || s[0] == '.') return (char *)s;
  if (pathenv == NULL) pathenv = getenv("PATH");
  if (pathenv == NULL) pathenv = _PATH_DEFPATH;

  char *dir;
  char *pathenv_strdup = strdup(pathenv);
  for (dir = strtok(pathenv_strdup, ":" ); dir; dir = strtok( NULL, ":" )) {
    if (snprintf(buf, PATH_MAX, "%s/%s", dir, s) >= PATH_MAX) continue;
    // TODO: rewrite buf
    if (access(buf, X_OK) == 0) {
      free(pathenv_strdup);
      return buf;
    }
  }
  free(pathenv_strdup);
  return NULL;
}

WRAPPER(int, execvp)(const char * path, char * const argv[])
{
  int (*_execvp) (const char *, char * const argv[]) = LOOKUP_REAL(execvp);
  char pathbuf[PATH_MAX];
  char buf[PATH_MAX];
  return _execvp(rewrite_exe(resolve_path(path, pathbuf, NULL), buf), argv);
}
WRAPPER_DEF(execvp)

WRAPPER(int, execvP)(const char * path, const char *search_path, char * const argv[])
{
  int (*_execvp) (const char *, char * const argv[]) = LOOKUP_REAL(execvp);
  char pathbuf[PATH_MAX];
  char buf[PATH_MAX];
  return _execvp(rewrite_exe(resolve_path(path, pathbuf, search_path), buf), argv);
}
WRAPPER_DEF(execvP)

WRAPPER(int, execve)(const char * path, char * const argv[], char * const envp[])
{
  int (*_execve) (const char *, char * const argv[], char * const envp[]) = LOOKUP_REAL(execve);
  char buf[PATH_MAX];
  return _execve(rewrite_exe(path, buf), argv, envp);
}
WRAPPER_DEF(execve)

WRAPPER(DIR *, opendir)(const char * path)
{
  char buf[PATH_MAX];
  DIR * (*_opendir) (const char*) = LOOKUP_REAL(opendir);

  return _opendir(rewrite(path, buf));
}
WRAPPER_DEF(opendir)

#define SYSTEM_CMD_MAX 512

  static char * replace_substring(char * source, char * buf, char * replace_string, char * start_ptr, char * suffix_ptr) {
    char head[SYSTEM_CMD_MAX] = {0};
    strncpy(head, source, start_ptr - source);

    char tail[SYSTEM_CMD_MAX] = {0};
    if(suffix_ptr < source + strlen(source)) {
      strcpy(tail, suffix_ptr);
    }

    sprintf(buf, "%s%s%s", head, replace_string, tail);
    return buf;
  }

static char * replace_string(char * buf, char * from, char * to) {
  int num_matches = 0;
  char * matches[SYSTEM_CMD_MAX];
  int from_len = strlen(from);
  for(int i=0; i<strlen(buf); i++){
    char *cmp_start = buf + i;
    if(strncmp(from, cmp_start, from_len) == 0){
      matches[num_matches] = cmp_start;
      num_matches++;
    }
  }
  int len_diff = strlen(to) - strlen(from);
  for(int n = 0; n < num_matches; n++) {
    char replaced[SYSTEM_CMD_MAX];
    replace_substring(buf, replaced, to, matches[n], matches[n]+from_len);
    strcpy(buf, replaced);
    for(int nn = n+1; nn < num_matches; nn++) {
      matches[nn] += len_diff;
    }
  }
  return buf;
}

static void rewriteSystemCall(const char * command, char * buf) {
  char * p = buf;

  // The dyld environment variable is not inherited by the subprocess spawned
  // by system(), so this hack redefines it.
  Dl_info info;
  dladdr(&rewriteSystemCall, &info);
  p = stpcpy(p, "export DYLD_INSERT_LIBRARIES=");
  p = stpcpy(p, info.dli_fname);
  p = stpcpy(p, ";");

  stpcpy(p, command);

  for (int n = 0; n < nrRedirects; ++n) {
    replace_string(buf, from[n], to[n]);
  }
}

WRAPPER(int, system)(const char *command)
{
  int (*_system) (const char*) = LOOKUP_REAL(system);

  char newCommand[SYSTEM_CMD_MAX];
  rewriteSystemCall(command, newCommand);
  return _system(newCommand);
}
WRAPPER_DEF(system)

WRAPPER(int, chdir)(const char *path)
{
  int (*chdir_real) (const char *) = LOOKUP_REAL(chdir);
  char buf[PATH_MAX];
  return chdir_real(rewrite(path, buf));
}
WRAPPER_DEF(chdir);

WRAPPER(int, mkdir)(const char *path, mode_t mode)
{
  int (*mkdir_real) (const char *path, mode_t mode) = LOOKUP_REAL(mkdir);
  char buf[PATH_MAX];
  return mkdir_real(rewrite(path, buf), mode);
}
WRAPPER_DEF(mkdir)

WRAPPER(int, mkdirat)(int dirfd, const char *path, mode_t mode)
{
  int (*mkdirat_real) (int dirfd, const char *path, mode_t mode) = LOOKUP_REAL(mkdirat);
  char buf[PATH_MAX];
  // FIXME: rewrite has to care about dirfd
  return mkdirat_real(dirfd, rewrite(path, buf), mode);
}
WRAPPER_DEF(mkdirat)

WRAPPER(int, unlink)(const char *path)
{
  int (*unlink_real) (const char *path) = LOOKUP_REAL(unlink);
  char buf[PATH_MAX];
  return unlink_real(rewrite(path, buf));
}
WRAPPER_DEF(unlink)

WRAPPER(int, unlinkat)(int dirfd, const char *path, int flags)
{
  int (*unlinkat_real) (int dirfd, const char *path, int flags) = LOOKUP_REAL(unlinkat);
  char buf[PATH_MAX];
  // FIXME: rewrite has to care about dirfd
  return unlinkat_real(dirfd, rewrite(path, buf), flags);
}
WRAPPER_DEF(unlinkat)

WRAPPER(int, rmdir)(const char *path)
{
  int (*rmdir_real) (const char *path) = LOOKUP_REAL(rmdir);
  char buf[PATH_MAX];
  return rmdir_real(rewrite(path, buf));
}
WRAPPER_DEF(rmdir)

  static void copy_temp_wildcard(char * dest, char * src, int suffixlen) {
    int dest_len = strnlen(dest, PATH_MAX);
    int src_len = strnlen(src, PATH_MAX);
    memcpy(dest + dest_len - (6 + suffixlen), src + src_len - (6 + suffixlen), 6);
  }

WRAPPER(int, mkstemp)(char *template)
{
  int (*mkstemp_real) (char *template) = LOOKUP_REAL(mkstemp);
  char buf[PATH_MAX];
  char * rewritten = rewrite_non_const(template, buf);
  int retval = mkstemp_real(rewritten);
  if (retval >= 0 && rewritten != template) {
    copy_temp_wildcard(template, rewritten, 0);
  }
  return retval;
}
WRAPPER_DEF(mkstemp)

WRAPPER(int, mkostemp)(char *template, int flags)
{
  int (*mkostemp_real) (char *template, int flags) = LOOKUP_REAL(mkostemp);
  char buf[PATH_MAX];
  char * rewritten = rewrite_non_const(template, buf);
  int retval = mkostemp_real(rewritten, flags);
  if (retval >= 0 && rewritten != template) {
    copy_temp_wildcard(template, rewritten, 0);
  }
  return retval;
}
WRAPPER_DEF(mkostemp)

WRAPPER(int, mkstemps)(char *template, int suffixlen)
{
  int (*mkstemps_real) (char *template, int suffixlen) = LOOKUP_REAL(mkstemps);
  char buf[PATH_MAX];
  char * rewritten = rewrite_non_const(template, buf);
  int retval = mkstemps_real(rewritten, suffixlen);
  if (retval >= 0 && rewritten != template) {
    copy_temp_wildcard(template, rewritten, suffixlen);
  }
  return retval;
}
WRAPPER_DEF(mkstemps)

WRAPPER(int, mkostemps)(char *template, int suffixlen, int flags)
{
  int (*mkostemps_real) (char *template, int suffixlen, int flags) = LOOKUP_REAL(mkostemps);
  char buf[PATH_MAX];
  char * rewritten = rewrite_non_const(template, buf);
  int retval = mkostemps_real(rewritten, suffixlen, flags);
  if (retval >= 0 && rewritten != template) {
    copy_temp_wildcard(template, rewritten, suffixlen);
  }
  return retval;
}
WRAPPER_DEF(mkostemps)

WRAPPER(char *, mkdtemp)(char *template)
{
  char * (*mkdtemp_real) (char *template) = LOOKUP_REAL(mkdtemp);
  char buf[PATH_MAX];
  char * rewritten = rewrite_non_const(template, buf);
  char * retval = mkdtemp_real(rewritten);
  if (retval == NULL) {
    return retval;
  };
  if (rewritten != template) {
    copy_temp_wildcard(template, rewritten, 0);
  }
  return template;
}
WRAPPER_DEF(mkdtemp)

WRAPPER(char *, mktemp)(char *template)
{
  char * (*mktemp_real) (char *template) = LOOKUP_REAL(mktemp);
  char buf[PATH_MAX];
  char * rewritten = rewrite_non_const(template, buf);
  char * retval = mktemp_real(rewritten);
  if (retval == NULL) {
    return retval;
  };
  if (rewritten != template) {
    copy_temp_wildcard(template, rewritten, 0);
  }
  return template;
}
WRAPPER_DEF(mktemp)

  // No need to wrap basename, dirname, etc., as they do not check the real files.

WRAPPER(char *, realpath)(const char *restrict file_name, char *resolved_name)
{
  char *(*realpath_real) (const char *restrict file_name, char *) = LOOKUP_REAL(realpath);
  char buf[PATH_MAX];
  char *retval = realpath_real(rewrite(file_name, buf), resolved_name);
  if (retval == NULL) return NULL;
  char *rewritten = rewrite_rev_non_const(retval, buf);
  if (rewritten == NULL) return retval;
  size_t sz = MIN(strlen(retval)+1, PATH_MAX);
  memmove(retval, rewritten, sz);
  return retval;
}
WRAPPER_DEF(realpath)

  // See dyld(3)
WRAPPER(int, _NSGetExecutablePath)(char* xbuf, uint32_t* xbufsize)
{
  int (*_NSGetExecutablePath_real) (char* xbuf, uint32_t* xbufsize) = LOOKUP_REAL(_NSGetExecutablePath);
  int rc = _NSGetExecutablePath(xbuf, xbufsize);
  if (rc != 0) return rc;
  char *rewritten = NULL;
  if (strstr(xbuf, altbinDirPath)) rewritten = xbuf + strlen(altbinDirPath) + 1;
  if (rewritten == NULL) return rc;
  size_t sz = MIN(strlen(xbuf)+1, PATH_MAX);
  memmove(xbuf, rewritten, sz);
  return 0;
}
WRAPPER_DEF(_NSGetExecutablePath)

WRAPPER(int, ftw)(const char *path, int (*fn)(const char *, const struct stat *ptr, int flag), int depth)
{
  int (*ftw_real) (const char *path, int (*fn)(const char *, const struct stat *ptr, int flag), int depth) = LOOKUP_REAL(ftw);
  char buf[PATH_MAX];
  return ftw_real(rewrite(path, buf), fn, depth);
}
WRAPPER_DEF(ftw)

WRAPPER(int, nftw)(const char *path, int (*fn)(const char *, const struct stat *ptr, int flag, struct FTW *), int depth, int flags)
{
  int (*nftw_real )(const char *path, int (*fn)(const char *, const struct stat *ptr, int flag, struct FTW *), int depth, int flags) = LOOKUP_REAL(nftw);
  char buf[PATH_MAX];
  return nftw_real(rewrite(path, buf), fn, depth, flags);
}
WRAPPER_DEF(nftw)

WRAPPER(FTS *, fts_open)(char * const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **))
{
  FTS * (*fts_open_real) (char * const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **)) = LOOKUP_REAL(fts_open);
  char **f;
  for (f = (char **)path_argv; *f != NULL; f++) {
    char *buf = (char *)alloca(PATH_MAX);
    *f = rewrite_non_const(*f, buf);
  }
  return fts_open_real(path_argv, options, compar);
}
WRAPPER_DEF(fts_open)

WRAPPER(FTS *, fts_open_b)(char * const *path_argv, int options, int (^compar)(const FTSENT **, const FTSENT **))
{
  FTS * (*fts_open_b_real) (char * const *path_argv, int options, int (^compar)(const FTSENT **, const FTSENT **)) = LOOKUP_REAL(fts_open_b);
  char **f;
  for (f = (char **)path_argv; *f != NULL; f++) {
    char *buf = (char *)alloca(PATH_MAX);
    *f = rewrite_non_const(*f, buf);
  }
  return fts_open_b_real(path_argv, options, compar);
}
WRAPPER_DEF(fts_open_b)

WRAPPER(int, getattrlist)(const char* path, void * attrList, void * attrBuf, size_t attrBufSize, unsigned int options)
{
  int (*getattrlist_real) (const char* path, void * attrList, void * attrBuf, size_t attrBufSize, unsigned int options) = LOOKUP_REAL(getattrlist);
  char buf[PATH_MAX];
  return getattrlist_real(rewrite(path, buf), attrList, attrBuf, attrBufSize, options);
}
WRAPPER_DEF(getattrlist);

WRAPPER(int, getattrlistat)(int fd, const char* path, void * attrList, void * attrBuf, size_t attrBufSize, unsigned long options)
{
  int (*getattrlistat_real) (int fd, const char* path, void * attrList, void * attrBuf, size_t attrBufSize, unsigned long options) = LOOKUP_REAL(getattrlistat);
  char buf[PATH_MAX];
  // FIXME: rewrite has to care about dirfd
  return getattrlistat_real(fd, rewrite(path, buf), attrList, attrBuf, attrBufSize, options);
}
WRAPPER_DEF(getattrlistat);

WRAPPER(ssize_t, listxattr)(const char *path, char *namebuf, size_t size, int options)
{
  ssize_t (*listxattr_real) (const char *path, char *namebuf, size_t size, int options) = LOOKUP_REAL(listxattr);
  char buf[PATH_MAX];
  return listxattr_real(rewrite(path, buf), namebuf, size, options);
}
WRAPPER_DEF(listxattr)

WRAPPER(ssize_t, getxattr) (const char *path, const char *name, void *value, size_t size, u_int32_t position, int options)
{
  ssize_t (*getxattr_real) (const char *path, const char *name, void *value, size_t size, u_int32_t position, int options) = LOOKUP_REAL(getxattr);
  char buf[PATH_MAX];
  return getxattr_real(rewrite(path, buf), name, value, size, position, options);
}
WRAPPER_DEF(getxattr)

WRAPPER(int, removexattr)(const char *path, const char *name, int options)
{
  int (*removexattr_real) (const char *path, const char *name, int options) = LOOKUP_REAL(removexattr);
  char buf[PATH_MAX];
  return removexattr_real(rewrite(path, buf), name, options);
}
WRAPPER_DEF(removexattr)

WRAPPER(void *, dlopen)(const char *path, int mode)
{
  void* (*dlopen_real) (const char *path, int mode) = LOOKUP_REAL(dlopen);
  char buf[PATH_MAX];
  return dlopen_real(rewrite(path, buf), mode);
}
WRAPPER_DEF(dlopen);

WRAPPER(bool, dlopen_preflight)(const char *path)
{
  bool (*dlopen_preflight_real) (const char *path) = LOOKUP_REAL(dlopen_preflight);
  char buf[PATH_MAX];
  return dlopen_preflight_real(rewrite(path, buf));
}
WRAPPER_DEF(dlopen_preflight);

/*
 * TODO: popen
 */
