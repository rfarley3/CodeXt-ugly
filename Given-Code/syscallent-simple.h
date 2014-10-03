/* file taken from strace-4.6: linux/i386/syscallent.h */

/*
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995 Rick Sladkey <jrs@world.std.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	$Id$
 */

	{ 0,	0,	"restart_syscall" }, /* 0 */
	{ 1,	TP,		"_exit"}, /* 1 */
	{ 0,	TP,		"fork"}, /* 2 */
	{ 3,	TD,		"read"}, /* 3 */
	{ 3,	TD,		"write"}, /* 4 */
	{ 3,	TD|TF,		"open"		}, /* 5 */
	{ 1,	TD,		"close"		}, /* 6 */
	{ 3,	TP,		"waitpid"}, /* 7 */
	{ 2,	TD|TF,		"creat"		}, /* 8 */
	{ 2,	TF,		"link"		}, /* 9 */
	{ 1,	TF,		"unlink"	}, /* 10 */
	{ 3,	TF|TP,		"execve"}, /* 11 */
	{ 1,	TF,		"chdir"		}, /* 12 */
	{ 1,	0,		"time"		}, /* 13 */
	{ 3,	TF,		"mknod"		}, /* 14 */
	{ 2,	TF,		"chmod"		}, /* 15 */
	{ 3,	TF,		"lchown"	}, /* 16 */
	{ 0,	0,		"break"		}, /* 17 */
	{ 2,	TF,		"oldstat"	}, /* 18 */
	{ 3,	TD,		"lseek"		}, /* 19 */
	{ 0,	0,		"getpid"	}, /* 20 */
	{ 5,	TF,		"mount"		}, /* 21 */
	{ 1,	TF,		"oldumount"	}, /* 22 */
	{ 1,	0,		"setuid"	}, /* 23 */
	{ 0,	NF,		"getuid"	}, /* 24 */
	{ 1,	0,		"stime"		}, /* 25 */
	{ 4,	0,		"ptrace"	}, /* 26 */
	{ 1,	0,		"alarm"		}, /* 27 */
	{ 2,	TD,		"oldfstat"	}, /* 28 */
	{ 0,	TS,		"pause"		}, /* 29 */
	{ 2,	TF,		"utime"		}, /* 30 */
	{ 2,	0,		"stty"		}, /* 31 */
	{ 2,	0,		"gtty"		}, /* 32 */
	{ 2,	TF,		"access"	}, /* 33 */
	{ 1,	0,		"nice"		}, /* 34 */
	{ 0,	0,		"ftime"		}, /* 35 */
	{ 0,	0,		"sync"		}, /* 36 */
	{ 2,	TS,		"kill"		}, /* 37 */
	{ 2,	TF,		"rename"	}, /* 38 */
	{ 2,	TF,		"mkdir"		}, /* 39 */
	{ 1,	TF,		"rmdir"		}, /* 40 */
	{ 1,	TD,		"dup"		}, /* 41 */
	{ 1,	TD,		"pipe"		}, /* 42 */
	{ 1,	0,		"times"		}, /* 43 */
	{ 0,	0,		"prof"		}, /* 44 */
	{ 1,	0,		"brk"		}, /* 45 */
	{ 1,	0,		"setgid"	}, /* 46 */
	{ 0,	NF,		"getgid"	}, /* 47 */
	{ 3,	TS,		"signal"	}, /* 48 */
	{ 0,	NF,		"geteuid"	}, /* 49 */
	{ 0,	NF,		"getegid"	}, /* 50 */
	{ 1,	TF,		"acct"		}, /* 51 */
	{ 2,	TF,		"umount"	}, /* 52 */
	{ 0,	0,		"lock"		}, /* 53 */
	{ 3,	TD,		"ioctl"		}, /* 54 */
	{ 3,	TD,		"fcntl"		}, /* 55 */
	{ 0,	0,		"mpx"		}, /* 56 */
	{ 2,	0,		"setpgid"	}, /* 57 */
	{ 2,	0,		"ulimit"	}, /* 58 */
	{ 1,	0,	"oldolduname"	}, /* 59 */
	{ 1,	0,		"umask"		}, /* 60 */
	{ 1,	TF,		"chroot"	}, /* 61 */
	{ 2,	0,		"ustat"		}, /* 62 */
	{ 2,	TD,		"dup2"		}, /* 63 */
	{ 0,	0,		"getppid"	}, /* 64 */
	{ 0,	0,		"getpgrp"	}, /* 65 */
	{ 0,	0,		"setsid"	}, /* 66 */
	{ 3,	TS,		"sigaction"	}, /* 67 */
	{ 0,	TS,		"siggetmask"	}, /* 68 */
	{ 1,	TS,		"sigsetmask"	}, /* 69 */
	{ 2,	0,		"setreuid"	}, /* 70 */
	{ 2,	0,		"setregid"	}, /* 71 */
	{ 3,	TS,		"sigsuspend"	}, /* 72 */
	{ 1,	TS,		"sigpending"	}, /* 73 */
	{ 2,	0,	"sethostname"	}, /* 74 */
	{ 2,	0,		"setrlimit"	}, /* 75 */
	{ 2,	0,		"old_getrlimit"	}, /* 76 */
	{ 2,	0,		"getrusage"	}, /* 77 */
	{ 2,	0,	"gettimeofday"	}, /* 78 */
	{ 2,	0,	"settimeofday"	}, /* 79 */
	{ 2,	0,		"getgroups"	}, /* 80 */
	{ 2,	0,		"setgroups"	}, /* 81 */
	{ 1,	TD,		"oldselect"	}, /* 82 */
	{ 2,	TF,		"symlink"	}, /* 83 */
	{ 2,	TF,		"oldlstat"	}, /* 84 */
	{ 3,	TF,		"readlink"	}, /* 85 */
	{ 1,	TF,		"uselib"	}, /* 86 */
	{ 1,	TF,		"swapon"	}, /* 87 */
	{ 3,	0,		"reboot"	}, /* 88 */
	{ 3,	TD,		"readdir"	}, /* 89 */
	{ 6,	TD,		"old_mmap"	}, /* 90 */
	{ 2,	0,		"munmap"	}, /* 91 */
	{ 2,	TF,		"truncate"	}, /* 92 */
	{ 2,	TD,		"ftruncate"	}, /* 93 */
	{ 2,	TD,		"fchmod"	}, /* 94 */
	{ 3,	TD,		"fchown"	}, /* 95 */
	{ 2,	0,	"getpriority"	}, /* 96 */
	{ 3,	0,	"setpriority"	}, /* 97 */
	{ 4,	0,		"profil"	}, /* 98 */
	{ 2,	TF,		"statfs"	}, /* 99 */
	{ 2,	TD,		"fstatfs"	}, /* 100 */
	{ 3,	0,		"ioperm"	}, /* 101 */
	{ 2,	TD,		"socketcall"}, /* 102 */
	{ 3,	0,		"syslog"	}, /* 103 */
	{ 3,	0,		"setitimer"	}, /* 104 */
	{ 2,	0,		"getitimer"	}, /* 105 */
	{ 2,	TF,		"stat"		}, /* 106 */
	{ 2,	TF,		"lstat"		}, /* 107 */
	{ 2,	TD,		"fstat"		}, /* 108 */
	{ 1,	0,		"olduname"	}, /* 109 */
	{ 1,	0,		"iopl"		}, /* 110 */
	{ 0,	0,		"vhangup"	}, /* 111 */
	{ 0,	0,		"idle"		}, /* 112 */
	{ 1,	0,		"vm86old"	}, /* 113 */
	{ 4,	TP,		"wait4"}, /* 114 */
	{ 1,	TF,		"swapoff"	}, /* 115 */
	{ 1,	0,		"sysinfo"	}, /* 116 */
	{ 6,	0,		"ipc"}, /* 117 */
	{ 1,	TD,		"fsync"		}, /* 118 */
	{ 1,	TS,		"sigreturn"	}, /* 119 */
	{ 5,	TP,		"clone"}, /* 120 */
	{ 2,	0,	"setdomainname"	}, /* 121 */
	{ 1,	0,		"uname"		}, /* 122 */
	{ 3,	0,		"modify_ldt"	}, /* 123 */
	{ 1,	0,		"adjtimex"	}, /* 124 */
	{ 3,	0,		"mprotect"	}, /* 125 */
	{ 3,	TS,	"sigprocmask"	}, /* 126 */
	{ 2,	0,	"create_module"	}, /* 127 */
	{ 3,	0,	"init_module"	}, /* 128 */
	{ 2,	0,	"delete_module"	}, /* 129 */
	{ 1,	0,	"get_kernel_syms"}, /* 130 */
	{ 4,	0,		"quotactl"	}, /* 131 */
	{ 1,	0,		"getpgid"	}, /* 132 */
	{ 1,	TD,		"fchdir"	}, /* 133 */
	{ 0,	0,		"bdflush"	}, /* 134 */
	{ 3,	0,		"sysfs"}, /* 135 */
	{ 1,	0,	"personality"	}, /* 136 */
	{ 5,	0,	"afs_syscall"	}, /* 137 */
	{ 1,	NF,		"setfsuid"	}, /* 138 */
	{ 1,	NF,		"setfsgid"	}, /* 139 */
	{ 5,	TD,		"_llseek"	}, /* 140 */
	{ 3,	TD,		"getdents"	}, /* 141 */
	{ 5,	TD,		"select"	}, /* 142 */
	{ 2,	TD,		"flock"		}, /* 143 */
	{ 3,	0,		"msync"		}, /* 144 */
	{ 3,	TD,		"readv"}, /* 145 */
	{ 3,	TD,		"writev"}, /* 146 */
	{ 1,	0,		"getsid"	}, /* 147 */
	{ 1,	TD,		"fdatasync"	}, /* 148 */
	{ 1,	0,		"_sysctl"	}, /* 149 */
	{ 2,	0,		"mlock"		}, /* 150 */
	{ 2,	0,		"munlock"	}, /* 151 */
	{ 2,	0,		"mlockall"	}, /* 152 */
	{ 0,	0,		"munlockall"	}, /* 153 */
	{ 0,	0,	"sched_setparam"}, /* 154 */
	{ 2,	0,	"sched_getparam"}, /* 155 */
	{ 3,	0,	"sched_setscheduler"}, /* 156 */
	{ 1,	0,	"sched_getscheduler"}, /* 157 */
	{ 0,	0,	"sched_yield"}, /* 158 */
	{ 1,	0,"sched_get_priority_max"}, /* 159 */
	{ 1,	0,"sched_get_priority_min"}, /* 160 */
	{ 2,	0,"sched_rr_get_interval"}, /* 161 */
	{ 2,	0,		"nanosleep"	}, /* 162 */
	{ 5,	0,		"mremap"	}, /* 163 */
	{ 3,	0,		"setresuid"	}, /* 164 */
	{ 3,	0,		"getresuid"	}, /* 165 */
	{ 5,	0,		"vm86"		}, /* 166 */
	{ 5,	0,	"query_module"	}, /* 167 */
	{ 3,	TD,		"poll"		}, /* 168 */
	{ 3,	0,		"nfsservctl"	}, /* 169 */
	{ 3,	0,		"setresgid"	}, /* 170 */
	{ 3,	0,		"getresgid"	}, /* 171 */
	{ 5,	0,		"prctl"		}, /* 172 */
	{ 1,	TS,		"rt_sigreturn"	}, /* 173 */
	{ 4,	TS,	"rt_sigaction"  }, /* 174 */
	{ 4,	TS,	"rt_sigprocmask"}, /* 175 */
	{ 2,	TS,	"rt_sigpending"	}, /* 176 */
	{ 4,	TS,	"rt_sigtimedwait"}, /* 177 */
	{ 3,	TS,    "rt_sigqueueinfo"}, /* 178 */
	{ 2,	TS,	"rt_sigsuspend"	}, /* 179 */

	{ 5,	TD,		"pread64"}, /* 180 */
	{ 5,	TD,		"pwrite64"}, /* 181 */
	{ 3,	TF,		"chown"		}, /* 182 */
	{ 2,	TF,		"getcwd"	}, /* 183 */
	{ 2,	0,		"capget"	}, /* 184 */
	{ 2,	0,		"capset"	}, /* 185 */
	{ 2,	TS,	"sigaltstack"	}, /* 186 */
	{ 4,	TD|TN,		"sendfile"	}, /* 187 */
	{ 5,	0,		"getpmsg"	}, /* 188 */
	{ 5,	0,		"putpmsg"	}, /* 189 */
	{ 0,	TP,		"vfork"}, /* 190 */
	{ 2,	0,		"getrlimit"	}, /* 191 */
	{ 6,	TD,		"mmap2"		}, /* 192 */
	{ 3,	TF,		"truncate64"	}, /* 193 */
	{ 3,	TD,	"ftruncate64"	}, /* 194 */
	{ 2,	TF,		"stat64"	}, /* 195 */
	{ 2,	TF,		"lstat64"	}, /* 196 */
	{ 2,	TD,		"fstat64"	}, /* 197 */
	{ 3,	TF,		"lchown32"	}, /* 198 */
	{ 0,	NF,		"getuid32"	}, /* 199 */

	{ 0,	NF,		"getgid32"	}, /* 200 */
	{ 0,	NF,		"geteuid32"	}, /* 201 */
	{ 0,	NF,		"getegid32"	}, /* 202 */
	{ 2,	0,		"setreuid32"	}, /* 203 */
	{ 2,	0,		"setregid32"	}, /* 204 */
	{ 2,	0,	"getgroups32"	}, /* 205 */
	{ 2,	0,	"setgroups32"	}, /* 206 */
	{ 3,	TD,		"fchown32"	}, /* 207 */
	{ 3,	0,		"setresuid32"	}, /* 208 */
	{ 3,	0,		"getresuid32"	}, /* 209 */
	{ 3,	0,		"setresgid32"	}, /* 210 */
	{ 3,	0,		"getresgid32"	}, /* 211 */
	{ 3,	TF,		"chown32"	}, /* 212 */
	{ 1,	0,		"setuid32"	}, /* 213 */
	{ 1,	0,		"setgid32"	}, /* 214 */
	{ 1,	NF,		"setfsuid32"	}, /* 215 */
	{ 1,	NF,		"setfsgid32"	}, /* 216 */
	{ 2,	TF,		"pivot_root"	}, /* 217 */
	{ 3,	0,		"mincore"	}, /* 218 */
	{ 3,	0,		"madvise"	}, /* 219 */
	{ 3,	TD,		"getdents64"	}, /* 220 */
	{ 3,	TD,		"fcntl64"	}, /* 221 */
	{ 4,	0,		"SYS_222"	}, /* 222 */
/*TODO*/{ 5,	0,		"security"	}, /* 223 */
	{ 0,	0,		"gettid"	}, /* 224 */
	{ 4,	TD,		"readahead"	}, /* 225 */
	{ 5,	TF,		"setxattr"	}, /* 226 */
	{ 5,	TF,		"lsetxattr"	}, /* 227 */
	{ 5,	TD,		"fsetxattr"	}, /* 228 */
	{ 4,	TF,		"getxattr"	}, /* 229 */
	{ 4,	TF,		"lgetxattr"	}, /* 230 */
	{ 4,	TD,		"fgetxattr"	}, /* 231 */
	{ 3,	TF,		"listxattr"	}, /* 232 */
	{ 3,	TF,		"llistxattr"	}, /* 233 */
	{ 3,	TD,		"flistxattr"	}, /* 234 */
	{ 2,	TF,	"removexattr"	}, /* 235 */
	{ 2,	TF,	"lremovexattr"	}, /* 236 */
	{ 2,	TD,	"fremovexattr"	}, /* 237 */
	{ 2,	TS,		"tkill"		}, /* 238 */
	{ 4,	TD|TN,		"sendfile64"	}, /* 239 */
	{ 6,	0,		"futex"		}, /* 240 */
	{ 3,	0,	"sched_setaffinity" },/* 241 */
	{ 3,	0,	"sched_getaffinity" },/* 242 */
	{ 1,	0,	"set_thread_area" }, /* 243 */
	{ 1,	0,	"get_thread_area" }, /* 244 */
	{ 2,	0,		"io_setup"	}, /* 245 */
	{ 1,	0,		"io_destroy"	}, /* 246 */
	{ 5,	0,	"io_getevents"	}, /* 247 */
	{ 3,	0,		"io_submit"	}, /* 248 */
	{ 3,	0,		"io_cancel"	}, /* 249 */
	{ 5,	TD,		"fadvise64"	}, /* 250 */
	{ 5,	0,		"SYS_251"	}, /* 251 */
	{ 1,	TP,		"exit_group"}, /* 252 */
	{ 4,	0,		"lookup_dcookie"}, /* 253 */
	{ 1,	TD,	"epoll_create"	}, /* 254 */
	{ 4,	TD,		"epoll_ctl"	}, /* 255 */
	{ 4,	TD,		"epoll_wait"	}, /* 256 */
	{ 5,	0,	"remap_file_pages"}, /* 257 */
	{ 1,	0,		"set_tid_address"}, /* 258 */
	{ 3,	0,	"timer_create"	}, /* 259 */
	{ 4,	0,	"timer_settime"	}, /* 260 */
	{ 2,	0,	"timer_gettime"	}, /* 261 */
	{ 1,	0,	"timer_getoverrun"}, /* 262 */
	{ 1,	0,	"timer_delete"	}, /* 263 */
	{ 2,	0,	"clock_settime"	}, /* 264 */
	{ 2,	0,	"clock_gettime"	}, /* 265 */
	{ 2,	0,	"clock_getres"	}, /* 266 */
	{ 4,	0,	"clock_nanosleep"}, /* 267 */
	{ 3,	TF,		"statfs64"	}, /* 268 */
	{ 3,	TD,		"fstatfs64"	}, /* 269 */
	{ 3,	TS,		"tgkill"	}, /* 270 */
	{ 2,	TF,		"utimes"	}, /* 271 */
	{ 6,	TD,	"fadvise64_64"	}, /* 272 */
	{ 5,	0,		"vserver"	}, /* 273 */
	{ 6,	0,		"mbind"		}, /* 274 */
	{ 5,	0,	"get_mempolicy"	}, /* 275 */
	{ 3,	0,	"set_mempolicy"	}, /* 276 */
	{ 4,	0,		"mq_open"	}, /* 277 */
	{ 1,	0,		"mq_unlink"	}, /* 278 */
	{ 5,	0,	"mq_timedsend"	}, /* 279 */
	{ 5,	0,	"mq_timedreceive" }, /* 280 */
	{ 2,	0,		"mq_notify"	}, /* 281 */
	{ 3,	0,	"mq_getsetattr"	}, /* 282 */
	{ 5,	0,		"kexec_load"	}, /* 283 */
	{ 5,	TP,		"waitid"}, /* 284 */
	{ 5,	0,		"SYS_285"	}, /* 285 */
	{ 5,	0,		"add_key"	}, /* 286 */
	{ 4,	0,		"request_key"	}, /* 287 */
	{ 5,	0,		"keyctl"	}, /* 288 */
	{ 3,	0,		"ioprio_set"	}, /* 289 */
	{ 2,	0,		"ioprio_get"	}, /* 290 */
	{ 0,	TD,		"inotify_init"	}, /* 291 */
	{ 3,	TD,	"inotify_add_watch" }, /* 292 */
	{ 2,	TD,	"inotify_rm_watch" }, /* 293 */
	{ 4,	0,		"migrate_pages"	}, /* 294 */
	{ 4,	TD|TF,		"openat"	}, /* 295 */
	{ 3,	TD|TF,		"mkdirat"	}, /* 296 */
	{ 4,	TD|TF,		"mknodat"	}, /* 297 */
	{ 5,	TD|TF,		"fchownat"	}, /* 298 */
	{ 3,	TD|TF,		"futimesat"	}, /* 299 */
	{ 4,	TD|TF,		"fstatat64"	}, /* 300 */
	{ 3,	TD|TF,		"unlinkat"	}, /* 301 */
	{ 4,	TD|TF,		"renameat"	}, /* 302 */
	{ 5,	TD|TF,		"linkat"	}, /* 303 */
	{ 3,	TD|TF,		"symlinkat"	}, /* 304 */
	{ 4,	TD|TF,		"readlinkat"	}, /* 305 */
	{ 3,	TD|TF,		"fchmodat"	}, /* 306 */
	{ 3,	TD|TF,		"faccessat"	}, /* 307 */
	{ 6,	TD,		"pselect6"	}, /* 308 */
	{ 5,	TD,		"ppoll"		}, /* 309 */
	{ 1,	TP,		"unshare"	}, /* 310 */
	{ 2,	0,		"set_robust_list" }, /* 311 */
	{ 3,	0,		"get_robust_list" }, /* 312 */
	{ 6,	TD,		"splice"	}, /* 313 */
	{ 4,	TD,		"sync_file_range" }, /* 314 */
	{ 4,	TD,		"tee"		}, /* 315 */
	{ 4,	TD,		"vmsplice"	}, /* 316 */
	{ 6,	0,		"move_pages"	}, /* 317 */
	{ 3,	0,		"getcpu"	}, /* 318 */
	{ 5,	TD,	"epoll_pwait"	}, /* 319 */
	{ 4,	TD|TF,		"utimensat"	}, /* 320 */
	{ 3,	TD|TS,		"signalfd"	}, /* 321 */
	{ 2,	TD,	"timerfd_create"}, /* 322 */
	{ 1,	TD,		"eventfd"	}, /* 323 */
	{ 6,	TD,		"fallocate"	}, /* 324 */
	{ 4,	TD,	"timerfd_settime"}, /* 325 */
	{ 2,	TD,	"timerfd_gettime"}, /* 326 */
	{ 4,	TD|TS,		"signalfd4"	}, /* 327 */
	{ 2,	TD,		"eventfd2"	}, /* 328 */
	{ 1,	TD,	"epoll_create1"	}, /* 329 */
	{ 3,	TD,		"dup3"		}, /* 330 */
	{ 2,	TD,		"pipe2"		}, /* 331 */
	{ 1,	TD,	"inotify_init1"	}, /* 332 */
	{ 5,	TD,		"preadv"	}, /* 333 */
	{ 5,	TD,		"pwritev"	}, /* 334 */
	{ 4,	TP|TS,		"rt_tgsigqueueinfo"}, /* 335 */
	{ 5,	TD,		"perf_event_open"}, /* 336 */
	{ 5,	TN,		"recvmmsg"	}, /* 337 */
	{ 2,	TD,		"fanotify_init"	}, /* 338 */
	{ 5,	TD|TF,		"fanotify_mark"	}, /* 339 */
	{ 4,	0,		"prlimit64"	}, /* 340 */
	{ 5,	0,		"SYS_341"	}, /* 341 */
	{ 5,	0,		"SYS_342"	}, /* 342 */
	{ 5,	0,		"SYS_343"	}, /* 343 */
	{ 5,	0,		"SYS_344"	}, /* 344 */
	{ 5,	0,		"SYS_345"	}, /* 345 */
	{ 5,	0,		"SYS_346"	}, /* 346 */
	{ 5,	0,		"SYS_347"	}, /* 347 */
	{ 5,	0,		"SYS_348"	}, /* 348 */
	{ 5,	0,		"SYS_349"	}, /* 349 */
	{ 5,	0,		"SYS_350"	}, /* 350 */
	{ 5,	0,		"SYS_351"	}, /* 351 */
	{ 5,	0,		"SYS_352"	}, /* 352 */
	{ 5,	0,		"SYS_353"	}, /* 353 */
	{ 5,	0,		"SYS_354"	}, /* 354 */
	{ 5,	0,		"SYS_355"	}, /* 355 */
	{ 5,	0,		"SYS_356"	}, /* 356 */
	{ 5,	0,		"SYS_357"	}, /* 357 */
	{ 5,	0,		"SYS_358"	}, /* 358 */
	{ 5,	0,		"SYS_359"	}, /* 359 */
	{ 5,	0,		"SYS_360"	}, /* 360 */
	{ 5,	0,		"SYS_361"	}, /* 361 */
	{ 5,	0,		"SYS_362"	}, /* 362 */
	{ 5,	0,		"SYS_363"	}, /* 363 */
	{ 5,	0,		"SYS_364"	}, /* 364 */
	{ 5,	0,		"SYS_365"	}, /* 365 */
	{ 5,	0,		"SYS_366"	}, /* 366 */
	{ 5,	0,		"SYS_367"	}, /* 367 */
	{ 5,	0,		"SYS_368"	}, /* 368 */
	{ 5,	0,		"SYS_369"	}, /* 369 */
	{ 5,	0,		"SYS_370"	}, /* 370 */
	{ 5,	0,		"SYS_371"	}, /* 371 */
	{ 5,	0,		"SYS_372"	}, /* 372 */
	{ 5,	0,		"SYS_373"	}, /* 373 */
	{ 5,	0,		"SYS_374"	}, /* 374 */
	{ 5,	0,		"SYS_375"	}, /* 375 */
	{ 5,	0,		"SYS_376"	}, /* 376 */
	{ 5,	0,		"SYS_377"	}, /* 377 */
	{ 5,	0,		"SYS_378"	}, /* 378 */
	{ 5,	0,		"SYS_379"	}, /* 379 */
	{ 5,	0,		"SYS_380"	}, /* 380 */
	{ 5,	0,		"SYS_381"	}, /* 381 */
	{ 5,	0,		"SYS_382"	}, /* 382 */
	{ 5,	0,		"SYS_383"	}, /* 383 */
	{ 5,	0,		"SYS_384"	}, /* 384 */
	{ 5,	0,		"SYS_385"	}, /* 385 */
	{ 5,	0,		"SYS_386"	}, /* 386 */
	{ 5,	0,		"SYS_387"	}, /* 387 */
	{ 5,	0,		"SYS_388"	}, /* 388 */
	{ 5,	0,		"SYS_389"	}, /* 389 */
	{ 5,	0,		"SYS_390"	}, /* 390 */
	{ 5,	0,		"SYS_391"	}, /* 391 */
	{ 5,	0,		"SYS_392"	}, /* 392 */
	{ 5,	0,		"SYS_393"	}, /* 393 */
	{ 5,	0,		"SYS_394"	}, /* 394 */
	{ 5,	0,		"SYS_395"	}, /* 395 */
	{ 5,	0,		"SYS_396"	}, /* 396 */
	{ 5,	0,		"SYS_397"	}, /* 397 */
	{ 5,	0,		"SYS_398"	}, /* 398 */
	{ 5,	0,		"SYS_399"	}, /* 399 */

	{ 8,	0,		"socket_subcall"}, /* 400 */
	{ 3,	TN,		"socket"	}, /* 401 */
	{ 3,	TN,		"bind"		}, /* 402 */
	{ 3,	TN,		"connect"	}, /* 403 */
	{ 2,	TN,		"listen"	}, /* 404 */
	{ 3,	TN,		"accept"	}, /* 405 */
	{ 3,	TN,	"getsockname"	}, /* 406 */
	{ 3,	TN,	"getpeername"	}, /* 407 */
	{ 4,	TN,		"socketpair"	}, /* 408 */
	{ 4,	TN,		"send"}, /* 409 */
	{ 4,	TN,		"recv"}, /* 410 */
	{ 6,	TN,		"sendto"}, /* 411 */
	{ 6,	TN,		"recvfrom"}, /* 412 */
	{ 2,	TN,		"shutdown"	}, /* 413 */
	{ 5,	TN,		"setsockopt"	}, /* 414 */
	{ 5,	TN,		"getsockopt"	}, /* 415 */
	{ 5,	TN,		"sendmsg"	}, /* 416 */
	{ 5,	TN,		"recvmsg"	}, /* 417 */
	{ 4,	TN,		"accept4"	}, /* 418 */
	{ 5,	TN,		"recvmmsg"	}, /* 419 */

	{ 4,	0,		"ipc_subcall"	}, /* 420 */
	{ 4,	TI,		"semop"		}, /* 421 */
	{ 4,	TI,		"semget"	}, /* 422 */
	{ 4,	TI,		"semctl"	}, /* 423 */
	{ 5,	TI,		"semtimedop"	}, /* 424 */
	{ 4,	0,		"ipc_subcall"	}, /* 425 */
	{ 4,	0,		"ipc_subcall"	}, /* 426 */
	{ 4,	0,		"ipc_subcall"	}, /* 427 */
	{ 4,	0,		"ipc_subcall"	}, /* 428 */
	{ 4,	0,		"ipc_subcall"	}, /* 429 */
	{ 4,	0,		"ipc_subcall"	}, /* 430 */
	{ 4,	TI,		"msgsnd"	}, /* 431 */
	{ 4,	TI,		"msgrcv"	}, /* 432 */
	{ 4,	TI,		"msgget"	}, /* 433 */
	{ 4,	TI,		"msgctl"	}, /* 434 */
	{ 4,	0,		"ipc_subcall"	}, /* 435 */
	{ 4,	0,		"ipc_subcall"	}, /* 436 */
	{ 4,	0,		"ipc_subcall"	}, /* 437 */
	{ 4,	0,		"ipc_subcall"	}, /* 438 */
	{ 4,	0,		"ipc_subcall"	}, /* 439 */
	{ 4,	0,		"ipc_subcall"	}, /* 440 */
	{ 4,	TI,		"shmat"		}, /* 441 */
	{ 4,	TI,		"shmdt"		}, /* 442 */
	{ 4,	TI,		"shmget"	}, /* 443 */
	{ 4,	TI,		"shmctl"	}, /* 444 */
