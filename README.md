# DESCRIPTION
Jaa is a tool to distribute programs through SSH. If a program takes too long to run on a single machine, you can split it up and distribute it to many.

# GENERAL USE
```{bash}
jaa
```
Jaa does not take any arguments, it searches the current directory for a `dist.jaa` file that specifies how your program should be distributed i.e. to what host machines / ssh addresses and what cmds to run.

# DEPENDENCIES
- libssh-dev
- libtermbox2 which you can find from [https://github.com/termbox/termbox2](the-termbox2-github-page)

# CREATING PROGRAMS FOR JAA
Jaa does not automatically segment your program, you have to do that yourself. Jaa just runs the commands specified on the addresses specified.

# BUILDING
Change the INCPATHS and LIBPATHS to match where your installation of libssh is, if they are installed globally, you can remove the path `dependencies/*`

# DIST.JAA FILE EXAMPLE
```
//comments
//white space between tags is ignored

[hosts] //mandatory
befunge.org.aalto.fi
emo.org.aalto.fi
entropy.org.aalto.fi

[username] //mandatory, login username for all the hosts
longhuo1

[cmd] //mandatory
cd ~/where/my/program/is; python3 test.py arg1 arg2
cd ~/where/my/program/is; python3 test.py arg3 arg4
cd ~/where/my/program/is; python3 test.py arg5 arg6
cd ~/where/my/program/is; python3 test.py arg6 arg7
```

# EDGE CASES
If you specify more arguments than hosts, the left-over arguments will sit in queue and wait for a machine to be done with an earlier process. All arguments will run eventually.
