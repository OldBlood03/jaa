# DESCRIPTION
Jaa is a tool to distribute programs through SSH. If a program takes too long to run on a single machine, you can split it up and distribute it to many.

# GENERAL USE
```{bash}
jaa
```
Without arguments, jaa searches the current directory for a `*.jaa` file that specifies how your program should be distributed i.e. to what host machines / ssh addresses, what cmd to run, where to run it, and with what arguments. You can optionally specify a filepath with the `-f` flag.
# DEPENDENCIES
- libssh-dev

# CREATING PROGRAMS FOR JAA
Jaa has a custom protocol for how it extracts the current progress of your program: it reads the stdout of the running program and searches for a string of the form `[%d/%d]` and reports the progress as `%d/%d` complete. If your program does not print anything of this form, the progress will not be accurately reported. However, the programs will still run without issue. 

Jaa does not automatically segment your program, you have to do that yourself. Jaa runs the same program on different machines with the arguments specified.

# BUILDING
Change the INCPATHS and LIBPATHS to match where your installation of libssh is, if they are installed globally, you can remove the path `dependencies/*`

# JAA FILE EXAMPLE
```
//comments
//leading white space is ignored

[hosts]
befunge.org.aalto.fi
bit.org.aalto.fi
bogo.org.aalto.fi
brainfuck.org.aalto.fi
deadfish.org.aalto.fi
emo.org.aalto.fi
entropy.org.aalto.fi

[username]
longhuo1

[cmd]
python3 test.py

[path] //this is the **absolute** path from which everything is excecuted
/m/home/home6/69/longhuo1/unix/projects/ssh-distribute

[args] //optional
arg 1
[logfile] //optional
//log files go here, one line, one log file
//the number of log files has to match the number 
```

# EDGE CASES
If you specify more arguments than hosts, the left-over arguments will sit in queue and wait for a machine to be done with an earlier process. All arguments will run eventually.
