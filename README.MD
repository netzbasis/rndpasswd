rndpasswd(1) utility

Uses the OpenBSD build system and can be installed by

    $ make
    $ doas make install

# NAME

**rndpasswd** - create random passwords

# SYNOPSIS

**rndpasswd**
\[**-aenrs**]
\[**-b**&nbsp;*rounds*]
\[**-l**&nbsp;*length*]

# DESCRIPTION

**rndpasswd**
prints random strings to standard output.
The default output is of length 12 and consists of alphanumeric and special
characters.

The options are as follows:

**-a**

> Use alphabet characters.

**-b** *rounds*

> Rounds for bcrypt hashing (min: 4, max: 31, defaults to auto).
> This inferres -e.

**-e**

> Output the encrypted password hash next to the string.

**-l** *length*

> Length of output (min: 1, max: 127).

**-n**

> Use numbers.

**-r**

> Repeatedly print new random strings.
> One per line.

**-s**

> Use special characters.

# EXAMPLES

Generate new htpasswd entry:

	$ PLAIN=$(rndpasswd); echo username:$PLAIN | htpasswd

Create a list of 20 plaintext and encrypted passwords using only numbers:

	$ rndpasswd -enr | head -n 20

# SEE ALSO

encrypt(1),
htpasswd(1),
arc4random(3),
crypt\_newhash(3)

# CAVEATS

The result is truely random, there is no metric that guarantees that alphabetic
cahracter and/or numbers and/or special charaters are present in the generated
string.

