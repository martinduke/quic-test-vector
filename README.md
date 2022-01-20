# quic-test-vector
Scripts to help create QUIC version test vectors in RFC 9001 format.

Just type 'make all' to build everything.

There are two tools here:

## testvector

This program takes one command line argument, the QUIC version. It currently supports 1 (RFC9000) and 2 (draft-ietf-quic-v2-01).

It prints to stdout a markdown version of a test vector appendix that can be cut-and-paste into an internet-draft markdown file. If you use the argument '1', it will output Appendix A from RFC 9001. Input '2', and you will see Appendix A of draft-ietf-quic-v2.

To roll out a new version, you will have to update the switch statement at the start of int main. This will generally involve also updating the constants declared at the start of the file. If there are any changes beyond the type of changes that occur in v2, you may have to edit more of the code.

int main() declares all the variables that will later be output in the markdown, and then calls various functions to execute all the crypto operations.

Most of 'int main' is just the entire markdown file as a series of printfs. the HEX, HEXLEN, and HEXINDENT macros help create hexdumps in a way that gives the
appearance of it all being one printf.

## expand

expand is a useful tool to take a text hexdump and parse it into a comma separated sequence suitable for use as a C array. For example, you could input

    fd3483a8eb382904

and it would output

    0xfd, 0x34, 0x83, 0a8, 0xeb, 0x28, 0x29, 0x04,
    
This is way easier than typing in packet traces and such.

To use expand, type 'expand'

Then there will be a prompt. Cut and paste the hexdump and press enter. Then press Ctrl-C to exit.

There will be a file called 'hex' which has the parsed data.


