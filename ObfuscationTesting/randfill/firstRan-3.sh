#! /bin/sh

echo "Executing the S2E Shellcode Forensics Tracer"
./shellcode-wrapper -i randfill-102400kb:0-cd80.rawshell -x


# catch any orphaned states
./s2ekill
