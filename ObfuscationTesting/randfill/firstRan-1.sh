#! /bin/sh

echo "Executing the S2E Shellcode Forensics Tracer"
./shellcode-wrapper -i randfill-1024kb:115-cd80.rawshell -x


# catch any orphaned states
./s2ekill
