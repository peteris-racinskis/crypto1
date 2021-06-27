#!/usr/bin/env sh

# To demonstrate key generation, execute: (order irrelevant)
# ./launcher.sh cbc-encrypt-nokey
# ./launcher.sh cfb-encrypt-nokey
#
# For cbc pipeline, execute in order:
# ./launcher.sh cbc-encrypt
#  ^-- inspect results in outputs/
# ./launcher.sh cbc-decrypt
#  ^-- inspect results in outputs/
#
# For cfb pipeline, execute in order:
# ./launcher.sh cfb-encrypt
#  ^-- inspect results in outputs/
# ./launcher.sh cfb-decrypt
#  ^-- inspect results in outputs/

echo $1
cfb=""
case $1 in
    "cbc-encrypt-nokey")
        outfile="--outfile outputs/cbc-keygen"
        test_command="encrypt"
        args="outputs/plaintext.txt"
        ;;
    "cfb-encrypt-nokey")
        outfile="--outfile outputs/cbc-keygen"
        cfb=" --cfb"
        test_command="encrypt"
        args="outputs/plaintext.txt"
        ;;
    "cbc-encrypt")
        outfile="--outfile outputs/encrypted-test-cbc"
        test_command="encrypt"
        args="outputs/plaintext.txt --key-enc outputs/symkey.txt"
        ;;
    "cbc-decrypt")
        outfile="--outfile outputs/decrypted-test-cbc"
        test_command="decrypt"
        args="outputs/encrypted-test-cbc-out.bin outputs/symkey.txt"
        ;;
    "cfb-encrypt")
        outfile="--outfile outputs/encrypted-test-cfb"
        cfb=" --cfb"
        test_command="encrypt"
        args="outputs/plaintext.txt --key-enc outputs/symkey.txt --key-sig outputs/signkey.txt"
        ;;
    "cfb-decrypt")
        outfile="--outfile outputs/decrypted-test-cbc"
        cfb=" --cfb"
        test_command="decrypt"
        args="outputs/encrypted-test-cfb-out.bin outputs/symkey.txt --MAC outputs/encrypted-test-cfb-mac.bin --key-ver outputs/signkey.txt"
        ;;
    * )
        echo "Choose a test command"
        ;;
esac
arguments="./crypto1 $outfile$cfb $test_command $args"

exec $arguments
