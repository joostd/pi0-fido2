#!/bin/bash

function handle_ctrlc()
{
    ./stop.sh
    echo "Bye!"
    exit
}

# trapping the SIGINT signal
trap handle_ctrlc SIGINT

./start.sh
./sk.py
