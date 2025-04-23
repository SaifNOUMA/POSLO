
#!/bin/bash

gpu_iterations=1000
n1=$1
inlen=$2
if [ -z "$n1" ]; then
    n1=15
fi
if [ -z "$inlen" ]; then
    inlen=32
fi
make clean ; make

rm out/*.csv

for inlen in 8 16 32; do
    for n1 in $(seq 1 8); do
        echo "n1 = $n1" "inlen = $inlen"
        ./bin/oslo_sha256_sha256 inlen=$inlen n1=$n1 gpu_iterations=$gpu_iterations
    done

    for n1 in $(seq 9 15); do
        echo "n1 = $n1"
        gpu_iterations=100
        ./bin/oslo_sha256_sha256 inlen=$inlen n1=$n1 gpu_iterations=$gpu_iterations
    done
done

for inlen in 8 16 32; do
    for n1 in $(seq 1 8); do
        echo "n1 = $n1" "inlen = $inlen"
        ./bin/oslo_aes128_aes128 inlen=$inlen n1=$n1 gpu_iterations=$gpu_iterations
    done

    for n1 in $(seq 9 15); do
        echo "n1 = $n1"
        gpu_iterations=100
        ./bin/oslo_aes128_aes128 inlen=$inlen n1=$n1 gpu_iterations=$gpu_iterations
    done
done

for inlen in 8 16 32; do
    for n1 in $(seq 1 8); do
        echo "n1 = $n1" "inlen = $inlen"
        ./bin/oslo_aes128_arithm inlen=$inlen n1=$n1 gpu_iterations=$gpu_iterations
    done

    for n1 in $(seq 9 15); do
        echo "n1 = $n1"
        gpu_iterations=100
        ./bin/oslo_aes128_arithm inlen=$inlen n1=$n1 gpu_iterations=$gpu_iterations
    done
done
