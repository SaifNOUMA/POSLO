
#!/bin/bash

cpu_iterations=1000

make clean ; make
# echo "OSLO_1 CPU Benchmarking"
# for inlen in 8 16 32 ; do
#     for n1 in $(seq 15); do
#         echo "n1 = $n1" "inlen = $inlen"

#         ./bin/oslo_sha256_sha256 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#     done

#     for n1 in $(seq 9 15); do
#         echo "n1 = $n1" "inlen = $inlen"
#         ./bin/oslo_sha256_sha256 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#     done
# done


# echo "OSLO_2 CPU Benchmarking"

# for inlen in 8 16 32 ; do
#     for n1 in $(seq 15); do
#         echo "n1 = $n1" "inlen = $inlen"
#         ./bin/oslo_aes128_aes128 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#     done

#     for n1 in $(seq 9 15); do
#         echo "n1 = $n1" "inlen = $inlen"
#         ./bin/oslo_aes128_aes128 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#     done
# done


echo "OSLO_3 CPU Benchmarking"

for inlen in 8 16 32 ; do
    for n1 in $(seq 15); do
        echo "n1 = $n1" "inlen = $inlen"
        ./bin/oslo_aes128_arithm inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
    done

    for n1 in $(seq 9 15); do
        echo "n1 = $n1" "inlen = $inlen"
        ./bin/oslo_aes128_arithm inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
    done
done



# #!/bin/bash

# cpu_iterations=1000

# make clean ; make
# # rm -f *.csv

# for inlen in 8 16 32 64 ; do
#     for n1 in $(seq 15); do
#         echo "n1 = $n1" "inlen = $inlen"

#     #     # mkdir ../data/crypto/seed_method_sha256/hash_method_arithm/inlen_${inlen}/n1_${n1}/pk
#     #     # mkdir ../data/crypto/seed_method_aes128/hash_method_sha256/inlen_${inlen}/n1_${n1}/pk
#     #     # mkdir ../data/crypto/seed_method_aes128/hash_method_arithm/inlen_${inlen}/n1_${n1}/pk

#         ./bin/oslo_sha256_sha256 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#     #     # ./bin/oslo_aes128_sha256 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#         # ./bin/oslo_sha256_arithm inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#         ./bin/oslo_aes128_arithm inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#         ./bin/oslo_aes128_aes128 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#     done

#     for n1 in $(seq 9 15); do
#         # mkdir -p ../data/crypto/seed_method_sha256/hash_method_aes128/inlen_${inlen}/n1_${n1}/pk
#         # mkdir -p ../data/crypto/seed_method_sha256/hash_method_sha256/inlen_${inlen}/n1_${n1}/pk
#         # mkdir -p ../data/crypto/seed_method_aes128/hash_method_aes128/inlen_${inlen}/n1_${n1}/pk
#         # mkdir -p ../data/crypto/seed_method_aes128/hash_method_sha256/inlen_${inlen}/n1_${n1}/pk
#         # mkdir -p ../data/crypto/seed_method_aes128/hash_method_artihm/inlen_${inlen}/n1_${n1}/pk
#         echo "n1 = $n1" "inlen = $inlen"
#     #     cpu_iterations=1
#         ./bin/oslo_sha256_sha256 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#         # ./bin/oslo_aes128_sha256 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#         # ./bin/oslo_sha256_arithm inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations 
#         ./bin/oslo_aes128_arithm inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#         ./bin/oslo_aes128_aes128 inlen=$inlen n1=$n1 cpu_iterations=$cpu_iterations
#     done
# done