current_dir=$PWD
gmssl_dir=${current_dir}/common/ext

cd ${current_dir}
source common/script/env.sh

cd ${current_dir}

# install gmssl
if [ ! -d "${gmssl_dir}/gmssl" ]; then
    cd ${gmssl_dir} 
    rm -rf GmSSL-master
    mkdir GmSSL-master
    unzip -d GmSSL-master GmSSL-master.zip 
    cd GmSSL-master 
    chmod +x config
    # ./config shared --prefix=${gmssl_dir}/gmssl -debug
    ./config --prefix=${gmssl_dir}/gmssl -debug
    make 
    make install_sw 
    mkdir ${gmssl_dir}/gmssl/ssl
    cp apps/openssl.cnf ${gmssl_dir}/gmssl/bin
    cp apps/openssl.cnf ${gmssl_dir}/gmssl/ssl
    # cd ${gmssl_dir} 
    # rm -rf GmSSL-master
fi

cd ${current_dir}
make clean
make

cp output/libcrypto_api.a common/ext/gmssl/lib/

echo -e "\nCrypto API and Application Build Done.\n"
