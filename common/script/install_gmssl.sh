gmssl_dir="$(pwd)/../common/ext"

if [ ! -d "${gmssl_dir}/gmssl" ]; then
    cd ${gmssl_dir} 
    rm -rf GmSSL-master
    mkdir GmSSL-master
    unzip -d GmSSL-master GmSSL-master.zip 
    cd GmSSL-master 
    chmod +x config
    ./config --prefix=${gmssl_dir}/gmssl -debug
    # ./config shared --prefix=${gmssl_dir}/gmssl -debug
    make 
    make install_sw 
    mkdir ${gmssl_dir}/gmssl/ssl
    cp apps/openssl.cnf ${gmssl_dir}/gmssl/bin
    cp apps/openssl.cnf ${gmssl_dir}/gmssl/ssl
    # cd ${gmssl_dir} 
    # rm -rf GmSSL-master
fi
