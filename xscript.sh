#!/bin/bash
again='n'
while [[ $again != 'Y' ]] || [[ $again != 'y' ]];
do
clear
echo -e " Informasi \t\t\t\t\t\tDebian 11 server\t\t\t\t\tPENGATURAN"
echo -e " [1] Ping 8.8.8.8 dan google.com \t\t\t[51] Instalasi Observium server\t\t\t\t[201] PROXMOX";
echo -e " [2] ifconfig \t\t\t\t\t\t[52] Instalasi Openvpn server\t\t\t\t[202] VIRTUALBOX";
echo -e " [3] route -n \t\t\t\t\t\t[53] Instalasi Asterisk server\t\t\t\t[203] QEMU";
echo -e " [4] traceroute 8.8.8.8 \t\t\t\t[54] Instalasi Xampp server\t\t\t\t[204] DNS";
echo -e " [5] df -h \t\t\t\t\t\t[55] Instalasi DNS server\t\t\t\t[205] WEB";
echo -e " [6] flush memory\t\t\t\t\t[56] Instalasi LDAP server\t\t\t\t[206] OBSERVIUM";
echo -e " [7] uptime\t\t\t\t\t\t[57] Instalasi NAT";
echo -e " [8] top\t\t\t\t\t\t\t\t\t\t\t\t\t";
echo -e " [9] iperf3 -c 202.158.68.36\t\t\t\t\t\t\t\t\t\t\t\t";
echo -e " \t\t\t\t\t\t\t\t\t\t\t\t\t\t"
echo -e " cat file\t\t\t\t\t\tDownload\t\t\t\t\t\t"
echo -e " [11] cat /etc/network/interfaces\t\t\t[71]\t\t\t\t\t\t\t";
echo -e " [12] cat /etc/rc.local\t\t\t\t\t[72]\t\t\t\t\t\t\t";
echo -e " [13] cat /etc/resolv.conf\t\t\t\t[73]\t\t\t\t\t\t\t";
echo -e " [14] cat /etc/hosts\t\t\t\t\t[74]";

echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t\t[220] list aktiv vpn"
echo -e " Edit\t\t\t\t\t\t\tLogin SSH"
echo -e " [21] nano /etc/network/interfaces\t\t\t[81] server openvpn publik";
echo -e " [22] nano /etc/rc.local\t\t\t\t[82] server openvpn";
echo -e " [23] nano /etc/resolv.conf\t\t\t\t[83] server vpn observium Radensaleh";
echo -e " [24] nano /etc/hosts\t\t\t\t\t[84] server vpn observium Sampoerna";

echo -e " \t\t\t\t\t\t\t[85] server vpn observium Surabaya"
echo -e " Instalasi\t\t\t\t\t\t[86] server vpn observium Semarang"
echo -e " [41] Instalasi tools\t\t\t\t\t[87] server vpn observium Bandung";
echo -e " [42] Instalasi ip statik\t\t\t\t[88] server vpn observium Medan";
echo -e " [43] Instalasi snmp client\t\t\t\t[89] server vpn observium WEJ Maybank";
echo -e " [44] Instalasi rc.local\t\t\t\t[90] server vpn observium BSD";
echo -e " [45] Instalasi openvpn client";

echo ""
echo -e " [98] Openvpn stop\t\t\t\t\t[100] backup log\t\t\t\t\t[102] update xscript.sh"
echo -e " [99] Openvpn start\t\t\t\t\t[101] backup restore image proxmox\t\t\t[103] update xcek.sh"
echo ""
echo " [0] Exit                                                           ";
echo ""
hostname
read -p " Nomor : " choice;
echo "";
case $choice in

1)  clear
    if [ -z "$(ping 8.8.8.8 -c2)" ]; then
    echo ""
    echo "koneksi internet tidak ada"
    echo ""
    else
    ping 8.8.8.8 -c5
    echo ""
    fi
    if [ -z "$(ping google.com -c2)" ]; then
    echo ""
    echo "dns tidak aktif atau terblok"
    echo ""
    else
    ping google.com -c5
    echo ""
    traceroute -m 5 8.8.8.8
    fi
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

2)  clear
    echo ""
    ifconfig
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

3)  clear
    route -n
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

4)  clear
    traceroute google.com
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

5)  clear
    df -h
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

6)  clear
    echo -e "echo 3 > /proc/sys/vm/drop_caches"
    echo 3 > /proc/sys/vm/drop_caches
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

7)  clear
    uptime
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

8) top
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r
    
;;

9) 
    iperf3 -c 10.8.0.1
    echo ""
    echo ""

    iperf3 -c 202.158.68.36

    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r
    
;;


11) 
    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\t#cat /etc/network/interfaces"
    echo ""
    echo ""
    echo "======================================================================================================================"
    echo ""
    echo ""
    cat /etc/network/interfaces
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

12) 
    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\t#cat /etc/rc.local"
    echo ""
    echo ""
    echo "======================================================================================================================"
    echo ""
    echo ""
    cat /etc/rc.local
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r
;;

13) 
    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\t#cat /etc/resolv.conf"
    echo ""
    echo ""
    echo "======================================================================================================================"
    echo ""
    echo ""
    cat /etc/resolv.conf
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r
;;

14) 
    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\t#cat /etc/hosts"
    echo ""
    echo ""
    echo "======================================================================================================================"
    echo ""
    echo ""
    cat /etc/hosts
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

21) 
    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\t#nano /etc/network/interfaces"
    echo ""
    echo ""
    echo "======================================================================================================================"
    echo ""
    echo ""
    nano /etc/network/interfaces
;;

22) 
    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\t#nano /etc/rc.local"
    echo ""
    echo ""
    echo "======================================================================================================================"
    echo ""
    echo ""
    nano /etc/rc.local
;;

23) 
    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\t#nano /etc/resolv.conf"
    echo ""
    echo ""
    echo "======================================================================================================================"
    echo ""
    echo ""
    nano /etc/resolv.conf
;;

24) 
    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\t#nano /etc/hosts"
    echo ""
    echo ""
    echo "======================================================================================================================"
    echo ""
    echo ""
    nano /etc/hosts

;;


41)

    clear
    echo " *--------------------------------------------------------------*"
    echo ""
    echo -e "  \tUpdate dan install command service yang sering digunakan " 
    echo ""
    echo " *---------------------------------------------------------------*"
    echo ""
    echo ""
    read -p "Proses akan di lakukan , ctr+z untuk membatalkan" -n 1 -r
 
    apt update
    apt install mc -y
    apt install screen -y
    apt install sshfs -y
    apt install sshpass -y
    apt install openvpn -y
    apt install iperf3 -y
    apt install snmpd -y
    apt install net-tools -y
    apt install iptables -y
    apt install openssl shellinabox -y

export PATH=$PATH:/usr/sbin
 
read -p "Ubah hostname ? y/n :" -n 1 -r
    echo 
    if [[ ! $REPLY =~ ^[Nn]$ ]]
    then
    echo ""
    read -p "Masukan nama host :   " NAMAHOST
    hostname $NAMAHOST
    echo "$NAMAHOST" > /etc/hostname 
    fi

    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r
 

;;

42)

    clear
    echo " *-----------------------------------------------------*"
    echo ""
    echo "  Menambah ip konfigurasi /etc/network/interfaces " 
    echo ""
    echo " *-----------------------------------------------------*"
    
    ifconfig

    echo ""
    read -p "Masukan type ethernet (contoh . eth0, eth0:1, eth1, dsb...):   " INTERFACE
    echo ""
    read -p "Masukan IP addres ( contoh 192.168.100.1 )  :   " IPADDR
    echo ""
    read -p "Masukan Netmask ( contoh 255.255.255.0 )  :   " NETM
    echo ""
    read -p "Masukan IP Gateway  :   " IPGW
    echo ""
    read -p "Masukan IP DNS :   " IPDNS

    cp /etc/network/interfaces /etc/network/interfaces.bak

    #echo "auto lo" > /etc/network/interfaces
    #echo "iface lo inet loopback" >> /etc/network/interfaces
    echo "" >> /etc/network/interfaces
    echo "auto $INTERFACE " >> /etc/network/interfaces
    echo "iface $INTERFACE inet static " >> /etc/network/interfaces
    echo "    address $IPADDR " >> /etc/network/interfaces
    echo "    netmask $NETM " >> /etc/network/interfaces
    echo "    gateway $IPGW " >> /etc/network/interfaces
    echo "    dns-nameservers $IPDNS " >> /etc/network/interfaces

    nano /etc/network/interfaces

    service networking restart

    ifconfig

    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

43)
    clear
    echo " *-------------------------------------------------------------------------------*"
    echo ""
    echo "  Instalasi snmp client " 
    echo ""
    echo "  1. Copy file snmpd.conf menjadi snmpd.conf.bak " 
    echo ""
    echo "  2. restart service snmpd" 
    echo ""
    echo " *-------------------------------------------------------------------------------*"

    echo ""
    read -p "lokasi :   " LOKASI
    echo ""
    read -p "kontak person / unit : " KONTAKEMAIL
    echo ""
    read -p "email  : " EMAIL
    echo ""

    echo ""
    echo ""
    read -p "Proses akan di lakukan , ctr+z untuk membatalkan" -n 1 -r

    cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.bak

    cat << EOF > /etc/snmp/snmpd.conf

    # Listen di semua interface protocol UDP port 161 
    # agentAddress  udp:161 
    # Only allow Localhost 
    #          sec.name        source      community 
                com2sec         readonly             default        public 
    #     name sec.model  sec.name 
    group network01 v2c        readonly 
    #    target incl/excl   subtree 
    view all    included  .1 
    #      name  context model level   prefix  read    write  notify (unused) 
    access network01 ""      any       noauth    exact  all    none   none 
    # Device Location 
    syslocation $LOKASI
    # System Contact 
    syscontact $KONTAK $EMAIL 
    # Accurate Uptime for Observium 
    extend uptime /bin/cat /proc/uptime 

EOF

    service snmpd restart

;;

44)
    clear
    echo " *-------------------------------------------------------------------------------*"
    echo ""
    echo "  Instalasi rc.local " 
    echo ""
    echo " *-------------------------------------------------------------------------------*"

    echo ""
    echo ""
    read -p "Proses akan di lakukan , ctr+z untuk membatalkan" -n 1 -r

    cat << EOF >> /etc/systemd/system/rc-local.service

[unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target

EOF

    cat << EOF >> /etc/rc.local
#!/bin/sh -e
openvpn --daemon --config /root/openvpn.ovpn
exit 0 

EOF

    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl daemon-reload
    systemctl status rc-local

;;

45)
    clear
    echo " *-------------------------------------------------------------------------------*"
    echo ""
    echo "  Instalasi openvpn client " 
    echo ""
    echo "  1. Copy file openvpn dengak extensi .ovpn " 
    echo ""
    echo "  2. jalankan perintah #openvpn --daemon --config /root/filekonfigurasi.ovpn" 
    echo ""
    echo " *-------------------------------------------------------------------------------*"

    echo ""
    read -p "Masukan nama file ovpn :   " FILEOVPN
    #echo ""
    #read -p "Masukan directory local untuk file ovpn (contoh /home/monitor/ ) :   " DIRECTORYOVPN
    echo ""

    echo ""
    echo ""
    read -p "Proses akan di lakukan , ctr+z untuk membatalkan" -n 1 -r

    #cd $DIRECTORYOVPN
    wget http://202.158.68.36/download/$FILEOVPN
    cp $FILEOVPN /root/openvpn.ovpn

    openvpn --daemon --config $DIRECTORYOVPN$FILEOVPN

    sleep 5

    ifconfig
 
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r
 
;;

51)
    wget http://www.observium.org/observium_installscript.sh
    chmod +x observium_installscript.sh
    ./observium_installscript.sh


;;


55)

    clear
    echo " *-------------------------------------------------------------------------------*"
    echo ""
    echo "  Instalasi DNS server " 
    echo ""
    echo "  1. instalasi bind9 " 
    echo ""
    echo "  2. konfigurasi domain dan ip " 
    echo ""
    echo " *-------------------------------------------------------------------------------*"

    echo ""
    lsb_release -a
    echo ""
    named -v
    echo ""

    read -p "Apakah anda akan update? y/n :" -n 1 -r
    echo 
    if [[ ! $REPLY =~ ^[Nn]$ ]]
    then
    apt update && apt upgrade -y
    fi

    apt install -y bind9 bind9utils bind9-doc dnsutils
    echo ""
    read -p "tekan sembarang" -n 1 -r

    clear
    ifconfig
    cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bak
    cp /etc/bind/named.conf.local /etc/bind/named.conf.local.bak
    cp /etc/bind/named.conf.default-zones /etc/bind/named.conf.default-zones.bak
    cp /etc/bind/named.conf /etc/bind/named.conf.bak

    echo ""

    read -p "Masukan nama Domain  ( contoh labkom.com, labkom.net dll ):   " DOMAIN1
    read -p "Masukan IP address Domain ( contoh 192.168.100.17 ) : " ZIPADDR
    read -p "Masukan 3 bagian segment ip dng urutan 3.2.1  ( contoh 100.168.192 ):" REVERSE
    read -p "Masukan bagian ke 4 dari ip terakhir ( contoh 17 ) :" REVERSE2

    read -p "Masukan ip dns server ( contoh 192.168.100.2 ) :" IPDNS

    cat << EOF >> /etc/bind/named.conf.local
    zone  "$DOMAIN1" IN

    {

         type master ;

         file "/etc/bind/db.$DOMAIN1";

     };



    zone  "$REVERSE.in-addr.arpa {" IN

    {

         type master ;

         file "/etc/bind/db.$REVERSE";

     };
EOF



echo "$""TTL    604800" > /etc/bind/db.$DOMAIN1
cat << EOF >> /etc/bind/db.$DOMAIN1
;
; BIND data file for local loopback interface
; 
@       IN      SOA     $DOMAIN1. root.$DOMAIN1. (

                              2         ; Serial

                         604800         ; Refresh

                          86400         ; Retry

                        2419200         ; Expire

                         604800 )       ; Negative Cache TTL
;
@       IN      NS      $DOMAIN1.
@       IN      A       $ZIPADDR

EOF



echo "$""TTL    604800" > /etc/bind/db.$REVERSE
cat << EOF >> /etc/bind/db.$REVERSE
;
; BIND reverse data file for local loopback interface
;
@       IN      SOA     $DOMAIN1. root.$DOMAIN1. (

                              1         ; Serial

                         604800         ; Refresh

                          86400         ; Retry

                        2419200         ; Expire

                         604800 )       ; Negative Cache TTL

;
@       IN      NS      $DOMAIN1.
$REVERSE2     IN      PTR     $DOMAIN1.
EOF

    cat << EOF > /etc/bind/named.conf.options
    options {

        directory "/var/cache/bind";



        // If there is a firewall between you and nameservers you want

        // to talk to, you may need to fix the firewall to allow multiple

        // ports to talk.  See http://www.kb.cert.org/vuls/id/800113



        // If your ISP provided one or more IP addresses for stable 

        // nameservers, you probably want to use them as forwarders.  

        // Uncomment the following block, and insert the addresses replacing 

        // the all-0's placeholder.



        forwarders {

                $IPDNS;
                8.8.8.8;
        };



        //========================================================================

        // If BIND logs error messages about the root key being expired,

        // you will need to update your keys.  See https://www.isc.org/bind-keys

        //========================================================================

        dnssec-validation auto;



        listen-on-v6 { any; };

    };

EOF

    cat << EOF > /etc/resolv.conf
    nameserver $ZIPADDR
EOF

#    nano /etc/bind/named.conf.local
#    nano /etc/bind/db.$DOMAIN1
#    nano /etc/bind/db.$REVERSE
#    nano /etc/bind/named.conf.options
#    nano /etc/resolv.conf

    service bind9 restart

    sleep 5

    ping $DOMAIN1 -c5

    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;

57) 
    clear
    echo " *-----------------------------------------------------*"
    echo ""
    echo -e " \t Mengaktifkan service NAT pada server " 
    echo ""
    echo " *-----------------------------------------------------*"

    ifconfig
    echo ""
    read -p "Masukan type ethernet ( contoh . eth0, eth0:1, eth1, dsb...)  :   " INTERFACE
    echo YOUR INTERFACE IS.. $INTERFACE

    echo ""
    echo ""

    read -p "Proses konfigurasi NAT di jalankan ? y/n :" -n 1 -r
    echo 
    if [[ ! $REPLY =~ ^[Nn]$ ]]
    then
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
    iptables -t nat -L

    ping 8.8.8.8 -c3

    fi

;;



81)
    ssh -o StrictHostKeyChecking=no root@202.158.68.36

;;

82)
    ssh -o StrictHostKeyChecking=no root@10.8.0.1 

;;

83)
    ssh -o StrictHostKeyChecking=no root@10.8.0.58
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;


84)
    ssh -o StrictHostKeyChecking=no root@10.8.0.47

;;

85)
    ssh -o StrictHostKeyChecking=no root@10.8.0.7

;;

86)
    ssh -o StrictHostKeyChecking=no root@10.8.0.7

;;

87)
    ssh -o StrictHostKeyChecking=no root@10.8.0.7

;;

88)
    ssh -o StrictHostKeyChecking=no root@10.8.0.7

;;

89)
    ssh -o StrictHostKeyChecking=no root@10.8.0.7

;;

90)
    ssh -o StrictHostKeyChecking=no root@10.8.0.7

;;

98)
    sudo killall openvpn
    sudo pkill openvpn
;;

99)
    sudo killall openvpn
    route -n
    sudo route del -net 0.0.0.0/0 gw 10.8.0.1
    sudo ifconfig tun0 down
    sudo openvpn --daemon --config /home/adi/laptopdell.ovpn
    route -n
    ping 10.8.0.1 -c10

;;


102)

    wget http://202.158.68.36/download/xscript.sh

;;

201) 
    again2='n'
    while [[ $again2 != 'Y' ]] || [[ $again2 != 'y' ]];
    do



    clear
    echo "======================================================================================================================"
    echo ""
    echo ""
    echo -e "\t\t\t\tPROXMOX"
    echo ""
    echo -e "\t[0] exit [1] list [2] start [3] stop [4] restart [5] clone [6] delete"
    echo "======================================================================================================================"
    hostname
    read -p " Nomor : " choice2;
    echo "";
    case $choice2 in

    1)  
        echo -e "\tList mesin vm "
        cat /etc/hosts

    ;;

    2)  
        echo -e "\tstart mesin vm "

        qm list

    ;;

    3)  
        echo -e "\tstop mesin vm "

        qm list

    ;;

    4)  
        echo -e "\trestart mesin vm "

        qm list

    ;;

    5)  
        echo -e "\tclone mesin vm "

        qm list

    ;;

    6)  
        echo -e "\tdelete mesin vm "

        qm list

    ;;

    0) again2='Y'
    ;;
    esac
    echo ""
    echo ""
done
;;


205)

vzdump 101 --dumpdir /root/vzdump_backup/ --mode snapshot

;;

206)

qmrestore /mnt/zorin/vzdump-qemu-100-2018_08_18-02_51_31.vma 113

;;

210)

    clear
    echo
    #VBoxManage list hdds
    VBoxManage list vms
    echo 
    echo
    echo " Virtual yang aktif"
    echo
    VBoxManage list runningvms
    echo 
    echo


    echo " Info virtual"
    read -p "Nama virtual :" VMNYA
    echo
    echo " ----- Informasi vrtual -----"
    VBoxManage showvminfo $VMNYA

    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r
;;

211)

    clear
    echo 
    VBoxManage list vms
    echo 
    echo
    echo " Virtual yang aktif"
    echo
    VBoxManage list runningvms
    echo 
    echo
    echo " Start virtual"
    read -p "Nama virtual :" VMNYA
    VBoxManage startvm "$VMNYA" --type headless 

;;

212)
    clear
    echo 
    VBoxManage list vms
    echo 
    echo
    echo " Virtual yang aktif"
    echo
    VBoxManage list runningvms
    echo 
    echo
    echo " Stop virtual"
    read -p "Nama virtual :" VMNYA
    VBoxManage controlvm "$VMNYA" poweroff --type headless


;;

213)
    clear
    echo 
    VBoxManage list vms
    echo 
    echo
    echo " Virtual yang aktif"
    echo
    VBoxManage list runningvms
    echo 
    echo
    echo " Restart virtual"
    read -p "Nama virtual :" VMNYA
    VBoxManage controlvm "$VMNYA" poweroff --type headless
    VBoxManage startvm "$VMNYA" --type headless 


;;

214)
    clear
    echo 
    #VBoxManage list hdds
    VBoxManage list vms
    echo 
    echo
    echo " Virtual yang aktif"
    echo
    VBoxManage list runningvms
    echo 
    echo
    echo " Delete virtual"
    read -p "Nama virtual :" VMNYA
    VBoxManage unregistervm VNAS –delete


;;


215)
    clear
    echo 
    VBoxManage list vms
    echo 
    echo
    echo " Virtual yang aktif"
    echo
    VBoxManage list runningvms
    echo 
    echo
    echo " Clone virtual"
    read -p "Nama master virtual :" VMNYA
    read -p "Nama clone virtual :" VMCLONE
    VBoxManage clonevm $VMNYA --name="$VMCLONE" --register --mode=all --options=keepallmacs --options=keepdisknames --options=keephwuuids

;;

220)
    clear
    sshpass ssh -o StrictHostKeyChecking=no root@10.8.0.1 'cat /etc/openvpn/server/openvpn-status.log | grep ROUTING'
    echo ""
    echo ""
    read -p "Tekan sembarang tombol , kembali ke menu, ctr+z untuk selesai" -n 1 -r

;;


98) echo "Copy file xscript.sh ke server"
   
   echo -n "username : "
   read username
   echo -n "password : "
   read passwordnya
   echo -n "ip server : "
   read ipserver
   echo -n "directory : "
   read directorynya
   sudo sed -i "/exit 0/i\sudo scp -p"$passwordnya" xscript.sh "$username"@"$ipserver":"$directorynya""

   ;;

101)  if [ -z "$(sudo ls -A /etc/default/grub)" ]; then
    echo "Tidak terdeteksi grub, anda yakin pakai Ubuntu 20.04 ?"
    else
    sudo apt-get install ifupdown
    sudo apt-get install net-tools
    sudo cp support/grub /etc/default/grub
    sudo grub-mkconfig -o /boot/grub/grub.cfg
    sudo cp support/resolved.conf /etc/systemd/
    sudo systemctl restart systemd-resolved
    sudo cp support/interfaces /etc/network/
    sudo cp support/rc.local /etc/
    sudo chmod 777 rc.local
    sudo sysmctl enable rc-local.service
    sudo apt-get update
    sudo apt-get install arp-scan
    sudo nano /etc/network/interfaces
    read -p "Tekan enter untuk restart"
    reboot
    fi
    ;;

102)  if [ -z "$(ls -l /etc/network/interfaces)" ]; then
    echo "Tidak terdeteksi ada /etc/network/interfaces"
    else
    sudo nano /etc/network/interfaces
    read -p "Apakah anda mau restart koneksi eth0 & eth1 sekarang? y/n :" -n 1 -r
    echo 
        if [[ ! $REPLY =~ ^[Nn]$ ]]
        then
        ip addr flush eth0 && sudo systemctl restart networking.service
        ip addr flush eth1 && sudo systemctl restart networking.service
        sudo ifconfig
        fi
    fi
    ;;

3)  read -p "Apakah anda mau yakin mau install NAT, DHCP Server, dan iptraf ? y/n :" -n 1 -r
    echo  ""
    if [[ ! $REPLY =~ ^[Nn]$ ]]
    then
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo /sbin/iptables -P FORWARD ACCEPT
    sudo /sbin/iptables --table nat -A POSTROUTING -o eth0 -j MASQUERADE
    sudo cp support/rc.local /etc/
    sudo chmod 777 rc.local
    sudo sysmctl enable rc-local.service
    echo "NAT sudah diinstall"
    sudo apt-get install isc-dhcp-server
    sudo mv /etc/dhcp/dhcp.conf /tmp
    sudo cp support/dhcpd.conf /etc/dhcp
    sudo nano /etc/dhcp/dhcpd.conf
    sudo service isc-dhcp-server restart
    echo "DHCP Server sudah diinstall"
    sudo apt-get install iptraf
    echo "iptraff sudah diinstall"
    fi
    ;;

4)  if [ -z "$(ls -A /etc/dhcp/dhcpd.conf)" ]; then
    echo "Tidak terdeteksi DHCP Server"
    else
    echo "Setting DHCP Server"
    sudo nano /etc/dhcp/dhcpd.conf
    service isc-dhcp-server restart
    fi
    ;;   

5) sudo iptraf-ng
    ;;

6) echo "Isi file rc.local :"
   sudo cat /etc/rc.local
   echo -n "Masukkan ip WAN pada router : "
   read ipwan
   echo "Daftar ip LAN yang dapat dituju :"
   sudo arp-scan --interface=eth1 --localnet
   echo -n "Masukkan ip LAN pada server yang dituju : "
   read iplan
   echo -n "Masukkan nomor port yang akan diforward : "
   read portip
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo iptables -t nat -A PREROUTING -j DNAT -d $ipwan -p tcp --dport $portip --to $iplan
   sudo sed -i "/exit 0/i\sudo iptables -t nat -A PREROUTING -j DNAT -d "$ipwan" -p tcp --dport "$portip" --to "$iplan"" /etc/rc.local
   ;;

7) read -p "Apakah anda yakin install VPN Server PPTP  ? y/n :" -n 1 -r
    echo  ""
    if [[ ! $REPLY =~ ^[Nn]$ ]]
    then
    if [ -z "$(ls -l /etc/pptpd.conf)" ]; then
    echo "Install PPTP Server" 
    sudo apt-get install pptpd
    sudo cp support/etc/pptpd.conf /etc
    sudo cp support/chap-secrets /etc/ppp
    sudo cp support/ppptpd-options /etc/ppp
    sudo nano /etc/pptpd.conf
    sudo nano /etc/ppp/chap-secrets
    sudo nano /etc/ppp/pptpd-options
    sudo service pptpd restart
    else
    echo "Sudah ada PPTP Server"
    fi
    fi
    ;;

8) if [ -z "$(ls -l /etc/pptpd.conf)" ]; then
    echo "Tidak terdeteksi file pptpd.conf pada VPN Server"
    else
    echo "Edit pptpd.conf" 
    sudo nano /etc/pptpd.conf
    sudo service pptpd restart
    fi
    ;;

9) if [ -z "$(ls -l /etc/ppp/chap-secrets)" ]; then
    echo "Tidak terdeteksi file chap-secrets pada VPN Server"
    else
    echo "Edit file chap-secrets" 
    sudo nano /etc/ppp/chap-secrets
    sudo service pptpd restart
    fi
    ;;

10) if [ -z "$(ls -l /etc/pptpd.conf)" ]; then
    echo "Tidak terdeteksi file pptpd-options pada VPN Server"
    else
    echo "Edit file pptpd-options" 
    sudo nano /etc/ppp/pptpd-options
    sudo service pptpd restart
    fi
    ;;

11) if [ -z "$(ls -l /var/lib/dhcp/dhcpd.leases)" ]; then
    echo "Tidak terdeteksi DHCP Server"
    else
    sudo perl support/dhcplist.pl
    fi
    ;;

12) sudo cp support/rc.local /etc/
    sudo chmod 777 rc.local
    sudo sysmctl enable rc-local.service
    ;; 

13) sudo nano /etc/rc.local
    ;;

99) read -p "Apakah anda yakin akan restart? y/n :" -n 1 -r
    echo 
    if [[ ! $REPLY =~ ^[Nn]$ ]]
    then
    reboot
    fi
    ;;

0) exit
    ;;
esac
echo ""
echo ""
done