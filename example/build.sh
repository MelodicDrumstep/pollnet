set -e

#TCPDIRECT_OPT="-DUSE_TCPDIRECT -lonload_zf"
EFVI_OPT="-DUSE_EFVI -lciul1"

#g++ -O3 -Wall tcpclient.cc -o tcpclient $TCPDIRECT_OPT $EFVI_OPT 
#g++ -O3 -Wall tcpserver.cc -o tcpserver $TCPDIRECT_OPT $EFVI_OPT
#g++ -O3 -Wall udpreceiver.cc -o udpreceiver $EFVI_OPT
#g++ -O3 -Wall tcpsniffer.cc -o tcpsniffer $EFVI_OPT
g++ -O3 -Wall udpping.cc -o udpping 
g++ -O3 -Wall udppong.cc -o udppong
#g++ -O3 -Wall udpping.cc -o udpping_efvi $EFVI_OPT
#g++ -O3 -Wall udppong.cc -o udppong_efvi $EFVI_OPT
#g++ -O3 -Wall udprecv.cc -o udprecv $EFVI_OPT
#g++ -O3 -Wall udpsend.cc -o udpsend $EFVI_OPT
#g++ -O3 -Wall efvi_ping.cc -o efvi_ping -lciul1
#g++ -O3 -Wall efvitcp_client.cc -o efvitcp_client -lciul1 -DEFVITCP_DEBUG
#g++ -O3 -Wall efvitcp_server.cc -o efvitcp_server -lciul1 -DEFVITCP_DEBUG
