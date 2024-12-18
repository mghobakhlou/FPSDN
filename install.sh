#install all the dependencies
sudo apt-get update
sudo apt install git python3-pip --assume-yes
sudo apt install tshark libncurses5 opam --assume-yes
pip3 install pandas pyshark matplotlib numpy networkx


#install NetKAT tool
# git clone https://github.com/netkat-lang/netkat/
cd netkat
opam init -y
eval $(opam env)
opam install printbox-text printbox-html -y
opam install mparser=1.2.3 -y
opam install . --deps-only -y
opam install core_unix -y
eval $(opam env)
make
cd ..

#download Maude
wget maude.cs.illinois.edu/w/images/3/38/Maude-3.1-linux.zip
unzip Maude-3.1-linux.zip
rm Maude-3.1-linux.zip
cd maude-3.1
chmod +x maude.linux64
cd ..
chmod +x run_test.sh
chmod +x run_fault_scenarios.sh
chmod +x run_extraction_rules_expriments.sh
