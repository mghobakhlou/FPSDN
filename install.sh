#install all the dependencies
# sudo apt-get update
sudo apt install tshark libncurses5 opam git python3-pip --assume-yes
pip3 install numpy networkx --break-system-packages
pip3 install pyshark matplotlib --break-system-packages

#install NetKAT tool
# git clone https://github.com/netkat-lang/netkat/
cd netkat
eval $(opam env)
opam init -y
eval $(opam env)
opam install mparser=1.2.3 -y
opam install . --deps-only -y
opam install printbox printbox-text printbox-html
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
pip3 install numpy
