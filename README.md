
## Fault Prediction in Software Defined Networks (FPSDN)

This project provides a robust framework for extracting specifications from real-world Software Defined Network (SDN) datasets using [DyNetKAT](https://arxiv.org/abs/2102.10035) and identifying potential faulty behaviors within these networks. Our goal is to enhance the reliability and efficiency of SDNs by facilitating detailed analysis and troubleshooting in a fully automated manner. This project builds on the DyNetiKAT tool to provide enhanced network verification capabilities based on the DyNetKAT language. The tool allows for reasoning on reachability and waypointing properties within dynamic networks. Our implementation integrates additional functionalities for extracting topology and DyNetKAT rules from various experiments, including a FatTree example.

## Requirements
  
A linux enviroment with [Python (>= 3.10.12)](https://www.python.org/downloads/)

##  HOW TO INSTALL FPSDN

  #### Steps
  1. Clone this repository if it's not yet on your machine.
  2. Navigate to the root of the FPSDN project (FPSDN folder that contain install.sh)
  3. Run the following commands: `chmod +x install.sh` and `./install.sh`
      > Note: this can take a while.
  4. To check instalation run `./run_test.sh`, you should get the following output:
  
      ```sh
        ~/FPSDN$  ./run_test.sh
        Packet: int_to_ext - property: #0: property satisfied.
        Packet: int_to_ext - property: #1: property satisfied.
        Packet: ext_to_int - property: #0: property satisfied.
        Packet: ext_to_int - property: #1: property satisfied.
      ```

## Usage

    python ./FPSDN/FPSDN.py <path_to_maude> <path_to_netkat> <path_to_logfiles(directory of .pcapng files)>
     
 
    Options:
     -h, --help            show this help message and exit
     -e, --extraction-expriments
                           Extract Topology and DyNetKAT rules of expriments
                           (linear topology with 4 switches, linear topology with
                           10 switches, fattree topology, fattree topology with
                           more complicated log file) and save results.
     -f, --fault_scenarios
                           Fault Scenarios: Extract Topology and DyNetKAT rules of fault scenarios and save                                 results.
     -l, --from-logfiles    Extract Topology and DyNetKAT rules of your specific log files.

`<path_to_maude>` --> The path should be as follows: `./maude-3.1/maude.linux64`. <br>
`<path_to_netkat>` --> The path should be as follows: `./netkat/_build/install/default/bin/katbv`.
`<path_to_logfiles(directory of .pcapng files)>` --> The path should be as follows: `./Expriments/Fault_Scenarios`


## Replicating Results of Fault Scenarios

To replicate the results presented in the "[Faults Prediction in Software Defined Networks](https://www.overleaf.com/read/qxhpvjvccdnf#7b3104)" section on "Fault Scenarios", execute the following command in your terminal:

    ./run_fault_scenarios.sh  




## Replicating Result of Extraction Rules Experiments
To replicate the results presented in the "[Faults Prediction in Software Defined Networks](https://www.overleaf.com/read/qxhpvjvccdnf#7b3104)" section on "Implementation", execute the following command in your terminal:

    ./run_extraction_rules_expriments.sh
    

## Input format

The input to this tool can include a `.pcapng` log file captured via Wireshark. This file format is used to store network packet data and is essential for extracting topology and DyNetKAT rules.
## output

This tool extracts network topology and DyNetKAT specifications from log files located in the [/FPSDN/Expriments/](https://github.com/mghobakhlou/FPSDN/tree/main/Expriments).
