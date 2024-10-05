
## Fault Prediction in Software Defined Networks (FPSDN)

This project provides a robust framework for extracting specifications from real-world Software Defined Network (SDN) datasets using [DyNetKAT](https://arxiv.org/abs/2102.10035) and identifying potential faulty behaviors within these networks. Our goal is to enhance the reliability and efficiency of SDNs by facilitating detailed analysis and troubleshooting in a fully automated manner. This project builds on the DyNetiKAT tool to provide enhanced network verification capabilities based on the DyNetKAT language. The tool allows for reasoning on reachability and waypointing properties within dynamic networks. Our implementation integrates additional functionalities for extracting topology and DyNetKAT rules from various experiments, including a FatTree example.

## Requirements
  
A linux enviroment with [Python (>= 3.10.12)](https://www.python.org/downloads/)

##  HOW TO INSTALL FPSDN

  #### Steps
  1. Clone this repository if it's not yet on your machine.
  2. Navigate to the root of the FPSDN project (FPSDN folder that contain install.sh)
  3. Run the following commands: `Chmod +x install.sh` and `./install.sh`
      > Note: this can take a while.
  4. To check instalation run `bash run_test.sh`, you should get the following output:
  
      ```sh
        ~/FPSDN$  ./run_test.sh
        Packet: int_to_ext - property: #0: property satisfied.
        Packet: int_to_ext - property: #1: property satisfied.
        Packet: ext_to_int - property: #0: property satisfied.
        Packet: ext_to_int - property: #1: property satisfied.
      ```

## Usage

    python ./FPSDN/FPSDN.py <path_to_maude> <path_to_netkat> <input_log_file_path(.pcapng)>
     
 
    Options:
     -h, --help            show this help message and exit
     -e, --extraction-expriments
                           Extract Topology and DyNetKAT rules of expriments
                           (linear topology with 4 switches, linear topology with
                           10 switches, fattree topology, fattree topology with
                           more complicated log file) and save results.
     -f, --fattree-expriment
                           Fault Scenario: Extract Topology and DyNetKAT rules of
                           Fattree example and save results.
     -l, --from-logfile    Extract Topology and DyNetKAT rules of your specific
                           logfile (provide correct .pcapng log file path).


## Replicating Results of FatTree Fault Scenario

To replicate the results presented in the "[Faults Prediction in Software Defined Networks](https://www.overleaf.com/read/qxhpvjvccdnf#7b3104)" section on "Fault Scenario", execute the following command in your terminal:

    `./run_fattree_fault_scenario.sh`  




## Replicating Result of Extraction Rules Experiments
To replicate the results presented in the "[Faults Prediction in Software Defined Networks](https://www.overleaf.com/read/qxhpvjvccdnf#7b3104)" section on "Implementation", execute the following command in your terminal:

    `./run_extraction_rules_4expriments.sh`
    

## Input format

The input to this tool can include a `.pcapng` log file captured via Wireshark. This file format is used to store network packet data and is essential for extracting topology and DyNetKAT rules.
## output

This tool extracts network topology and DyNetKAT specifications from log files located in the [/FPSDN/output](/FPSDN/output).
