
## Fault Prediction in Software Defined Networks (FPSDN)

This project provides a robust framework for extracting specifications from real-world Software Defined Network (SDN) datasets using [DyNetKAT](https://arxiv.org/abs/2102.10035) and identifying potential faulty behaviors within these networks. Our goal is to enhance the reliability and efficiency of SDNs by facilitating detailed analysis and troubleshooting in a fully automated manner. This project builds on the DyNetiKAT tool to provide enhanced network verification capabilities based on the DyNetKAT language. The tool allows for reasoning on reachability and waypointing properties within dynamic networks. Our implementation integrates additional functionalities for extracting topology and DyNetKAT rules from various experiments, including a FatTree example.

## Requirements

To run this project, ensure you have the following dependencies installed:

[DyNetiKAT](https://github.com/hcantunc/DyNetiKAT/tree/master): If you encounter any issues during installation, please follow the instructions provided in [this document](https://docs.google.com/document/d/1DMl_rSSX-YirfjB2lLB2S2PeMhQExXavpIEZJ_5Mxos/edit?usp=sharing).
 
[Python (>= 3.7)](https://www.python.org/downloads/) including the packages: pyshark and networkx.

[Maude (>= 3.0)](http://maude.cs.illinois.edu/w/index.php/All_Maude_3_versions)

NetKAT tool ([netkat-idd](https://github.com/netkat-lang/netkat))

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
                           logfile (provide correct lof file path).


## Replicating Experiments

To replicate the experiments conducted in this project, you can use the provided script to extract topology and DyNetKAT rules for the specified experiments, including those based on the FatTree topology. The following command will help you run these experiments:

    python3 ./FPSDN/FPSDN.py --extraction-expriments --fattree-expriment <path_to_maude> <path_to_netkat>
    
## Experiment Results

## Input format

The input to this tool can include a `.pcapng` log file captured via Wireshark. This file format is used to store network packet data and is essential for extracting topology and DyNetKAT rules.
## output

This tool extracts network topology and DyNetKAT specifications from log files located in the [/FPSDN/output](/FPSDN/output).
