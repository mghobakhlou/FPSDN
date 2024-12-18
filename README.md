
## Fault Prediction in Software Defined Networks (FPSDN)

This project provides a robust framework for extracting specifications from real-world Software Defined Network (SDN) datasets using [DyNetKAT](https://arxiv.org/abs/2102.10035) and identifying potential faulty behaviors within these networks. Our goal is to enhance the reliability and efficiency of SDNs by facilitating detailed analysis and troubleshooting in a fully automated manner. This project builds on the DyNetiKAT tool to provide enhanced network verification capabilities based on the DyNetKAT language. The tool allows for reasoning on reachability and waypointing properties within dynamic networks. Our implementation integrates additional functionalities for extracting topology and DyNetKAT rules from various experiments, including a FatTree example.


##  HOW TO Install and Use FPSDN.
  In this section, we provide guidelines on how to install FPSDN on Ubuntu OS or any Docker environment.
  
  The best way to use FPSDN is on a Ubuntu OS version earlier than 22.04 with [Python (>= 3.10.12)](https://www.python.org/downloads/). 

  ### Install On Ubuntu 22.04
  1. Clone this repository if it's not yet on your machine.
  2. Navigate to the root of the FPSDN project (FPSDN folder that contain install.sh)
  3. Run the following commands: `chmod +x install.sh` and `./install.sh`
      > Note: this can take a while.
  4. To check instalation run `./run_test.sh`. You should get the following output:

      ```sh
        ~/FPSDN$  ./run_test.sh
        Packet: int_to_ext - property: #0: property satisfied.
        Packet: int_to_ext - property: #1: property satisfied.
        Packet: ext_to_int - property: #0: property satisfied.
        Packet: ext_to_int - property: #1: property satisfied.
      ```
  ### Installation Using Docker (Any OS)
  1. Install Docker on your machine by following [this link](https://docs.docker.com/engine/install/). We strongly recommend that Windows users use WSL2 for running Docker.

  2. Clone this repository if it is not already on your machine. Then, navigate to the root of the FPSDN project (the FPSDN folder that contains the Dockerfile).
  
  3.Open a shell or terminal. If you are a Windows user, we recommend using PowerShell or Git Bash. To load the Docker image, run the following command:
      
  > Note: this can take more than 15 minutes based on your machine.
      
      docker build -t fpsdn .
      
       
  This command creates the Docker image "fpsdn:latest".
  You now need to run the image and access a shell inside the container using the following command.
  This command also mounts the app/Expriments directory in the Docker container to the ./Expriments directory on your computer, where input and output files are located.

  Run the following command if you are using a Linux-based OS:
          
      docker run -v "${pwd}"/Expriments:/app/Expriments -it --entrypoint=/bin/bash fpsdn -i
          
  If you are using PowerShell on Windows, run the following command:
        
      docker run -v ${pwd}/Expriments:/app/Expriments -it --entrypoint=/bin/bash fpsdn -i
         
  And run the following command if you are using Git Bash on Windows:
  
      docker run -v "${pwd}/Expriments":/app/Expriments -it --entrypoint= bash fpsdn -i
  
  Some systems ask user to give access to mount the directory, give them this access.
      
  4. The environment is ready. Enjoy FPSDN.
     
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

To replicate the results presented in the "[Faults Prediction in Software Defined Networks](https://www.overleaf.com/read/qxhpvjvccdnf#7b3104)" section on "Fault Scenarios", execute the following command in your terminal or in the docker shell:

    ./run_fault_scenarios.sh  




## Replicating Result of Extraction Rules Experiments
To replicate the results presented in the "[Faults Prediction in Software Defined Networks](https://www.overleaf.com/read/qxhpvjvccdnf#7b3104)" section on "Implementation", execute the following command in your terminal or in the docker shell:

    ./run_extraction_rules_expriments.sh
    

## Input format

The input to this tool can include a `.pcapng` log file captured via Wireshark. This file format is used to store network packet data and is essential for extracting topology and DyNetKAT rules.
## output

This tool extracts network topology and DyNetKAT specifications from log files located in the [/FPSDN/Expriments/](https://github.com/mghobakhlou/FPSDN/tree/main/Expriments).
