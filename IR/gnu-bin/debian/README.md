# Add Apt sources.lst
                            wget -q -O - https://updates.atomicorp.com/installers/atomic | sudo bash
    
                            # Update apt data
                            sudo apt-get update
    
                            # Server
                            sudo apt-get install ossec-hids-server
    
                            # Agent
                            sudo apt-get install ossec-hids-agent


