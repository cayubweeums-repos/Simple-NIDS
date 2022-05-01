# Plan
- **Optimisitc** 
	- Expand Simple-NIDS to be able to intake any pcap file and give option to:
		- Set individual training set and testing set
		- Split a single pcap into a training and testing set
	- Option to run tests for an existing model or create a new model and test it
		- After test data is shown for new models give option to save it
	- Option to use existing model for realtime test
		- Give real time graphs and charts when using this option
	- Get working LSTM, KNN and Naive Bayes
		- LSTM kinda works, but we will need to see observability in order to check why not fully

## Progress
### Notes / Reminders
- Adapt the attempt at making an interactive menu with rich `rmenu.py` to the menu used to show observability display panels
- Add to README.md
  - Steps to get data set
    - Acquire snort via a ubuntu/debian system
      - I was only able to get snort functional via installing from the apt package manager
      - Download the rules from [here](https://www.snort.org/downloads) for the right version of snort
        - Place these at `/etc/snort/rules/`
      - In the snort.conf located at /etc/snort/snort.conf add the following:
        - In the 'Step #6' portion
          - `output alert_csv: stdout default`
        - In the 'Step #7' portion
          - `include $RULE_PATH/{rule files added previously}`
      - In terminal run the following to have snort generate an alert file based on a .pcap:
        - run `sudo snort -c /etc/snort/snort.conf -r {name or file path to .pcap} > snort-output.log > alerts.csv`
      - IDK where to put this but I added the filter `ip.dst` to wireshark and then exported
        - This is the data set i used to train the models as the program only handles ip packets and this filters everything else out
  - Under assumptions
    - I am assuming that if you are using a different .pcap than the one provided that you have used snort to identify which packets in your dataset are malicious and placed those packets in a .csv file named `alerts.csv`
    - I am also assuming this file is in the `data/` folder

### Anomaly Based detection
- Currently, ensuring that the timestamps for the training/testing packets are in the same format as the alert csv lines
  - I am assuming these are off due to the fact that the csv files exclusively have the label 'normal'
- Next steps
  - Add observability to testing sections
  - Add realtime observability to prediction section
- Want to figure out if there is a way to have a rich.layout and then place *termplots* inside a specific panel
