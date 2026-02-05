# IT_359_Final_Project_Spring_2026
Our final project for IT 359 will be based upon fileless malware. Fileless malware is a type of malware that oeprates within a computer's RAM, instead of writing files to the hard drive.

## Team Name
 - Hack the Blocks
   
## Team Members
 - Zac Davis
 - Caleb Clauson

## Purpose of the Project
The primary goal of this project is to explore the shift in the cybersecurity landscape from file-based threats to behavior-based threats. As modern operating systems become better at scanning files on disk, attackers have pivoted to memory-resident techniques that leave no traditional footprint.

## Full Project Idea
The goal of our project is to create a "Red Team" script that stimulates Fileless malware using PowerShell and Python. We will utilize PowerShell to create the malware, while Python will be used as the Command and Control listener. For the PowerShell script, we will use the script to execute all of the commands in memory. With the Python script, our goal is to create a script that will run on a seperate attacking machine to recieve data via HTTP/HTTPS. 

Then for the "Blue Team" aspect of the project, we plan to create a script, likely in Python, to detect the threat. Additonally, we plan to utilize artificial intelligence/machine learning to detect the fileless malware in a defensive way. One way to do this is training a model to detect the fileless malware to prevent the attack from continuing.

