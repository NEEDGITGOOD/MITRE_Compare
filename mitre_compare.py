import json
import os
import colorama
from colorama import init, Fore, Back, Style
import time
import sys

# Initialize Colorama and set reset
init(autoreset=True)

# Function to clear the screen
def clear_screen():
    if os.name == 'nt': 
        os.system('cls')
    else:  # for Unix & MAC
        os.system('clear')

# Get the Current Folder/Path
script_dir = os.path.dirname(__file__)

# Map of user input to file names
file_map = {
    "1": "malwarebytes.json",
    "2": "cynet.json",
    "3": "deepinstinct.json",
    "4": "mcafee.json",
    "5": "sophos.json",
    "6": "Symantec.json",
    "7": "microsoft.json",
    "8": "elastic.json",
    "9": "eset.json",
    "10": "paloaltonetworks.json",
    "11": "uptycs.json",
    "12": "qualys.json",
    "13": "rapid7.json",
    "14": "vmware.json",
    "15": "withsecure.json",
    "16": "ibmsecurity.json",
    "17": "cycraft.json",
    "18": "cisco.json",
    "19": "bitdefender.json",
    "20": "ahnlab.json",
    "21": "fireeye.json",
    "22": "crowdstrike.json",
    "23": "cyberreason.json",
    "24": "cylance.json",
    "25": "fidelis.json",
    "26": "fortinet.json",
    "27": "sentinelone.json",
    "28": "somma.json",
    "29": "trendmicro.json",
    "30": "checkpoint.json",
}

# Display options for the user
for key, value in file_map.items():
    print(f"{key}. {value.split('.')[0]}")

print(Fore.RED + "Which File?")
user_vendor_input = input("")

# Check if the user input is in the file_map
if user_vendor_input in file_map:
    imported_file = os.path.join("JSON", file_map[user_vendor_input])
else:
    print(Fore.RED + "Invalid selection.")
    sys.exit(1)

# Get the Full Path
full_path = os.path.join(script_dir, imported_file)

# Open the JSON file
with open(full_path, 'r') as imported_json:
    # Load JSON data from file
    data = json.load(imported_json)

# Set Data Directories
aggregates = data["Adversaries"][0]["Aggregate_Data"]["Aggregates"]
current_participant_name = data["Participant_Name"]
current_year = data["Adversaries"][0]["Evaluation_Year"]
steps_data_scenario1 = data["Adversaries"][0]["Detections_By_Step"]["Scenario_1"]["Steps"]
steps_data_scenario2 = data["Adversaries"][0]["Detections_By_Step"]["Scenario_2"]["Steps"]
protection_tests = data["Adversaries"][0]["Protections"]["Protection_Tests"]

# Display the Participant and current year
print(Fore.BLUE + "")
print("This is data about " + str(current_participant_name) + " in the year " + str(current_year) )
print(data["Adversaries"] [0] ["Display_Name"])
print("")

# Display the Data
print("Analytical Coverage: " + data["Adversaries"][0]["Aggregate_Data"]["Aggregates"]["Analytic_Coverage"])
print("Telemetry Coverage: " + data["Adversaries"][0]["Aggregate_Data"]["Aggregates"]["Telemetry_Coverage"])
print("Visibility Coverage: " + data["Adversaries"][0]["Aggregate_Data"]["Aggregates"]["Visibility"])

# Ask for Overview
print("")
ask_user_overview = input(Fore.RED + "Show Overview? (Y/N)") 
if ask_user_overview == "Y":
    clear_screen()
    time.sleep(0.1)
          
    print(Fore.GREEN + "Category 1: The Detection is a Technique" )     
    print(Fore.GREEN + "Insight into: How was it Performed or What was Done")
    print(Fore.GREEN + 'Example: A detection called "Credential Dumping" is triggered with enough detail to show what process originated the behavior against lsass.exe and/or provides detail on what type of credential dumping occurred.')
    print("")
    print(Fore.BLUE + "Category 2: The Detection is a Tactic ")       
    print(Fore.BLUE + "Insight into: Why this would be done")  
    print(Fore.BLUE + 'Example: A detection called “Malicious Discovery” is triggered on a series of discovery techniques. The detection does not identify the specific type of discovery performed')  
    print("") 
    print(Fore.LIGHTCYAN_EX + "Category 3: The Detection is a General")   
    print(Fore.LIGHTCYAN_EX + "Informs that malicious/abnormal event(s) occurred, with relation to the behavior under test. No or limited details are provided as to why the action was performed (tactic), or details for how the action was performed (technique).")   
    print(Fore.LIGHTCYAN_EX + 'Example: cmd.exe /c copy cmd.exe sethc.exe" as abnormal/malicious activity.')    
    print("")
    print(Fore.YELLOW + "Category 4: The Detection is a Telemetry ") 
    print(Fore.YELLOW + "Minimally processed data collected, shows that behavior occurred and be related to the execution mechanism (did happen vs may have happened).") 
    print(Fore.YELLOW + "Example: Command-line output is produced that shows a certain command was run on a workstation by a given username.") 
    print("")
    print(Fore.RED + "Category 5: The Detection is None")    
    print(Fore.RED + "Did not detect the event")  
    print("")
    print(Fore.MAGENTA + "Category 6: The Detection is NA (Not Available)") 
    print(Fore.MAGENTA + "Example: No sensor was deployed in the Linux systems within the environment to capture command-line activity, which would have been required to satisfy the detection criteria of the technique under test.") 
    print("")

# Ask for Steps
ask_user_steps = input(Fore.RED + "Show steps? (Y/N)")
if ask_user_steps == "Y":
    clear_screen()
    ask_user_steps_choice = input(Fore.RED + "Which Scenario? (1 or 2), press 3 for the Protection Test")

else:
    clear_screen()
    print(f" {ask_user_steps} is not an Valid Option. Exiting...")
    sys.exit(1)


# Set Detection to 0
detection_technique = 0
detection_tactic = 0
detection_general = 0
detection_telemetry = 0
detection_none = 0
detection_na = 0

# Set Variables for Protection Tests
protection_none = 0
protection_blocked = 0
protection_na = 0

# If user presses "1" continue with Scenario 1
if ask_user_steps_choice == "1":
    clear_screen()
    print("Displaying Scenario 1")

    for step in steps_data_scenario1:
        print("")
        time.sleep(0.1)
        print(Fore.BLACK + str(step["Step_Num"]) + ". " +  str(step["Step_Name"]))

    # Iterate over the substeps of the current step
        for substep in step["Substeps"]:
         time.sleep(0.05)
         print(" " + str(substep["Substep"]) + ". " +  str(substep["Criteria"]))
         for technique in substep["Detections"]:
          time.sleep(0.05)
          if str(technique["Detection_Type"]) == "Technique":
           print(Fore.GREEN + "             - The Detection is a " + str(technique["Detection_Type"]))  
           detection_technique = detection_technique + 1

          if str(technique["Detection_Type"]) == "Tactic":
           print(Fore.BLUE + "             - The Detection is a " + str(technique["Detection_Type"]))  
           detection_tactic = detection_tactic + 1

          if str(technique["Detection_Type"]) == "General":
           print(Fore.LIGHTCYAN_EX + "             - The Detection is a " + str(technique["Detection_Type"]))
           detection_general = detection_general + 1  

          if str(technique["Detection_Type"]) == "Telemetry":
           print(Fore.YELLOW + "             - The Detection is a " + str(technique["Detection_Type"]))  
           detection_telemetry = detection_telemetry + 1

          if str(technique["Detection_Type"]) == "None":
           print(Fore.RED + "             - The Detection is a " + str(technique["Detection_Type"])) 
           detection_none = detection_none + 1 

          if str(technique["Detection_Type"]) == "N/A":
           print(Fore.MAGENTA + "             - The Detection is a " + str(technique["Detection_Type"])) 
           detection_na = detection_na + 1 

    print("")
    print("That was " + imported_file)
    print("There were " )
    print(Fore.GREEN +  str(detection_technique) + "  Technique Detections")
    print(Fore.BLUE + str(detection_tactic) + "   Tactic Detections")
    print(Fore.LIGHTCYAN_EX + str(detection_general) + "   General Detections")
    print(Fore.YELLOW + str(detection_telemetry) + "   Telemetry Detections")
    print(Fore.RED + str(detection_none) + "   None Detections")
    print(Fore.MAGENTA + str(detection_na) + "   NA Detections")
    exit_prompt = input("Press any Key to exit... ")
    clear_screen()
    print("Exiting...")
    sys.exit(0)

# If user presses "2" continue with Scenario 2
if ask_user_steps_choice == "2":
    clear_screen()
    print("Displaying Scenario 2")   

    for step in steps_data_scenario2:
        print("")
        time.sleep(0.05)
        print(Fore.BLACK + str(step["Step_Num"]) + ". " +  str(step["Step_Name"]))

    # Iterate over the substeps of the current step
        for substep in step["Substeps"]:
         time.sleep(0.05)
         print(" " + str(substep["Substep"]) + ". " +  str(substep["Criteria"]))

         for technique in substep["Detections"]:
          time.sleep(0.1)

          if str(technique["Detection_Type"]) == "Technique":
           print(Fore.GREEN + "             - The Detection is a " + str(technique["Detection_Type"]))  
           detection_technique = detection_technique + 1

          if str(technique["Detection_Type"]) == "Tactic":
           print(Fore.BLUE + "             - The Detection is a " + str(technique["Detection_Type"]))  
           detection_tactic = detection_tactic + 1

          if str(technique["Detection_Type"]) == "General":
           print(Fore.LIGHTCYAN_EX + "             - The Detection is a " + str(technique["Detection_Type"]))  
           detection_general = detection_general + 1

          if str(technique["Detection_Type"]) == "Telemetry":
           print(Fore.YELLOW + "             - The Detection is a " + str(technique["Detection_Type"]))  
           detection_telemetry = detection_telemetry + 1

          if str(technique["Detection_Type"]) == "None":
           print(Fore.RED + "             - The Detection is a " + str(technique["Detection_Type"]))  
           detection_none = detection_none + 1 

          if str(technique["Detection_Type"]) == "N/A":
           print(Fore.MAGENTA + "             - The Detection is a " + str(technique["Detection_Type"]))
           detection_na = detection_na + 1   

    print("")
    print("That was " + imported_file)
    print("There were " )
    print(Fore.GREEN +  str(detection_technique) + "  Technique Detections")
    print(Fore.BLUE + str(detection_tactic) + "   Tactic Detections")
    print(Fore.LIGHTCYAN_EX + str(detection_general) + "   General Detections")
    print(Fore.YELLOW + str(detection_telemetry) + "   Telemetry Detections")
    print(Fore.RED + str(detection_none) + "   None Detections")
    print(Fore.MAGENTA + str(detection_na) + "   NA Detections")
    exit_prompt = input("Press any Key to exit... ")
    clear_screen()
    print("Exiting...")
    sys.exit(0)


# If user presses "3" continue with Protection Tests
if ask_user_steps_choice == "3":
    clear_screen()
    print("Displaying Protection Tests")   

    for protection in protection_tests :
        print("")
        time.sleep(0.1)
        print(Fore.BLACK + str(protection["Test_Num"]) + ". " +  str(protection["Test_Name"]))

    # Iterate over the substeps of the current step
        for substep in protection["Substeps"]:
         time.sleep(0.1)
         print(" " + str(substep["Substep"]) + ". " +  str(substep["Criteria"]))

         if str(substep["Protection_Type"]) == "None":
           print(Fore.RED + "             - Technique got executed by the threat actor.")  
           protection_none = protection_none + 1

         if str(substep["Protection_Type"]) == "Blocked":
           print(Fore.GREEN + "             - The Threat was detected and blocked!" )  
           protection_blocked = protection_blocked + 1

         if str(substep["Protection_Type"]) == "N/A":
           print(Fore.LIGHTBLACK_EX + "             - There is no detection : N/A")  
           protection_na = protection_na + 1

        print("")
        print("That was " + imported_file)
        print("There were " )
        print(Fore.RED +  str(protection_none) + "  Techniques missed")
        print(Fore.GREEN + str(protection_blocked) + "   Techniques blocked")
        print(Fore.LIGHTBLACK_EX + str(protection_na) + "   N/A (Already Blocked or not participating in the linux test)")

        exit_prompt = input("Press any Key to exit... ")
        clear_screen()
        print("Exiting...")
        sys.exit(0)

# If user presses anything other than "1", "2", or "3", exit
if ask_user_steps_choice not in ["1", "2", "3"]:
    clear_screen()
    print("Invalid Selection. Exiting...")
    sys.exit(1)
