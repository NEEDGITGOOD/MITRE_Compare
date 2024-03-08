import json
import os
import colorama
from colorama import init, Fore, Back, Style
import time

#Initializie Colorama and set reset
init(autoreset=True)

# Get the Current Folder/Path
absolute_path = os.path.dirname(os.path.abspath(__file__))

# Choose File
print("1. Malwarebytes")
print("2. Cynet")
print("3. Deepinstinct")
print("4. Mcafee")
print("5. Sophos")
print("6. Symantec")
print("7. Microsoft")
print("8. Elastic")
print("9. ESET")
print("10. Palo Alto Networks")
print("11. Uptycs")
print("12. Qualys")
print("13. Rapid7")
print("14. VMware")
print("15. Withsecure")
print("16. IBM Security")
print("17. Cycraft")
print("18. Cisco")
print("19. Bitdefender")
print("20. Ahnlab")
print("21. Fire Eye")
print("22. Crowdstrike")
print("23. Cyberreason")
print("24. Cyclance")
print("25. Fidelis")
print("26. Fortinet")
print("27. Sentinel One")
print("28. Somma")
print("29. Trendmicro")
print("30. Checkpoint")
print(Fore.RED + "Which File?")
user_vendor_input = input("")

# Define User based input to the file
if user_vendor_input == "1":
    imported_file = "json\\malwarebytes.json"
if user_vendor_input == "2":
    imported_file = "json\\cynet.json"
if user_vendor_input == "3":
    imported_file = "json\\deepinstinct.json"
if user_vendor_input == "4":
    imported_file = "json\\mcafee.json"
if user_vendor_input == "5":
    imported_file = "json\\sophos.json"
if user_vendor_input == "6":
    imported_file = "json\\Symantec.json"
if user_vendor_input == "7":
    imported_file = "json\\microsoft.json"
if user_vendor_input == "8":
    imported_file = "json\\elastic.json"
if user_vendor_input == "9":
    imported_file = "json\\eset.json"
if user_vendor_input == "10":
    imported_file = "json\\paloaltonetworks.json"
if user_vendor_input == "11":
    imported_file = "json\\uptycs.json"
if user_vendor_input == "12":
    imported_file = "json\\qualys.json"
if user_vendor_input == "13":
    imported_file = "json\\rapid7.json"
if user_vendor_input == "14":
    imported_file = "json\\vmware.json"
if user_vendor_input == "15":
    imported_file = "json\\withsecure.json"
if user_vendor_input == "16":
    imported_file = "json\\ibmsecurity.json"
if user_vendor_input == "17":
    imported_file = "json\\cycraft.json"
if user_vendor_input == "18":
    imported_file = "json\\cisco.json"
if user_vendor_input == "19":
    imported_file = "json\\bitdefender.json"
if user_vendor_input == "20":
    imported_file = "json\\ahnlab.json"
if user_vendor_input == "21":
    imported_file = "json\\fireeye.json"
if user_vendor_input == "22":
    imported_file = "json\\crowdstrike.json"
if user_vendor_input == "23":
    imported_file = "json\\cyberreason.json"
if user_vendor_input == "24":
    imported_file = "json\\cylance.json"
if user_vendor_input == "25":
    imported_file = "json\\fidelis.json"
if user_vendor_input == "26":
    imported_file = "json\\fortinet.json"
if user_vendor_input == "27":
    imported_file = "json\\sentinelone.json"
if user_vendor_input == "28":
    imported_file = "json\\somma.json"
if user_vendor_input == "29":
    imported_file = "json\\trendmicro.json"    
if user_vendor_input == "30":
    imported_file = "json\\checkpoint.json"

# Get the Full OS Path
full_path = os.path.join(absolute_path, imported_file)

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

# Clear the Screen
os.system('cls')

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

    os.system('cls')

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

    os.system('cls')

    ask_user_steps_choice = input(Fore.RED + "Which Scenario? (1 or 2), press 3 for the Protection Test")

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

# If user presses "2" continue with Scenario 2
if ask_user_steps_choice == "2":
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

# If user presses "3" continue with Protection Tests
if ask_user_steps_choice == "3":
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

# If user presses anything other than "3" continue with Protection Tests
if ask_user_steps_choice != "3":
    print("")
    print("That was " + imported_file)
    print("There were " )
    print(Fore.GREEN +  str(detection_technique) + "  Technique Detections")
    print(Fore.BLUE + str(detection_tactic) + "   Tactic Detections")
    print(Fore.LIGHTCYAN_EX + str(detection_general) + "   General Detections")
    print(Fore.YELLOW + str(detection_telemetry) + "   Telemetry Detections")
    print(Fore.RED + str(detection_none) + "   None Detections")
    print(Fore.MAGENTA + str(detection_na) + "   NA Detections")
else:
    print("")
    print("That was " + imported_file)
    print("There were " )
    print(Fore.RED +  str(protection_none) + "  Techniques missed")
    print(Fore.GREEN + str(protection_blocked) + "   Techniques blocked")
    print(Fore.LIGHTBLACK_EX + str(protection_na) + "   N/A (Already Blocked or not participating in the linux test)")
