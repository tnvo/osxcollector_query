# osxcollector_query
Note from a training at BrrCon

Using Yelp's Open source:
https://github.com/Yelp/osxcollector

Along with: https://github.com/Yelp/osxcollector_output_filters

To pipe out >> output.json

```
To run on mac: (if installed python via home-brew)
 sudo /usr/bin/python2.7 osxcollector.py
```

```

pretty json:
cat osxcollect-2018_06_08-10_35_14.json | jq '.' 

how many output;
cat osxcollect-2018_06_08-10_35_14.json | wc -l 
   66768

how many sections & subsections:
cat osxcollect-2018_06_08-10_35_14.json | jq '.osxcollector_section' | sort | uniq
"accounts"
"applications"
"chrome"
"downloads"
"executables"
"firefox"
"kext"
"mail"
"quarantines"
"safari"
"startup"
"system_info"
"version"

subsections:
cat osxcollect-2018_06_08-10_35_14.json | jq '.osxcollector_subsection' | sort | uniq
"addons"
"applications"
"archived_history"
"content_prefs"
"cookies"
"databases"
"downloads"
"email_downloads"
"extension"
"extension_files"
"extensions"
"formhistory"
"health_report"
"history"
"install_history"
"json_files"
"launch_agents"
"local_storage"
"localstorage"
"login_data"
"login_items"
"old_email_downloads"
"permissions"
"preferences"
"recent_items"
"scripting_additions"
"signons"
"social_accounts"
"system_admins"
"system_users"
"top_sites"
"web_data"
"webapps_store"

List application :
cat osxcollect-2018_06_08-10_35_14.json | jq 'select(.osxcollector_section=="applications")’ 

Count number of apps cat output.json | jq 'select(.osxcollector_section=="applications")|.osxcollector_incident_id' | wc –l 

Count unique bundle ids (NOTE THAT SOME APPS MAY NOT HAVE THIS KEY) 
cat osxcollect-2018_06_08-10_35_14.json | jq 'select(.osxcollector_section=="applications")|.osxcollector_bundle_id' | sort | uniq | wc -l 

List kernel extensions using jq
cat osxcollect-2018_06_08-10_35_14.json | jq 'select(.osxcollector_section=="kext")’ 

List file paths for kernel extensions 
cat osxcollect-2018_05_18-12_01_56.json | jq 'select(.osxcollector_section=="kext")|.file_path' | sort | uniq

What browsers were used:
cat osxcollect-2018_05_18-12_01_56.json | jq '.osxcollector_section + "." + .osxcollector_subsection' | sort | uniq

Unique urls:
cat osxcollect-2018_05_18-12_01_56.json | jq 'select(.osxcollector_section=="safari" and .osxcollector_subsection=="history")|.url' 

Use grep to select the time frame you want, then jq to parse the json. 
cat osxcollect-2018_05_18-12_01_56.json | grep ‘2018-02-02’ | jq … 

For a specific date/hour: 
cat  osxcollect-2018_05_18-12_01_56.json | grep ‘2018-02-02 20:’ | jq … 

For a specific time range: 
cat  osxcollect-2018_05_18-12_01_56.json | grep ‘2018-02-02 20:3[2-6]’ | jq …

Find events that happened near time "2018-05-17 13:38”. 
cat  osxcollect-2018_05_18-12_01_56.json | grep "2018-05-17 13:38" | jq '.osxcollector_section' | sort | uniq

How many sections have hashes? 
cat  osxcollect-2018_05_18-12_01_56.json |  jq   z002kmz@acbc32b40e83
'select(has("md5"))|.osxcollector_section' | sort | uniq

Step 2: Select all relevant entries and print out the hash of your choice 
cat  osxcollect-2018_05_18-12_01_56.json | jq 'select(.osxcollector_section=="applications" or .osxcollector_section=="kext" or .osxcollector_section=="startup")|.sha1’ | sort | uniq >> hash_whitelist.txt

Explore json output
cat  osxcollect-2018_05_18-12_01_56.json |  jq '.osxcollector_section + "." + .osxcollector_subsection' | sort | uniq -c | sort -r 


What was flagged by VT on a blacklist? cat analysis.json | jq 'select(false == has("osxcollector_shadowserver")) | select(has("osxcollector_vthash") or has("osxcollector_vtdomain") or has("osxcollector_opendns") or has("osxcollector_blacklist") or has("osxcollector_related"))'

Where where quarantined files downloaded from?
cat analysis.json | jq 'select(.osxcollector_section=="quarantines")| .LSQuarantineOriginURLString'

Exclude whitelisted hashes during commandline analysis. 
cat analysis.json | grep -v -f hash_whitelist.txt | grep -v "plist file not found" 
cat output.json | grep thingy | jq '.osxcollector_section + "." + .osxcollector_subsection' | sort | uniq -c 

What was flagged by VT? On a blacklist? 
cat analysis.json | jq 'select(false == has("osxcollector_shadowserver")) | select(has("osxcollector_vthash") or has("osxcollector_vtdomain") or has("osxcollector_opendns") or has("osxcollector_blacklist") or has("osxcollector_related"))' 

Where where quarantined files downloaded from?
cat analysis.json | jq 'select(.osxcollector_section=="quarantines")| .LSQuarantineOriginURLString'

Exclude whitelisted hashes during commandline analysis. 
cat analysis.json | grep -v -f hash_whitelist.txt | grep -v "plist file not found"

List and count the unique sections with that string. 
cat output.json | grep thingy | jq '.osxcollector_section + "." + .osxcollector_subsection' | sort | uniq -c 

```
