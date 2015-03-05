######DISCLAIMER: I'M NOT RESPONSIBLE FOR ANY MISUSE OF THIS SCRIPT. IT IS FOR EDUCATIONAL PURPOSES ONLY. NEVER EMAIL PEOPLE WITHOUT THEIR CONSENT. DO NOT USE THIS SCRIPT FOR SPAMMING.
######Changing credits does not make you the coder !
#Description
This mailer is intended to solve common sending problems. It uses the same concept of sending with other problems such as AMS and SendBlaster. It can relay emails via linux SendMail and SMTP for now. It uses a heavily modified PHPMailer class. Read the below sections to understand the advanced functionality of this script. 

#SMTP Settings
This section does not a take a lot of explanation. Enable SMTP and provide the script with its data and let us do the work for you !

#Email data.
This is where the real work comes in. 
####Universal randomizing
This sole concept of this mailer script is randomization so it does not trigger suspicions. 
Let's go through variables one by one, you can input those in all fields.: <br>

&name&*<br>
&surname&*<br>
&to& : victims email<br>
* - Only available when "Use email|name|surname format." is enabled<br>

[random_string] : Will be replaced with a 15 character long string<br>
[random_int] :Will be replaced with a 6 random digits string.<br>

&date& : Time and date of sending
&from& : The sender email adress after randomization (If we have any of course) 


####Subject field
Multiple subjects can be separated by ||, each letter will have a random one. Universal randomizing works here. 

####The sender field
Sender email field. Must be a valid email. Universal randomizing works here. 

####The Reply to field
Reply to email field. Must be a valid email. Universal randomizing works here. It's possible to set it equal to sender (after randomization) if the corresponding case is checked.)

####Real name field
Multiple names can be set using comma "," between them ,each letter will have a random one.

####Attachment
Attach a file to your recipients, note that different hosts have different limits. 

####Priority
Set the XPriority header from Lowest to Highest. This will bring it to the top of the emails. 

####Encoding
This is to set encoding for letters. It could be 7bit, 8bit, Quoted-Printable, base64, binary.

####Email content fields
I use multi-part emails. You can let me generate the text part from the html one. This should be enough not to trigger alerts. You can set it yourself too. 

####Emails field
This field is a bit special, you can personalize your emails if you have their respective names. use the email|name|surname format, place the &name& and &surname& and let us do the rest!

####Bypass attempts
This is basically tampering headers. <br>
 Forge MS Outlook Identity : Forges MSOutlook XSender header<br>
 Make it look as newsletter : Forge newsletter headers (unsubscribe, spam score, etc..)<br>
 Fake OVH headers : Fake OVH headers (Works in almost all mail hosts, well except for major ones: gmail, ymail, hotmail, etc..<br>
 Add verified symbol to the title. : Adds the verified symbol to the title.<br>
 
#CLI USE
This script can be used via CLI Too. use [path/to/your/php]/php mailer.php data.ini maillist.txt<br>
data.ini is a configuration file generated using the WEB interface or a manual edit of the template.<br>
All features are enabled in cli mode except for file joining. It's still not implemented for the moment.<br>


###We are UTS. We are spammers. Provoke us, we will l33t you ! 
###Praise for Souheyel!
