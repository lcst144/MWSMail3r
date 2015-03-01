
#Description
This mailer is intended to solve common sending problems. It uses the same concept of sending with other problems such as AMS and SendBlaster. It can relay emails via linux SendMail and SMTP for now. It uses a heavily modified PHPMailer class. Read the below sections to understand the advanced functionality of this script. 

#SMTP Settings
This section does not a take a lot of explanation. Enable SMTP and provide the script with its data and let us do the work for you !

#Email data.
This is where the real work comes in. 
<h4>Universal randomizing</h4>
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


<h4>Subject field</h4>
Multiple subjects can be separated by ||, each letter will have a random one. Universal randomizing works here. 

<h4>The sender field</h4>
Sender email field. Must be a valid email. Universal randomizing works here. 

<h4>The Reply to field</h4>
Reply to email field. Must be a valid email. Universal randomizing works here. It's possible to set it equal to sender (after randomization) if the corresponding case is checked.)

<h4>Real name field</h4>
Multiple names can be set using comma "," between them ,each letter will have a random one.

<h4>Attachment</h4>
Attach a file to your recipients, note that different hosts have different limits. 

<h4>Priority</h4>
Set the XPriority header from Lowest to Highest. This will bring it to the top of the emails. 

<h4>Encoding</h4>
This is to set encoding for letters. It could be 7bit, 8bit, Quoted-Printable, base64, binary.

<h4>Email content fields</h4>
I use multi-part emails. You can let me generate the text part from the html one. This should be enough not to trigger alerts. You can set it yourself too. 

<h4>Emails field</h4>
This field is a bit special, you can personalize your emails if you have their respective names. use the email|name|surname format, place the &name& and &surname& and let us do the rest!

<h4>Bypass attempts</h4>
This is basically tampering headers. 
 Forge MS Outlook Identity : Forges MSOutlook XSender header
 Make it look as newsletter : Forge newsletter headers (unsubscribe, spam score, etc..)
 Fake OVH headers : Fake OVH headers (Works in almost all mail hosts, well except for major ones: gmail, ymail, hotmail, etc..
 Add verified symbol to the title. : Adds the verified symbol to the title.
 
<h2>We are UTS. We are spammers. Provoke us, we will l33t you ! </h2>
