# Server Management Panel
A simple Server Management Panel, powered with n8n and MySQL

## What can it do?
This Panel allows you to send quick commands to your server.
Just create a server, give it a server id and a label, add the server id in n8n and connect n8n via ssh to your server.
Now cou can create commands and quickly send them to the server, without the need to ssh into them first.   
It even comes with a speedtest function, to quickly test the network speed.  
A diagnostic feature is included as well, which allows you to quickly run a diagnostic on the server, which is done by integrating OpenAI into the n8n workflow.

## Admin Page
The Panel has an admin page, which is locked behind credentials. 
This Page allows you to create, edit or delete servers and commands, as well as toggle the visibility of the commands/servers to users who are not logged in.

## Setup
To set the panel up follow this [documentation for linux](https://github.com/sapooze/server-management-panel/wiki/Setup-%E2%80%90-Linux).
