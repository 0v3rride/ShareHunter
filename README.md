# ShareHunter
The Python script is a work in progress and does not fully function as intended.

* Python
  * Requires Python 3 and pysmb module. 
  * Currently works the best on Windows at the moment.
  * Share permission checks are not entierly accurate. Currently working on finding a way to correct this.
  
* PowerShell
  * Calls the net executable with the view option and parses the output which is then feed to the Get-Acl cmdlet.

### Why?
* MSF auxiliary/scanner/smb/smb_enumshares doesn't spider shares despite arguments given.
* SMBmap's password flag doesn't allow passwords with metachars (!, ?, etc.) due to the way bash interprets these characters.
* Wanted to try something new.

### Todo list
* Create a working version for Linux (Python) 
* Add functionality to enumerate shares as a different user with credentials (PowerShell)
