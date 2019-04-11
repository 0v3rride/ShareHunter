# ShareHunter.py
This is a work in progress and does not fully function as intended.

* Requires Python 3 and pysmb module. 
* Currently works the best on Windows at the moment.
* Share permission checks are not entierly accurate. Currently working on finding a way to correct this.

### Why?
* MSF auxiliary/scanner/smb/smb_enumshares doesn't spider shares despite arguments given.
* SMBmap's password flag doesn't allow passwords with metachars (!, ?, etc.) due to the way bash interprets these characters.
* Wanted to try something new.

### Todo list
* Create a working version for Linux 
